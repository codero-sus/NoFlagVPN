"""``nfvpn doctor``: what this machine is about to look like on the wire.

Three groups of checks:

**Environment** — Python version, cryptographic backend and a measured
throughput, so a user can tell "the tunnel is slow" from "my relay is far away".

**Local hygiene** — file permissions on key material, whether the proxy is bound
to anything but loopback, whether a relay has been configured to dial private
addresses.  These are the mistakes that actually get people compromised, and
they are all visible from inside.

**Traffic shape** — what the shaping profile does to a realistic mix of
payloads: how much overhead it costs and how many distinct sizes an observer
gets to see.  A single fixed size for everything is a fingerprint; so is a
distribution with one bucket.
"""

from __future__ import annotations

import json
import os
import platform
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from nfvpn.config import ClientConfig, ServerConfig, config_dir
from nfvpn.core.primitives import backend_name
from nfvpn.framing.constants import HEADER_SIZE, TAG_SIZE
from nfvpn.traffic import Shaper, get_profile, profile_names

__all__ = ["Audit", "benchmark_backends", "run_doctor"]


@dataclass
class Audit:
    """Findings, grouped by how much they matter."""

    findings: list[tuple[str, str, str]] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    def add(self, level: str, title: str, detail: str = "") -> None:
        self.findings.append((level, title, detail))

    @property
    def warnings(self) -> list[tuple[str, str, str]]:
        return [item for item in self.findings if item[0] == "warn"]

    def render(self) -> str:
        lines = []
        if self.facts:
            lines.append("environment")
            width = max(len(str(key)) for key in self.facts) + 2
            for key, value in self.facts.items():
                lines.append(f"  {key!s:<{width}}{value}")
            lines.append("")
        lines.append("findings")
        for level, title, detail in self.findings:
            marker = {"ok": "  ok  ", "warn": " warn ", "info": " info "}[level]
            lines.append(f"  [{marker}] {title}" + (f"\n           {detail}" if detail else ""))
        lines.append("")
        if self.warnings:
            lines.append(f"{len(self.warnings)} thing(s) worth fixing.")
        else:
            lines.append("Nothing alarming found.")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "facts": self.facts,
            "findings": [
                {"level": level, "title": title, "detail": detail}
                for level, title, detail in self.findings
            ],
            "warnings": len(self.warnings),
        }


def benchmark_backends(payload_size: int = 1 << 16, rounds: int = 8) -> dict:
    """Time the available AEAD backends on a realistic payload size."""
    from nfvpn.core import primitives

    results: dict = {"active": backend_name(), "python": sys.version.split()[0]}
    payload = bytes(payload_size)
    key = bytes(range(32))
    nonce = b"\x00" * 12
    for name in ("pure", "cryptography"):
        try:
            primitives.use_backend(name)
        except Exception:
            continue
        start = time.perf_counter()
        for _ in range(rounds):
            primitives.seal(key, nonce, payload, b"")
        elapsed = time.perf_counter() - start
        if elapsed <= 0:  # pragma: no cover - clock resolution
            continue
        results[f"{name}_mb_per_second"] = round(payload_size * rounds / elapsed / 1e6, 2)
    primitives.use_backend("pure")
    return results


def _permission_findings(audit: Audit, directory: Path) -> None:
    if not directory.exists():
        audit.add("info", "no configuration directory yet", str(directory))
        return
    secrets = [
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix in (".key", ".json")
    ]
    if not secrets:
        audit.add("info", "no key material found", f"nothing in {directory}")
        return
    exposed: list[str] = []
    for path in secrets:
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            exposed.append(f"{path.name} ({stat.S_IMODE(mode):04o})")
    if exposed:
        audit.add(
            "warn",
            "key material is readable by other users",
            "chmod 600 " + " ".join(str(directory / name.split(" ")[0]) for name in exposed),
        )
    else:
        audit.add("ok", "key material is private", f"{len(secrets)} file(s) at 0600 in {directory}")


def _policy_findings(audit: Audit, directory: Path) -> None:
    relay_path = directory / "relay.json"
    if relay_path.exists():
        try:
            server = ServerConfig.load(relay_path)
        except Exception as exc:
            audit.add("warn", "relay.json could not be read", str(exc))
        else:
            if server.egress.allow_private_literals:
                audit.add(
                    "warn",
                    "the relay will dial private addresses",
                    "allow_private_literals is on: this relay can reach your LAN and "
                    "the cloud metadata service on behalf of any member",
                )
            else:
                audit.add(
                    "ok",
                    "relay egress policy blocks private ranges",
                    f"{len(server.egress.deny_networks)} ranges denied, "
                    f"{len(server.egress.deny_ports)} ports denied",
                )
            if not server.tls_cert:
                audit.add(
                    "warn",
                    "the relay is not using TLS",
                    "a passive observer sees the WebSocket handshake; "
                    "put a TLS terminator in front or configure tls_cert/tls_key",
                )
    else:
        audit.add("info", "no relay configuration here", f"{relay_path} does not exist")

    client_path = directory / "client.json"
    if client_path.exists():
        try:
            client = ClientConfig.load(client_path)
        except Exception as exc:
            audit.add("warn", "client.json could not be read", str(exc))
        else:
            if client.listen_host not in ("127.0.0.1", "::1", "localhost"):
                audit.add(
                    "warn",
                    "the local proxy is bound beyond loopback",
                    f"listen_host={client.listen_host}: anyone who can reach that port "
                    "can use your tunnel (use --proxy-auth if that is intentional)",
                )
            else:
                audit.add("ok", "the local proxy stays on loopback", client.listen_host)
            if client.insecure_tls:
                audit.add(
                    "warn",
                    "TLS certificate validation is disabled",
                    "the carrier can be impersonated; use --ca with your own CA instead",
                )
    else:
        audit.add("info", "no client configuration here", f"{client_path} does not exist")


def _shape_findings(audit: Audit, profile_name: str) -> None:
    import random

    shaper = Shaper(get_profile(profile_name), random.Random(1234))
    payloads = [64, 256, 1400, 4096, 16384, 65536]
    rows = []
    for payload in payloads:
        plaintext = shaper.padded_plaintext(payload + 2)
        total = HEADER_SIZE + TAG_SIZE + plaintext
        rows.append((payload, total, total - payload))
    overhead = sum(row[2] for row in rows) / sum(row[0] + row[2] for row in rows)
    sizes = {
        HEADER_SIZE + TAG_SIZE + shaper.padded_plaintext(length + 2)
        for length in range(0, 20000, 13)
    }
    audit.facts["shaping profile"] = profile_name
    audit.facts["wire sizes seen"] = f"{len(sizes)} distinct sizes between {min(sizes)} and {max(sizes)} B"
    audit.facts["overhead"] = f"{overhead * 100:.1f}% at typical payload sizes"

    if profile_name == "off":
        audit.add(
            "warn",
            "traffic shaping is off",
            "packet sizes follow your traffic exactly, which is the strongest signal "
            "a passive observer can ask for",
        )
    elif len(sizes) < 4:
        audit.add("warn", "the shaping profile has few size classes", f"{len(sizes)} distinct sizes")
    else:
        audit.add(
            "ok",
            "payload sizes are quantised into size classes",
            f"{len(sizes)} distinct wire sizes; overhead {overhead * 100:.1f}%",
        )

    profile = get_profile(profile_name)
    if profile.cover_interval:
        audit.add(
            "info",
            "cover traffic is scheduled",
            f"a padding record roughly every {profile.cover_interval:.0f}s of silence",
        )
    if profile.base_delay or profile.mean_jitter:
        audit.add(
            "info",
            "timing is shaped",
            f"+{profile.base_delay * 1000:.0f} ms base and "
            f"{profile.mean_jitter * 1000:.0f} ms mean jitter (costs latency)",
        )


def run_doctor(*, json_output: bool = False) -> int:
    """Collect findings and print them; exits non-zero when there are warnings."""
    audit = Audit()
    audit.facts["python"] = f"{platform.python_version()} ({platform.system()} {platform.release()})"
    audit.facts["crypto backend"] = backend_name()
    audit.facts["config directory"] = str(config_dir())
    audit.facts["profiles"] = ", ".join(profile_names())

    supported = sys.version_info >= (3, 10)
    audit.add(
        "ok" if supported else "warn",
        f"Python {platform.python_version()}",
        "" if supported else "NoFlagVPN targets Python 3.10 or newer",
    )

    timings = benchmark_backends()
    for name, value in timings.items():
        if name.endswith("_mb_per_second"):
            audit.facts[f"{name.removesuffix('_mb_per_second')} throughput"] = f"{value:.1f} MB/s"
    pure_rate = timings.get("pure_mb_per_second", 0.0)
    if pure_rate < 2.0:  # pragma: no cover - very slow machine
        audit.add(
            "warn",
            "the pure-Python cipher is slow on this machine",
            f"{pure_rate:.1f} MB/s. Install the `cryptography` package for ~100x more, "
            "or use a lower-latency profile so fewer bytes are padded",
        )
    else:
        audit.add(
            "ok",
            "throughput is adequate for browsing and games",
            f"{pure_rate:.1f} MB/s pure Python"
            + (
                f", {timings['cryptography_mb_per_second']:.0f} MB/s accelerated"
                if "cryptography_mb_per_second" in timings
                else " (no accelerated backend installed)"
            ),
        )

    _permission_findings(audit, config_dir())
    _policy_findings(audit, config_dir())

    profile = os.environ.get("NFVPN_PROFILE", "balanced")
    _shape_findings(audit, profile)

    if json_output:
        print(json.dumps(audit.as_dict(), indent=2))
    else:
        print(audit.render())
    return 1 if audit.warnings else 0
