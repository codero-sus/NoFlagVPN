"""Probing an endpoint the way a censor's scanner would.

The question this answers is not "does it work" but **"what does it look like
from outside?"**  So the probe behaves like an ordinary network scanner: it
opens a TCP connection, makes a plain HTTP request, attempts a WebSocket
upgrade, and finally pounds on the port with junk that is shaped like a
handshake.  Then it reports what came back.

What you want to see:

* an ordinary web server — headers, a 404 page, a normal TLS certificate,
* no response to junk beyond what a WebSocket server would send,
* no version string, no product banner, no distinguishable error,
* a handshake-shaped probe answered with a *fixed-size* reply that reveals
  nothing about whether the peer was recognised, or silence — both fine, as long
  as it is the same for every probe.

What you do not want to see: different replies for "unknown peer", "known peer",
"expired peer", or an error page that names the software.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from dataclasses import dataclass, field

from nfvpn.errors import TransportError
from nfvpn.transport import Endpoint
from nfvpn.transport.websocket import (
    OP_BINARY,
    compute_accept,
    perform_client_handshake,
    read_frame,
    write_frame,
)

__all__ = ["ProbeReport", "probe_endpoint"]

#: A handshake-shaped probe: 128 bytes of noise, the size every real handshake
#: message has.  A relay must answer such a thing exactly as it answers a
#: legitimate handshake from someone who simply is not a member.
_HANDSHAKE_SHAPED_PROBE = bytes(range(128))

#: How long to wait for a reply before calling it silence.
DEFAULT_TIMEOUT = 6.0


@dataclass
class ProbeReport:
    """Everything the probe learned, phrased as findings rather than raw bytes."""

    target: str
    reachable: bool = False
    tls: bool = False
    tls_details: dict[str, str] = field(default_factory=dict)
    http_status: str = ""
    http_headers: dict[str, str] = field(default_factory=dict)
    http_body_sample: str = ""
    websocket_upgrade: bool = False
    websocket_accept_valid: bool = False
    probe_reply_sizes: list[int] = field(default_factory=list)
    probe_reply_seconds: list[float] = field(default_factory=list)
    silence_after_probe: bool = False
    errors: list[str] = field(default_factory=list)

    # -- findings ----------------------------------------------------------
    def findings(self) -> list[tuple[str, str, str]]:
        """``(level, title, detail)`` triples: level is ok / warn / info."""
        findings: list[tuple[str, str, str]] = []

        if not self.reachable:
            findings.append(("warn", "no connection", "nothing answered on that port"))
            return findings

        findings.append(
            (
                "ok" if self.http_headers else "warn",
                "answers like a web server" if self.http_headers else "not an HTTP server",
                f"{self.http_status} · " + ", ".join(
                    f"{name}: {value}" for name, value in list(self.http_headers.items())[:4]
                )
                if self.http_headers
                else "a plain HTTP request got no HTTP response",
            )
        )

        banner = " ".join(
            value
            for name, value in self.http_headers.items()
            if name.lower() in ("server", "x-powered-by", "via")
        )
        if banner:
            findings.append(
                ("info", "product banner", f"{banner!r} — make sure this is what you meant to look like")
            )
        else:
            findings.append(("ok", "no product banner", "no Server/X-Powered-By header"))

        if self.websocket_upgrade and self.websocket_accept_valid:
            findings.append(
                ("ok", "valid WebSocket upgrade", "the handshake is the real thing, as browsers expect")
            )
        elif self.websocket_upgrade:
            findings.append(
                ("warn", "upgrade without a valid accept", "not a real WebSocket server")
            )
        else:
            findings.append(("info", "no WebSocket upgrade", "the port is not serving WebSockets"))

        sizes = sorted(set(self.probe_reply_sizes))
        if not self.probe_reply_sizes:
            if self.silence_after_probe:
                findings.append(
                    ("ok", "silent for junk", "a handshake-shaped probe got nothing back")
                )
        elif len(sizes) == 1:
            findings.append(
                (
                    "ok",
                    "uniform reply to junk",
                    f"every probe got exactly {sizes[0]} bytes — a prober cannot tell "
                    "a member from a stranger",
                )
            )
        else:
            findings.append(
                (
                    "warn",
                    "replies vary",
                    f"probes got {sizes} bytes; if the smaller reply means 'not a member', "
                    "that difference is a fingerprint",
                )
            )

        if self.probe_reply_seconds:
            spread = max(self.probe_reply_seconds) - min(self.probe_reply_seconds)
            findings.append(
                (
                    "info" if spread < 0.25 else "warn",
                    "reply timing",
                    f"{spread * 1000:.0f} ms spread over {len(self.probe_reply_seconds)} probes "
                    + (
                        "(consistent)"
                        if spread < 0.25
                        else "(a refusal that returns faster than an acceptance is a signal)"
                    ),
                )
            )

        for error in self.errors:
            findings.append(("warn", "error", error))
        return findings

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "reachable": self.reachable,
            "tls": self.tls,
            "tls_details": self.tls_details,
            "http_status": self.http_status,
            "http_headers": self.http_headers,
            "http_body_sample": self.http_body_sample,
            "websocket_upgrade": self.websocket_upgrade,
            "websocket_accept_valid": self.websocket_accept_valid,
            "probe_reply_sizes": self.probe_reply_sizes,
            "probe_reply_seconds": self.probe_reply_seconds,
            "silence_after_probe": self.silence_after_probe,
            "errors": self.errors,
            "findings": [
                {"level": level, "title": title, "detail": detail}
                for level, title, detail in self.findings()
            ],
        }


async def probe_endpoint(
    target: str,
    *,
    path: str = "/",
    timeout: float = DEFAULT_TIMEOUT,
    rounds: int = 3,
    insecure: bool = False,
) -> ProbeReport:
    """Run the whole battery against ``target`` (``host``, ``host:port`` or a URI)."""
    endpoint = Endpoint.parse(target if "://" in target else f"wss://{target}")
    report = ProbeReport(target=endpoint.url())

    context: ssl.SSLContext | None = None
    if endpoint.uses_tls:
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                endpoint.host,
                endpoint.port,
                ssl=context,
                server_hostname=endpoint.host if context else None,
            ),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        report.errors.append(f"{type(exc).__name__}: {exc}")
        return report

    report.reachable = True
    if endpoint.uses_tls:
        report.tls = True
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is not None:
            report.tls_details = {
                "version": ssl_object.version() or "",
                "cipher": (ssl_object.cipher() or ("",))[0],
                "alpn": ssl_object.selected_alpn_protocol() or "",
                "sni": str(ssl_object.server_hostname or ""),
            }
            with contextlib.suppress(Exception):
                certificate = ssl_object.getpeercert() or {}
                names = [
                    value
                    for key, value in certificate.get("subject", ())
                    for value in key
                    if key == "commonName"
                ]
                report.tls_details["subject_cn"] = ", ".join(names)
                issuer = [
                    value
                    for key, value in certificate.get("issuer", ())
                    for value in key
                    if key == "commonName"
                ]
                report.tls_details["issuer_cn"] = ", ".join(issuer)
                not_after = certificate.get("notAfter")
                if not_after:
                    report.tls_details["not_after"] = str(not_after)

    # 1. an ordinary HTTP request, exactly what a scanner sends.
    try:
        writer.write(
            f"GET {path} HTTP/1.1\r\nHost: {endpoint.authority}\r\n"
            "User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        report.http_status = status_line.decode("latin-1").strip()
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if line in (b"\r\n", b"\n", b""):
                break
            if b":" in line:
                name, _, value = line.decode("latin-1").partition(":")
                report.http_headers[name.strip()] = value.strip()
        body = await asyncio.wait_for(reader.read(512), timeout=timeout)
        report.http_body_sample = body.decode("latin-1", "replace")
    except (TimeoutError, asyncio.TimeoutError, ConnectionError, OSError) as exc:
        report.errors.append(f"plain HTTP request: {type(exc).__name__}")
    finally:
        with contextlib.suppress(Exception):
            writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    # 2. a real WebSocket upgrade, then repeated handshake-shaped junk.
    for attempt in range(max(1, rounds)):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    endpoint.host,
                    endpoint.port,
                    ssl=context,
                    server_hostname=endpoint.host if context else None,
                ),
                timeout=timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            report.errors.append(f"reconnect failed: {exc}")
            break
        try:
            headers = await perform_client_handshake(
                reader, writer, host=endpoint.authority, path=path, timeout=timeout
            )
            if attempt == 0:
                report.websocket_upgrade = True
                report.websocket_accept_valid = "sec-websocket-accept" in headers

            started = time.perf_counter()
            writer.write(write_frame(OP_BINARY, _HANDSHAKE_SHAPED_PROBE, mask=True))
            await writer.drain()
            try:
                frame = await asyncio.wait_for(read_frame(reader), timeout=timeout)
                report.probe_reply_sizes.append(len(frame.payload))
                report.probe_reply_seconds.append(time.perf_counter() - started)
            except (TimeoutError, asyncio.TimeoutError):
                report.silence_after_probe = True
                report.probe_reply_seconds.append(time.perf_counter() - started)
            except TransportError:
                report.silence_after_probe = True
        except (TransportError, TimeoutError, asyncio.TimeoutError, ConnectionError, OSError) as exc:
            report.errors.append(f"websocket probe: {type(exc).__name__}: {exc}")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    return report


def format_report(report: ProbeReport) -> str:
    """Plain-text rendering for the CLI."""
    lines = [f"probe of {report.target}", ""]
    if report.tls:
        details = ", ".join(f"{key}={value}" for key, value in report.tls_details.items() if value)
        lines.append(f"TLS: {details or 'no details'}")
    lines.append(f"HTTP: {report.http_status or 'no response'}")
    if report.http_headers:
        for name, value in list(report.http_headers.items())[:6]:
            lines.append(f"  {name}: {value}")
    if report.probe_reply_sizes:
        lines.append(
            "handshake-shaped probes answered with: "
            + ", ".join(f"{size}B" for size in report.probe_reply_sizes)
        )
    elif report.silence_after_probe:
        lines.append("handshake-shaped probes answered with: silence")
    lines.append("")
    for level, title, detail in report.findings():
        marker = {"ok": "  ok  ", "warn": " warn ", "info": " info "}[level]
        lines.append(f"[{marker}] {title}: {detail}")
    return "\n".join(lines)


__all__ += ["compute_accept", "format_report"]
