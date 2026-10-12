"""The end-to-end self-test behind ``nfvpn selftest``.

It is deliberately the *whole* stack, on loopback, with no mocks: a real relay
process object, a real client, the real SOCKS5 and HTTP proxy paths, and a real
origin web server.  If this passes, the pieces fit; if it does not, the output
says which promise broke.

The only concession to being a test is the egress policy: the origin lives on
127.0.0.1, which the default policy correctly refuses, so the relay here is
started with ``allow_private_literals=True`` — *after* checking that the default
policy does refuse it.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import sys
import time
from dataclasses import dataclass, field

from nfvpn.client.proxy import LocalProxy
from nfvpn.client.tunnel import Tunnel
from nfvpn.config import ClientConfig, ServerConfig
from nfvpn.core.encoding import b64e
from nfvpn.core.keys import Identity, Member, MembershipStore, generate_psk, parse_psk
from nfvpn.core.primitives import backend_name
from nfvpn.detect.audit import benchmark_backends
from nfvpn.errors import HandshakeError, NoFlagVPNError
from nfvpn.framing.constants import HEADER_SIZE, TAG_SIZE
from nfvpn.server.egress import EgressPolicy
from nfvpn.server.relay import Relay
from nfvpn.session.handshake import HANDSHAKE_SIZE, HandshakeInitiator
from nfvpn.traffic import Shaper, get_profile
from nfvpn.transport import accept_transport, dial, Endpoint
from nfvpn.transport.websocket import OP_BINARY, read_frame, write_frame

__all__ = ["Check", "Report", "run_selftest", "start_origin"]

ORIGIN_BODY = (
    "<html><head><title>NoFlagVPN self-test origin</title></head>"
    "<body><h1>self-test origin</h1><p>you are reading this through the tunnel</p></body></html>"
)


@dataclass
class Check:
    """One assertion, with the evidence it was based on."""

    name: str
    passed: bool
    detail: str = ""

    def line(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        return f"[{mark}] {self.name}" + (f" — {self.detail}" if self.detail else "")


@dataclass
class Report:
    """Collects checks and turns them into an exit code."""

    checks: list[Check] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append(Check(name, bool(passed), detail))
        return bool(passed)

    @property
    def failures(self) -> list[Check]:
        return [check for check in self.checks if not check.passed]

    def render(self, *, verbose: bool = True) -> str:
        lines = [check.line() for check in self.checks]
        lines.append("")
        passed = len(self.checks) - len(self.failures)
        lines.append(f"{passed}/{len(self.checks)} checks passed")
        if self.failures:
            lines.append("")
            lines.append("what failed:")
            for check in self.failures:
                lines.append(f"  - {check.name}: {check.detail}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "passed": len(self.checks) - len(self.failures),
            "total": len(self.checks),
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.checks
            ],
            "extra": self.extra,
        }


# --------------------------------------------------------------------------- #
# a tiny origin server
# --------------------------------------------------------------------------- #
async def start_origin(host: str = "127.0.0.1", port: int = 0) -> tuple[asyncio.AbstractServer, str]:
    """Start an HTTP server that stands in for the site you want to reach."""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not request_line:
                return
            parts = request_line.decode("latin-1").split()
            target = parts[1] if len(parts) > 1 else "/"
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if line in (b"\r\n", b"\n", b""):
                    break
            if target.startswith("/large"):
                size = 256 * 1024
                if "=" in target:
                    with contextlib.suppress(ValueError):
                        size = min(int(target.split("=", 1)[1]), 8 << 20)
                body = bytes((index % 251) for index in range(size))
                headers = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            else:
                body = ORIGIN_BODY.encode()
                headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            writer.write(
                headers
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        except (ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    server = await asyncio.start_server(handler, host, port)
    bound_port = server.sockets[0].getsockname()[1]
    return server, f"http://{host}:{bound_port}/"


# --------------------------------------------------------------------------- #
# SOCKS5 / HTTP clients for the test itself
# --------------------------------------------------------------------------- #
async def _socks5_connect(reader, writer, host: str, port: int) -> int:
    """Negotiate a SOCKS5 CONNECT; returns the reply code."""
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    greeting = await asyncio.wait_for(reader.readexactly(2), timeout=10)
    if greeting != b"\x05\x00":
        return 0xFF
    encoded = host.encode()
    writer.write(
        b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + port.to_bytes(2, "big")
    )
    await writer.drain()
    reply = await asyncio.wait_for(reader.readexactly(10), timeout=20)
    return reply[1]


async def _http_get(reader, writer, host: str, path: str = "/") -> tuple[int, bytes]:
    writer.write(
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nfvpn-selftest\r\n"
        "Connection: close\r\n\r\n".encode()
    )
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(), timeout=60)
    status_line, _, rest = raw.partition(b"\r\n\r\n")
    code = 0
    with contextlib.suppress(ValueError, IndexError):
        code = int(status_line.split(b" ")[1])
    return code, rest


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# --------------------------------------------------------------------------- #
# the run
# --------------------------------------------------------------------------- #
async def run_selftest(*, verbose: bool = True, json_output: bool = False) -> int:
    """Run every check.  Returns a process exit code."""
    started = time.monotonic()
    report = Report()

    # --- 1. policy defaults -------------------------------------------------
    default_policy = EgressPolicy()
    for address, label in (
        ("127.0.0.1", "loopback"),
        ("10.0.0.1", "private"),
        ("169.254.169.254", "cloud metadata"),
        ("::1", "IPv6 loopback"),
    ):
        allowed, _ = default_policy.address_allowed(address)
        report.check(f"default egress policy refuses {label} ({address})", not allowed)
    allowed, _ = default_policy.address_allowed("93.184.216.34")
    report.check("default egress policy allows a public address", allowed)
    allowed, _ = default_policy.port_allowed(25)
    report.check("default egress policy refuses SMTP", not allowed)

    # --- 2. crypto ----------------------------------------------------------
    report.check("crypto backend selected", True, backend_name())
    timing = benchmark_backends()
    report.check(
        "pure-python backend encrypts at a usable rate",
        timing["pure_mb_per_second"] > 2.0,
        f"{timing['pure_mb_per_second']:.1f} MB/s",
    )
    report.extra["crypto"] = timing

    # --- 3. shaper sanity ---------------------------------------------------
    shaper = Shaper(get_profile("balanced"))
    sizes = {shaper.padded_plaintext(length) + HEADER_SIZE + TAG_SIZE for length in range(0, 4096, 7)}
    report.check(
        "shaping spreads payloads over many size classes",
        len(sizes) > 5,
        f"{len(sizes)} distinct wire sizes for 0–4095-byte payloads",
    )
    report.check(
        "shaped records stay inside the carrier limit",
        max(sizes) <= 16432,
        f"largest is {max(sizes)} bytes",
    )

    # --- 4. the whole stack on loopback ------------------------------------
    origin, origin_url = await start_origin()
    relay_identity = Identity.generate("selftest-relay")
    client_identity = Identity.generate("selftest-client")
    psk = parse_psk(generate_psk())
    stranger_identity = Identity.generate("stranger")

    membership = MembershipStore()
    membership.add(Member(name="selftest-client", public_key=client_identity.public_key, psk=psk))

    relay_port = _free_port()
    proxy_port = _free_port()
    relay_config = ServerConfig(
        listen_host="127.0.0.1",
        listen_port=relay_port,
        ws_path="/cdn/stream",
        profile="balanced",
        # See the module docstring: the origin is on loopback on purpose, and the
        # default policy is verified separately above.
        egress=EgressPolicy(allow_private_literals=True),
        log_level="warning",
    )
    relay = Relay(relay_config, relay_identity, membership)
    await relay.start()

    client_config = ClientConfig(
        relay=f"ws://127.0.0.1:{relay_port}/cdn/stream",
        peer_public_key=b64e(relay_identity.public_key),
        psk=b64e(psk),
        listen_host="127.0.0.1",
        listen_port=proxy_port,
        profile="balanced",
        log_level="warning",
    )
    tunnel = Tunnel(client_config, client_identity, psk, relay_identity.public_key)
    proxy = LocalProxy(tunnel, client_config)

    try:
        await tunnel.connect()
        report.check("handshake completes and the tunnel comes up", tunnel.connected,
                     tunnel.describe() if tunnel.connected else "no session")
        bound = await proxy.start()
        report.extra["proxy"] = bound

        origin_port = int(origin_url.rsplit(":", 1)[1].strip("/"))
        origin_host = "127.0.0.1"

        # 4a. SOCKS5 CONNECT
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        code = await _socks5_connect(reader, writer, origin_host, origin_port)
        if report.check("SOCKS5 CONNECT is accepted", code == 0, f"reply code 0x{code:02x}"):
            status, body = await _http_get(reader, writer, origin_host)
            report.check(
                "page fetched over SOCKS5 matches the origin",
                status == 200 and ORIGIN_BODY.encode() in body,
                f"HTTP {status}, {len(body)} bytes",
            )
        with contextlib.suppress(Exception):
            writer.close()

        # 4b. HTTP CONNECT
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"CONNECT {origin_host}:{origin_port} HTTP/1.1\r\n"
            f"Host: {origin_host}:{origin_port}\r\n\r\n".encode()
        )
        await writer.drain()
        head = await asyncio.wait_for(reader.readline(), timeout=20)
        if report.check(
            "HTTP CONNECT is accepted", b"200" in head, head.decode("latin-1").strip()
        ):
            status, body = await _http_get(reader, writer, origin_host)
            report.check(
                "page fetched over HTTP CONNECT matches the origin",
                status == 200 and ORIGIN_BODY.encode() in body,
                f"HTTP {status}, {len(body)} bytes",
            )
        with contextlib.suppress(Exception):
            writer.close()

        # 4c. a bulk transfer, to exercise flow control and many records
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        code = await _socks5_connect(reader, writer, origin_host, origin_port)
        if code == 0:
            status, body = await _http_get(reader, writer, origin_host, "/large?bytes=1048576")
            report.check(
                "a 1 MiB transfer survives flow control",
                status == 200 and len(body) >= 1048576,
                f"{len(body)} bytes",
            )
        with contextlib.suppress(Exception):
            writer.close()

        report.check(
            "the tunnel carried many streams",
            tunnel.stats.streams >= 3,
            f"{tunnel.stats.streams} streams, {tunnel.describe()}",
        )

        # --- 5. probing behaviour ------------------------------------------
        probe_sizes, probe_times = [], []
        for _ in range(3):
            transport = await dial(Endpoint.parse(f"ws://127.0.0.1:{relay_port}/cdn/stream"))
            started_at = time.perf_counter()
            await transport.send_message(bytes(range(HANDSHAKE_SIZE)))
            try:
                reply = await asyncio.wait_for(transport.receive_message(), timeout=5)
                probe_sizes.append(len(reply))
            except (asyncio.TimeoutError, NoFlagVPNError):
                probe_sizes.append(0)
            probe_times.append(time.perf_counter() - started_at)
            await transport.close()

        report.check(
            "a handshake-shaped probe gets a fixed-size reply",
            set(probe_sizes) == {HANDSHAKE_SIZE},
            f"replies were {probe_sizes} bytes",
        )
        spread = max(probe_times) - min(probe_times)
        report.check(
            "refusal timing does not advertise itself",
            spread < 1.5,
            f"{spread * 1000:.0f} ms spread over {len(probe_times)} probes",
        )

        # --- 6. authentication actually authenticates ----------------------
        transport = await dial(Endpoint.parse(f"ws://127.0.0.1:{relay_port}/cdn/stream"))
        initiator = HandshakeInitiator(client_identity, relay_identity.public_key, b"\x00" * 32)
        await transport.send_message(initiator.hello())
        response = await asyncio.wait_for(transport.receive_message(), timeout=10)
        report.check(
            "a wrong pre-shared key still gets a well-formed reply",
            len(response) == HANDSHAKE_SIZE,
            f"{len(response)} bytes",
        )
        try:
            initiator.finish(response)
            report.check("a wrong pre-shared key is rejected", False, "it authenticated!")
        except HandshakeError:
            report.check("a wrong pre-shared key is rejected", True)
        await transport.close()

        # --- 7. the cover story --------------------------------------------
        reader, writer = await asyncio.open_connection("127.0.0.1", relay_port)
        writer.write(b"GET /admin HTTP/1.1\r\nHost: relay\r\n\r\n")
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(), timeout=10)
        report.check(
            "a plain HTTP request gets a plausible web page",
            b"HTTP/1.1 404" in raw and b"<html" in raw.lower(),
            raw.split(b"\r\n", 1)[0].decode("latin-1"),
        )
        with contextlib.suppress(Exception):
            writer.close()

        reader, writer = await asyncio.open_connection("127.0.0.1", relay_port)
        writer.write(
            b"GET / HTTP/1.1\r\nHost: relay\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: not-a-valid-key\r\n\r\n"
        )
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(), timeout=10)
        report.check(
            "an invalid upgrade looks like an ordinary web server too",
            b"HTTP/1.1 404" in raw,
            raw.split(b"\r\n", 1)[0].decode("latin-1"),
        )
        with contextlib.suppress(Exception):
            writer.close()

        # --- 8. relay counters ---------------------------------------------
        report.extra["relay_stats"] = {
            "connections": relay.stats.connections,
            "authorized": relay.stats.handshakes_ok,
            "refused": relay.stats.handshakes_refused,
            "cover_responses": relay.stats.cover_responses,
            "streams": relay.stats.streams_opened,
        }
        report.check(
            "the relay counted the authorized session",
            relay.stats.handshakes_ok >= 1,
            f"{relay.stats.handshakes_ok} authorized, {relay.stats.handshakes_refused} refused",
        )
        report.check(
            "the relay refused the unauthenticated probes",
            relay.stats.handshakes_refused >= 3,
            f"{relay.stats.handshakes_refused} refusals",
        )
    finally:
        with contextlib.suppress(Exception):
            await proxy.stop()
        with contextlib.suppress(Exception):
            await tunnel.close()
        with contextlib.suppress(Exception):
            await relay.stop()
        origin.close()
        with contextlib.suppress(Exception):
            await origin.wait_closed()

    report.extra["duration_seconds"] = round(time.monotonic() - started, 2)

    if json_output:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(report.render(verbose=verbose))
        if verbose and not report.failures:
            print("")
            print("Everything works.  Next: point a browser at a SOCKS5 proxy and play.")
    return 0 if not report.failures else 1
