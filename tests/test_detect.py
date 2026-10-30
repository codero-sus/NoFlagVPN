"""The detector's side of the story: probing, and auditing a local setup.

`nfvpn probe` exists so that the person running a relay can look at it the way a
censor's scanner would: connect, ask for a web page, try a WebSocket upgrade,
then send junk shaped like a handshake and measure what comes back.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest
from nfvpn.detect import audit, probe
from nfvpn.detect.probe import ProbeReport, format_report, probe_endpoint

pytestmark = pytest.mark.timeout(120)


class FakeServer:
    """A stand-in relay port with a scripted set of answers."""

    def __init__(self, *, websocket: bool = True, answer: bytes | None = None) -> None:
        self.websocket = websocket
        self.answer = answer
        self.port = 0
        self.server: asyncio.AbstractServer | None = None
        self.request_lines: list[bytes] = []

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = int(self.server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            self.request_lines.append(request.split(b"\r\n", 1)[0])
            if b"upgrade: websocket" in request.lower() and self.websocket:
                await self._serve_websocket(reader, writer, request)
            else:
                writer.write(
                    b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 22\r\n\r\n"
                    b"<html>404</html>     \n"
                )
                await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _serve_websocket(self, reader, writer, request: bytes) -> None:
        from nfvpn.transport.websocket import compute_accept, read_frame, write_frame

        key = ""
        for line in request.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                key = line.split(b":", 1)[1].strip().decode()
        accept = compute_accept(key or "dGhlIHNhbXBsZSBub25jZQ==")
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            + f"Sec-WebSocket-Accept: {accept}\r\n\r\n".encode()
        )
        await writer.drain()
        while True:
            await read_frame(reader)
            if self.answer is not None:
                writer.write(write_frame(0x2, self.answer, mask=False))
                await writer.drain()


@pytest.fixture
async def fake():
    server = FakeServer(answer=b"x" * 128)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


async def test_probing_a_plain_web_port(fake):
    report = await probe_endpoint(f"ws://127.0.0.1:{fake.port}", rounds=2, timeout=3.0)
    assert report.reachable is True
    assert "404" in report.http_status
    assert report.findings()


async def test_a_verdict_is_always_a_triple(fake):
    report = await probe_endpoint(f"ws://127.0.0.1:{fake.port}", rounds=1, timeout=3.0)
    for level, title, detail in report.findings():
        assert level in {"ok", "warn", "info", "error"}
        assert title
        assert isinstance(detail, str)


async def test_probing_a_closed_port():
    report = await probe_endpoint("ws://127.0.0.1:1", rounds=1, timeout=1.0)
    assert report.reachable is False
    levels = [level for level, _title, _detail in report.findings()]
    assert "warn" in levels


def test_the_report_renders_and_serialises():
    report = ProbeReport(target="example.com:443", reachable=True, http_status="404 Not Found")
    text = format_report(report)
    assert "example.com:443" in text
    payload = report.as_dict()
    assert payload["target"] == "example.com:443"
    assert payload["reachable"] is True


def test_reports_are_json_serialisable(fake):
    report = ProbeReport(target="x:1", reachable=True)
    import json

    json.dumps(report.as_dict())


async def test_a_fixed_size_reply_is_noted(fake):
    """The property that matters: every probe gets the same number of bytes."""
    report = await probe_endpoint(f"ws://127.0.0.1:{fake.port}", rounds=3, timeout=3.0)
    sizes = set(report.probe_reply_sizes)
    assert sizes == {128}, report.probe_reply_sizes


async def test_a_handshake_module_is_worth_reading():
    """The audit is a local report; it must never raise on a fresh machine."""
    code = audit.run_doctor(json_output=False)
    assert code in (0, 1)


def test_benchmark_reports_both_backends():
    timings = audit.benchmark_backends(payload_size=4096, rounds=2)
    assert timings["active"] in {"pure", "cryptography"}
    assert timings["pure_mb_per_second"] > 0
    # The accelerated backend is optional, so it may or may not be measured.
    assert timings.get("cryptography_mb_per_second", 0) >= 0
    accelerated = timings.get("cryptography_mb_per_second")
    if accelerated is not None:
        assert accelerated > timings["pure_mb_per_second"]


def test_the_audit_object_collects_findings():
    record = audit.Audit()
    record.add("ok", "fine")
    record.add("warn", "not fine", "because")
    record.facts["python"] = "3.x"
    assert [level for level, _t, _d in record.warnings] == ["warn"]
    rendered = record.render()
    assert "fine" in rendered
    assert "because" in rendered
    assert record.as_dict()["warnings"] == 1


async def test_a_bare_host_port_is_tried_over_tls_and_then_plain(fake):
    """A scanner tries both; so do we, and the report names what answered."""
    report = await probe_endpoint(f"127.0.0.1:{fake.port}", rounds=1, timeout=3.0)
    assert report.reachable is True
    assert report.target.startswith("ws://"), report.target
    assert report.websocket_upgrade is True


async def test_nothing_answering_reports_every_scheme_tried():
    report = await probe_endpoint("127.0.0.1:1", rounds=1, timeout=1.0)
    assert report.reachable is False
    assert len(report.errors) >= 1
    assert all("127.0.0.1:1" in error for error in report.errors)


def test_candidates_respect_an_explicit_scheme():
    assert [endpoint.scheme for endpoint in probe._candidates("wss://x/")] == ["wss"]
    assert [endpoint.scheme for endpoint in probe._candidates("tcp://x:1")] == ["tcp"]
    assert [endpoint.scheme for endpoint in probe._candidates("x:443")] == ["wss", "ws"]


def test_probe_helpers_are_exported():
    assert probe.format_report is format_report
    assert probe.DEFAULT_TIMEOUT > 0
