"""Scanner-facing probe behaviour across TLS, HTTP, and noisy WebSocket replies.

The existing integration tests exercise the ordinary plain-WebSocket path. This
file pins the decision/reporting branches around it: TLS inspection (including
certificate-library failures), incomplete HTTP responses, reconnect failures,
and the difference between a quiet peer and one whose replies fingerprint it.
"""
from __future__ import annotations

import asyncio
import ssl
from types import SimpleNamespace

from nfvpn.detect import probe
from nfvpn.detect.probe import ProbeReport, format_report
from nfvpn.errors import TransportError
from nfvpn.transport import Endpoint


class FakeSSLObject:
    def __init__(self, *, fail_certificate: bool = False) -> None:
        self.fail_certificate = fail_certificate

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def selected_alpn_protocol(self):
        return "http/1.1"

    @property
    def server_hostname(self):
        return "probe.example"

    def getpeercert(self):
        if self.fail_certificate:
            raise ValueError("certificate unavailable")
        return {
            "subject": ((('commonName', 'probe.example'),),),
            "issuer": ((('commonName', 'Test CA'),),),
            "notAfter": "Dec 31 23:59:59 2030 GMT",
        }


class ScriptReader:
    def __init__(self, *, fail_http: bool = False) -> None:
        self.lines = iter(
            [
                b"HTTP/1.1 404 Not Found\r\n",
                b"Server: nginx\r\n",
                b"X-Powered-By: test-app\r\n",
                b"\r\n",
            ]
        )
        self.fail_http = fail_http

    async def readline(self):
        if self.fail_http:
            raise asyncio.TimeoutError
        return next(self.lines, b"")

    async def read(self, size):
        return b"sample body"[:size]


class ScriptWriter:
    def __init__(self, ssl_object=None) -> None:
        self.ssl_object = ssl_object
        self.writes: list[bytes] = []
        self.closed = False

    def get_extra_info(self, name):
        return self.ssl_object if name == "ssl_object" else None

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


async def scripted_probe(monkeypatch, *, handshake=None, frame=None, fail_http=False):
    reader = ScriptReader(fail_http=fail_http)
    writer = ScriptWriter(FakeSSLObject())
    monkeypatch.setattr(
        probe,
        "_connect",
        lambda *args, **kwargs: asyncio.sleep(0, result=(reader, writer, object())),
    )

    async def reconnect(*args, **kwargs):
        return reader, writer

    async def do_handshake(*args, **kwargs):
        if handshake is not None:
            raise handshake
        return {"sec-websocket-accept": "valid"}

    async def receive_frame(*args, **kwargs):
        if frame is not None:
            raise frame
        return SimpleNamespace(payload=b"reply")

    monkeypatch.setattr(probe.asyncio, "open_connection", reconnect)
    monkeypatch.setattr(probe, "perform_client_handshake", do_handshake)
    monkeypatch.setattr(probe, "read_frame", receive_frame)
    return await probe.probe_endpoint("wss://probe.example/", rounds=1, timeout=0.1)


def test_findings_cover_unreachable_and_every_websocket_verdict():
    offline = ProbeReport(target="offline")
    assert offline.findings() == [("warn", "no connection", "nothing answered on that port")]

    invalid = ProbeReport(target="x", reachable=True, websocket_upgrade=True)
    assert any(title == "upgrade without a valid accept" for _, title, _ in invalid.findings())

    absent = ProbeReport(target="x", reachable=True)
    assert any(title == "no WebSocket upgrade" for _, title, _ in absent.findings())


def test_findings_flag_variable_reply_sizes_and_timing_as_a_fingerprint():
    report = ProbeReport(
        target="x",
        reachable=True,
        probe_reply_sizes=[128, 64, 128],
        probe_reply_seconds=[0.01, 0.50],
        errors=["handshake refused"],
    )
    findings = report.findings()
    assert any(level == "warn" and title == "replies vary" for level, title, _ in findings)
    assert any(level == "warn" and title == "reply timing" for level, title, _ in findings)
    assert ("warn", "error", "handshake refused") in findings


def test_findings_report_silence_and_consistent_timing():
    report = ProbeReport(
        target="x", reachable=True, silence_after_probe=True, probe_reply_seconds=[0.1, 0.2]
    )
    findings = report.findings()
    assert any(title == "silent for junk" for _, title, _ in findings)
    assert any(level == "info" and title == "reply timing" for level, title, _ in findings)


def test_format_report_includes_tls_and_only_six_headers():
    report = ProbeReport(
        target="secure.example",
        reachable=True,
        tls=True,
        tls_details={"version": "TLSv1.3", "empty": ""},
        http_headers={f"X-{i}": str(i) for i in range(8)},
        probe_reply_sizes=[3, 4],
    )
    rendered = format_report(report)
    assert "TLS: version=TLSv1.3" in rendered
    assert "X-5: 5" in rendered
    assert "X-6: 6" not in rendered
    assert "3B, 4B" in rendered


def test_format_report_names_a_silent_probe():
    rendered = format_report(ProbeReport(target="x", reachable=True, silence_after_probe=True))
    assert "handshake-shaped probes answered with: silence" in rendered


async def test_tls_insecure_mode_disables_certificate_verification(monkeypatch):
    context = SimpleNamespace(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
    monkeypatch.setattr(probe.ssl, "create_default_context", lambda: context)
    called = {}

    async def open_connection(host, port, **kwargs):
        called.update(host=host, port=port, **kwargs)
        return object(), object()

    monkeypatch.setattr(probe.asyncio, "open_connection", open_connection)
    _reader, _writer, result = await probe._connect(
        Endpoint.parse("wss://probe.example:443/"), timeout=2, insecure=True
    )
    assert result is context
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE
    assert called["server_hostname"] == "probe.example"


async def test_tls_probe_reports_peer_certificate_and_http_data(monkeypatch):
    report = await scripted_probe(monkeypatch)
    assert report.tls is True
    assert report.tls_details == {
        "version": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "alpn": "http/1.1",
        "sni": "probe.example",
        "subject_cn": "probe.example",
        "issuer_cn": "Test CA",
        "not_after": "Dec 31 23:59:59 2030 GMT",
    }
    assert report.http_status == "HTTP/1.1 404 Not Found"
    assert report.http_headers["Server"] == "nginx"
    assert report.http_body_sample == "sample body"
    assert report.websocket_accept_valid is True
    assert report.probe_reply_sizes == [5]


async def test_certificate_inspection_failure_does_not_abort_probe(monkeypatch):
    reader = ScriptReader()
    writer = ScriptWriter(FakeSSLObject(fail_certificate=True))
    monkeypatch.setattr(
        probe,
        "_connect",
        lambda *args, **kwargs: asyncio.sleep(0, result=(reader, writer, object())),
    )
    monkeypatch.setattr(probe.asyncio, "open_connection", lambda *args, **kwargs: asyncio.sleep(0, result=(reader, writer)))
    monkeypatch.setattr(probe, "perform_client_handshake", lambda *args, **kwargs: asyncio.sleep(0, result={"sec-websocket-accept": "ok"}))
    monkeypatch.setattr(probe, "read_frame", lambda *args, **kwargs: asyncio.sleep(0, result=SimpleNamespace(payload=b"ok")))
    report = await probe.probe_endpoint("wss://probe.example", rounds=1, timeout=0.1)
    assert report.tls is True
    assert "version" in report.tls_details
    assert "subject_cn" not in report.tls_details
    assert report.probe_reply_sizes == [2]


async def test_http_timeout_is_recorded_and_failed_reconnect_stops_rounds(monkeypatch):
    reader = ScriptReader(fail_http=True)
    writer = ScriptWriter(FakeSSLObject())
    monkeypatch.setattr(
        probe,
        "_connect",
        lambda *args, **kwargs: asyncio.sleep(0, result=(reader, writer, object())),
    )

    async def fail_reconnect(*args, **kwargs):
        raise OSError("network down")

    monkeypatch.setattr(probe.asyncio, "open_connection", fail_reconnect)
    report = await probe.probe_endpoint("wss://probe.example", rounds=3, timeout=0.1)
    assert "plain HTTP request: TimeoutError" in report.errors
    assert len(report.errors) == 2
    assert "reconnect failed: network down" in report.errors[1]


async def test_handshake_refusal_and_silent_probe_are_distinguished(monkeypatch):
    refused = await scripted_probe(
        monkeypatch, handshake=TransportError("bad accept")
    )
    assert refused.websocket_upgrade is False
    assert any("websocket probe: TransportError: bad accept" in error for error in refused.errors)

    silent = await scripted_probe(monkeypatch, frame=asyncio.TimeoutError())
    assert silent.silence_after_probe is True
    assert len(silent.probe_reply_seconds) == 1
    assert not silent.probe_reply_sizes


async def test_malformed_probe_reply_counts_as_silence(monkeypatch):
    report = await scripted_probe(monkeypatch, frame=TransportError("invalid frame"))
    assert report.silence_after_probe is True
    assert report.probe_reply_sizes == []
    # A malformed frame is not a measured reply, so there is no timing sample.
    assert report.probe_reply_seconds == []
