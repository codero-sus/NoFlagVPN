"""The local proxy's failure paths and protocol edges.

``test_proxy_compat.py`` proves that the byte shapes real clients send work
against a live relay.  This file is the other half: what the proxy does when the
client is broken, the tunnel refuses, or the destination is one the relay will
not reach - and what it counts while doing it.

The tunnel is faked, so a refusal can be produced on demand instead of by
arranging a real relay that refuses a real destination.  Everything else - the
server, the sniffer, the pumps - is the real code.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import socket
import struct

import pytest
from nfvpn.client.proxy import LocalAuth, LocalProxy
from nfvpn.config import ClientConfig
from nfvpn.errors import ProtocolError, TransportError
from nfvpn.framing.constants import CloseReason
from nfvpn.session.streams import StreamClosedError


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FakeStream:
    """Enough of a Stream for the pump: it echoes what it is sent."""

    def __init__(self, echo: bool = True) -> None:
        self.sent: list[bytes] = []
        self.closed_with: CloseReason | None = None
        self._inbox: asyncio.Queue = asyncio.Queue()
        self.echo = echo

    async def send(self, data: bytes) -> None:
        self.sent.append(data)
        if self.echo:
            for line in data.splitlines(keepends=True):
                await self._inbox.put(line)

    async def receive(self) -> bytes | None:
        item = await self._inbox.get()
        return None if item is _EOF else item

    async def close(self, reason: CloseReason = CloseReason.NORMAL) -> None:
        self.closed_with = reason
        await self._inbox.put(_EOF)

    def finish(self) -> None:
        self._inbox.put_nowait(_EOF)


_EOF = object()


class FakeStreams:
    def __init__(self) -> None:
        self.detached: list[FakeStream] = []

    def detach(self, stream) -> None:
        self.detached.append(stream)


class FakeSession:
    def __init__(self) -> None:
        self.streams = FakeStreams()


class FakeTunnel:
    """A tunnel that answers ``open()`` however the test tells it to."""

    def __init__(self, outcome="accept") -> None:
        self.outcome = outcome
        self.opened: list[tuple[str, int]] = []
        self.active_endpoint = "127.0.0.1:1/healthz"
        self.session = FakeSession()
        self.streams: list[FakeStream] = []

    async def open(self, host: str, port: int, *, timeout: float = 15.0) -> FakeStream:
        self.opened.append((host, port))
        if self.outcome == "accept":
            stream = FakeStream()
            self.streams.append(stream)
            return stream
        if isinstance(self.outcome, CloseReason):
            raise StreamClosedError(self.outcome)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        raise AssertionError(f"unknown outcome {self.outcome!r}")


def client_config(port: int) -> ClientConfig:
    return ClientConfig(
        relay="ws://127.0.0.1:1/healthz",
        peer_public_key="",
        psk="",
        listen_host="127.0.0.1",
        listen_port=port,
        profile="balanced",
        log_level="critical",
    )


async def start_proxy(tunnel=None, *, auth: LocalAuth | None = None):
    tunnel = tunnel or FakeTunnel()
    proxy = LocalProxy(tunnel, client_config(free_port()), auth=auth)
    await proxy.start()
    return proxy, tunnel


# --------------------------------------------------------------------------- #
# the sniffer and the greeting
# --------------------------------------------------------------------------- #
async def test_the_first_byte_picks_the_protocol_and_nonsense_gets_nothing():
    proxy, _tunnel = await start_proxy()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"\x16\x03\x01\x00\x50")  # the start of a TLS ClientHello
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), timeout=5) == b"", "no reply, just close"
        writer.close()
        assert proxy.connections == 1
        assert proxy.denied == 0, "a stranger is not a denial, it is not a client"
    finally:
        await proxy.stop()


async def test_a_client_that_says_nothing_is_dropped_without_a_reply():
    proxy, _tunnel = await start_proxy()
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        await asyncio.sleep(0.05)
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()
        await asyncio.sleep(0.05)
        assert proxy.connections == 1
    finally:
        await proxy.stop()


async def test_an_http_method_is_recognised_by_its_first_letter():
    """A client sends the method in the first write; the sniffer must not lose it."""
    proxy, tunnel = await start_proxy()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        await writer.drain()
        # The fake origin echoes the request it was given, which proves the
        # first byte survived the sniffer and became an origin-form request.
        forwarded = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert forwarded.startswith(b"GET /index.html HTTP/1.1\r\n")
        assert tunnel.opened == [("example.com", 80)]
        writer.close()
    finally:
        await proxy.stop()


# --------------------------------------------------------------------------- #
# SOCKS5 authentication
# --------------------------------------------------------------------------- #
async def test_no_acceptable_method_is_answered_with_the_socks_refusal():
    proxy, _tunnel = await start_proxy(auth=LocalAuth("u", "p"))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"\x05\x01\x00")  # "no authentication please"
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(2), timeout=5) == b"\x05\xff"
        writer.close()
        assert proxy.denied == 1
    finally:
        await proxy.stop()


async def test_username_and_password_are_checked_and_wrong_ones_are_counted():
    proxy, tunnel = await start_proxy(auth=LocalAuth("user", "pass"))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        assert await reader.readexactly(2) == b"\x05\x02"  # sub-negotiation accepted

        writer.write(b"\x01\x04nope\x04nope")
        await writer.drain()
        verdict = await asyncio.wait_for(reader.readexactly(2), timeout=5)
        assert verdict[1] == 0x01, "failure, not success"
        writer.close()
        await asyncio.sleep(0.05)
        assert proxy.denied == 1
        assert tunnel.opened == [], "the tunnel is never touched without credentials"
    finally:
        await proxy.stop()


async def test_correct_credentials_get_through_to_the_handshake():
    proxy, tunnel = await start_proxy(auth=LocalAuth("user", "pass"))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        await reader.readexactly(2)
        writer.write(b"\x01\x04user\x04pass")
        await writer.drain()
        verdict = await asyncio.wait_for(reader.readexactly(2), timeout=5)
        assert verdict[1] == 0x00

        writer.write(b"\x05\x01\x00\x01" + bytes([93, 184, 216, 34]) + struct.pack(">H", 443))
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(10), timeout=5)
        assert reply[1] == 0x00
        assert tunnel.opened == [("93.184.216.34", 443)]
        writer.close()
        assert proxy.denied == 0
    finally:
        await proxy.stop()


# --------------------------------------------------------------------------- #
# SOCKS5 request forms
# --------------------------------------------------------------------------- #
async def read_socks_reply(reader: asyncio.StreamReader) -> int:
    head = await asyncio.wait_for(reader.readexactly(4), timeout=5)
    if head[3] == 0x01:
        await reader.readexactly(6)
    elif head[3] == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    else:
        await reader.readexactly(18)
    return head[1]


async def socks_client(port: int):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    await reader.readexactly(2)
    return reader, writer


async def test_an_unknown_address_type_is_answered_with_08():
    proxy, tunnel = await start_proxy()
    try:
        reader, writer = await socks_client(proxy.config.listen_port)
        writer.write(b"\x05\x01\x00\x09\x00\x00\x00\x00\x00\x50")
        await writer.drain()
        assert await read_socks_reply(reader) == 0x08
        writer.close()
        assert tunnel.opened == []
    finally:
        await proxy.stop()


@pytest.mark.parametrize("command", [0x02, 0x03])  # BIND, UDP ASSOCIATE
async def test_commands_other_than_connect_are_answered_with_07(command):
    proxy, _tunnel = await start_proxy()
    try:
        reader, writer = await socks_client(proxy.config.listen_port)
        writer.write(bytes([0x05, command, 0x00, 0x01]) + b"\x00\x00\x00\x00" + b"\x00\x50")
        await writer.drain()
        assert await read_socks_reply(reader) == 0x07
        writer.close()
    finally:
        await proxy.stop()


async def test_an_ipv6_literal_is_passed_on_in_its_own_form():
    proxy, tunnel = await start_proxy()
    try:
        reader, writer = await socks_client(proxy.config.listen_port)
        raw = bytes.fromhex("20010db8000000000000000000000001")
        writer.write(b"\x05\x01\x00\x04" + raw + struct.pack(">H", 443))
        await writer.drain()
        assert await read_socks_reply(reader) == 0x00
        assert tunnel.opened == [("2001:db8::1", 443)]
        writer.close()
    finally:
        await proxy.stop()


async def test_a_hostname_is_never_resolved_locally():
    """Names travel as names: that is what keeps DNS off the local network."""
    proxy, tunnel = await start_proxy()
    try:
        reader, writer = await socks_client(proxy.config.listen_port)
        host = b"a-name-that-does-not-resolve.invalid"
        writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", 8443))
        await writer.drain()
        assert await read_socks_reply(reader) == 0x00
        assert tunnel.opened == [(host.decode(), 8443)]
        writer.close()
    finally:
        await proxy.stop()


# --------------------------------------------------------------------------- #
# what the client is told when the tunnel refuses
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "reason, socks_code",
    [
        (CloseReason.DENIED, 0x02),
        (CloseReason.REFUSED, 0x05),
        (CloseReason.TIMEOUT, 0x06),
        (CloseReason.LIMIT, 0x02),
        (CloseReason.REMOTE_ERROR, 0x01),
    ],
)
async def test_a_refused_destination_maps_to_the_documented_socks_code(reason, socks_code):
    proxy, _tunnel = await start_proxy(FakeTunnel(reason))
    try:
        reader, writer = await socks_client(proxy.config.listen_port)
        writer.write(b"\x05\x01\x00\x01" + bytes([93, 184, 216, 34]) + struct.pack(">H", 25))
        await writer.drain()
        assert await read_socks_reply(reader) == socks_code
        writer.close()
        await asyncio.sleep(0.05)
        assert proxy.denied == 1
        assert proxy.failed == 0
    finally:
        await proxy.stop()


@pytest.mark.parametrize(
    "reason, status, message",
    [
        (CloseReason.DENIED, b"403", b"egress policy"),
        (CloseReason.REFUSED, b"502", b"could not reach"),
        (CloseReason.TIMEOUT, b"502", b"could not reach"),
    ],
)
async def test_a_refused_destination_maps_to_an_http_status(reason, status, message):
    proxy, _tunnel = await start_proxy(FakeTunnel(reason))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"CONNECT blocked.example:25 HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(200), timeout=5)
        assert status in head.split(b"\r\n")[0]
        assert message in head
        writer.close()
    finally:
        await proxy.stop()


@pytest.mark.parametrize(
    "outcome, socks_code, status",
    [
        (TransportError("could not reach any relay"), 0x04, b"504"),
        (TimeoutError("nobody answered"), 0x04, b"504"),
        (ProtocolError("the relay did not like the request"), 0x01, b"502"),
    ],
)
async def test_tunnel_trouble_is_reported_as_unreachable_not_refused(outcome, socks_code, status):
    proxy, _tunnel = await start_proxy(FakeTunnel(outcome))
    try:
        reader, writer = await socks_client(proxy.config.listen_port)
        writer.write(b"\x05\x01\x00\x01" + bytes([93, 184, 216, 34]) + struct.pack(">H", 443))
        await writer.drain()
        assert await read_socks_reply(reader) == socks_code
        writer.close()

        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(200), timeout=5)
        assert status in head.split(b"\r\n")[0]
        writer.close()
        await asyncio.sleep(0.05)
        assert proxy.failed == 2
        assert proxy.denied == 0
    finally:
        await proxy.stop()


# --------------------------------------------------------------------------- #
# a successful connection: reply, pump, cleanup
# --------------------------------------------------------------------------- #
async def test_a_socks_client_gets_its_reply_and_the_bytes_flow_both_ways():
    proxy, tunnel = await start_proxy()
    try:
        reader, writer = await socks_client(proxy.config.listen_port)
        writer.write(b"\x05\x01\x00\x03\x0bexample.com" + struct.pack(">H", 80))
        await writer.drain()
        assert await read_socks_reply(reader) == 0x00

        writer.write(b"hello origin\n")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(13), timeout=5) == b"hello origin\n"
        assert tunnel.streams[0].sent == [b"hello origin\n"]

        writer.close()
        await asyncio.sleep(0.1)
        assert tunnel.session.streams.detached == [tunnel.streams[0]], "the stream is released"
    finally:
        await proxy.stop()


async def test_a_plain_http_request_is_forwarded_in_origin_form():
    # Note the shape: a plain http:// request is answered by the origin, not by
    # the proxy, so there is no 200 from us and no CONNECT handshake.
    proxy, tunnel = await start_proxy()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(
            b"GET http://example.com:8080/a/b?c=d HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Proxy-Connection: keep-alive\r\n"
            b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
            b"Connection: keep-alive\r\n"
            b"Accept: */*\r\n\r\n"
        )
        await writer.drain()
        deadline = asyncio.get_running_loop().time() + 2.0
        while not tunnel.opened and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.02)
        assert tunnel.opened == [("example.com", 8080)]
        echoed = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert echoed.startswith(b"GET /a/b?c=d HTTP/1.1"), "bytes flow back too"
        forwarded = tunnel.streams[0].sent[0]
        assert forwarded.startswith(b"GET /a/b?c=d HTTP/1.1\r\n")
        assert b"Host: example.com" in forwarded
        assert b"Proxy-Authorization" not in forwarded, "hop-by-hop header must not travel"
        assert b"Proxy-Connection" not in forwarded
        assert b"Connection: keep-alive" not in forwarded
        assert forwarded.endswith(b"Connection: close\r\n\r\n")
        writer.close()
    finally:
        await proxy.stop()


async def test_connect_without_a_port_defaults_to_https():
    proxy, tunnel = await start_proxy()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert tunnel.opened == [("example.com", 443)]
        writer.close()
    finally:
        await proxy.stop()


# --------------------------------------------------------------------------- #
# HTTP parsing edges and local authentication
# --------------------------------------------------------------------------- #
async def test_a_request_line_without_three_parts_is_a_400():
    proxy, _tunnel = await start_proxy()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"GARBAGE\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(200), timeout=5)
        assert head.startswith(b"HTTP/1.1 400")
        writer.close()
    finally:
        await proxy.stop()


async def test_a_relative_url_is_refused_with_an_explanation():
    proxy, _tunnel = await start_proxy()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"GET /only-a-path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(400), timeout=5)
        assert head.startswith(b"HTTP/1.1 400")
        assert b"CONNECT or an absolute http:// URL" in head, "say what would have worked"
        writer.close()
    finally:
        await proxy.stop()


async def test_enormous_headers_are_cut_off_with_431():
    proxy, _tunnel = await start_proxy()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"GET http://example.com/ HTTP/1.1\r\n")
        for _ in range(2000):
            writer.write(b"X-Padding: " + b"a" * 60 + b"\r\n")
        writer.write(b"\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(200), timeout=5)
        assert head.startswith(b"HTTP/1.1 431")
        writer.close()
    finally:
        await proxy.stop()


@pytest.mark.parametrize(
    "header",
    [
        b"",  # no credentials at all
        b"Proxy-Authorization: Bearer abc123\r\n",
        b"Proxy-Authorization: Basic !!!not-base64!!!\r\n",
        b"Proxy-Authorization: Basic " + base64.b64encode(b"user:wrong") + b"\r\n",
    ],
)
async def test_http_credentials_are_demanded_and_checked(header):
    proxy, tunnel = await start_proxy(auth=LocalAuth("user", "pass"))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n" + header + b"\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(300), timeout=5)
        assert head.startswith(b"HTTP/1.1 407")
        assert b'Proxy-Authenticate: Basic realm="nfvpn"' in head
        writer.close()
        await asyncio.sleep(0.05)
        assert proxy.denied == 1
        assert tunnel.opened == []
    finally:
        await proxy.stop()


async def test_correct_http_credentials_are_accepted():
    proxy, tunnel = await start_proxy(auth=LocalAuth("user", "pass"))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.config.listen_port)
        token = base64.b64encode(b"user:pass")
        writer.write(
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic "
            + token
            + b"\r\n\r\n"
        )
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert head.startswith(b"HTTP/1.1 200")
        assert tunnel.opened == [("example.com", 443)]
        writer.close()
        assert proxy.denied == 0
    finally:
        await proxy.stop()


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
async def test_binding_the_same_port_twice_says_so():
    port = free_port()
    proxy = LocalProxy(FakeTunnel(), client_config(port))
    await proxy.start()
    try:
        second = LocalProxy(FakeTunnel(), client_config(port))
        with pytest.raises(TransportError, match="could not listen"):
            await second.start()
    finally:
        await proxy.stop()


async def test_start_reports_the_address_it_is_listening_on():
    proxy = LocalProxy(FakeTunnel(), client_config(free_port()))
    bound = await proxy.start()
    try:
        assert bound == [f"127.0.0.1:{proxy.config.listen_port}"]
    finally:
        await proxy.stop()


async def test_serve_forever_returns_when_stopped_and_stopping_twice_is_fine():
    proxy = LocalProxy(FakeTunnel(), client_config(free_port()))
    serving = asyncio.create_task(proxy.serve_forever())
    await asyncio.sleep(0.05)
    await proxy.stop()
    await asyncio.wait_for(serving, timeout=5)
    await proxy.stop()


async def test_a_client_that_disappears_mid_tunnel_does_not_disturb_the_proxy():
    proxy, tunnel = await start_proxy()
    try:
        reader, writer = await socks_client(proxy.config.listen_port)
        writer.write(b"\x05\x01\x00\x01" + bytes([93, 184, 216, 34]) + struct.pack(">H", 443))
        await writer.drain()
        assert await read_socks_reply(reader) == 0x00
        writer.write(b"some bytes\r\n")
        await writer.drain()
        writer.transport.abort()  # a rude disconnect, not a clean close

        # The proxy still serves the next client.
        reader2, writer2 = await socks_client(proxy.config.listen_port)
        writer2.write(b"\x05\x01\x00\x03\x0bexample.com" + struct.pack(">H", 80))
        await writer2.drain()
        assert await read_socks_reply(reader2) == 0x00
        writer2.close()
        assert proxy.connections == 2
        assert tunnel.session.streams.detached, "the abandoned stream is still released"
    finally:
        await proxy.stop()


async def test_stop_closes_live_tunnels_rather_than_hanging():
    proxy, _tunnel = await start_proxy()
    try:
        reader, writer = await socks_client(proxy.config.listen_port)
        writer.write(b"\x05\x01\x00\x03\x0bexample.com" + struct.pack(">H", 80))
        await writer.drain()
        assert await read_socks_reply(reader) == 0x00
        await proxy.stop()
        assert proxy._tasks == set(), "no leftover client tasks"
        with contextlib.suppress(ConnectionError):
            assert await asyncio.wait_for(reader.read(), timeout=5) in (b"", None)
        writer.close()
    finally:
        with contextlib.suppress(Exception):
            await proxy.stop()
