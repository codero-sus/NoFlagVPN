"""The carrier's corners: frame codec edges, both handshakes, and framing.

``test_transport.py`` covers the happy round trip in both encodings and the two
cover responses.  This file is about the parts a peer only reaches when it is
broken, hostile, or a real website:

* the frame codec at its boundaries (length prefixes, masking, control-frame
  limits) and every malformed frame it must refuse;
* the client handshake's validation - the Accept check is the only thing
  standing between a client and a man in the middle that answers 101 itself;
* the server handshake's cover behaviour, including the case that matters most:
  a *malformed* upgrade must look exactly like a plain page.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import struct

import pytest
from nfvpn.errors import TransportError
from nfvpn.transport.websocket import (
    OP_BINARY,
    OP_CLOSE,
    OP_CONTINUATION,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    PayloadEncoding,
    WebSocketTransport,
    _looks_like_ws_key,
    compute_accept,
    perform_client_handshake,
    perform_server_handshake,
    read_frame,
    write_frame,
)


def reader_for(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


async def read_one(data: bytes):
    return await read_frame(reader_for(data))


def server_transport(reader, writer, **kwargs) -> WebSocketTransport:
    return WebSocketTransport(reader, writer, server_side=True, **kwargs)


# --------------------------------------------------------------------------- #
# frame codec
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "size, prefix",
    [
        (0, 2),
        (125, 2),
        (126, 4),  # the 16-bit form, starting here
        (65535, 4),
        (65536, 10),  # the 64-bit form
    ],
)
async def test_length_prefixes_use_the_shortest_form_that_fits(size, prefix):
    payload = b"x" * size
    frame = write_frame(OP_BINARY, payload)
    assert len(frame) == prefix + size, "header size tells which form was used"
    decoded = await read_one(frame)
    assert decoded.payload == payload
    assert decoded.opcode == OP_BINARY
    assert decoded.fin is True


async def test_a_masked_frame_carries_a_key_and_its_payload_is_not_the_original():
    payload = b"the quick brown fox"
    frame = write_frame(OP_BINARY, payload, mask=True)
    assert frame[1] & 0x80, "the mask bit is set"
    assert frame[2:6] != payload[:4], "a mask key is present"
    assert payload not in frame, "the plaintext must not appear in the clear"
    assert (await read_one(frame)).payload == payload, "and it still decodes"


async def test_a_big_frame_is_still_masked_correctly():
    payload = os.urandom(70000)
    frame = write_frame(OP_BINARY, payload, mask=True)
    assert frame[1] & 0x80
    assert (await read_one(frame)).payload == payload


def test_control_frames_may_not_exceed_125_bytes():
    assert write_frame(OP_PING, b"x" * 125)
    with pytest.raises(TransportError, match="125 bytes"):
        write_frame(OP_PING, b"x" * 126)
    with pytest.raises(TransportError, match="125 bytes"):
        write_frame(OP_CLOSE, b"x" * 200)


def test_the_continuation_opcode_is_not_a_control_frame():
    assert write_frame(OP_CONTINUATION, b"x" * 500)


async def test_rsv_bits_are_refused():
    """RSV set means an extension we never negotiated; guessing is unsafe."""
    frame = bytearray(write_frame(OP_BINARY, b"data"))
    frame[0] |= 0x40
    with pytest.raises(TransportError, match="RSV bits"):
        await read_one(bytes(frame))


async def test_a_fragmented_control_frame_is_refused():
    frame = bytearray(write_frame(OP_PING, b"hi"))
    frame[0] &= 0x7F  # FIN = 0
    with pytest.raises(TransportError, match="fragmented control frame"):
        await read_one(bytes(frame))


async def test_an_oversized_control_frame_is_refused():
    header = bytes([0x80 | OP_PING, 126]) + struct.pack(">H", 500)
    with pytest.raises(TransportError, match="oversized control frame"):
        await read_one(header + b"x" * 500)


async def test_a_64_bit_length_with_the_high_bit_set_is_refused():
    header = bytes([0x80 | OP_BINARY, 127]) + struct.pack(">Q", 1 << 63)
    with pytest.raises(TransportError, match="high bit"):
        await read_one(header)


@pytest.mark.parametrize(
    "data, message",
    [
        (b"", "frame header"),
        (b"\x82", "frame header"),
        (b"\x82\x7e\x00", "16-bit frame length"),
        (b"\x82\x7f\x00\x00\x00\x00\x00\x00", "64-bit frame length"),
        (b"\x82\x81\x00\x01", "masking key"),
        (b"\x82\x81\x00\x01\x02\x03", "mid-frame"),
    ],
)
async def test_truncated_frames_are_refused_with_a_reason(data, message):
    with pytest.raises(TransportError, match=message):
        await read_one(data)


async def test_a_zero_length_frame_needs_no_payload_bytes():
    frame = await read_one(bytes([0x80 | OP_BINARY, 0]))
    assert frame.payload == b""


async def test_fin_is_reported_so_fragments_can_be_assembled():
    assert (await read_one(write_frame(OP_BINARY, b"a", fin=False))).fin is False


# --------------------------------------------------------------------------- #
# the client handshake: what it must refuse
# --------------------------------------------------------------------------- #
class FakeServer:
    """Answers the client handshake with whatever bytes a test hands it."""

    def __init__(
        self, reply: bytes | None = None, *, echo_accept: bool = False, silent: bool = False
    ) -> None:
        self.reply = reply
        self.echo_accept = echo_accept
        self.silent = silent
        self.received = b""
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = int(self._server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        try:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                request += chunk
            self.received = request
            if self.silent:
                await asyncio.sleep(30)
                return
            if self.reply is not None:
                writer.write(self.reply)
                await writer.drain()
                return
            if self.echo_accept:
                key = b""
                for line in request.split(b"\r\n"):
                    if line.lower().startswith(b"sec-websocket-key:"):
                        key = line.split(b":", 1)[1].strip().decode()
                writer.write(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {compute_accept(key)}\r\n"
                        "Server: nginx\r\n\r\n"
                    ).encode()
                )
                await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()


@contextlib.asynccontextmanager
async def fake_server(reply: bytes | None = None, *, echo_accept: bool = False, silent: bool = False):
    server = FakeServer(reply, echo_accept=echo_accept, silent=silent)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


async def client_handshake(port: int, **kwargs):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    kwargs.setdefault("host", f"127.0.0.1:{port}")
    kwargs.setdefault("timeout", 5)
    try:
        return await perform_client_handshake(reader, writer, path="/cdn", **kwargs)
    finally:
        with contextlib.suppress(Exception):
            writer.close()


async def test_a_correct_handshake_returns_the_response_headers():
    async with fake_server(echo_accept=True) as server:
        headers = await client_handshake(server.port)
    assert headers["upgrade"].lower() == "websocket"
    assert headers["server"] == "nginx"


async def test_the_client_request_looks_like_a_browser():
    async with fake_server(echo_accept=True) as server:
        await client_handshake(server.port)
    request = server.received.decode("latin-1")
    assert request.startswith("GET /cdn HTTP/1.1\r\n")
    for header in (
        "Host:",
        "User-Agent: Mozilla/5.0",
        "Accept: */*",
        "Accept-Language:",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key:",
    ):
        assert header in request, header
    assert f"Origin: https://127.0.0.1:{server.port}" in request, "a browser sends Origin"


async def test_extra_headers_and_subprotocol_are_sent_when_asked():
    async with fake_server(echo_accept=True) as server:
        await client_handshake(
            server.port, subprotocol="graphql-ws", extra_headers={"X-Forwarded-For": "10.0.0.1"}
        )
    request = server.received.decode("latin-1")
    assert "Sec-WebSocket-Protocol: graphql-ws" in request
    assert "X-Forwarded-For: 10.0.0.1" in request


async def test_a_wrong_accept_header_is_refused():
    """This check is the client's only defence against a fake 101."""
    response = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
    )
    async with fake_server(response) as server:
        with pytest.raises(TransportError, match="Sec-WebSocket-Accept"):
            await client_handshake(server.port)


async def test_a_non_101_status_is_refused_with_its_first_line():
    response = b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
    async with fake_server(response) as server:
        with pytest.raises(TransportError) as caught:
            await client_handshake(server.port)
    assert "302" in str(caught.value), "the status the relay actually sent is the useful part"


async def test_a_101_without_the_upgrade_header_is_refused():
    response = b"HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\n\r\n"
    async with fake_server(response) as server:
        with pytest.raises(TransportError, match="not a WebSocket upgrade"):
            await client_handshake(server.port)


async def test_a_malformed_response_header_is_refused():
    response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nno-colon-here\r\n\r\n"
    async with fake_server(response) as server:
        with pytest.raises(TransportError, match="malformed header"):
            await client_handshake(server.port)


async def test_a_server_that_hangs_up_mid_handshake_is_reported():
    async with fake_server(b"") as server:
        with pytest.raises(TransportError, match="closed the connection during the handshake"):
            await client_handshake(server.port)


async def test_a_server_that_never_answers_times_out():
    async with fake_server(None, silent=True) as server:
        with pytest.raises(TransportError, match="timed out waiting"):
            await client_handshake(server.port, timeout=0.3)


async def test_the_host_header_can_carry_a_real_domain():
    async with fake_server(echo_accept=True) as server:
        await client_handshake(server.port, host="cdn.example.com")
    assert b"Host: cdn.example.com" in server.received
    assert b"Origin: https://cdn.example.com" in server.received


# --------------------------------------------------------------------------- #
# the server handshake: cover traffic and upgrades
# --------------------------------------------------------------------------- #
class FakeClient:
    """A raw connection to the server handshake, so bytes can be malformed."""

    def __init__(self, server) -> None:
        self.server = server

    async def request(self, raw: bytes, read_until: int = 4096) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.server.port)
        try:
            writer.write(raw)
            await writer.drain()
            with contextlib.suppress(asyncio.TimeoutError):
                return await asyncio.wait_for(reader.read(read_until), timeout=5)
            return b""
        finally:
            writer.close()


@pytest.fixture
async def cover_server():
    async def handle(reader, writer):
        try:
            await perform_server_handshake(reader, writer, timeout=5)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                await writer.drain()
                writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    server.port = int(server.sockets[0].getsockname()[1])  # type: ignore[attr-defined]
    try:
        yield server
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


def upgrade_request(key: str = "dGhlIHNhbXBsZSBub25jZQ==", extra: str = "") -> bytes:
    return (
        "GET /cdn HTTP/1.1\r\n"
        "Host: relay.example\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"{extra}"
        "\r\n"
    ).encode()


async def test_a_plain_browser_request_gets_the_cover_page(cover_server):
    client = FakeClient(cover_server)
    response = await client.request(b"GET / HTTP/1.1\r\nHost: relay.example\r\n\r\n")
    assert response.startswith(b"HTTP/1.1 404 Not Found")
    assert b"Server: nginx" in response, "the cover page claims a real server"
    assert b"Content-Type: text/html" in response
    assert b"Content-Length:" in response


@pytest.mark.parametrize(
    "request_bytes",
    [
        b"GET /cdn HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",  # no key, no version
        upgrade_request(extra=""),  # fine
        upgrade_request(key="not-base64!!"),  # a key a real client would never send
        upgrade_request(key=base64.b64encode(b"too-short").decode()),  # 9 bytes, not 16
        b"GET /cdn HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Version: 8\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    ],
)
async def test_malformed_upgrades_are_indistinguishable_from_the_cover_page(
    cover_server, request_bytes
):
    """The point of cover traffic: a prober cannot tell this apart from nginx."""
    response = await FakeClient(cover_server).request(request_bytes)
    if response.startswith(b"HTTP/1.1 101"):
        assert b"Sec-WebSocket-Accept" in response
    else:
        assert response.startswith(b"HTTP/1.1 404 Not Found"), response[:64]
        assert b"nginx" in response


async def test_too_many_headers_gets_the_status_a_real_server_would_send(cover_server):
    padding = "".join(f"X-Filler-{index}: {'a' * 60}\r\n" for index in range(400))
    response = await FakeClient(cover_server).request(upgrade_request(extra=padding))
    assert response.startswith(b"HTTP/1.1 431"), response[:80]
    assert b"nginx" in response, "even a refusal keeps the cover server header"


async def test_a_header_line_without_a_colon_is_skipped_not_fatal(cover_server):
    response = await FakeClient(cover_server).request(
        upgrade_request(extra="garbage-without-a-colon\r\n")
    )
    assert response.startswith(b"HTTP/1.1 101"), "a real server would still upgrade"


async def test_the_upgrade_accepts_a_valid_key_and_echoes_the_accept(cover_server):
    response = await FakeClient(cover_server).request(upgrade_request())
    head = response.split(b"\r\n\r\n")[0].decode()
    assert head.startswith("HTTP/1.1 101 Switching Protocols")
    assert compute_accept("dGhlIHNhbXBsZSBub25jZQ==") in head
    assert "Server: nginx" in head


async def test_no_server_header_is_sent_when_the_operator_turned_it_off():
    async def handle(reader, writer):
        try:
            await perform_server_handshake(
                reader, writer, server_header=None, timeout=5, cover_body=b"<html></html>"
            )
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    server.port = int(server.sockets[0].getsockname()[1])  # type: ignore[attr-defined]
    try:
        response = await FakeClient(server).request(b"GET / HTTP/1.1\r\n\r\n")
        assert b"Server:" not in response
        assert b"ngin" not in response
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


async def test_a_silent_connection_is_dropped_without_a_reply(cover_server):
    reader, writer = await asyncio.open_connection("127.0.0.1", cover_server.port)
    try:
        with contextlib.suppress(asyncio.TimeoutError):
            data = await asyncio.wait_for(reader.read(100), timeout=6)
            assert data == b"", "no bytes, no banner"
    finally:
        writer.close()


async def test_the_chosen_subprotocol_is_echoed_when_it_was_offered():
    async def handle(reader, writer):
        try:
            result = await perform_server_handshake(
                reader, writer, subprotocols=("graphql-ws",), timeout=5
            )
            assert result.subprotocol == "graphql-ws"
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        response = await FakeClient(type("S", (), {"port": port})()).request(
            upgrade_request(extra="Sec-WebSocket-Protocol: graphql-ws\r\n")
        )
        assert b"Sec-WebSocket-Protocol: graphql-ws" in response
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


def test_key_shape_validation():
    assert _looks_like_ws_key(base64.b64encode(os.urandom(16)).decode())
    assert not _looks_like_ws_key("short")
    assert not _looks_like_ws_key("not base64 !!!")
    assert not _looks_like_ws_key(base64.b64encode(os.urandom(20)).decode()), "not 16 bytes"
    assert not _looks_like_ws_key("")


# --------------------------------------------------------------------------- #
# transport framing
# --------------------------------------------------------------------------- #
class Pipe:
    """A transport on a real socket pair, with the peer under test control."""

    def __init__(self, *, server_side: bool, encoding: str = "binary", max_size: int = 1 << 20):
        self.server_side = server_side
        self.encoding = encoding
        self.max_size = max_size
        self.transport: WebSocketTransport | None = None
        self.server: asyncio.AbstractServer | None = None
        self.peer_reader: asyncio.StreamReader | None = None
        self.peer_writer: asyncio.StreamWriter | None = None
        self.connected = asyncio.Event()

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        port = int(self.server.sockets[0].getsockname()[1])
        self.peer_reader, self.peer_writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.wait_for(self.connected.wait(), timeout=5)
        return self

    async def _accept(self, reader, writer):
        self.transport = WebSocketTransport(
            reader,
            writer,
            peer="127.0.0.1:0",
            server_side=self.server_side,
            encoding=self.encoding,
            max_message_size=self.max_size,
        )
        self.connected.set()
        await asyncio.sleep(10)

    async def __aexit__(self, *exc):
        with contextlib.suppress(Exception):
            if self.peer_writer is not None:
                self.peer_writer.close()
        if self.server is not None:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()


async def test_ping_is_answered_automatically_and_pongs_are_ignored():
    async with Pipe(server_side=True) as pipe:
        # Control frames are handled inside receive_message(), so a reader has to
        # be waiting for the pong to be sent at all.
        pending = asyncio.create_task(pipe.transport.receive_message())
        pipe.peer_writer.write(write_frame(OP_PING, b"keepalive", mask=True))
        await pipe.peer_writer.drain()
        reply = await asyncio.wait_for(read_frame(pipe.peer_reader), timeout=5)
        assert reply.opcode == OP_PONG
        assert reply.payload == b"keepalive"
        assert reply.payload != b"\x00", "not masked: the answer came from the server"

        # An unsolicited pong is skipped, and the message behind it still arrives.
        pipe.peer_writer.write(write_frame(OP_PONG, b"unsolicited", mask=True))
        pipe.peer_writer.write(write_frame(OP_BINARY, b"payload", mask=True))
        await pipe.peer_writer.drain()
        assert await asyncio.wait_for(pending, timeout=5) == b"payload"


async def test_a_close_frame_ends_the_carrier_and_is_answered():
    async with Pipe(server_side=True) as pipe:
        pipe.peer_writer.write(write_frame(OP_CLOSE, struct.pack(">H", 1000), mask=True))
        await pipe.peer_writer.drain()
        with pytest.raises(TransportError, match="peer closed the carrier"):
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)
        reply = await asyncio.wait_for(read_frame(pipe.peer_reader), timeout=5)
        assert reply.opcode == OP_CLOSE


async def test_fragments_are_assembled_into_one_message():
    async with Pipe(server_side=True) as pipe:
        pipe.peer_writer.write(write_frame(OP_BINARY, b"first ", mask=True, fin=False))
        pipe.peer_writer.write(write_frame(OP_CONTINUATION, b"second ", mask=True, fin=False))
        pipe.peer_writer.write(write_frame(OP_CONTINUATION, b"third", mask=True, fin=True))
        await pipe.peer_writer.drain()
        assert await asyncio.wait_for(pipe.transport.receive_message(), timeout=5) == b"first second third"


async def test_a_message_split_into_many_fragments_is_reassembled():
    """Three or more frames is the case that used to fail.

    A reassembled-but-unfinished message cleared the marker that says a message
    is in progress, so the *third* frame onwards looked like a continuation with
    no start and the carrier was dropped.  Two-frame fragmentation - the shape
    of a small message - worked, which is why this survived.
    """
    async with Pipe(server_side=True) as pipe:
        pipe.peer_writer.write(write_frame(OP_BINARY, b"one ", mask=True, fin=False))
        for piece in (b"two ", b"three ", b"four "):
            pipe.peer_writer.write(write_frame(OP_CONTINUATION, piece, mask=True, fin=False))
        pipe.peer_writer.write(write_frame(OP_CONTINUATION, b"five", mask=True, fin=True))
        await pipe.peer_writer.drain()
        assert (
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)
            == b"one two three four five"
        )


async def test_a_fragmented_message_leaves_the_carrier_usable():
    async with Pipe(server_side=True) as pipe:
        pipe.peer_writer.write(write_frame(OP_BINARY, b"a", mask=True, fin=False))
        pipe.peer_writer.write(write_frame(OP_CONTINUATION, b"b", mask=True, fin=False))
        pipe.peer_writer.write(write_frame(OP_CONTINUATION, b"c", mask=True, fin=False))
        pipe.peer_writer.write(write_frame(OP_CONTINUATION, b"d", mask=True, fin=True))
        pipe.peer_writer.write(write_frame(OP_BINARY, b"next message", mask=True))
        await pipe.peer_writer.drain()
        assert await asyncio.wait_for(pipe.transport.receive_message(), timeout=5) == b"abcd"
        assert (
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)
            == b"next message"
        )


async def test_a_continuation_without_a_start_is_refused():
    async with Pipe(server_side=True) as pipe:
        pipe.peer_writer.write(write_frame(OP_CONTINUATION, b"orphan", mask=True))
        await pipe.peer_writer.drain()
        with pytest.raises(TransportError, match="continuation frame without a start"):
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)


async def test_an_unsupported_opcode_is_refused():
    async with Pipe(server_side=True) as pipe:
        pipe.peer_writer.write(write_frame(0x3, b"data", mask=True))  # a reserved data opcode
        await pipe.peer_writer.drain()
        with pytest.raises(TransportError, match="unsupported opcode 0x3"):
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)


async def test_an_oversized_message_is_refused_with_the_limit():
    async with Pipe(server_side=True, max_size=1024) as pipe:
        pipe.peer_writer.write(write_frame(OP_BINARY, b"x" * 2000, mask=True))
        await pipe.peer_writer.drain()
        with pytest.raises(TransportError, match="1024-byte carrier limit"):
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)


async def test_a_websocket_message_in_the_wrong_encoding_is_skipped_as_noise():
    """A real site may send any HTML at us; noise is skipped, not fatal."""
    async with Pipe(server_side=True, encoding="binary") as pipe:
        pipe.peer_writer.write(write_frame(OP_TEXT, b"<html>hello</html>", mask=True))
        pipe.peer_writer.write(write_frame(OP_BINARY, b"real message", mask=True))
        await pipe.peer_writer.drain()
        assert await asyncio.wait_for(pipe.transport.receive_message(), timeout=5) == b"real message"


async def test_text_mode_decodes_base64_and_refuses_a_bad_encoding():
    async with Pipe(server_side=True, encoding="text") as pipe:
        pipe.peer_writer.write(write_frame(OP_TEXT, base64.b64encode(b"secret"), mask=True))
        pipe.peer_writer.write(write_frame(OP_TEXT, b"!!! not base64 !!!", mask=True))
        await pipe.peer_writer.drain()
        assert await asyncio.wait_for(pipe.transport.receive_message(), timeout=5) == b"secret"
        with pytest.raises(TransportError, match="malformed base64"):
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)


async def test_text_mode_sends_base64_text_frames():
    async with Pipe(server_side=True, encoding="text") as pipe:
        await pipe.transport.send_message(b"\x00\xff binary bytes")
        frame = await asyncio.wait_for(read_frame(pipe.peer_reader), timeout=5)
        assert frame.opcode == OP_TEXT
        assert base64.b64decode(frame.payload) == b"\x00\xff binary bytes"


async def test_sending_after_close_is_a_transport_error():
    async with Pipe(server_side=True) as pipe:
        await pipe.transport.close()
        with pytest.raises(TransportError, match="carrier is closed"):
            await pipe.transport.send_message(b"too late")
        with pytest.raises(TransportError, match="carrier is closed"):
            await pipe.transport.receive_message()


async def test_closing_twice_is_harmless():
    async with Pipe(server_side=True) as pipe:
        await pipe.transport.close()
        await pipe.transport.close()


async def test_ping_truncates_its_payload_to_the_control_limit():
    async with Pipe(server_side=True) as pipe:
        await pipe.transport.ping(b"x" * 500)
        frame = await asyncio.wait_for(read_frame(pipe.peer_reader), timeout=5)
        assert frame.opcode == OP_PING
        assert len(frame.payload) == 125


async def test_info_describes_the_carrier():
    async with Pipe(server_side=True) as pipe:
        info = pipe.transport.info
        assert info.kind == "websocket", "plain ws, no TLS"
        assert info.encrypted is False
        assert "path /" in info.detail
        assert pipe.transport.encoding == PayloadEncoding.BINARY


async def test_a_server_side_transport_without_an_upgrade_refuses():
    async with Pipe(server_side=True) as pipe:
        with pytest.raises(TransportError, match="no WebSocket upgrade"):
            await pipe.transport.open()


# --------------------------------------------------------------------------- #
# the raw carrier, which is the same contract with four bytes of framing
# --------------------------------------------------------------------------- #
from nfvpn.transport.raw import RawTCPTransport  # noqa: E402


class RawPipe:
    """A RawTCPTransport on a real socket pair, with the peer under our control."""

    def __init__(self, *, max_size: int = 1 << 20) -> None:
        self.transport: RawTCPTransport | None = None
        self.server: asyncio.AbstractServer | None = None
        self.peer_reader: asyncio.StreamReader | None = None
        self.peer_writer: asyncio.StreamWriter | None = None
        self.ready = asyncio.Event()
        self.max_size = max_size

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        port = int(self.server.sockets[0].getsockname()[1])
        self.peer_reader, self.peer_writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.wait_for(self.ready.wait(), timeout=5)
        return self

    async def _accept(self, reader, writer):
        self.transport = RawTCPTransport(
            reader, writer, peer="127.0.0.1:0", max_message_size=self.max_size
        )
        await self.transport.open()
        self.ready.set()
        await asyncio.sleep(10)

    async def __aexit__(self, *exc):
        with contextlib.suppress(Exception):
            if self.peer_writer is not None:
                self.peer_writer.close()
        if self.server is not None:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()


async def test_raw_framing_is_a_four_byte_length_and_the_bytes():
    async with RawPipe() as pipe:
        await pipe.transport.send_message(b"hello raw")
        assert await asyncio.wait_for(pipe.peer_reader.readexactly(13), timeout=5) == (
            b"\x00\x00\x00\x09hello raw"
        )
        assert pipe.transport.bytes_sent == 9, "the counter is the payload, not the header"


async def test_raw_framing_decodes_and_handles_empty_messages():
    async with RawPipe() as pipe:
        pipe.peer_writer.write(struct.pack(">I", 0))
        pipe.peer_writer.write(struct.pack(">I", 4) + b"data")
        await pipe.peer_writer.drain()
        assert await asyncio.wait_for(pipe.transport.receive_message(), timeout=5) == b""
        assert await asyncio.wait_for(pipe.transport.receive_message(), timeout=5) == b"data"


async def test_a_truncated_length_prefix_is_a_closed_carrier():
    async with RawPipe() as pipe:
        pipe.peer_writer.write(b"\x00\x00")
        pipe.peer_writer.close()
        with pytest.raises(TransportError, match="carrier closed"):
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)


async def test_a_message_that_stops_mid_way_is_a_closed_carrier():
    async with RawPipe() as pipe:
        pipe.peer_writer.write(struct.pack(">I", 100) + b"only-a-few")
        await pipe.peer_writer.drain()
        pipe.peer_writer.close()
        with pytest.raises(TransportError, match="mid-message"):
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)


async def test_a_peer_that_announces_gigabytes_is_refused_before_allocating():
    async with RawPipe(max_size=4096) as pipe:
        pipe.peer_writer.write(struct.pack(">I", 1 << 30))
        await pipe.peer_writer.drain()
        with pytest.raises(TransportError, match="oversized message"):
            await asyncio.wait_for(pipe.transport.receive_message(), timeout=5)


async def test_sending_past_the_limit_is_refused_client_side():
    async with RawPipe(max_size=64) as pipe:
        with pytest.raises(TransportError, match="carrier limit"):
            await pipe.transport.send_message(b"x" * 65)
        await pipe.transport.send_message(b"x" * 64)


async def test_raw_close_is_idempotent_and_sending_afterwards_is_refused():
    async with RawPipe() as pipe:
        await pipe.transport.close()
        await pipe.transport.close()
        with pytest.raises(TransportError, match="carrier is closed"):
            await pipe.transport.send_message(b"nope")
        with pytest.raises(TransportError, match="carrier is closed"):
            await pipe.transport.receive_message()


async def test_raw_info_describes_the_carrier():
    async with RawPipe() as pipe:
        assert pipe.transport.info.kind == "raw"
        assert pipe.transport.info.encrypted is False
        assert pipe.transport.info.detail == "length-prefixed"
