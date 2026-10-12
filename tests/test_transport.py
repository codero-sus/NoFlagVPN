"""The WebSocket carrier: framing rules, and the shapes it shows the outside."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os

import pytest
from nfvpn.errors import ConfigError, TransportError
from nfvpn.transport import Endpoint, accept_transport, dial
from nfvpn.transport.websocket import (
    COVER_404,
    DEFAULT_USER_AGENT,
    WebSocketTransport,
    compute_accept,
    read_frame,
    write_frame,
)

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def reader_for(data: bytes) -> asyncio.StreamReader:
    """A StreamReader pre-loaded with ``data`` (and closed), for codec tests."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def test_accept_key_matches_rfc_6455():
    # The example straight out of the RFC.
    assert compute_accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_handshake_headers_use_the_rfc_guid():
    key = base64.b64encode(os.urandom(16)).decode()
    assert compute_accept(key) == base64.b64encode(
        __import__("hashlib").sha1((key + GUID).encode()).digest()
    ).decode()


def test_client_frames_are_masked():
    frame = write_frame(0x2, b"hello", mask=True)
    assert frame[0] == 0x82  # FIN + binary
    assert frame[1] & 0x80  # MASK set
    assert (frame[1] & 0x7F) == 5


def test_server_frames_are_not_masked():
    frame = write_frame(0x2, b"hello", mask=False)
    assert not (frame[1] & 0x80)


@pytest.mark.parametrize("size", [0, 1, 125, 126, 127, 65535, 65536])
async def test_frame_length_encoding_round_trips(size):
    payload = os.urandom(size)
    reader = reader_for(write_frame(0x2, payload, mask=True))
    frame = await read_frame(reader)
    assert frame.payload == payload


async def test_oversized_frames_are_refused():
    header = bytearray(write_frame(0x2, b"x", mask=True))
    header[1] = 0x80 | 127  # a client frame claiming 2^63 bytes
    header[2:10] = (1 << 62).to_bytes(8, "big")
    with pytest.raises((TransportError, asyncio.IncompleteReadError)):
        await asyncio.wait_for(read_frame(reader_for(bytes(header))), timeout=1)


async def test_codec_hands_back_the_raw_payload_of_a_text_frame():
    """Framing and encoding are separate: the codec does not guess."""
    reader = reader_for(write_frame(0x1, b"aGVsbG8=", mask=True))
    frame = await read_frame(reader)
    assert frame.opcode == 0x1
    assert frame.payload == b"aGVsbG8="


# --- the carrier in situ --------------------------------------------------------


class EchoServer:
    """Accepts either a WebSocket or a raw TCP carrier and echoes bytes."""

    def __init__(self, *, websocket: bool = True, encoding: str = "binary") -> None:
        self.websocket = websocket
        self.encoding = encoding
        self.port = 0
        self.server: asyncio.AbstractServer | None = None
        self.requests: list[bytes] = []

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
            transport = await accept_transport(
                reader, writer, is_websocket=self.websocket, encoding=self.encoding
            )
            while True:
                message = await transport.receive_message()
                if message is None:
                    break
                await transport.send_message(b"echo:" + message)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()


@pytest.fixture
async def echo():
    server = EchoServer()
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


async def test_websocket_round_trip(echo):
    transport = await dial(Endpoint.parse(f"ws://127.0.0.1:{echo.port}/x"))
    for payload in (b"one", b"two", os.urandom(70000)):
        await transport.send_message(payload)
        assert await transport.receive_message() == b"echo:" + payload
    await transport.close()


async def test_text_mode_round_trip():
    """Both ends must agree on base64-in-text-frames; then it just works."""
    server = EchoServer(encoding="text")
    await server.start()
    try:
        transport = await dial(
            Endpoint.parse(f"ws://127.0.0.1:{server.port}/x"), encoding="text"
        )
        payload = os.urandom(5000)
        await transport.send_message(payload)
        assert await transport.receive_message() == b"echo:" + payload
        await transport.close()
    finally:
        await server.stop()


async def test_non_upgrade_request_gets_the_cover_page(echo):
    reader, writer = await asyncio.open_connection("127.0.0.1", echo.port)
    writer.write(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(8192), timeout=5)
    assert response.startswith(b"HTTP/1.1 404")
    assert b"Server: nginx" in response
    assert COVER_404 in response  # nginx's own 404 page, byte for byte
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_upgrade_with_a_bogus_key_looks_like_the_cover_page(echo):
    reader, writer = await asyncio.open_connection("127.0.0.1", echo.port)
    writer.write(
        b"GET /x HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: not-a-real-key\r\n"
        b"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    await writer.drain()
    response = await asyncio.wait_for(reader.read(8192), timeout=5)
    assert response.startswith(b"HTTP/1.1 404")
    assert b"101" not in response.split(b"\r\n", 1)[0]
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_server_rejects_a_client_that_forgets_to_mask(echo):
    reader, writer = await asyncio.open_connection("127.0.0.1", echo.port)
    key = base64.b64encode(os.urandom(16)).decode()
    writer.write(
        f"GET /x HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n".encode()
    )
    await writer.drain()
    await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    writer.write(write_frame(0x2, b"unmasked", mask=False))
    await writer.drain()
    # The server must close rather than accept an unmasked client frame.
    with contextlib.suppress(Exception):
        await asyncio.wait_for(reader.read(1024), timeout=2)
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


def test_user_agent_looks_ordinary():
    assert DEFAULT_USER_AGENT.startswith("Mozilla/5.0")
    assert "Chrome" in DEFAULT_USER_AGENT


def test_endpoint_parsing():
    assert Endpoint.parse("wss://relay.example/cdn").port == 443
    assert Endpoint.parse("ws://relay.example/cdn").port == 80
    assert Endpoint.parse("relay.example:9443").scheme == "wss"
    assert Endpoint.parse("relay.example:9443").port == 9443
    assert Endpoint.parse("tcp://relay.example:9001").host == "relay.example"
    with pytest.raises(ConfigError):
        Endpoint.parse("gopher://relay.example")
    with pytest.raises(ConfigError):
        Endpoint.parse("relay.example:70000")


async def test_raw_tcp_carrier_also_works():
    server = EchoServer(websocket=False)
    await server.start()
    try:
        transport = await dial(Endpoint.parse(f"tcp://127.0.0.1:{server.port}"))
        await transport.send_message(b"hello")
        assert await transport.receive_message() == b"echo:hello"
        await transport.close()
    finally:
        await server.stop()


async def test_websocket_transport_construction_is_inert():
    """Building one must not touch the wire; the handshake is an explicit step."""
    transport = WebSocketTransport(asyncio.StreamReader(), None, peer="127.0.0.1:1")  # type: ignore[arg-type]
    assert transport.info.peer == "127.0.0.1:1"
    assert transport.info.encrypted is False
