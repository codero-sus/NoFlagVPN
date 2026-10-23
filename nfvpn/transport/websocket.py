"""An RFC 6455 WebSocket carrier, client and server side.

WebSocket is the carrier of choice for two reasons that have nothing to do with
convenience:

1. **It is everywhere.**  A port serving WebSocket traffic is a port serving
   video calls, dashboards, chat and games.  Blocking it wholesale costs the
   censor a great deal, which is exactly the situation we want to create.
2. **It is cheap to look normal.**  The handshake we send is the handshake a
   browser sends, the cover response we give a non-upgrade request is the default
   page of the web server everyone deploys, and the frames on the wire are the
   frames any browser produces.

What this implementation deliberately does *not* do: negotiate extensions
(``permessage-deflate`` is a fingerprint and a compression side channel), send
non-zero RSV bits, or accept unmasked client frames — a real server rejects
those, so we do too.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import secrets
import struct
from dataclasses import dataclass

from nfvpn.errors import TransportError
from nfvpn.transport.base import Transport, TransportInfo

__all__ = [
    "COVER_404",
    "DEFAULT_USER_AGENT",
    "WS_GUID",
    "Frame",
    "PayloadEncoding",
    "WebSocketTransport",
    "compute_accept",
    "perform_client_handshake",
    "perform_server_handshake",
    "read_frame",
    "write_frame",
]

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

#: A realistic desktop Chrome UA.  `nfvpn doctor` warns if the platform you run
#: on makes this lie obvious (e.g. an Android UA string on a Linux server).
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

#: The default page nginx serves for an unknown path.  Returning *this* to
#: scanners matters more than it looks: it means an active prober that knocks on
#: our port with ordinary HTTP sees an ordinary web server, not a protocol error.
COVER_404 = (
    b"<html>\r\n<head><title>404 Not Found</title></head>\r\n"
    b"<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
    b"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
)

_MAX_CONTROL_PAYLOAD = 125


class PayloadEncoding(str):
    """How record bytes ride inside WebSocket frames."""

    BINARY = "binary"
    TEXT = "text"


@dataclass(frozen=True)
class Frame:
    """One decoded WebSocket frame."""

    opcode: int
    payload: bytes
    fin: bool = True
    masked: bool = False


def compute_accept(key: str) -> str:
    """``base64(SHA1(key ‖ GUID))`` — the server's proof it spoke WebSocket (RFC 6455 §4.2.2)."""
    from hashlib import sha1

    digest = sha1(key.strip().encode("ascii") + WS_GUID.encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


# --------------------------------------------------------------------------- #
# Frame codec
# --------------------------------------------------------------------------- #
def write_frame(opcode: int, payload: bytes = b"", *, mask: bool = False, fin: bool = True) -> bytes:
    """Serialise one WebSocket frame."""
    if opcode >= 0x8 and len(payload) > _MAX_CONTROL_PAYLOAD:
        raise TransportError("control frames may not exceed 125 bytes")

    header = bytearray()
    header.append((0x80 if fin else 0x00) | (opcode & 0x0F))
    length = len(payload)
    mask_bit = 0x80 if mask else 0x00
    if length < 126:
        header.append(mask_bit | length)
    elif length < (1 << 16):
        header.append(mask_bit | 126)
        header += struct.pack(">H", length)
    else:
        header.append(mask_bit | 127)
        header += struct.pack(">Q", length)

    if not mask:
        return bytes(header) + payload

    key = secrets.token_bytes(4)
    masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return bytes(header) + key + masked


async def read_frame(
    reader: asyncio.StreamReader, *, max_payload_size: int | None = None
) -> Frame:
    """Read one WebSocket frame, optionally bounding its payload before allocation.

    Raises:
        TransportError: connection closed mid-frame, or a malformed/oversized frame.
    """
    try:
        head = await reader.readexactly(2)
    except asyncio.IncompleteReadError as exc:
        raise TransportError("carrier closed while reading a frame header") from exc

    first, second = head[0], head[1]
    fin = bool(first & 0x80)
    if first & 0x70:
        raise TransportError("RSV bits set: extension negotiation is not supported")
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F

    if opcode >= 0x8:
        if not fin:
            raise TransportError("fragmented control frame")
        if length > _MAX_CONTROL_PAYLOAD:
            raise TransportError("oversized control frame")

    if length == 126:
        try:
            (length,) = struct.unpack(">H", await reader.readexactly(2))
        except asyncio.IncompleteReadError as exc:
            raise TransportError("truncated 16-bit frame length") from exc
    elif length == 127:
        try:
            (length,) = struct.unpack(">Q", await reader.readexactly(8))
        except asyncio.IncompleteReadError as exc:
            raise TransportError("truncated 64-bit frame length") from exc
        if length & (1 << 63):
            raise TransportError("frame length with the high bit set is ill-formed")

    if max_payload_size is not None and length > max_payload_size:
        raise TransportError(
            f"frame payload of {length} bytes exceeds the "
            f"{max_payload_size}-byte carrier limit"
        )

    mask_key = b""
    if masked:
        try:
            mask_key = await reader.readexactly(4)
        except asyncio.IncompleteReadError as exc:
            raise TransportError("truncated masking key") from exc

    try:
        payload = await reader.readexactly(length) if length else b""
    except asyncio.IncompleteReadError as exc:
        raise TransportError("carrier closed mid-frame") from exc

    if masked:
        payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))

    return Frame(opcode=opcode, payload=payload, fin=fin, masked=masked)


# --------------------------------------------------------------------------- #
# Handshakes
# --------------------------------------------------------------------------- #
async def perform_client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    host: str,
    path: str = "/",
    user_agent: str = DEFAULT_USER_AGENT,
    origin: bool = True,
    subprotocol: str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> dict[str, str]:
    """Send a browser-shaped upgrade request and validate the response.

    Returns the response headers.  Raises :class:`TransportError` if the server
    answered something other than a valid 101.
    """
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    headers = {
        "Host": host,
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key,
    }
    if origin:
        headers["Origin"] = f"https://{host}"
    if subprotocol:
        headers["Sec-WebSocket-Protocol"] = subprotocol
    if extra_headers:
        headers.update(extra_headers)

    request = [f"GET {path} HTTP/1.1", *(f"{name}: {value}" for name, value in headers.items())]
    writer.write(("\r\n".join(request) + "\r\n\r\n").encode("ascii"))
    try:
        await writer.drain()
    except (ConnectionError, OSError) as exc:
        raise TransportError(f"failed to send the upgrade request: {exc}") from exc

    try:
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except (TimeoutError, asyncio.TimeoutError) as exc:
        raise TransportError("timed out waiting for the WebSocket response") from exc
    if not status_line:
        raise TransportError("server closed the connection during the handshake")

    parts = status_line.decode("latin-1").rstrip("\r\n").split(" ", 2)
    if len(parts) < 2 or parts[1] != "101":
        raise TransportError(f"carrier refused the upgrade: {status_line.strip()!r}")

    response: dict[str, str] = {}
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line or line in (b"\r\n", b"\n"):
            break
        if b":" not in line:
            raise TransportError("malformed header in the WebSocket response")
        name, _, value = line.decode("latin-1").partition(":")
        response[name.strip().lower()] = value.strip()

    if response.get("upgrade", "").lower() != "websocket":
        raise TransportError("response is not a WebSocket upgrade")
    expected = compute_accept(key)
    if not secrets.compare_digest(response.get("sec-websocket-accept", ""), expected):
        raise TransportError("the server's Sec-WebSocket-Accept did not match")
    return response


@dataclass
class ServerHandshake:
    """Result of reading one HTTP request from a not-yet-WebSocket connection."""

    upgraded: bool
    request_path: str = ""
    headers: dict[str, str] | None = None
    websocket_key: str = ""
    subprotocol: str | None = None


async def perform_server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    cover_body: bytes = COVER_404,
    server_header: str | None = "nginx",
    subprotocols: tuple[str, ...] = (),
    max_header_bytes: int = 16 * 1024,
    timeout: float = 15.0,
) -> ServerHandshake:
    """Read a request; upgrade it if it is a WebSocket request, else serve cover.

    A relay that answers everything the same way is not interesting to probe.
    So: valid upgrade → 101; anything else *including* a malformed upgrade
    attempt → the cover page, with the status a real server would use.
    """
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except (TimeoutError, asyncio.TimeoutError):
        return ServerHandshake(upgraded=False)
    if not request_line:
        return ServerHandshake(upgraded=False)

    headers: dict[str, str] = {}
    consumed = len(request_line)
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except (TimeoutError, asyncio.TimeoutError):
            return ServerHandshake(upgraded=False)
        if not line or line in (b"\r\n", b"\n"):
            break
        consumed += len(line)
        if consumed > max_header_bytes:
            await _send_cover(writer, cover_body, server_header, status="431 Too Many Headers")
            return ServerHandshake(upgraded=False)
        if b":" in line:
            name, _, value = line.decode("latin-1").partition(":")
            headers[name.strip().lower()] = value.strip()

    parts = request_line.decode("latin-1").split()
    path = parts[1] if len(parts) >= 2 else "/"

    upgrade = headers.get("upgrade", "").lower()
    connection = headers.get("connection", "").lower()
    ws_key = headers.get("sec-websocket-key", "")
    ws_version = headers.get("sec-websocket-version", "")

    if (
        upgrade != "websocket"
        or "upgrade" not in connection
        or ws_version != "13"
        or not _looks_like_ws_key(ws_key)
    ):
        await _send_cover(writer, cover_body, server_header)
        return ServerHandshake(upgraded=False, request_path=path, headers=headers)

    chosen = None
    offered = headers.get("sec-websocket-protocol")
    if subprotocols and offered:
        wanted = [item.strip() for item in offered.split(",")]
        chosen = next((item for item in wanted if item in subprotocols), None)

    lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {compute_accept(ws_key)}",
    ]
    if chosen:
        lines.append(f"Sec-WebSocket-Protocol: {chosen}")
    if server_header:
        lines.insert(1, f"Server: {server_header}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    try:
        await writer.drain()
    except (ConnectionError, OSError):
        return ServerHandshake(upgraded=False)
    return ServerHandshake(
        upgraded=True,
        request_path=path,
        headers=headers,
        websocket_key=ws_key,
        subprotocol=chosen,
    )


def _looks_like_ws_key(value: str) -> bool:
    try:
        return len(base64.b64decode(value.strip(), validate=True)) == 16
    except (binascii.Error, ValueError):
        return False


async def _send_cover(
    writer: asyncio.StreamWriter, body: bytes, server_header: str | None, status: str = "404 Not Found"
) -> None:
    headers = [
        f"HTTP/1.1 {status}",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if server_header:
        headers.insert(1, f"Server: {server_header}")
    writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body)
    with contextlib.suppress(ConnectionError, OSError):
        await writer.drain()


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #
class WebSocketTransport(Transport):
    """A message pipe over a WebSocket connection, either side of the handshake."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        peer: str,
        encrypted: bool = False,
        server_side: bool = False,
        encoding: str = PayloadEncoding.BINARY,
        max_message_size: int = 1 << 20,
        request_path: str = "/",
        user_agent: str = DEFAULT_USER_AGENT,
        subprotocol: str | None = None,
        extra_headers: dict[str, str] | None = None,
        host_header: str | None = None,
        handshake_timeout: float = 15.0,
        detail: str = "",
        cover_body: bytes = COVER_404,
        server_header: str | None = "nginx",
    ) -> None:
        super().__init__()
        self._reader = reader
        self._writer = writer
        self._peer = peer
        self._encrypted = encrypted
        self._server_side = server_side
        self._encoding = encoding
        self._max_message_size = max_message_size
        self._request_path = request_path
        self._user_agent = user_agent
        self._subprotocol = subprotocol
        self._extra_headers = extra_headers or {}
        self._host_header = host_header or peer.rsplit(":", 1)[0]
        self._handshake_timeout = handshake_timeout
        self._detail = detail
        self._cover_body = cover_body
        self._server_header = server_header
        self._write_lock = asyncio.Lock()
        self._fragments: list[bytes] = []
        self._fragment_size = 0
        self._fragment_opcode: int | None = None
        self.response_headers: dict[str, str] = {}

    async def open(self) -> None:
        """Run the handshake for whichever side this transport is."""
        if self._server_side:
            result = await perform_server_handshake(
                self._reader,
                self._writer,
                cover_body=self._cover_body,
                server_header=self._server_header,
                subprotocols=(self._subprotocol,) if self._subprotocol else (),
                timeout=self._handshake_timeout,
            )
            if not result.upgraded:
                await self.close()
                raise TransportError("no WebSocket upgrade on this connection")
            self.response_headers = result.headers or {}
        else:
            self.response_headers = await perform_client_handshake(
                self._reader,
                self._writer,
                host=self._host_header,
                path=self._request_path,
                user_agent=self._user_agent,
                subprotocol=self._subprotocol,
                extra_headers=self._extra_headers,
                timeout=self._handshake_timeout,
            )

    async def close(self) -> None:
        """Send a close frame (best effort) and drop the socket."""
        if self._closed:
            return
        self._closed = True
        try:
            async with self._write_lock:
                self._writer.write(
                    write_frame(OP_CLOSE, struct.pack(">H", 1000), mask=not self._server_side)
                )
                await self._writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass
        try:
            self._writer.close()
            await asyncio.wait_for(self._writer.wait_closed(), timeout=5)
        except (ConnectionError, OSError, RuntimeError, asyncio.TimeoutError):
            pass

    async def send_message(self, payload: bytes) -> None:
        """Send one application message (binary frame, or base64 text frame)."""
        if self._closed:
            raise TransportError("carrier is closed")
        if len(payload) > self._max_message_size:
            raise TransportError(
                f"message of {len(payload)} bytes exceeds the "
                f"{self._max_message_size}-byte carrier limit"
            )
        if self._encoding == PayloadEncoding.TEXT:
            opcode, body = OP_TEXT, base64.b64encode(payload)
        else:
            opcode, body = OP_BINARY, payload
        # Clients must mask, servers must not (RFC 6455 §5.1).
        frame = write_frame(opcode, body, mask=not self._server_side)
        try:
            async with self._write_lock:
                self._writer.write(frame)
                await self._writer.drain()
        except (ConnectionError, OSError, RuntimeError) as exc:
            self._closed = True
            raise self._wrap_error(exc, "carrier write failed") from exc
        self._note_sent(len(frame))

    async def receive_message(self) -> bytes:
        """Return the next application message, transparently handling control frames."""
        if self._closed:
            raise TransportError("carrier is closed")
        frame_limit = self._max_message_size
        if self._encoding == PayloadEncoding.TEXT:
            frame_limit = 4 * ((self._max_message_size + 2) // 3)
        while True:
            try:
                frame = await read_frame(self._reader, max_payload_size=frame_limit)
            except TransportError as exc:
                self._closed = True
                raise TransportError(f"carrier read failed: {exc}") from exc

            if frame.masked != self._server_side:
                self._closed = True
                peer_role = "client" if self._server_side else "server"
                requirement = "must be masked" if self._server_side else "must not be masked"
                raise TransportError(f"{peer_role} frames {requirement}")

            if frame.opcode == OP_PING:
                await self._send_control(OP_PONG, frame.payload)
                continue
            if frame.opcode == OP_PONG:
                continue
            if frame.opcode == OP_CLOSE:
                await self._send_control(OP_CLOSE, frame.payload[:2])
                self._closed = True
                raise TransportError("peer closed the carrier")

            if frame.opcode in (OP_TEXT, OP_BINARY):
                if self._fragment_opcode is not None:
                    raise TransportError("new data frame received before fragmented message completed")
                if frame.fin:
                    message_opcode = frame.opcode
                    wire_message = frame.payload
                else:
                    self._fragment_opcode = frame.opcode
                    self._fragments = [frame.payload]
                    self._fragment_size = len(frame.payload)
                    if self._fragment_size > frame_limit:
                        raise TransportError(
                            f"message exceeds the {self._max_message_size}-byte carrier limit"
                        )
                    continue
            elif frame.opcode == OP_CONTINUATION:
                if self._fragment_opcode is None:
                    raise TransportError("continuation frame without a start")
                self._fragments.append(frame.payload)
                self._fragment_size += len(frame.payload)
                if self._fragment_size > frame_limit:
                    raise TransportError(
                        f"message exceeds the {self._max_message_size}-byte carrier limit"
                    )
                if not frame.fin:
                    continue
                message_opcode = self._fragment_opcode
                wire_message = b"".join(self._fragments)
                self._fragments = []
                self._fragment_size = 0
                self._fragment_opcode = None
            else:
                raise TransportError(f"unsupported opcode 0x{frame.opcode:x}")

            if message_opcode == OP_TEXT:
                if self._encoding != PayloadEncoding.TEXT:
                    # A text message we did not expect: treat it as noise rather
                    # than a protocol error, since a real site may send any HTML.
                    continue
                try:
                    message = base64.b64decode(wire_message, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise TransportError("malformed base64 text message") from exc
            elif self._encoding == PayloadEncoding.TEXT:
                continue
            else:
                message = wire_message

            if len(message) > self._max_message_size:
                raise TransportError(
                    f"message of {len(message)} bytes exceeds the "
                    f"{self._max_message_size}-byte carrier limit"
                )
            self._note_received(len(message))
            return message

    async def _send_control(self, opcode: int, payload: bytes = b"") -> None:
        try:
            async with self._write_lock:
                self._writer.write(write_frame(opcode, payload, mask=not self._server_side, fin=True))
                await self._writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass

    async def ping(self, payload: bytes = b"") -> None:
        """Send a WebSocket ping (a carrier-level keepalive, invisible to the tunnel)."""
        await self._send_control(OP_PING, payload[:125])

    @property
    def info(self) -> TransportInfo:
        return TransportInfo(
            kind="websocket" + ("+tls" if self._encrypted else ""),
            peer=self._peer,
            encrypted=self._encrypted,
            detail=self._detail or f"path {self._request_path}",
        )

    @property
    def encoding(self) -> str:
        return self._encoding
