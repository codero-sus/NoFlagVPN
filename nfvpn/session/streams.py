"""Many logical streams inside one tunnel.

A browser opening a page opens a dozen connections at once, and a game keeps a
few long-lived ones.  Each becomes a *stream* here: a numbered, ordered,
flow-controlled byte pipe carried by DATA records, opened by OPEN, politely shut
by CLOSE.

Two design points worth naming:

**One tunnel, many streams.**  The expensive part of a tunnel is the handshake
and the carrier connection; a stream costs a control record.  So the client
dials the relay once and multiplexes everything over it, which also means a
blocked website never costs you a reconnect.

**Flow control is per stream and honest.**  The receiver hands out credit as it
drains bytes to the application, and the sender refuses to have more than a
window's worth of unacknowledged data in flight.  Without that, a fast server
feeding a slow client would turn the relay's memory into the bottleneck — and
"the relay crashed" is a much better denial-of-service story than a fingerprint
is.

Stream identifiers are chosen by the opener as ``(counter << 1) | parity`` where
parity is 0 for the initiator and 1 for the responder, so the two ends can never
collide on an id.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from nfvpn.errors import NoFlagVPNError, ProtocolError, TransportError
from nfvpn.framing.constants import (
    CTRL_CLOSE,
    CTRL_OPEN,
    CTRL_OPENED,
    CTRL_PING,
    CTRL_PONG,
    CTRL_WINDOW,
    MAX_PAYLOAD,
    CloseReason,
    RecordType,
    StreamProto,
)

__all__ = [
    "DEFAULT_MAX_STREAMS",
    "DEFAULT_WINDOW",
    "OpenRequest",
    "Stream",
    "StreamMultiplexer",
    "pack_close",
    "pack_open",
    "pack_window",
    "unpack_open",
]

#: How many unacknowledged bytes a stream may have in flight.
DEFAULT_WINDOW = 256 * 1024

#: Cap on concurrent streams per tunnel.  Reached means "slow down", not "die".
DEFAULT_MAX_STREAMS = 256

_U32 = struct.Struct(">I")
_PORT = struct.Struct(">H")

#: Sentinel pushed into a stream's queue when the far end stops talking.
_EOF = object()


@dataclass(frozen=True)
class OpenRequest:
    """What the opener wants: a TCP connection to host:port."""

    host: str
    port: int
    proto: StreamProto = StreamProto.TCP

    def label(self) -> str:
        return f"{self.host}:{self.port}"


def pack_open(request: OpenRequest) -> bytes:
    host = request.host.encode("utf-8")
    if len(host) > 255:
        raise ProtocolError("hostname is too long for an OPEN message")
    return (
        bytes([int(request.proto)])
        + _PORT.pack(request.port)
        + bytes([len(host)])
        + host
    )


def unpack_open(payload: bytes) -> OpenRequest:
    if len(payload) < 4:
        raise ProtocolError("OPEN message is too short")
    proto, port, host_length = payload[0], _PORT.unpack_from(payload, 1)[0], payload[3]
    if len(payload) != 4 + host_length:
        raise ProtocolError("OPEN message length does not match its host field")
    try:
        proto_enum = StreamProto(proto)
    except ValueError as exc:
        raise ProtocolError(f"unsupported stream protocol {proto}") from exc
    try:
        host = payload[4:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("OPEN message has a non-UTF-8 host") from exc
    if not host:
        raise ProtocolError("OPEN message has an empty host")
    return OpenRequest(host=host, port=port, proto=proto_enum)


def pack_close(reason: CloseReason) -> bytes:
    return bytes([int(reason)])


def pack_window(delta: int) -> bytes:
    return _U32.pack(delta)


def unpack_window(payload: bytes) -> int:
    if len(payload) != 4:
        raise ProtocolError("WINDOW message must be exactly 4 bytes")
    return _U32.unpack(payload)[0]


@dataclass
class Stream:
    """One flow inside the tunnel, as seen by whoever opened or accepted it."""

    stream_id: int
    request: OpenRequest
    window: int = DEFAULT_WINDOW
    opened_by_us: bool = True

    _queue: asyncio.Queue = field(default_factory=asyncio.Queue, repr=False)
    _credits: int = 0
    _credit_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _closed: bool = False
    _eof_seen: bool = False
    _consumed_since_ack: int = 0
    _ack_threshold: int = field(default=0, repr=False)
    """How much the application must drain before we return credit.

    Derived from this stream's own window, not the class default.  A stream with
    a window of 16 KiB whose acknowledgements waited for half of the *default*
    256 KiB would never send one: the sender would go quiet after 16 KiB and
    both ends would wait for each other forever.
    """
    _mux: StreamMultiplexer | None = field(default=None, repr=False)
    _open_future: asyncio.Future | None = field(default=None, repr=False)
    close_reason: CloseReason | None = None
    bytes_sent: int = 0
    bytes_received: int = 0

    def __post_init__(self) -> None:
        self._credits = self.window
        self._ack_threshold = max(1, self.window // 2)
        self._credit_event.set()

    # -- application API ---------------------------------------------------
    async def send(self, data: bytes) -> None:
        """Send bytes on this stream, respecting the peer's credit.

        Raises:
            StreamClosedError: the stream is gone (locally or remotely).
        """
        if self._mux is None:
            raise ProtocolError("stream is not attached to a multiplexer")
        offset = 0
        while offset < len(data):
            await self._wait_for_credit()
            if self._closed:
                raise StreamClosedError(self.close_reason or CloseReason.LOCAL_SHUTDOWN)
            chunk = data[offset : offset + min(MAX_PAYLOAD, self._credits)]
            await self._mux._send_data(self.stream_id, chunk)
            self._credits -= len(chunk)
            self.bytes_sent += len(chunk)
            offset += len(chunk)

    async def receive(self) -> bytes | None:
        """Return the next chunk, or ``None`` once the far end has finished."""
        if self._eof_seen and self._queue.empty():
            return None
        item = await self._queue.get()
        if item is _EOF:
            self._eof_seen = True
            return None
        self.bytes_received += len(item)
        if self._mux is not None:
            self._consumed_since_ack += len(item)
            if self._consumed_since_ack >= self._ack_threshold:
                with contextlib.suppress(TransportError, NoFlagVPNError):
                    await self._mux._send_control(
                        CTRL_WINDOW, self.stream_id, pack_window(self._consumed_since_ack)
                    )
                self._consumed_since_ack = 0
        return item

    async def close(self, reason: CloseReason = CloseReason.NORMAL) -> None:
        """Tell the peer this stream is over and stop accepting data for it."""
        if self._closed:
            return
        self._closed = True
        self.close_reason = reason
        self._queue.put_nowait(_EOF)
        if self._mux is not None:
            with contextlib.suppress(TransportError, NoFlagVPNError):
                await self._mux._send_control(CTRL_CLOSE, self.stream_id, pack_close(reason))

    # -- multiplexer callbacks --------------------------------------------
    def _deliver(self, chunk: bytes) -> None:
        if not self._closed:
            self._queue.put_nowait(chunk)

    def _deliver_eof(self, reason: CloseReason) -> None:
        self._closed = True
        self.close_reason = reason
        self._queue.put_nowait(_EOF)

    def _grant(self, credits: int) -> None:
        self._credits += credits
        self._credit_event.set()

    async def _wait_for_credit(self) -> None:
        while self._credits <= 0 and not self._closed:
            self._credit_event.clear()
            await self._credit_event.wait()

    def _resolve_open(self, error: BaseException | None = None) -> None:
        if self._open_future is not None and not self._open_future.done():
            if error is None:
                self._open_future.set_result(None)
            else:
                self._open_future.set_exception(error)

    # -- introspection -----------------------------------------------------
    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def buffered(self) -> int:
        return self._queue.qsize()

    @property
    def credits(self) -> int:
        return self._credits

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "closed" if self._closed else "open"
        return f"<Stream {self.stream_id} {self.request.label()} {state}>"


class StreamClosedError(NoFlagVPNError):
    """Raised when writing to a stream the peer has already shut down."""

    def __init__(self, reason: CloseReason) -> None:
        super().__init__(f"stream closed ({reason.name.lower()})")
        self.reason = reason


class StreamMultiplexer:
    """Owns the stream table for one tunnel and pumps control messages."""

    def __init__(
        self,
        channel,
        *,
        initiator: bool,
        window: int = DEFAULT_WINDOW,
        max_streams: int = DEFAULT_MAX_STREAMS,
    ) -> None:
        self.channel = channel
        self.initiator = initiator
        self.window = window
        self.max_streams = max_streams
        self._streams: dict[int, Stream] = {}
        self._next_id = 1 if not initiator else 2
        self._open_handler: Callable[[Stream, OpenRequest], Awaitable[None]] | None = None
        self._handler_tasks: set[asyncio.Task[None]] = set()
        self.handler_errors: list[BaseException] = []
        self._closed = False
        self.opened_total = 0
        self.rejected_total = 0

    # -- configuration -----------------------------------------------------
    def set_open_handler(
        self, handler: Callable[[Stream, OpenRequest], Awaitable[None]]
    ) -> None:
        """Register the coroutine that serves inbound streams (the relay dials out)."""
        self._open_handler = handler

    # -- outgoing ----------------------------------------------------------
    async def open(
        self,
        host: str,
        port: int,
        *,
        proto: StreamProto = StreamProto.TCP,
        timeout: float = 15.0,
    ) -> Stream:
        """Open a stream and wait until the peer accepts it.

        Raises:
            StreamClosedError: the peer refused (see ``.reason``).
            TimeoutError: the peer never answered.
        """
        if self._closed:
            raise TransportError("tunnel is closed")
        if len(self._streams) >= self.max_streams:
            self.rejected_total += 1
            raise StreamClosedError(CloseReason.LIMIT)

        stream_id = self._next_id
        self._next_id += 2
        request = OpenRequest(host=host, port=port, proto=proto)
        stream = Stream(
            stream_id=stream_id,
            request=request,
            window=self.window,
            opened_by_us=True,
            _mux=self,
        )
        stream._open_future = asyncio.get_running_loop().create_future()
        self._streams[stream_id] = stream
        self.opened_total += 1

        await self._send_control(CTRL_OPEN, stream_id, pack_open(request))
        try:
            await asyncio.wait_for(stream._open_future, timeout=timeout)
        except TimeoutError:
            self._forget(stream_id)
            raise
        return stream

    async def _send_data(self, stream_id: int, chunk: bytes) -> None:
        await self.channel.send(RecordType.DATA, stream_id, chunk)

    async def _send_control(self, code: int, stream_id: int, body: bytes = b"") -> None:
        await self.channel.send(RecordType.CTRL, stream_id, bytes([code]) + body)

    # -- incoming ----------------------------------------------------------
    async def handle_record(self, record) -> None:
        """Dispatch one decoded record from the channel."""
        if record.type is RecordType.DATA:
            stream = self._streams.get(record.stream_id)
            if stream is None:
                # Data for a stream we already forgot: drop it, but tell the peer
                # so it stops wasting bandwidth.
                await self._send_control(
                    CTRL_CLOSE, record.stream_id, pack_close(CloseReason.REMOTE_ERROR)
                )
                return
            stream._deliver(record.payload)
            return

        if record.type is not RecordType.CTRL:
            return

        payload = record.payload
        if not payload:
            raise ProtocolError("control record with an empty payload")
        code, body = payload[0], payload[1:]

        if code == CTRL_OPEN:
            await self._handle_open(record.stream_id, unpack_open(body))
        elif code == CTRL_OPENED:
            stream = self._streams.get(record.stream_id)
            if stream is not None:
                stream._resolve_open()
        elif code == CTRL_CLOSE:
            reason = CloseReason(body[0]) if body else CloseReason.NORMAL
            stream = self._streams.get(record.stream_id)
            if stream is None:
                return
            stream._resolve_open(StreamClosedError(reason))
            stream._deliver_eof(reason)
            self._forget(record.stream_id)
        elif code == CTRL_WINDOW:
            stream = self._streams.get(record.stream_id)
            if stream is not None:
                stream._grant(unpack_window(body))
        elif code == CTRL_PING:
            await self._send_control(CTRL_PONG, record.stream_id, body)
        elif code == CTRL_PONG:
            return
        else:
            raise ProtocolError(f"unknown control code {code}")

    async def _handle_open(self, stream_id: int, request: OpenRequest) -> None:
        if self._open_handler is None:
            await self._send_control(CTRL_CLOSE, stream_id, pack_close(CloseReason.DENIED))
            return
        if stream_id in self._streams:
            await self._send_control(CTRL_CLOSE, stream_id, pack_close(CloseReason.REMOTE_ERROR))
            return
        if len(self._streams) >= self.max_streams:
            self.rejected_total += 1
            await self._send_control(CTRL_CLOSE, stream_id, pack_close(CloseReason.LIMIT))
            return

        stream = Stream(
            stream_id=stream_id,
            request=request,
            window=self.window,
            opened_by_us=False,
            _mux=self,
        )
        self._streams[stream_id] = stream
        self.opened_total += 1
        # The handler must not run inline: this method is called from the read
        # loop, and a handler that talks back over the tunnel (which is all of
        # them) would deadlock the very loop that has to deliver its records.
        task = asyncio.create_task(
            self._invoke_handler(stream, request), name=f"nfvpn-stream-{stream_id}"
        )
        self._handler_tasks.add(task)
        task.add_done_callback(self._handler_tasks.discard)

    async def _invoke_handler(self, stream: Stream, request: OpenRequest) -> None:
        """Run the inbound-stream handler, turning its failure into a CLOSE."""
        assert self._open_handler is not None
        try:
            await self._open_handler(stream, request)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.handler_errors.append(exc)
            with contextlib.suppress(TransportError, NoFlagVPNError):
                await self.refuse(stream, CloseReason.REMOTE_ERROR)

    # -- housekeeping ------------------------------------------------------
    async def accept(self, stream: Stream) -> None:
        """Tell the opener its stream is live."""
        await self._send_control(CTRL_OPENED, stream.stream_id)

    async def refuse(self, stream: Stream, reason: CloseReason) -> None:
        """Refuse an inbound stream; the opener sees ``StreamClosedError(reason)``."""
        await self._send_control(CTRL_CLOSE, stream.stream_id, pack_close(reason))
        self._forget(stream.stream_id)

    def _forget(self, stream_id: int) -> None:
        self._streams.pop(stream_id, None)

    def detach(self, stream: Stream) -> None:
        """Drop a finished stream from the table."""
        self._forget(stream.stream_id)

    async def close_all(self, reason: CloseReason = CloseReason.LOCAL_SHUTDOWN) -> None:
        """Shut every stream down; used when the tunnel itself is going away."""
        self._closed = True
        for task in list(self._handler_tasks):
            task.cancel()
        self._handler_tasks.clear()
        for stream in list(self._streams.values()):
            stream._deliver_eof(reason)
            with contextlib.suppress(TransportError, NoFlagVPNError):
                await self._send_control(CTRL_CLOSE, stream.stream_id, pack_close(reason))
        self._streams.clear()

    @property
    def stream_count(self) -> int:
        return len(self._streams)

    def __iter__(self):
        return iter(list(self._streams.values()))
