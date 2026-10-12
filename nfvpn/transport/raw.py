"""A length-prefixed raw TCP carrier.

Not every deployment can look like a website.  When a relay lives behind
something that already terminates TLS (a CDN, a corporate reverse proxy, an
SSH port-forward for testing), the only thing left is a plain byte stream on
which we impose our own trivial framing: a 4-byte big-endian length followed by
that many bytes.

This carrier is honest about what it is — it hides nothing by itself.  Use it
when something else is already doing the hiding, or in tests.
"""

from __future__ import annotations

import asyncio
import struct

from nfvpn.errors import TransportError
from nfvpn.transport.base import Transport, TransportInfo

__all__ = ["DEFAULT_MAX_MESSAGE", "RawTCPTransport"]

_LENGTH = struct.Struct(">I")

#: Sanity cap so a hostile peer cannot make us allocate gigabytes.
DEFAULT_MAX_MESSAGE = 1 << 20


class RawTCPTransport(Transport):
    """4-byte length-prefixed messages over a TCP (or TLS) stream."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        peer: str,
        encrypted: bool = False,
        max_message_size: int = DEFAULT_MAX_MESSAGE,
    ) -> None:
        super().__init__()
        self._reader = reader
        self._writer = writer
        self._peer = peer
        self._encrypted = encrypted
        self._max_message_size = max_message_size
        self._write_lock = asyncio.Lock()

    async def open(self) -> None:
        """Nothing to negotiate: the framing is the handshake."""
        return None

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._writer.close()
            await asyncio.wait_for(self._writer.wait_closed(), timeout=5)
        except (ConnectionError, OSError, RuntimeError, asyncio.TimeoutError):
            pass

    async def send_message(self, payload: bytes) -> None:
        if self._closed:
            raise TransportError("carrier is closed")
        if len(payload) > self._max_message_size:
            raise TransportError(
                f"message of {len(payload)} bytes exceeds the carrier limit"
            )
        frame = _LENGTH.pack(len(payload)) + payload
        try:
            async with self._write_lock:
                self._writer.write(frame)
                await self._writer.drain()
        except (ConnectionError, OSError, RuntimeError) as exc:
            self._closed = True
            raise self._wrap_error(exc, "carrier write failed") from exc
        self._note_sent(len(payload))

    async def receive_message(self) -> bytes:
        if self._closed:
            raise TransportError("carrier is closed")
        try:
            header = await self._reader.readexactly(_LENGTH.size)
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
            self._closed = True
            raise TransportError("carrier closed") from exc
        (length,) = _LENGTH.unpack(header)
        if length > self._max_message_size:
            raise TransportError(f"peer announced an oversized message ({length} bytes)")
        try:
            payload = await self._reader.readexactly(length) if length else b""
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
            self._closed = True
            raise TransportError("carrier closed mid-message") from exc
        self._note_received(len(payload))
        return payload

    @property
    def info(self) -> TransportInfo:
        return TransportInfo(
            kind="raw" + ("+tls" if self._encrypted else ""),
            peer=self._peer,
            encrypted=self._encrypted,
            detail="length-prefixed",
        )
