"""The carrier interface.

A carrier moves opaque messages between two endpoints.  Nothing above this layer
knows whether the bytes travelled inside a WebSocket frame, a raw TCP segment or
something else, which is the point: trying a different carrier must not mean
touching the protocol.

Implementations must be safe to use from several tasks at once: ``send_message``
may be called concurrently, and callers assume each call produces exactly one
message on the wire (no interleaving, no batching).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from nfvpn.errors import TransportError

__all__ = ["Transport", "TransportInfo"]


@dataclass(frozen=True)
class TransportInfo:
    """What we know about a carrier connection, for logs and `nfvpn doctor`."""

    kind: str
    peer: str
    encrypted: bool
    detail: str = ""

    def describe(self) -> str:
        lock = "TLS" if self.encrypted else "cleartext"
        extra = f" ({self.detail})" if self.detail else ""
        return f"{self.kind} → {self.peer} [{lock}]{extra}"


class Transport(abc.ABC):
    """A bidirectional, message-oriented, ordered byte pipe."""

    def __init__(self) -> None:
        self._closed = False
        self.messages_sent = 0
        self.messages_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0

    # -- lifecycle ---------------------------------------------------------
    @abc.abstractmethod
    async def open(self) -> None:
        """Establish the carrier connection (handshake included)."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Close the carrier, flushing anything already written if possible."""

    @abc.abstractmethod
    async def send_message(self, payload: bytes) -> None:
        """Send exactly one carrier message."""

    @abc.abstractmethod
    async def receive_message(self) -> bytes:
        """Return the next carrier message.

        Raises:
            TransportError: the connection is gone.  Callers treat this as the
                end of the session, never as something to retry mid-stream.
        """

    # -- conveniences ------------------------------------------------------
    @property
    def is_open(self) -> bool:
        return not self._closed

    @property
    @abc.abstractmethod
    def info(self) -> TransportInfo:
        """A description of this connection."""

    async def __aenter__(self) -> Transport:
        await self.open()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    def _note_sent(self, size: int) -> None:
        self.messages_sent += 1
        self.bytes_sent += size

    def _note_received(self, size: int) -> None:
        self.messages_received += 1
        self.bytes_received += size

    @staticmethod
    def _wrap_error(exc: BaseException, what: str) -> TransportError:
        if isinstance(exc, TransportError):
            return exc
        if isinstance(exc, TimeoutError):
            return TransportError(f"{what}: timed out")
        return TransportError(f"{what}: {type(exc).__name__}: {exc}")
