"""Wire protocol constants, shared by every layer.

Everything here is version 1 of the NoFlagVPN record protocol.  The layout is
described in ``docs/DESIGN.md``; this module is the single place where the
numbers live so that framing, shaping and the relay cannot drift apart.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = [
    "CTRL_CLOSE",
    "CTRL_CLOSE_REASONS",
    "CTRL_CONFIRM",
    "CTRL_OPEN",
    "CTRL_OPENED",
    "CTRL_PING",
    "CTRL_PONG",
    "CTRL_WINDOW",
    "HEADER_SIZE",
    "MAX_PAYLOAD",
    "MAX_RECORD_SIZE",
    "PROTOCOL_VERSION",
    "REPLAY_WINDOW",
    "TAG_SIZE",
    "CloseReason",
    "RecordType",
    "StreamProto",
]

#: Bumped whenever the record layout changes; peers refuse to talk across versions.
PROTOCOL_VERSION = 1

#: ``type:u8 | flags:u8 | reserved:u16 | stream_id:u32 | counter:u64``
HEADER_SIZE = 16

#: Poly1305 tag appended to every record.
TAG_SIZE = 16

#: Largest payload we put in a single record.  Chosen so that a record plus its
#: header and tag still fits inside one carrier message (a WebSocket frame, or a
#: TLS application data record without forcing a split).
MAX_PAYLOAD = 16 * 1024

#: Header + encrypted length field + payload + tag, with no shaping padding.
MAX_RECORD_SIZE = HEADER_SIZE + TAG_SIZE + 2 + MAX_PAYLOAD

#: Anti-replay window, in records.  4096 records of 16 KiB is 64 MiB of
#: reordering tolerance, far more than any sane carrier will produce.
REPLAY_WINDOW = 4096


class RecordType(IntEnum):
    """What a record is for.  Carried in the clear, authenticated by the AEAD."""

    DATA = 1
    """Payload bytes for a stream (or for the raw tunnel when stream_id is 0)."""

    CTRL = 2
    """Stream control: open/close/window.  First payload byte is a CTRL_* code."""

    REKEY = 3
    """The sender has switched to the next key generation (see docs/DESIGN.md)."""

    PAD = 4
    """Cover traffic.  Decrypts to nothing and is dropped."""


CTRL_OPEN = 1
CTRL_OPENED = 2
CTRL_CLOSE = 3
CTRL_WINDOW = 4
CTRL_PING = 5
CTRL_PONG = 6
CTRL_CONFIRM = 7


class CloseReason(IntEnum):
    """Why a stream ended; shown to the local application where it maps."""

    NORMAL = 0
    REFUSED = 1
    """The relay could not reach the target (connection refused/unreachable)."""

    DENIED = 2
    """Egress policy refused this destination.  Surfaced verbatim to the user."""

    TIMEOUT = 3
    REMOTE_ERROR = 4
    LOCAL_SHUTDOWN = 5
    LIMIT = 6
    """Too many streams, or a flow-control violation."""


CTRL_CLOSE_REASONS: dict[int, str] = {
    CloseReason.NORMAL: "closed",
    CloseReason.REFUSED: "target refused the connection",
    CloseReason.DENIED: "destination blocked by the relay's egress policy",
    CloseReason.TIMEOUT: "target timed out",
    CloseReason.REMOTE_ERROR: "remote error",
    CloseReason.LOCAL_SHUTDOWN: "local shutdown",
    CloseReason.LIMIT: "stream limit reached",
}


class StreamProto(IntEnum):
    """Requested protocol for a stream, sent in the OPEN control message."""

    TCP = 1
