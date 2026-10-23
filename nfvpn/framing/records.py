r"""The record format: one authenticated, padded, replay-checked message.

On the wire a record is::

    +--------+--------+---------+-----------+---------------+------------------+
    | type   | flags  | reserv. | stream_id |   counter     |   ciphertext     |
    | u8     | u8     | u16     | u32       |   u64         |   + 16-byte tag  |
    +--------+--------+---------+-----------+---------------+------------------+
      \____________________ 16-byte header, authenticated as AAD _______/

The plaintext that goes into the AEAD is ``u16 length ‖ payload ‖ zero padding``.
Two consequences worth stating plainly:

* Truncating or growing a record is not possible without the tag, so an active
  attacker cannot shave a byte off a TCP segment to desynchronise us.
* The real payload length lives *inside* the AEAD, so padding is not merely
  noise that the receiver strips — it is invisible to the observer, who only
  gets to see the padded size.

The counter doubles as the AEAD nonce (``counter ‖ 0x00000000``, 12 bytes).  Keys
are per direction — the two sides never share a key, so a counter may safely
restart at zero when a session rekeys.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from nfvpn.core.primitives import aead_open, aead_seal
from nfvpn.errors import AuthenticationError, ProtocolError
from nfvpn.framing.constants import (
    HEADER_SIZE,
    MAX_PAYLOAD,
    MAX_RECORD_SIZE,
    REPLAY_WINDOW,
    TAG_SIZE,
    RecordType,
)
from nfvpn.framing.replay import ReplayWindow

__all__ = ["FrameReader", "FrameWriter", "Record", "RecordHeader", "peek_type"]

_HEADER = struct.Struct(">BBHIQ")
_LENGTH = struct.Struct(">H")
_MAX_COUNTER = 0xFFFFFFFFFFFFFFFF


def _nonce(counter: int) -> bytes:
    """Deterministic 96-bit nonce: little-endian counter plus four zero bytes."""
    return counter.to_bytes(8, "little") + b"\x00\x00\x00\x00"

def _unsigned(value: int, bits: int, label: str) -> int:
    """Validate a value before packing it into an unsigned wire integer."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise ProtocolError(f"{label} must fit in an unsigned {bits}-bit integer")
    return value



@dataclass(frozen=True)
class RecordHeader:
    """The 16 unencrypted bytes that precede every record's ciphertext."""

    type: RecordType
    flags: int
    stream_id: int
    counter: int

    def pack(self) -> bytes:
        if isinstance(self.type, bool) or not isinstance(self.type, int):
            raise ProtocolError("record type must be a RecordType value")
        try:
            record_type = RecordType(self.type)
        except ValueError as exc:
            raise ProtocolError(f"unknown record type {self.type}") from exc
        flags = _unsigned(self.flags, 8, "record flags")
        stream_id = _unsigned(self.stream_id, 32, "stream id")
        counter = _unsigned(self.counter, 64, "record counter")
        return _HEADER.pack(int(record_type), flags, 0, stream_id, counter)

    @classmethod
    def unpack(cls, raw: bytes) -> RecordHeader:
        if len(raw) != HEADER_SIZE:
            raise ProtocolError(f"record header must be {HEADER_SIZE} bytes, got {len(raw)}")
        type_code, flags, reserved, stream_id, counter = _HEADER.unpack(raw)
        try:
            record_type = RecordType(type_code)
        except ValueError as exc:
            raise ProtocolError(f"unknown record type {type_code}") from exc
        if reserved != 0:
            raise ProtocolError("reserved header bits must be zero")
        return cls(type=record_type, flags=flags, stream_id=stream_id, counter=counter)


@dataclass(frozen=True)
class Record:
    """A decoded record: header plus the caller's payload."""

    type: RecordType
    flags: int
    stream_id: int
    counter: int
    payload: bytes

    @property
    def size(self) -> int:
        return len(self.payload)


class FrameWriter:
    """Seals outgoing records with one direction's key."""

    __slots__ = ("counter", "key", "sent_bytes", "shaper", "stream_prefix")

    def __init__(self, key: bytes, shaper=None, counter: int = 0) -> None:
        self.key = key
        self.counter = counter
        self.shaper = shaper
        self.sent_bytes = 0

    def encode(
        self,
        record_type: RecordType,
        stream_id: int,
        payload: bytes = b"",
        *,
        flags: int = 0,
    ) -> bytes:
        """Seal one record and return the bytes to hand to the carrier."""
        if len(payload) > MAX_PAYLOAD:
            raise ProtocolError(
                f"payload of {len(payload)} bytes exceeds the {MAX_PAYLOAD}-byte limit"
            )
        if isinstance(self.counter, bool) or not isinstance(self.counter, int) or self.counter < 0:
            raise ProtocolError("record counter cannot be negative or non-integral")
        if self.counter > _MAX_COUNTER:
            raise ProtocolError("record counter exhausted; rekey required")

        header = RecordHeader(
            type=record_type, flags=flags, stream_id=stream_id, counter=self.counter
        ).pack()

        needed = len(payload) + _LENGTH.size
        padded = self.shaper.padded_plaintext(needed - 2) if self.shaper else needed
        padded = max(padded, needed)
        plaintext = _LENGTH.pack(len(payload)) + payload + b"\x00" * (padded - needed)

        sealed = aead_seal(self.key, _nonce(self.counter), plaintext, header)
        self.counter += 1
        frame = header + sealed
        self.sent_bytes += len(frame)
        return frame

    def encode_pad(self) -> bytes:
        """Seal a cover-traffic record that carries nothing."""
        return self.encode(RecordType.PAD, 0, b"")

    def rotate(self, key: bytes) -> None:
        """Switch to the next key generation and restart the counter."""
        self.key = key
        self.counter = 0


class FrameReader:
    """Opens incoming records for one direction, rejecting replays.

    On rekeying the reader keeps the previous key around: the peer may still be
    sending under it while our REKEY is in flight.  Each key generation has its
    own replay window, because counters restart at zero each time.
    """

    #: Once this many records have arrived under the current key, the previous
    #: key generation is dropped: anything still in flight under it is lost, and
    #: that is the intended trade-off.
    CATCH_UP_RECORDS = 64

    __slots__ = (
        "_current",
        "_current_hits",
        "_current_window",
        "_previous",
        "_previous_window",
        "received_bytes",
    )

    def __init__(self, key: bytes, window_size: int = REPLAY_WINDOW) -> None:
        self._current = key
        self._current_window = ReplayWindow(window_size)
        self._previous: bytes | None = None
        self._previous_window: ReplayWindow | None = None
        self._current_hits = 0
        self.received_bytes = 0

    @property
    def highest_counter(self) -> int:
        """Highest counter accepted under the current key."""
        return self._current_window.highest

    def rotate(self, key: bytes, *, keep_previous: bool = True) -> None:
        """Adopt a new key generation, optionally still accepting the old one."""
        self._previous = self._current if keep_previous else None
        self._previous_window = self._current_window if keep_previous else None
        self._current = key
        self._current_window = ReplayWindow(self._current_window.size)
        self._current_hits = 0

    def drop_previous(self) -> None:
        """Stop accepting the old key generation (the peer has caught up)."""
        self._previous = None
        self._previous_window = None

    @property
    def holding_previous(self) -> bool:
        """Whether records under the previous key generation are still accepted."""
        return self._previous is not None

    def decode(self, frame: bytes) -> Record:
        """Validate and decrypt one carrier message.

        Raises:
            ProtocolError: the frame is malformed or shorter than a header.
            AuthenticationError: the tag did not verify under either key.
            ReplayError: the record was already delivered.
        """
        if len(frame) < HEADER_SIZE + TAG_SIZE:
            raise ProtocolError(f"record of {len(frame)} bytes is too short")
        if len(frame) > MAX_RECORD_SIZE + 4096:
            raise ProtocolError(f"record of {len(frame)} bytes is implausibly large")

        header_bytes = frame[:HEADER_SIZE]
        sealed = frame[HEADER_SIZE:]
        header = RecordHeader.unpack(header_bytes)

        attempts = [(self._current, self._current_window, True)]
        if self._previous is not None and self._previous_window is not None:
            attempts.append((self._previous, self._previous_window, False))

        failures = 0
        for key, window, is_current in attempts:
            try:
                plaintext = aead_open(key, _nonce(header.counter), sealed, header_bytes)
            except AuthenticationError:
                failures += 1
                continue
            window.check_and_update(header.counter)
            if is_current:
                # A record under the old key just means the peer has not caught
                # up with our REKEY yet; nothing to do but accept it.
                self._current_hits += 1
                if self._current_hits >= self.CATCH_UP_RECORDS:
                    self.drop_previous()
            self.received_bytes += len(frame)
            return Record(
                type=header.type,
                flags=header.flags,
                stream_id=header.stream_id,
                counter=header.counter,
                payload=self._strip_padding(plaintext, header.type),
            )

        if failures:
            raise AuthenticationError("record failed authentication")
        raise ProtocolError("no usable key for this record")

    @staticmethod
    def _strip_padding(plaintext: bytes, record_type: RecordType) -> bytes:
        """Remove the encrypted padding and return the caller's payload."""
        if len(plaintext) < _LENGTH.size:
            raise ProtocolError("record plaintext is too short to hold a length")
        (declared,) = _LENGTH.unpack_from(plaintext, 0)
        available = len(plaintext) - _LENGTH.size
        if declared > available:
            raise ProtocolError(
                f"record declares {declared} payload bytes but carries {available}"
            )
        if declared > MAX_PAYLOAD:
            raise ProtocolError(f"record declares an oversized payload ({declared} bytes)")
        if record_type is RecordType.PAD and declared != 0:
            raise ProtocolError("cover record with a non-empty payload")
        return plaintext[_LENGTH.size : _LENGTH.size + declared]


def peek_type(frame: bytes) -> RecordType | None:
    """The record type of a frame, or ``None`` if it is not even a header."""
    if len(frame) < HEADER_SIZE:
        return None
    try:
        return RecordType(frame[0])
    except ValueError:
        return None

