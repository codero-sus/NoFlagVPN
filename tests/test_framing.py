"""Records: padding, authentication, replay and rekeying."""

from __future__ import annotations

import os
import random

import pytest
from nfvpn.errors import AuthenticationError, ProtocolError, ReplayError
from nfvpn.framing import (
    HEADER_SIZE,
    TAG_SIZE,
    FrameReader,
    FrameWriter,
    RecordType,
    ReplayWindow,
)
from nfvpn.framing.records import peek_type
from nfvpn.traffic import Shaper, get_profile


@pytest.fixture
def key() -> bytes:
    return os.urandom(32)


def test_round_trip_without_shaping(key):
    writer, reader = FrameWriter(key), FrameReader(key)
    frame = writer.encode(RecordType.DATA, 42, b"hello")
    record = reader.decode(frame)
    assert (record.type, record.stream_id, record.payload) == (RecordType.DATA, 42, b"hello")
    assert record.counter == 0


@pytest.mark.parametrize("size", [0, 1, 100, 1400, 16384])
def test_round_trip_preserves_payload(key, size):
    writer, reader = FrameWriter(key), FrameReader(key)
    payload = os.urandom(size)
    assert reader.decode(writer.encode(RecordType.DATA, 1, payload)).payload == payload


def test_padding_hides_the_real_length(key):
    """An observer must not be able to read the payload length off the wire.

    Two properties matter.  Sizes are quantised into classes, so many different
    payloads produce the same bytes on the wire; and the classes are jittered, so
    a single fixed size (which would itself be a signature) is not what you get.
    The measure used here is the *anonymity set*: for an observed size, how many
    payload lengths could have produced it.
    """
    shaper = Shaper(get_profile("balanced"), random.Random(0))
    writer, reader = FrameWriter(key, shaper), FrameReader(key)

    overhead = HEADER_SIZE + TAG_SIZE

    def size_range(payload_length: int) -> tuple[int, int]:
        """The smallest and largest wire size this payload length can produce."""
        low, high = random.Random(0), random.Random(0)
        low.randrange = lambda _n: 0  # type: ignore[method-assign]
        high.randrange = lambda n: max(n - 1, 0)  # type: ignore[method-assign]
        profile = shaper.profile
        return (
            overhead + profile.padded_plaintext(payload_length, low),
            overhead + profile.padded_plaintext(payload_length, high),
        )

    lengths = list(range(1, 4000))
    ranges = {length: size_range(length) for length in lengths}

    candidates: list[int] = []
    for observed in sorted({low for low, _ in ranges.values()}):
        candidates.append(
            sum(1 for low, high in ranges.values() if low <= observed <= high)
        )
    median = sorted(candidates)[len(candidates) // 2]
    assert median >= 10, f"median anonymity set of {median} payloads hides almost nothing"

    distinct = {len(writer.encode(RecordType.DATA, 1, os.urandom(length))) for length in lengths}
    assert len(distinct) > 20, f"only {len(distinct)} wire sizes: fixed-size padding is a signature"

    record = reader.decode(writer.encode(RecordType.DATA, 1, b"x" * 10))
    assert record.payload == b"x" * 10


def test_padding_is_inside_the_authentication(key):
    shaper = Shaper(get_profile("balanced"), random.Random(1))
    writer, reader = FrameWriter(key, shaper), FrameReader(key)
    frame = bytearray(writer.encode(RecordType.DATA, 1, b"payload"))
    frame[-1] ^= 0xFF  # flip a padding byte
    with pytest.raises(AuthenticationError):
        reader.decode(bytes(frame))


def test_header_is_authenticated(key):
    writer, reader = FrameWriter(key), FrameReader(key)
    frame = bytearray(writer.encode(RecordType.DATA, 7, b"payload"))
    frame[4] ^= 0x01  # stream_id lives at offset 4
    with pytest.raises((AuthenticationError, ProtocolError)):
        reader.decode(bytes(frame))


def test_wrong_key_is_refused(key):
    frame = FrameWriter(key).encode(RecordType.DATA, 1, b"payload")
    with pytest.raises(AuthenticationError):
        FrameReader(os.urandom(32)).decode(frame)


def test_truncated_and_oversized_frames(key):
    reader = FrameReader(key)
    with pytest.raises(ProtocolError):
        reader.decode(b"\x01\x00")
    # A well-formed header with garbage where the ciphertext should be: the
    # header parses, the tag does not verify.
    bogus = bytes([RecordType.DATA, 0, 0, 0, 0, 0, 0, 1]) + b"\x00" * 8 + os.urandom(TAG_SIZE + 8)
    with pytest.raises(AuthenticationError):
        reader.decode(bogus)


def test_unknown_record_type_is_rejected(key):
    writer, reader = FrameWriter(key), FrameReader(key)
    frame = bytearray(writer.encode(RecordType.DATA, 1, b"x"))
    frame[0] = 99
    with pytest.raises(ProtocolError):
        reader.decode(bytes(frame))


def test_payload_limit(key):
    writer = FrameWriter(key)
    with pytest.raises(ProtocolError):
        writer.encode(RecordType.DATA, 1, b"x" * (20 * 1024))


def test_peek_type(key):
    frame = FrameWriter(key).encode(RecordType.PAD, 0, b"")
    assert peek_type(frame) is RecordType.PAD
    assert peek_type(b"\x00") is None


# replay ------------------------------------------------------------------------


def test_replay_window_rejects_the_second_copy():
    window = ReplayWindow(64)
    window.check_and_update(5)
    with pytest.raises(ReplayError):
        window.check_and_update(5)


def test_replay_window_tolerates_reordering():
    window = ReplayWindow(64)
    for counter in (10, 12, 11, 9, 8):
        window.check_and_update(counter)
    assert window.highest == 12
    assert window.seen(11)


def test_replay_window_rejects_ancient_counters():
    window = ReplayWindow(8)
    window.check_and_update(100)
    with pytest.raises(ReplayError):
        window.check_and_update(50)
    window.check_and_update(95)  # inside the window


def test_replay_protection_end_to_end(key):
    writer, reader = FrameWriter(key), FrameReader(key)
    frame = writer.encode(RecordType.DATA, 1, b"once")
    reader.decode(frame)
    with pytest.raises(ReplayError):
        reader.decode(frame)


# rekeying ----------------------------------------------------------------------


def test_reader_follows_the_peer_across_a_rekey(key):
    new_key = os.urandom(32)
    writer, reader = FrameWriter(key), FrameReader(key)
    reader.decode(writer.encode(RecordType.DATA, 1, b"old"))

    reader.rotate(new_key, keep_previous=True)
    writer.rotate(new_key)
    reader.decode(writer.encode(RecordType.DATA, 1, b"new"))

    # A record still in flight under the previous generation must still open.
    stale_writer = FrameWriter(key)
    stale_writer.counter = 9
    assert reader.decode(stale_writer.encode(RecordType.DATA, 1, b"straggler")).payload == b"straggler"


def test_previous_key_is_dropped_after_catch_up(key):
    new_key = os.urandom(32)
    writer, reader = FrameWriter(key), FrameReader(new_key)
    reader.rotate(new_key, keep_previous=True)
    reader._previous = key  # simulate "we have rotated, the peer has not"
    reader._previous_window = ReplayWindow(64)
    writer.rotate(new_key)
    for index in range(FrameReader.CATCH_UP_RECORDS):
        reader.decode(writer.encode(RecordType.DATA, 1, bytes([index % 256])))
    assert reader.holding_previous is False


def test_counters_restart_under_a_new_key(key):
    new_key = os.urandom(32)
    writer, reader = FrameWriter(key), FrameReader(key)
    writer.encode(RecordType.DATA, 1, b"a")
    writer.rotate(new_key)
    reader.rotate(new_key, keep_previous=False)
    assert writer.counter == 0
    assert reader.decode(writer.encode(RecordType.DATA, 1, b"b")).payload == b"b"


def test_replay_window_requires_a_positive_size():
    with pytest.raises(ValueError, match="size must be positive"):
        ReplayWindow(0)
    with pytest.raises(ValueError, match="size must be positive"):
        ReplayWindow(-1)


def test_replay_window_rejects_negative_counters():
    with pytest.raises(ReplayError, match="negative record counter"):
        ReplayWindow().check_and_update(-1)


def test_replay_window_trims_bits_and_expires_oldest_seen_counter():
    window = ReplayWindow(4)
    for counter in range(5):
        window.check_and_update(counter)
    assert window.highest == 4
    assert window.seen(4)
    assert window.seen(1)
    assert not window.seen(0), "the oldest value is outside the sliding window"
    with pytest.raises(ReplayError, match="older than the 4-record window"):
        window.check_and_update(0)


def test_replay_window_reset_forgets_the_old_key_generation():
    window = ReplayWindow(8)
    window.check_and_update(37)
    window.reset()
    assert window.highest == -1
    assert not window.seen(37)
    window.check_and_update(0)
    assert window.seen(0)
    assert "size=8, highest=0" in repr(window)


def test_replay_window_forgets_bits_on_a_huge_forward_jump_without_a_huge_shift():
    window = ReplayWindow(64)
    window.check_and_update(1)
    window.check_and_update(10**12)
    assert window.highest == 10**12
    assert window.seen(10**12)
    assert not window.seen(1)
