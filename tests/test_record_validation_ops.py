"""Wire-header integer bounds must fail as protocol errors, not struct crashes."""
from __future__ import annotations

import pytest
from nfvpn.errors import ProtocolError
from nfvpn.framing.constants import RecordType
from nfvpn.framing.records import FrameWriter, RecordHeader


@pytest.mark.parametrize(
    ("record_type", "flags", "stream_id", "counter"),
    [
        (RecordType.DATA, -1, 1, 0),
        (RecordType.DATA, 256, 1, 0),
        (RecordType.DATA, 0, -1, 0),
        (RecordType.DATA, 0, 1 << 32, 0),
        (RecordType.DATA, 0, 1, -1),
        (RecordType.DATA, 0, 1, 1 << 64),
        (99, 0, 1, 0),
    ],
)
def test_header_pack_rejects_unrepresentable_fields_as_protocol_errors(
    record_type, flags, stream_id, counter
):
    header = RecordHeader(record_type, flags, stream_id, counter)
    with pytest.raises(ProtocolError):
        header.pack()


def test_header_unpack_requires_exactly_one_full_header():
    with pytest.raises(ProtocolError, match="header must be 16 bytes"):
        RecordHeader.unpack(b"short")


def test_frame_writer_rejects_a_negative_nonce_counter_cleanly():
    with pytest.raises(ProtocolError, match="counter cannot be negative"):
        FrameWriter(b"k" * 32, counter=-1).encode(RecordType.DATA, 1, b"x")


def _authenticated_frame(key: bytes, record_type: RecordType, plaintext: bytes) -> bytes:
    import struct

    from nfvpn.core.primitives import aead_seal

    header = RecordHeader(record_type, 0, 1, 0).pack()
    nonce = struct.pack("<Q", 0) + b"\x00" * 4
    return header + aead_seal(key, nonce, plaintext, header)


def test_header_pack_rejects_non_integer_record_types():
    with pytest.raises(ProtocolError, match="record type must be a RecordType"):
        RecordHeader(1.0, 0, 1, 0).pack()  # type: ignore[arg-type]


def test_record_size_and_reader_highest_counter_properties():
    from nfvpn.framing.records import FrameReader, Record, peek_type

    assert Record(RecordType.DATA, 0, 1, 0, b"payload").size == 7
    assert FrameReader(b"k" * 32).highest_counter == -1
    assert peek_type(bytes([99]) + bytes(15)) is None


def test_writer_refuses_records_after_the_u64_counter_is_exhausted():
    writer = FrameWriter(b"k" * 32, counter=(1 << 64) - 1)
    writer.encode(RecordType.DATA, 1, b"last counter")
    with pytest.raises(ProtocolError, match="counter exhausted"):
        writer.encode(RecordType.DATA, 1, b"must rekey")


@pytest.mark.parametrize(
    ("record_type", "plaintext", "message"),
    [
        (RecordType.DATA, b"\x00", "too short to hold a length"),
        (RecordType.DATA, b"\x00\x04x", "declares 4 payload bytes but carries 1"),
        (RecordType.DATA, b"\x40\x01" + b"x" * 16385, "oversized payload"),
        (RecordType.PAD, b"\x00\x01x", "cover record with a non-empty payload"),
    ],
)
def test_authenticated_but_structurally_invalid_plaintexts_are_refused(
    record_type, plaintext, message
):
    from nfvpn.errors import ProtocolError
    from nfvpn.framing.records import FrameReader

    key = b"k" * 32
    with pytest.raises(ProtocolError, match=message):
        FrameReader(key).decode(_authenticated_frame(key, record_type, plaintext))
