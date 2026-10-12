"""The encrypted record layer: framing, padding, replay protection."""

from __future__ import annotations

from nfvpn.framing.constants import (
    HEADER_SIZE,
    MAX_PAYLOAD,
    PROTOCOL_VERSION,
    TAG_SIZE,
    CloseReason,
    RecordType,
    StreamProto,
)
from nfvpn.framing.records import FrameReader, FrameWriter, Record, RecordHeader, peek_type
from nfvpn.framing.replay import ReplayWindow

__all__ = [
    "HEADER_SIZE",
    "MAX_PAYLOAD",
    "PROTOCOL_VERSION",
    "TAG_SIZE",
    "CloseReason",
    "FrameReader",
    "FrameWriter",
    "Record",
    "RecordHeader",
    "RecordType",
    "ReplayWindow",
    "StreamProto",
    "peek_type",
]
