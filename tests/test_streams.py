"""Streams: identifiers, control messages, flow control and shutdown.

The multiplexer is where a dozen browser connections meet one tunnel, and most
of its interesting states are ones a happy-path test never reaches: a peer that
opens more streams than the limit, credit that runs out mid-write, data for a
stream that was already closed, a control record nobody asked for.

The channel is faked, so every assertion is about the multiplexer's own
decisions - what it sends, what it refuses, and what it hands the application -
rather than about timing.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct

import pytest
from nfvpn.errors import ProtocolError, TransportError
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
from nfvpn.framing.records import Record
from nfvpn.session.streams import (
    DEFAULT_MAX_STREAMS,
    DEFAULT_WINDOW,
    OpenRequest,
    Stream,
    StreamClosedError,
    StreamMultiplexer,
    pack_close,
    pack_open,
    pack_window,
    unpack_open,
    unpack_window,
)


class FakeChannel:
    """Records what the multiplexer sends, so a test can read it back."""

    def __init__(self) -> None:
        self.sent: list[tuple[RecordType, int, bytes]] = []

    async def send(self, record_type, stream_id: int, payload: bytes = b"", **kwargs) -> None:
        self.sent.append((record_type, stream_id, payload))

    # -- helpers for assertions -------------------------------------------
    def controls(self, code: int | None = None) -> list[tuple[int, bytes]]:
        found = []
        for record_type, stream_id, payload in self.sent:
            if record_type is not RecordType.CTRL:
                continue
            if code is None or payload[0] == code:
                found.append((stream_id, payload[1:]))
        return found

    def data(self) -> list[tuple[int, bytes]]:
        return [
            (stream_id, payload)
            for record_type, stream_id, payload in self.sent
            if record_type is RecordType.DATA
        ]


def record(record_type: RecordType, stream_id: int, payload: bytes) -> Record:
    return Record(type=record_type, flags=0, stream_id=stream_id, counter=0, payload=payload)


def control(code: int, body: bytes = b"") -> bytes:
    return bytes([code]) + body


def mux(
    *,
    initiator: bool = True,
    window: int = DEFAULT_WINDOW,
    max_streams: int = DEFAULT_MAX_STREAMS,
    handler=None,
):
    """A multiplexer on a fake channel.  The initiator opens even stream ids."""
    channel = FakeChannel()
    multiplexer = StreamMultiplexer(
        channel, initiator=initiator, window=window, max_streams=max_streams
    )
    if handler is not None:
        multiplexer.set_open_handler(handler)
    return multiplexer, channel


# --------------------------------------------------------------------------- #
# OPEN encoding
# --------------------------------------------------------------------------- #
def test_an_open_request_round_trips():
    request = OpenRequest(host="example.com", port=443)
    assert unpack_open(pack_open(request)) == request
    assert request.label() == "example.com:443"


def test_open_requests_refuse_nonsense_on_the_way_out():
    with pytest.raises(ProtocolError, match="too long"):
        pack_open(OpenRequest(host="x" * 256, port=443))


@pytest.mark.parametrize(
    "payload, message",
    [
        (b"\x01\x01\xbb", "too short"),
        (bytes([int(StreamProto.TCP)]) + struct.pack(">H", 80) + bytes([9]) + b"abc", "length does not match"),
        (bytes([99]) + struct.pack(">H", 80) + bytes([3]) + b"abc", "unsupported stream protocol"),
        (bytes([int(StreamProto.TCP)]) + struct.pack(">H", 80) + bytes([3]) + b"\xff\xfe\xfd", "non-UTF-8"),
        (bytes([int(StreamProto.TCP)]) + struct.pack(">H", 80) + bytes([0]), "empty host"),
    ],
)
def test_malformed_open_messages_are_refused(payload, message):
    with pytest.raises(ProtocolError, match=message):
        unpack_open(payload)


def test_a_window_message_is_four_bytes_and_no_other_size():
    assert unpack_window(pack_window(4096)) == 4096
    for size in (0, 3, 5, 8):
        with pytest.raises(ProtocolError, match="exactly 4 bytes"):
            unpack_window(bytes(size))


def test_close_reasons_are_one_byte():
    assert pack_close(CloseReason.LIMIT) == bytes([int(CloseReason.LIMIT)])


# --------------------------------------------------------------------------- #
# opening streams
# --------------------------------------------------------------------------- #
async def test_opening_sends_open_and_waits_for_opened():
    multiplexer, channel = mux()
    task = asyncio.create_task(multiplexer.open("example.com", 443))
    await asyncio.sleep(0.05)

    assert channel.controls(CTRL_OPEN), "OPEN must go out before anything else"
    stream_id, body = channel.controls(CTRL_OPEN)[0]
    assert unpack_open(body).host == "example.com"
    assert stream_id % 2 == 0, "the initiator uses even identifiers"
    assert not task.done(), "open() waits for the peer's answer"

    await multiplexer.handle_record(record(RecordType.CTRL, stream_id, control(CTRL_OPENED)))
    stream = await asyncio.wait_for(task, timeout=2)
    assert stream.stream_id == stream_id
    assert multiplexer.stream_count == 1
    assert multiplexer.opened_total == 1


async def test_responder_identifiers_are_odd():
    """Parity is what keeps the two ends from colliding on an id."""
    multiplexer, channel = mux(initiator=False)

    async def handler(stream: Stream, request: OpenRequest) -> None:
        await multiplexer.accept(stream)

    multiplexer.set_open_handler(handler)
    for stream_id in (7, 9):
        await multiplexer.handle_record(
            record(RecordType.CTRL, stream_id, control(CTRL_OPEN, pack_open(OpenRequest("host", 80))))
        )
    await asyncio.sleep(0.1)
    assert [stream_id for stream_id, _ in channel.controls(CTRL_OPENED)] == [7, 9]

    # The same multiplexer opening outbound streams uses its own parity: odd
    # ids for the responder, even for the initiator, so the two ends can never
    # collide.
    task = asyncio.create_task(multiplexer.open("example.com", 443))
    await asyncio.sleep(0.05)
    local_id = channel.controls(CTRL_OPEN)[-1][0]
    assert local_id % 2 == 1, "the responder's own streams are odd-numbered"
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def test_a_refused_open_raises_with_the_reason():
    multiplexer, channel = mux()
    task = asyncio.create_task(multiplexer.open("blocked.example", 25))
    await asyncio.sleep(0.05)
    stream_id = channel.controls(CTRL_OPEN)[0][0]

    await multiplexer.handle_record(
        record(RecordType.CTRL, stream_id, control(CTRL_CLOSE, pack_close(CloseReason.DENIED)))
    )
    with pytest.raises(StreamClosedError) as caught:
        await task
    assert caught.value.reason is CloseReason.DENIED
    assert "denied" in str(caught.value).lower()
    assert multiplexer.stream_count == 0, "a refused stream is forgotten"


async def test_an_unanswered_open_times_out_and_is_forgotten():
    multiplexer, _channel = mux()
    with pytest.raises(TimeoutError):
        await multiplexer.open("silent.example", 80, timeout=0.1)
    assert multiplexer.stream_count == 0


async def test_the_stream_limit_is_enforced_locally():
    multiplexer, _channel = mux(max_streams=1)
    task = asyncio.create_task(multiplexer.open("one.example", 80))
    await asyncio.sleep(0.05)

    with pytest.raises(StreamClosedError) as caught:
        await multiplexer.open("two.example", 80)
    assert caught.value.reason is CloseReason.LIMIT
    assert multiplexer.rejected_total == 1
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def test_opening_on_a_closed_tunnel_is_a_transport_error():
    multiplexer, _channel = mux()
    multiplexer._closed = True
    with pytest.raises(TransportError, match="closed"):
        await multiplexer.open("example.com", 80)


# --------------------------------------------------------------------------- #
# accepting streams (the responder side)
# --------------------------------------------------------------------------- #
async def test_no_handler_means_the_stream_is_denied():
    multiplexer, channel = mux()
    await multiplexer.handle_record(
        record(RecordType.CTRL, 4, control(CTRL_OPEN, pack_open(OpenRequest("host", 80))))
    )
    assert channel.controls(CTRL_CLOSE)[0] == (4, pack_close(CloseReason.DENIED))


async def test_a_duplicate_stream_id_is_refused():
    """Two streams on one id would silently merge; refuse the second."""
    seen = []

    async def handler(stream: Stream, request: OpenRequest) -> None:
        seen.append(stream.stream_id)
        await multiplexer.accept(stream)

    multiplexer, channel = mux(handler=handler)
    body = pack_open(OpenRequest("host", 80))
    for _ in range(2):
        await multiplexer.handle_record(record(RecordType.CTRL, 4, control(CTRL_OPEN, body)))
        await asyncio.sleep(0.05)
    assert seen == [4]
    assert channel.controls(CTRL_CLOSE)[0][1] == pack_close(CloseReason.REMOTE_ERROR)


async def test_a_peer_opening_more_than_the_limit_is_told_so():
    async def handler(stream: Stream, request: OpenRequest) -> None:
        await multiplexer.accept(stream)

    multiplexer, channel = mux(max_streams=1, handler=handler)
    body = pack_open(OpenRequest("host", 80))
    await multiplexer.handle_record(record(RecordType.CTRL, 2, control(CTRL_OPEN, body)))
    await asyncio.sleep(0.05)
    await multiplexer.handle_record(record(RecordType.CTRL, 4, control(CTRL_OPEN, body)))
    await asyncio.sleep(0.05)
    assert channel.controls(CTRL_CLOSE)[-1] == (4, pack_close(CloseReason.LIMIT))
    assert multiplexer.rejected_total == 1


async def test_a_handler_that_raises_does_not_take_the_tunnel_down():
    """One bad stream must not kill every other stream on the carrier."""
    async def handler(stream: Stream, request: OpenRequest) -> None:
        raise RuntimeError("the origin host is unreachable")

    multiplexer, channel = mux(handler=handler)
    await multiplexer.handle_record(
        record(RecordType.CTRL, 2, control(CTRL_OPEN, pack_open(OpenRequest("host", 80))))
    )
    await asyncio.sleep(0.1)
    assert channel.controls(CTRL_CLOSE)[0][1] == pack_close(CloseReason.REMOTE_ERROR)


async def test_accept_and_refuse_do_what_they_say():
    async def handler(stream: Stream, request: OpenRequest) -> None:
        return

    multiplexer, channel = mux(handler=handler)
    body = pack_open(OpenRequest("host", 80))
    for stream_id in (2, 4):
        await multiplexer.handle_record(record(RecordType.CTRL, stream_id, control(CTRL_OPEN, body)))
    await asyncio.sleep(0.1)

    accepted = multiplexer._streams[2]
    refused = multiplexer._streams[4]
    await multiplexer.accept(accepted)
    await multiplexer.refuse(refused, CloseReason.DENIED)
    assert (2, b"") in channel.controls(CTRL_OPENED)
    assert (4, pack_close(CloseReason.DENIED)) in channel.controls(CTRL_CLOSE)


# --------------------------------------------------------------------------- #
# data and flow control
# --------------------------------------------------------------------------- #
async def test_data_is_delivered_in_order():
    multiplexer, _channel = mux()
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), _mux=multiplexer)
    multiplexer._streams[2] = stream

    for chunk in (b"one", b"two", b"three"):
        await multiplexer.handle_record(record(RecordType.DATA, 2, chunk))
    assert [await stream.receive() for _ in range(3)] == [b"one", b"two", b"three"]
    assert stream.bytes_received == 11


async def test_data_for_a_forgotten_stream_is_dropped_and_reported():
    """Otherwise the peer keeps pushing bytes for a stream nobody has."""
    multiplexer, channel = mux()
    await multiplexer.handle_record(record(RecordType.DATA, 42, b"orphan"))
    assert channel.controls(CTRL_CLOSE) == [(42, pack_close(CloseReason.REMOTE_ERROR))]
    assert channel.data() == []


async def test_sending_consumes_credit_chunk_by_chunk():
    multiplexer, channel = mux()
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=8, _mux=multiplexer)
    multiplexer._streams[2] = stream

    await stream.send(b"12345678")
    assert channel.data() == [(2, b"12345678")]
    assert stream.credits == 0
    assert stream.bytes_sent == 8


async def test_a_send_waits_for_credit_and_resumes_when_it_arrives():
    multiplexer, channel = mux()
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=4, _mux=multiplexer)
    multiplexer._streams[2] = stream

    task = asyncio.create_task(stream.send(b"abcdefgh"))
    await asyncio.sleep(0.05)
    assert channel.data() == [(2, b"abcd")], "the first window goes out"
    assert not task.done(), "the rest waits for credit"

    await multiplexer.handle_record(record(RecordType.CTRL, 2, control(CTRL_WINDOW, pack_window(4))))
    await asyncio.wait_for(task, timeout=2)
    assert channel.data() == [(2, b"abcd"), (2, b"efgh")]


async def test_a_large_send_is_split_at_the_record_limit():
    multiplexer, channel = mux()
    window = MAX_PAYLOAD + 100
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=window, _mux=multiplexer)
    multiplexer._streams[2] = stream

    await stream.send(b"x" * (MAX_PAYLOAD + 10))
    sizes = [len(payload) for _stream, payload in channel.data()]
    assert sizes == [MAX_PAYLOAD, 10], "one record never exceeds MAX_PAYLOAD"


async def test_reading_enough_data_returns_credit_to_the_peer():
    """Flow control is only useful if the receiver acknowledges what it drained."""
    multiplexer, channel = mux(window=1000)
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=1000, _mux=multiplexer)
    multiplexer._streams[2] = stream

    # Half of this stream's 1000-byte window is the acknowledgement threshold.
    await multiplexer.handle_record(record(RecordType.DATA, 2, b"a" * 400))
    assert await stream.receive() == b"a" * 400
    assert channel.controls(CTRL_WINDOW) == [], "400 is below half the window"

    await multiplexer.handle_record(record(RecordType.DATA, 2, b"b" * 600))
    assert await stream.receive() == b"b" * 600
    assert channel.controls(CTRL_WINDOW) == [
        (2, pack_window(1000))
    ], "the drained bytes are returned as credit in one message"
    assert sum(unpack_window(body) for _id, body in channel.controls(CTRL_WINDOW)) == 1000


async def test_a_small_window_still_gets_its_credit_back():
    """The deadlock this guards against: a stream whose window is smaller than
    half the default one would wait for an acknowledgement that never came, and
    the sender would stop for good after one window of data."""
    multiplexer, channel = mux(window=4096)
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=4096, _mux=multiplexer)
    multiplexer._streams[2] = stream

    # Two thirds of the window: comfortably past half of it, far below half the
    # class default (128 KiB).
    await multiplexer.handle_record(record(RecordType.DATA, 2, b"a" * 3000))
    assert await stream.receive() == b"a" * 3000
    assert channel.controls(CTRL_WINDOW) == [
        (2, pack_window(3000))
    ], "credit must come back before the sender runs dry"


async def test_the_ack_threshold_follows_the_streams_own_window():
    narrow = Stream(stream_id=2, request=OpenRequest("host", 80), window=1024)
    wide = Stream(stream_id=4, request=OpenRequest("host", 80), window=1 << 20)
    assert narrow._ack_threshold == 512
    assert wide._ack_threshold == 1 << 19


async def test_sending_after_the_stream_closed_raises():
    multiplexer, _channel = mux()
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), _mux=multiplexer)
    multiplexer._streams[2] = stream
    await stream.close()
    with pytest.raises(StreamClosedError):
        await stream.send(b"too late")


async def test_an_unattached_stream_cannot_send():
    stream = Stream(stream_id=2, request=OpenRequest("host", 80))
    with pytest.raises(ProtocolError, match="not attached"):
        await stream.send(b"bye")


async def test_receive_returns_none_when_the_far_end_finishes():
    multiplexer, _channel = mux()
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), _mux=multiplexer)
    multiplexer._streams[2] = stream

    await multiplexer.handle_record(record(RecordType.DATA, 2, b"last"))
    await multiplexer.handle_record(record(RecordType.CTRL, 2, control(CTRL_CLOSE, pack_close(CloseReason.NORMAL))))

    assert await stream.receive() == b"last"
    assert await stream.receive() is None
    assert stream.closed
    assert stream.close_reason is CloseReason.NORMAL
    assert multiplexer.stream_count == 0


async def test_receiving_a_close_without_a_reason_means_normal():
    multiplexer, _channel = mux()
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), _mux=multiplexer)
    multiplexer._streams[2] = stream
    await multiplexer.handle_record(record(RecordType.CTRL, 2, control(CTRL_CLOSE)))
    assert stream.close_reason is CloseReason.NORMAL


async def test_data_after_a_close_is_ignored_rather_than_queued():
    multiplexer, _channel = mux()
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), _mux=multiplexer)
    multiplexer._streams[2] = stream
    await stream.close()
    await multiplexer.handle_record(record(RecordType.DATA, 2, b"ignored"))
    assert stream.buffered == 1, "only the EOF marker is queued"


# --------------------------------------------------------------------------- #
# control plumbing
# --------------------------------------------------------------------------- #
async def test_ping_is_answered_with_the_same_body():
    multiplexer, channel = mux()
    await multiplexer.handle_record(record(RecordType.CTRL, 0, control(CTRL_PING, b"round-trip")))
    assert channel.controls(CTRL_PONG) == [(0, b"round-trip")]


async def test_a_pong_is_a_no_op():
    multiplexer, channel = mux()
    await multiplexer.handle_record(record(RecordType.CTRL, 0, control(CTRL_PONG, b"whatever")))
    assert channel.sent == []


async def test_an_empty_control_record_is_a_protocol_error():
    multiplexer, _channel = mux()
    with pytest.raises(ProtocolError, match="empty payload"):
        await multiplexer.handle_record(record(RecordType.CTRL, 2, b""))


async def test_an_unknown_control_code_is_a_protocol_error():
    """A peer inventing control messages is not something to ignore quietly."""
    multiplexer, _channel = mux()
    with pytest.raises(ProtocolError, match="unknown control code"):
        await multiplexer.handle_record(record(RecordType.CTRL, 2, control(99)))


async def test_an_opened_for_a_stream_we_never_opened_is_ignored():
    multiplexer, channel = mux()
    await multiplexer.handle_record(record(RecordType.CTRL, 6, control(CTRL_OPENED)))
    assert channel.sent == []


async def test_a_window_for_an_unknown_stream_is_ignored():
    multiplexer, channel = mux()
    await multiplexer.handle_record(record(RecordType.CTRL, 6, control(CTRL_WINDOW, pack_window(10))))
    assert channel.sent == []


async def test_a_close_for_an_unknown_stream_is_ignored():
    multiplexer, channel = mux()
    await multiplexer.handle_record(record(RecordType.CTRL, 6, control(CTRL_CLOSE)))
    assert channel.sent == []


async def test_close_all_shuts_every_stream_and_tells_the_peer():
    multiplexer, channel = mux()
    streams = []
    for stream_id in (2, 4):
        stream = Stream(stream_id=stream_id, request=OpenRequest("host", 80), _mux=multiplexer)
        multiplexer._streams[stream_id] = stream
        streams.append(stream)

    await multiplexer.close_all(CloseReason.LOCAL_SHUTDOWN)
    assert all(stream.closed for stream in streams)
    assert set(channel.controls(CTRL_CLOSE)) == {
        (2, pack_close(CloseReason.LOCAL_SHUTDOWN)),
        (4, pack_close(CloseReason.LOCAL_SHUTDOWN)),
    }
    assert multiplexer.stream_count == 0
    assert [stream.stream_id for stream in multiplexer] == []


async def test_the_statistics_add_up():
    multiplexer, channel = mux()
    task = asyncio.create_task(multiplexer.open("example.com", 443))
    await asyncio.sleep(0.05)
    stream_id = channel.controls(CTRL_OPEN)[0][0]
    await multiplexer.handle_record(record(RecordType.CTRL, stream_id, control(CTRL_OPENED)))
    stream = await asyncio.wait_for(task, timeout=2)
    await stream.send(b"payload")
    await multiplexer.handle_record(record(RecordType.DATA, stream_id, b"reply"))
    assert await stream.receive() == b"reply"

    assert multiplexer.opened_total == 1
    assert multiplexer.rejected_total == 0
    assert stream.bytes_sent == 7
    assert stream.bytes_received == 5
    assert multiplexer.stream_count == 1
    assert [item.stream_id for item in multiplexer] == [stream_id]


async def test_peer_cannot_queue_more_data_than_the_receive_window():
    multiplexer, _channel = mux(window=4)
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=4, _mux=multiplexer)
    multiplexer._streams[2] = stream
    await multiplexer.handle_record(record(RecordType.DATA, 2, b"1234"))
    with pytest.raises(ProtocolError, match="flow-control window"):
        await multiplexer.handle_record(record(RecordType.DATA, 2, b"5"))
    assert stream.buffered == 1
    assert stream._recv_credit == 0


async def test_empty_data_records_cannot_bypass_byte_flow_control():
    multiplexer, _channel = mux()
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), _mux=multiplexer)
    multiplexer._streams[2] = stream
    with pytest.raises(ProtocolError, match="empty DATA"):
        await multiplexer.handle_record(record(RecordType.DATA, 2, b""))
    assert stream.buffered == 0


async def test_peer_cannot_grant_more_than_the_original_window():
    multiplexer, _channel = mux(window=4)
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=4, _mux=multiplexer)
    multiplexer._streams[2] = stream
    with pytest.raises(ProtocolError, match="more stream credit"):
        await multiplexer.handle_record(
            record(RecordType.CTRL, 2, control(CTRL_WINDOW, pack_window(5)))
        )


async def test_zero_window_updates_are_protocol_errors():
    multiplexer, _channel = mux(window=4)
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=4, _mux=multiplexer)
    multiplexer._streams[2] = stream
    with pytest.raises(ProtocolError, match="credit must be positive"):
        await multiplexer.handle_record(
            record(RecordType.CTRL, 2, control(CTRL_WINDOW, pack_window(0)))
        )


async def test_closing_a_stream_wakes_a_sender_waiting_for_credit():
    multiplexer, _channel = mux(window=4)
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=4, _mux=multiplexer)
    multiplexer._streams[2] = stream
    await stream.send(b"full")
    pending = asyncio.create_task(stream.send(b"more"))
    await asyncio.sleep(0)
    await stream.close(CloseReason.NORMAL)
    with pytest.raises(StreamClosedError):
        await asyncio.wait_for(pending, timeout=1)


async def test_concurrent_sends_do_not_spend_the_same_stream_credit_twice():
    class PausingChannel(FakeChannel):
        def __init__(self):
            super().__init__()
            self.data_started = asyncio.Event()
            self.release_data = asyncio.Event()

        async def send(self, record_type, stream_id, payload=b"", **kwargs):
            if record_type is RecordType.DATA:
                self.data_started.set()
                await self.release_data.wait()
            await super().send(record_type, stream_id, payload, **kwargs)

    multiplexer, _ = mux(window=4)
    channel = PausingChannel()
    multiplexer.channel = channel
    stream = Stream(stream_id=2, request=OpenRequest("host", 80), window=4, _mux=multiplexer)
    multiplexer._streams[2] = stream

    first = asyncio.create_task(stream.send(b"1111"))
    await channel.data_started.wait()
    second = asyncio.create_task(stream.send(b"2222"))
    await asyncio.sleep(0)
    assert stream.credits == 0
    assert not second.done()

    channel.release_data.set()
    await first
    assert channel.data() == [(2, b"1111")]
    await multiplexer.handle_record(
        record(RecordType.CTRL, 2, control(CTRL_WINDOW, pack_window(4)))
    )
    await second
    assert channel.data() == [(2, b"1111"), (2, b"2222")]
