"""Bidirectional pumps must account, rate-limit, and release both half-streams."""
from __future__ import annotations

import asyncio

import pytest
from nfvpn.errors import TransportError
from nfvpn.framing.constants import CloseReason
from nfvpn.pump import pump_bidirectional


class FakeReader:
    def __init__(self, chunks=()) -> None:
        self.chunks = list(chunks)
        self.started = asyncio.Event()
        self.block = asyncio.Event()

    async def read(self, size):
        self.started.set()
        if self.chunks:
            result = self.chunks.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        await self.block.wait()
        return b""


class FakeWriter:
    def __init__(self, *, drain_error=None) -> None:
        self.writes: list[bytes] = []
        self.drains = 0
        self.eof = 0
        self.drain_error = drain_error

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        self.drains += 1
        if self.drain_error:
            raise self.drain_error

    def write_eof(self):
        self.eof += 1


class FakeStream:
    def __init__(self, chunks=(), *, send_error=None, receive_error=None) -> None:
        self.chunks = list(chunks)
        self.sent: list[bytes] = []
        self.closed: list[CloseReason] = []
        self.send_error = send_error
        self.receive_error = receive_error
        self.started = asyncio.Event()
        self.block = asyncio.Event()

    async def send(self, data):
        if self.send_error:
            raise self.send_error
        self.sent.append(data)

    async def receive(self):
        self.started.set()
        if self.receive_error:
            raise self.receive_error
        if self.chunks:
            return self.chunks.pop(0)
        await self.block.wait()
        return None

    async def close(self, reason=CloseReason.NORMAL):
        self.closed.append(reason)


class FakeLimiter:
    def __init__(self) -> None:
        self.consumed: list[int] = []

    async def consume(self, size):
        self.consumed.append(size)


async def test_pump_forwards_both_directions_and_limits_payload_bytes():
    reader = FakeReader([b"up-one", b"up-two", b""])
    stream = FakeStream([b"down", b"stream", None])
    writer = FakeWriter()
    limiter = FakeLimiter()

    counts = await pump_bidirectional(stream, reader, writer, limiter=limiter)

    assert counts == (12, 10)
    assert stream.sent == [b"up-one", b"up-two"]
    assert writer.writes == [b"down", b"stream"]
    assert sorted(limiter.consumed) == [4, 6, 6, 6]
    assert stream.closed == [CloseReason.NORMAL]
    assert writer.eof == 1


async def test_pump_keeps_the_requested_close_reason():
    stream = FakeStream([None])
    await pump_bidirectional(stream, FakeReader([b""]), FakeWriter(), close_reason=CloseReason.DENIED)
    assert stream.closed == [CloseReason.DENIED]


async def test_a_stream_send_failure_stops_that_direction_and_closes_stream():
    stream = FakeStream([None], send_error=TransportError("relay left"))
    counts = await pump_bidirectional(stream, FakeReader([b"up", b""]), FakeWriter())
    assert counts == (0, 0)
    assert stream.closed == [CloseReason.NORMAL]


async def test_a_socket_read_failure_still_closes_the_stream():
    stream = FakeStream([None])
    counts = await pump_bidirectional(
        stream, FakeReader([ConnectionResetError("socket reset")]), FakeWriter()
    )
    assert counts == (0, 0)
    assert stream.closed == [CloseReason.NORMAL]
    assert stream.started.is_set()


async def test_a_socket_write_failure_half_closes_and_does_not_count_unsent_bytes():
    stream = FakeStream([b"cannot write", None])
    writer = FakeWriter(drain_error=BrokenPipeError("gone"))
    counts = await pump_bidirectional(stream, FakeReader([b""]), writer)
    assert counts == (0, 0)
    assert writer.writes == [b"cannot write"]
    assert writer.eof == 1


async def test_cancelling_a_pump_cleans_up_both_directions_and_propagates():
    reader = FakeReader()
    stream = FakeStream()
    writer = FakeWriter()
    task = asyncio.create_task(pump_bidirectional(stream, reader, writer))
    await asyncio.gather(reader.started.wait(), stream.started.wait())
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stream.closed == [CloseReason.NORMAL]
    assert writer.eof == 1
