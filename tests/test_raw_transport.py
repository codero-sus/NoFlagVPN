"""Raw carrier writer failures must close, normalize, and remain idempotent."""
from __future__ import annotations

import asyncio

import pytest
from nfvpn.errors import TransportError
from nfvpn.transport.raw import RawTCPTransport


class FakeReader:
    async def readexactly(self, size):
        raise AssertionError("no receive should occur in this test")


class FakeWriter:
    def __init__(self, *, drain_error=None, close_error=None) -> None:
        self.drain_error = drain_error
        self.close_error = close_error
        self.close_calls = 0
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        if self.drain_error:
            raise self.drain_error

    def close(self):
        self.close_calls += 1

    async def wait_closed(self):
        if self.close_error:
            raise self.close_error


def make_transport(writer):
    return RawTCPTransport(FakeReader(), writer, peer="peer:9001")


async def test_a_write_failure_closes_and_marks_the_carrier_dead():
    writer = FakeWriter(drain_error=ConnectionResetError("peer reset"))
    transport = make_transport(writer)
    with pytest.raises(TransportError, match="carrier write failed: ConnectionResetError"):
        await transport.send_message(b"payload")
    assert transport.is_open is False
    assert writer.close_calls == 1
    await transport.close()
    assert writer.close_calls == 1, "close remains idempotent after a write error"


async def test_a_close_timeout_is_suppressed_and_not_retried():
    writer = FakeWriter(close_error=asyncio.TimeoutError())
    transport = make_transport(writer)
    await transport.close()
    assert transport.is_open is False
    assert writer.close_calls == 1
    await transport.close()
    assert writer.close_calls == 1
