"""Session lifecycle and handshake-confirmation failure edges.

The end-to-end tests prove that two peers can exchange data. These tests pin the
less visible contract: a dead read loop is still cleaned up by close(), close
is safe under concurrent callers, and malformed or missing confirmation records
fail with an actionable handshake error.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from nfvpn.errors import HandshakeError, NoFlagVPNError, TransportError
from nfvpn.framing.constants import (
    CTRL_CONFIRM,
    CTRL_PING,
    HEADER_SIZE,
    TAG_SIZE,
    CloseReason,
    RecordType,
)
from nfvpn.session import session as session_module
from nfvpn.session.session import (
    DECOY_LINGER,
    Session,
    SessionInfo,
    _await_handshake_message,
    _confirmation_record_size,
    _decoy_record,
    _exchange_confirmations,
)


class FakeTransport:
    def __init__(self) -> None:
        self.closes = 0

    async def close(self) -> None:
        self.closes += 1


class FakeChannel:
    def __init__(self, records=(), *, failure=None, close_error=None) -> None:
        self.transport = FakeTransport()
        self.records = list(records)
        self.failure = failure
        self.close_error = close_error
        self.started = 0
        self.closed = 0
        self.flushed = 0
        self.sent = []
        self.stats = SimpleNamespace(summary=lambda: "records in 2, records out 3")
        self._blocked = asyncio.Event()

    async def start(self):
        self.started += 1

    async def close(self):
        self.closed += 1
        if self.close_error:
            raise self.close_error

    async def flush(self):
        self.flushed += 1

    async def send(self, *args):
        self.sent.append(args)

    async def receive(self):
        if self.records:
            result = self.records.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        await self._blocked.wait()
        raise AssertionError("unreachable")


class FakeStreams:
    def __init__(self, *, close_error=None) -> None:
        self.closed = []
        self.close_error = close_error
        self.records = []
        self.record_event = asyncio.Event()

    async def close_all(self, reason):
        self.closed.append(reason)
        if self.close_error:
            raise self.close_error

    async def handle_record(self, record):
        self.records.append(record)
        self.record_event.set()


def make_session(*, channel=None, streams=None, idle_timeout=30.0):
    channel = channel or FakeChannel()
    streams = streams or FakeStreams()
    info = SessionInfo("relay", b"k" * 32, True, "ws://relay")
    return Session(channel, streams, info, idle_timeout=idle_timeout)


class FakeHandshakeTransport:
    def __init__(self, message=None, error=None) -> None:
        self.message = message
        self.error = error

    async def receive_message(self):
        if self.error:
            raise self.error
        return self.message


class FakeConfirmChannel(FakeChannel):
    pass


def test_session_info_formats_both_roles_and_redacts_member_psk():
    client = SessionInfo("relay", b"k" * 32, True, "wss://example", member_psk=b"secret")
    relay = SessionInfo("client", b"k" * 32, False, "raw+tls", member_psk=b"secret")
    assert client.describe() == "session as client with relay over wss://example"
    assert relay.describe() == "session as relay with client over raw+tls"
    assert "secret" not in repr(client)


def test_confirmation_record_is_sized_with_and_without_padding():
    assert _confirmation_record_size(None) == HEADER_SIZE + TAG_SIZE + 33

    class Pad:
        def padded_plaintext(self, size):
            assert size == 33
            return 160

    assert _confirmation_record_size(Pad()) == HEADER_SIZE + TAG_SIZE + 160


def test_decoy_record_is_record_shaped_and_at_least_the_requested_size():
    decoy = _decoy_record(RecordType.CTRL, size=100)
    assert len(decoy) == 100
    assert decoy[:2] == bytes([int(RecordType.CTRL), 0])
    assert _decoy_record(size=1) != _decoy_record(size=1)
    assert len(_decoy_record(size=1)) >= HEADER_SIZE + TAG_SIZE


def test_await_handshake_message_accepts_only_the_fixed_size():
    payload = b"h" * session_module.HANDSHAKE_SIZE
    assert asyncio.run(_await_handshake_message(FakeHandshakeTransport(payload), 1, "hello")) == payload


def test_await_handshake_message_rejects_short_messages():
    with pytest.raises(HandshakeError, match="hello must be"):
        asyncio.run(_await_handshake_message(FakeHandshakeTransport(b"short"), 1, "hello"))


async def test_await_handshake_message_turns_a_timeout_into_a_handshake_error():
    transport = FakeHandshakeTransport(error=asyncio.TimeoutError())
    with pytest.raises(HandshakeError, match="timed out waiting for peer hello"):
        await _await_handshake_message(transport, 0.1, "peer hello")


async def test_start_and_ping_and_close_are_idempotent():
    channel = FakeChannel()
    streams = FakeStreams()
    session = make_session(channel=channel, streams=streams)
    await session.start()
    await session.start()
    assert channel.started == 2
    await session.ping()
    assert channel.sent == [(RecordType.CTRL, 0, bytes([CTRL_PING]))]
    await session.close(CloseReason.DENIED)
    await session.close()
    assert streams.closed == [CloseReason.DENIED]
    assert channel.closed == 1
    assert channel.transport.closes == 1
    assert session.closed is True


async def test_close_cleans_the_carrier_after_the_read_loop_already_died():
    """The read loop marks closed before a later explicit close performs teardown."""
    session = make_session(channel=FakeChannel(), idle_timeout=0.001)
    await session.start()
    await asyncio.wait_for(session.wait_closed(), timeout=1)
    assert session.closed is True
    await session.close()
    assert session.channel.transport.closes == 1, "a dead read loop must not leak its carrier"


async def test_read_loop_timeout_is_visible_as_the_last_error():
    session = make_session(idle_timeout=0.001)
    await session.run()
    assert isinstance(session.last_error, TransportError)
    assert "no traffic for 0s" in str(session.last_error)
    assert session.closed is True
    await session.close()


async def test_read_loop_preserves_channel_failure_and_dispatches_records():
    record = SimpleNamespace(type=RecordType.DATA, payload=b"data")
    channel = FakeChannel([record], failure=TransportError("sender failed"))
    streams = FakeStreams()
    session = make_session(channel=channel, streams=streams)
    await session.start()
    await asyncio.wait_for(session.wait_closed(), timeout=1)
    assert session.last_error is channel.failure
    assert streams.records == [], "a failed channel record is not dispatched"
    await session.close()

    other_channel = FakeChannel([record])
    other_streams = FakeStreams()
    other_session = make_session(channel=other_channel, streams=other_streams)
    await other_session.start()
    # After consuming one record the fake channel blocks; close cancels that read.
    await asyncio.wait_for(other_streams.record_event.wait(), timeout=1)
    assert other_streams.records == [record]
    await other_session.close()
    assert other_session.closed is True


@pytest.mark.parametrize("error", [TransportError("carrier gone"), NoFlagVPNError("protocol error")])
async def test_read_loop_records_known_errors_and_signals_closed(error):
    session = make_session(channel=FakeChannel([error]))
    await session.start()
    await asyncio.wait_for(session.wait_closed(), timeout=1)
    assert session.last_error is error
    assert session.closed is True
    await session.close()


async def test_close_still_closes_the_transport_if_channel_close_raises():
    channel = FakeChannel(close_error=RuntimeError("sender task failed"))
    session = make_session(channel=channel)
    with pytest.raises(RuntimeError, match="sender task failed"):
        await session.close()
    assert channel.transport.closes == 1
    # The failed close has still completed teardown and is not repeated.
    await session.close()
    assert channel.closed == 1


async def test_context_manager_starts_then_closes_session():
    session = make_session()
    async with session as entered:
        assert entered is session
        assert session.channel.started == 1
    assert session.closed is True
    assert session.channel.transport.closes == 1


async def test_close_suppresses_stream_and_flush_errors():
    channel = FakeChannel()
    channel.flush = _raise_runtime
    streams = FakeStreams(close_error=RuntimeError("streams already closed"))
    session = make_session(channel=channel, streams=streams)
    await session.close()
    assert channel.transport.closes == 1


async def _raise_runtime():
    raise RuntimeError("flush failed")


async def test_confirm_exchange_sends_and_verifies_the_peer_confirmation(monkeypatch):
    confirmation = b"c" * 32
    channel = FakeConfirmChannel(
        [SimpleNamespace(type=RecordType.CTRL, payload=bytes([CTRL_CONFIRM]) + confirmation)]
    )
    verified = []
    monkeypatch.setattr(
        session_module.HandshakeResponder,
        "verify_confirmation",
        lambda own, peer: verified.append((own, peer)),
    )
    await _exchange_confirmations(channel, confirmation, timeout=1)
    assert channel.sent == [(RecordType.CTRL, 0, bytes([CTRL_CONFIRM]) + confirmation)]
    assert channel.flushed == 1
    assert verified == [(confirmation, confirmation)]


@pytest.mark.parametrize(
    ("record", "message"),
    [
        (SimpleNamespace(type=RecordType.DATA, payload=b"x"), "expected a confirmation"),
        (SimpleNamespace(type=RecordType.CTRL, payload=b""), "expected a confirmation"),
        (SimpleNamespace(type=RecordType.CTRL, payload=b"\x00"), "unexpected control code"),
    ],
)
async def test_confirm_exchange_rejects_wrong_record_shapes(record, message):
    with pytest.raises(HandshakeError, match=message):
        await _exchange_confirmations(FakeConfirmChannel([record]), b"c" * 32, timeout=1)


async def test_confirm_exchange_reports_a_missing_peer_confirmation(monkeypatch):
    monkeypatch.setattr(session_module.time, "monotonic", lambda: 1000.0)
    with pytest.raises(HandshakeError, match="peer never confirmed"):
        await _exchange_confirmations(FakeConfirmChannel(), b"c" * 32, timeout=0)


async def test_confirm_exchange_applies_a_deadline_to_waiting_for_peer():
    with pytest.raises(asyncio.TimeoutError):
        await _exchange_confirmations(FakeConfirmChannel(), b"c" * 32, timeout=0.001)


def test_decoy_linger_is_positive():
    assert DECOY_LINGER > 0
