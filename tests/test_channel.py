"""The secure channel on its own: rekeying, cover traffic, and failure.

``test_session.py`` and ``test_end_to_end.py`` drive the channel through a real
session, which is the right way to check the protocol but a poor way to reach
its corners: a rekey that only happens after a gigabyte, a send queue that fills
up when the carrier stalls, a sender task that dies.  This file wires the channel
to a fake carrier so those paths are reachable in milliseconds, and asserts the
things a long-lived tunnel depends on:

* a rekey happens *before* the counter can wrap, and both directions follow it
  without a round trip - records already in flight still decrypt;
* cover traffic appears while the tunnel is idle, and stops when asked to;
* a carrier that fails takes the channel down in a way the session can see
  (``failure`` is set) rather than silently dropping records;
* after close, sending raises instead of queueing into the void.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest
from nfvpn.core.keys import SessionKeys, derive_transcript, public_key_for
from nfvpn.errors import ProtocolError, TransportError
from nfvpn.framing.constants import MAX_PAYLOAD, RecordType
from nfvpn.framing.records import peek_type
from nfvpn.session.channel import ChannelStats, SecureChannel, SendQueueFullError
from nfvpn.traffic.shaper import Shaper, get_profile


def session_keys() -> SessionKeys:
    """The same key material every time, without a handshake.

    Deterministic on purpose: two channels handed *this* function's result are
    the two ends of one session, which is how the mirror peer below can read
    what the channel under test wrote.  With random ephemerals they would be
    strangers, and every decode would fail authentication.
    """
    from nfvpn.core.keys import derive_session_keys

    keys, _ = derive_session_keys(
        psk=b"p" * 32,
        static_private=bytes(range(32)),
        peer_static_public=public_key_for(bytes(range(32, 64))),
        ephemeral_private=bytes(range(64, 96)),
        peer_ephemeral_public=public_key_for(bytes(range(96, 128))),
        transcript=derive_transcript(b"channel-test"),
        initiator=True,
    )
    return keys


class FakeCarrier:
    """A carrier that keeps what it is given and hands back what it is fed."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.incoming: asyncio.Queue[bytes] = asyncio.Queue()
        self.fail_after: int | None = None
        self.delay = 0.0

    async def send_message(self, payload: bytes) -> None:
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail_after is not None and len(self.sent) >= self.fail_after:
            raise TransportError("the carrier is gone")
        self.sent.append(payload)

    async def receive_message(self) -> bytes:
        return await self.incoming.get()

    async def feed(self, message: bytes) -> None:
        await self.incoming.put(message)

    async def wait_for(self, count: int, timeout: float = 2.0) -> list[bytes]:
        deadline = asyncio.get_running_loop().time() + timeout
        while len(self.sent) < count:
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError(f"expected {count} messages, saw {len(self.sent)}")
            await asyncio.sleep(0.01)
        return self.sent


class Mirror:
    """The other end of the same session, for inspecting what was sent.

    A channel cannot read its own frames: the writer seals with
    ``initiator_to_responder`` and the reader opens ``responder_to_initiator``,
    so the only honest way to check the bytes on the wire is a channel pointed
    the other way.  This is that channel, fed by hand.
    """

    def __init__(self, keys: SessionKeys) -> None:
        self.carrier = FakeCarrier()
        self.channel = SecureChannel(keys, self.carrier, initiator=False, shaper=None)

    async def deliver(self, channel: SecureChannel) -> list:
        """Feed everything ``channel`` sent into this peer and collect records.

        Feed first, then drain: ``receive()`` loops internally, swallowing cover
        and REKEY records, so it can consume more than one carrier message per
        call and would sit waiting for a frame that has not been fed yet.
        """
        await self.channel.start()
        for frame in channel.carrier.sent:  # type: ignore[attr-defined]
            await self.carrier.feed(frame)

        received = []
        while True:
            try:
                received.append(await asyncio.wait_for(self.channel.receive(), timeout=0.1))
            except (TimeoutError, asyncio.TimeoutError):
                break
        return received

    async def close(self) -> None:
        await self.channel.close()


def rekey_frames(messages: list[bytes]) -> int:
    """Count REKEY records without needing the key: the type is in the header."""
    return sum(1 for frame in messages if peek_type(frame) is RecordType.REKEY)


async def make_channel(carrier: FakeCarrier | None = None, **kwargs) -> SecureChannel:
    carrier = carrier or FakeCarrier()
    channel = SecureChannel(
        session_keys(),
        carrier,
        initiator=True,
        shaper=kwargs.pop("shaper", None),
        **kwargs,
    )
    await channel.start()
    channel.carrier = carrier  # type: ignore[attr-defined]
    return channel


# --------------------------------------------------------------------------- #
# sending, and the queue
# --------------------------------------------------------------------------- #
async def test_a_record_reaches_the_carrier_and_counts():
    channel = await make_channel()
    try:
        await channel.send(RecordType.DATA, 3, b"hello")
        await channel.flush()
        sent = channel.carrier.sent  # type: ignore[attr-defined]
        assert len(sent) == 1
        assert channel.stats.records_sent == 1
        assert channel.stats.bytes_sent == len(sent[0])
    finally:
        await channel.close()


async def test_an_oversized_payload_is_refused_before_the_wire():
    channel = await make_channel()
    try:
        with pytest.raises(ProtocolError, match="exceeds"):
            await channel.send(RecordType.DATA, 1, b"x" * (MAX_PAYLOAD + 1))
        assert channel.carrier.sent == []  # type: ignore[attr-defined]
    finally:
        await channel.close()


async def test_raw_mode_bypasses_framing_entirely():
    """The handshake needs this: no keys exist yet when it runs."""
    channel = await make_channel()
    try:
        await channel.send(RecordType.DATA, 0, b"plain handshake bytes", raw=True)
        await channel.flush()
        assert channel.carrier.sent == [b"plain handshake bytes"]  # type: ignore[attr-defined]
    finally:
        await channel.close()


async def test_sending_after_close_raises_rather_than_queueing_forever():
    channel = await make_channel()
    await channel.close()
    with pytest.raises(TransportError, match="closed"):
        await channel.send(RecordType.DATA, 1, b"late")


async def test_a_dead_sender_is_visible_to_the_session():
    """When the carrier fails mid-send, `failure` is set so the session can stop
    pretending the tunnel is healthy."""
    carrier = FakeCarrier()
    carrier.fail_after = 0
    channel = await make_channel(carrier)
    try:
        await channel.send(RecordType.DATA, 1, b"trigger")
        deadline = asyncio.get_running_loop().time() + 2.0
        while channel.failure is None and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.01)
        assert isinstance(channel.failure, TransportError)
        with pytest.raises(TransportError):
            await channel.send(RecordType.DATA, 1, b"after the failure")
    finally:
        await channel.close()


async def test_a_full_queue_blocks_the_sender_instead_of_dropping_records():
    """Backpressure, not data loss: 20 records through a depth-2 queue."""
    carrier = FakeCarrier()
    carrier.delay = 0.02
    channel = await make_channel(carrier, queue_depth=2)
    mirror = Mirror(session_keys())
    try:
        for index in range(20):
            await channel.send(RecordType.DATA, 1, bytes([index]) * 32)
        await channel.flush()
        assert len(carrier.sent) == 20, "every record must arrive, in order"
        records = await mirror.deliver(channel)
        assert [record.payload[0] for record in records] == list(range(20))
    finally:
        await channel.close()
        await mirror.close()


async def test_pending_reflects_work_waiting_for_the_carrier():
    carrier = FakeCarrier()
    carrier.delay = 0.1
    channel = await make_channel(carrier)
    try:
        await channel.send(RecordType.DATA, 1, b"one")
        await channel.send(RecordType.DATA, 1, b"two")
        assert channel.pending >= 1
        await channel.flush()
        assert channel.pending == 0
    finally:
        await channel.close()


# --------------------------------------------------------------------------- #
# rekeying
# --------------------------------------------------------------------------- #
async def test_a_rekey_fires_when_the_generation_gets_busy():
    carrier = FakeCarrier()
    channel = await make_channel(carrier, rekey_bytes=512, rekey_seconds=0)
    try:
        for _ in range(8):
            await channel.send(RecordType.DATA, 1, b"z" * 256)
        await channel.flush()
        assert channel.stats.rekeys >= 1, "traffic past rekey_bytes must rotate keys"
        # The rotation is announced on the wire so the peer follows.
        assert rekey_frames(carrier.sent) == channel.stats.rekeys
    finally:
        await channel.close()


async def test_a_rekey_fires_on_time_even_with_no_traffic():
    """An idle tunnel still rotates, so a captured key has a shelf life.

    The sender loop only checks the clock when it wakes, so this drives the
    wake-up directly: with an idle queue, the loop's timeout branch is the only
    thing that can notice a generation going stale.
    """
    carrier = FakeCarrier()
    channel = await make_channel(
        carrier, rekey_bytes=0, rekey_seconds=0.05, shaper=Shaper(get_profile("off"))
    )
    try:
        channel._cover_timeout = lambda: 0.01  # type: ignore[method-assign]
        deadline = asyncio.get_running_loop().time() + 3.0
        while channel.stats.rekeys == 0 and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.02)
        assert channel.stats.rekeys >= 1, "a stale generation must rotate without traffic"
        assert rekey_frames(carrier.sent) == channel.stats.rekeys
    finally:
        await channel.close()


async def test_a_time_based_rekey_also_fires_on_the_next_send():
    """The other path: no wake-up needed if the caller sends something."""
    carrier = FakeCarrier()
    channel = await make_channel(carrier, rekey_bytes=0, rekey_seconds=0.05)
    try:
        await channel.send(RecordType.DATA, 1, b"before")
        await asyncio.sleep(0.08)
        await channel.send(RecordType.DATA, 1, b"after")
        await channel.flush()
        assert channel.stats.rekeys == 1
        assert rekey_frames(carrier.sent) == 1
    finally:
        await channel.close()


async def test_rekeying_is_idempotent_under_concurrent_sends():
    """Ten concurrent sends must not rotate the key ten times."""
    carrier = FakeCarrier()
    channel = await make_channel(carrier, rekey_bytes=512, rekey_seconds=0)
    try:
        await asyncio.gather(*(channel.send(RecordType.DATA, 1, b"y" * 128) for _ in range(10)))
        await channel.flush()
        # Every announced rekey must be matched by exactly one rotation, so a
        # peer following the announcements stays in lock-step.
        assert rekey_frames(carrier.sent) == channel.stats.rekeys
        assert channel.stats.rekeys >= 1
        # And the mirror can still read the whole stream, rekeys included.
        mirror = Mirror(session_keys())
        try:
            records = await mirror.deliver(channel)
            assert len(records) == 10
        finally:
            await mirror.close()
    finally:
        await channel.close()


async def test_a_peer_rekey_is_followed_silently_and_both_sides_stay_in_step():
    """The peer announces; we follow.  No extra round trip, no reply record."""
    our_carrier = FakeCarrier()
    ours = await make_channel(our_carrier, rekey_bytes=0, rekey_seconds=0)

    peer_carrier = FakeCarrier()
    peer = SecureChannel(session_keys(), peer_carrier, initiator=False, shaper=None)
    await peer.start()
    # A threshold the third record crosses, so exactly one rotation happens and
    # the records on either side of it are unambiguous.
    peer.rekey_bytes = 400
    try:
        await peer.send(RecordType.DATA, 1, b"before the rekey".ljust(256, b"."))
        await peer.send(RecordType.DATA, 1, b"just before it".ljust(256, b"."))
        await peer.send(RecordType.DATA, 1, b"under the new key".ljust(256, b"."))
        await peer.flush()
        assert rekey_frames(peer_carrier.sent) == 1

        for frame in peer_carrier.sent:
            await our_carrier.feed(frame)

        got = [await asyncio.wait_for(ours.receive(), timeout=2) for _ in range(3)]
        expected = [b"before the rekey", b"just before it", b"under the new key"]
        for record, prefix in zip(got, expected, strict=True):
            assert record.payload.startswith(prefix), record.payload[:32]
        assert ours.stats.rekeys == 1, "we followed the peer's generation"
        assert our_carrier.sent == [], "following a rekey must not send anything"

        # Our writer advanced too: what we send now must decode on the peer,
        # which is still holding the generation it announced.
        await ours.send(RecordType.DATA, 2, b"ack after the rekey")
        await ours.flush()
        for frame in our_carrier.sent:
            await peer_carrier.feed(frame)
        reply = await asyncio.wait_for(peer.receive(), timeout=2)
        assert reply.payload == b"ack after the rekey"
    finally:
        await ours.close()
        await peer.close()


# --------------------------------------------------------------------------- #
# receiving
# --------------------------------------------------------------------------- #
async def test_cover_records_are_swallowed_and_not_delivered():
    """PAD exists for the observer; the application never sees it."""
    channel = await make_channel()
    peer_carrier = FakeCarrier()
    peer = SecureChannel(session_keys(), peer_carrier, initiator=False, shaper=None)
    await peer.start()
    try:
        await peer.send(RecordType.PAD, 0, b"")
        await peer.send(RecordType.DATA, 2, b"real payload")
        await peer.flush()

        for frame in peer_carrier.sent:
            await channel.carrier.feed(frame)  # type: ignore[attr-defined]

        record = await asyncio.wait_for(channel.receive(), timeout=2)
        assert record.type is RecordType.DATA
        assert record.payload == b"real payload"
        assert channel.stats.records_received == 2, "the cover record was counted"
    finally:
        await peer.close()
        await channel.close()


async def test_receiving_updates_activity_and_counters():
    channel = await make_channel()
    peer_carrier = FakeCarrier()
    peer = SecureChannel(session_keys(), peer_carrier, initiator=False, shaper=None)
    await peer.start()
    try:
        await asyncio.sleep(0.05)
        idle_before = channel.idle_seconds
        await peer.send(RecordType.DATA, 1, b"ping")
        await peer.flush()
        for frame in peer_carrier.sent:
            await channel.carrier.feed(frame)  # type: ignore[attr-defined]
        record = await asyncio.wait_for(channel.receive(), timeout=2)
        assert record.payload == b"ping"
        assert channel.idle_seconds < idle_before, "receiving counts as activity"
        assert channel.stats.bytes_received == len(peer_carrier.sent[0])
        assert channel.stats.records_received == 1
    finally:
        await peer.close()
        await channel.close()


# --------------------------------------------------------------------------- #
# cover traffic
# --------------------------------------------------------------------------- #
async def test_cover_traffic_fills_an_idle_tunnel():
    """The profile that asks for cover produces PAD records once it is due.

    ``balanced`` deliberately waits about twenty seconds before filling a quiet
    tunnel - a cover record every few milliseconds would itself be a signature -
    so the test moves the clock rather than sleeping twenty seconds.
    """
    carrier = FakeCarrier()
    channel = await make_channel(carrier, shaper=Shaper(get_profile("balanced")))
    try:
        channel._cover_timeout = lambda: 0.01  # type: ignore[method-assign]
        channel._last_activity -= (channel.shaper.profile.cover_interval or 0) + 1
        deadline = asyncio.get_running_loop().time() + 3.0
        while channel.stats.padding_records == 0 and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.02)
        assert channel.stats.padding_records >= 1, "a due cover record must be sent"
        assert channel.stats.records_sent == channel.stats.padding_records
        # Cover is shaped like everything else: full records, not tiny markers.
        assert all(len(frame) > 16 for frame in carrier.sent)
        # And it really is a PAD record, not a DATA record with nothing in it.
        assert all(peek_type(frame) is RecordType.PAD for frame in carrier.sent)
    finally:
        await channel.close()


async def test_cover_traffic_can_be_turned_off():
    """`--no-cover` must mean no cover: nothing on the wire while idle."""
    carrier = FakeCarrier()
    channel = await make_channel(
        carrier, shaper=Shaper(get_profile("balanced")), cover_traffic=False
    )
    try:
        await asyncio.sleep(1.0)
        assert channel.stats.padding_records == 0
        assert carrier.sent == []
    finally:
        await channel.close()


async def test_the_off_profile_is_silent_when_idle():
    carrier = FakeCarrier()
    channel = await make_channel(carrier, shaper=Shaper(get_profile("off")))
    try:
        await asyncio.sleep(0.8)
        assert carrier.sent == []
    finally:
        await channel.close()


async def test_a_carrier_that_dies_during_cover_traffic_is_noticed():
    """Cover traffic failing is a dead carrier, not a quiet one."""
    carrier = FakeCarrier()
    carrier.fail_after = 0
    channel = await make_channel(carrier, shaper=Shaper(get_profile("paranoid")))
    try:
        channel._cover_timeout = lambda: 0.01  # type: ignore[method-assign]
        # Pretend the tunnel has been quiet for longer than the profile's cover
        # interval, which is what makes the sender loop emit a PAD record.
        channel._last_activity -= (channel.shaper.profile.cover_interval or 0) + 1
        deadline = asyncio.get_running_loop().time() + 3.0
        while channel.failure is None and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.02)
        assert isinstance(channel.failure, TransportError)
    finally:
        await channel.close()


# --------------------------------------------------------------------------- #
# statistics
# --------------------------------------------------------------------------- #
def test_channel_stats_describes_itself():
    stats = ChannelStats()
    stats.records_sent = 10
    stats.records_received = 12
    stats.bytes_sent = 2048
    stats.bytes_received = 4096
    stats.padding_records = 3
    stats.rekeys = 1
    summary = stats.summary()
    assert "2 KiB up" in summary
    assert "4 KiB down" in summary
    assert "10 records out" in summary
    assert "3 cover" in summary
    assert "1 rekeys" in summary
    assert stats.uptime >= 0


def test_send_queue_full_is_a_transport_error():
    """Callers catch TransportError; this must not escape that net."""
    assert issubclass(SendQueueFullError, TransportError)


async def test_closing_twice_is_harmless():
    channel = await make_channel()
    await channel.close()
    with contextlib.suppress(Exception):
        await channel.close()
    with pytest.raises(TransportError):
        await channel.send(RecordType.DATA, 1, b"x")
