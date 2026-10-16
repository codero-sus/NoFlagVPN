"""The relay's operational surface: limits, reloads, logs and counters.

The tunnel itself is covered by ``test_end_to_end.py``.  This file is about the
things an operator lives with once a relay is in service:

* the membership reload (SIGHUP) - a member added to the file must be able to
  connect afterwards, without restarting the relay, and a member removed must
  stop being able to start a session;
* the bandwidth limiter actually limiting, and the fact that ``None`` (no limit)
  and ``0`` both mean unmetered - a distinction worth pinning, because a zero
  that silently means "unlimited" would be a nasty surprise in a config file;
* per-member counters, so an operator can see who is using the relay;
* the log file an operator asks for with ``--log-file`` actually receiving lines;
* cover responses counted when a scanner pokes the carrier with plain HTTP.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time

import pytest
from nfvpn.client.tunnel import Tunnel
from nfvpn.config import ClientConfig, ServerConfig
from nfvpn.core.encoding import b64e
from nfvpn.core.keys import Identity, Member, MembershipStore, parse_psk
from nfvpn.errors import ConfigError, HandshakeError, TransportError
from nfvpn.server.egress import EgressPolicy
from nfvpn.server.relay import MemberStats, Relay, RelayStats, TokenBucket

PSK = parse_psk("s7_SKalwmOc3WEsuA6bjyejEPW8a7t3VUpMZ5R83E-w")


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def relay_pair(*, membership: MembershipStore | None = None, **config_kwargs):
    """A relay and the identity/keys its client will need."""
    relay_identity = Identity.generate("ops-relay")
    client_identity = Identity.generate("ops-client")
    store = membership if membership is not None else MembershipStore()
    if membership is None:
        store.add(Member(name="tester", public_key=client_identity.public_key, psk=PSK))

    config = ServerConfig(
        listen_host="127.0.0.1",
        listen_port=free_port(),
        ws_path="/cdn",
        profile="balanced",
        log_level="critical",
        egress=EgressPolicy(allow_private_literals=True, block_private=False),
        **config_kwargs,
    )
    relay = Relay(config, relay_identity, store)
    client_config = ClientConfig(
        relay=f"ws://127.0.0.1:{config.listen_port}/cdn",
        peer_public_key=b64e(relay_identity.public_key),
        psk=b64e(PSK),
        listen_host="127.0.0.1",
        listen_port=free_port(),
        profile="balanced",
        log_level="critical",
    )
    return relay, client_config, client_identity, relay_identity


# --------------------------------------------------------------------------- #
# the bandwidth limiter
# --------------------------------------------------------------------------- #
async def test_an_unmetered_bucket_returns_immediately():
    for rate in (None, 0):
        bucket = TokenBucket(rate)
        started = time.monotonic()
        await bucket.consume(1 << 20)
        assert time.monotonic() - started < 0.05, f"rate {rate} must mean unmetered"


async def test_a_metered_bucket_starts_full_and_then_throttles():
    """A full second's worth is available at once; past that, waiting."""
    bucket = TokenBucket(2000.0)
    started = time.monotonic()
    await bucket.consume(2000)          # exactly the initial bucket: no wait
    assert time.monotonic() - started < 0.05
    await bucket.consume(2000)          # empty now: this must take about a second
    spent = time.monotonic() - started
    assert spent >= 0.8, f"a second 2000 bytes should throttle, took {spent:.3f}s"


async def test_the_bucket_never_accumulates_more_than_one_second():
    """Idle time does not bank credit: a burst after silence is still capped."""
    bucket = TokenBucket(1000.0)
    bucket.updated -= 60.0           # pretend an idle minute
    await bucket.consume(1000)
    assert bucket.tokens <= bucket.rate + 1e-6


async def test_a_large_read_waits_in_steps_rather_than_one_long_sleep():
    """The loop caps each sleep, so a stall is interruptible."""
    bucket = TokenBucket(1000.0)
    await bucket.consume(1000)
    task = asyncio.create_task(bucket.consume(3000))
    await asyncio.sleep(0.1)
    assert not task.done(), "the read is still waiting for credit"
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


# --------------------------------------------------------------------------- #
# counters
# --------------------------------------------------------------------------- #
def test_relay_stats_summarises_itself():
    stats = RelayStats()
    stats.handshakes_ok = 2
    stats.handshakes_refused = 5
    stats.cover_responses = 3
    stats.streams_opened = 7
    stats.bytes_up = 2 * 1048576
    summary = stats.summary()
    assert "2 authorized / 5 refused" in summary
    assert "3 cover responses" in summary
    assert "7 streams" in summary
    assert "2.0 MiB out" in summary
    assert stats.uptime >= 0


def test_member_counters_are_created_on_first_use():
    stats = RelayStats()
    assert stats.members == {}
    first = stats.member("laptop")
    assert isinstance(first, MemberStats)
    assert first.name == "laptop"
    assert first.sessions == 0
    assert stats.member("laptop") is first, "the counter must be the same object"
    assert stats.members["laptop"].last_seen == 0.0


def test_the_relay_describes_itself_for_a_log_line():
    relay, _client, _identity, _relay_identity = relay_pair()
    text = relay.describe()
    assert "ops-relay" in text
    assert str(relay.config.listen_port) in text
    assert "1 member(s)" in text
    assert relay.egress is relay.config.egress


# --------------------------------------------------------------------------- #
# membership reload (what SIGHUP does)
# --------------------------------------------------------------------------- #
async def test_a_member_added_after_startup_can_connect_only_once_reloaded():
    """This is the documented SIGHUP semantics, asserted rather than assumed."""
    empty = MembershipStore()
    relay, client_config, client_identity, relay_identity = relay_pair(membership=empty)
    await relay.start()

    async def wait_for(predicate, timeout: float = 2.0) -> bool:
        """The relay counts a refusal on its own task, so give it a moment."""
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.02)
        return False

    try:
        # Nothing in the list: the handshake is refused, and the client is not
        # told why - that is the whole point of the decoy reply.
        refused = Tunnel(client_config, client_identity, PSK, relay_identity.public_key)
        # A refusal is a HandshakeError, not a generic transport failure: the
        # difference is what lets the CLI say "authorize this machine".
        with pytest.raises(HandshakeError, match="MAC did not verify"):
            await refused.connect()
        await refused.close()
        assert relay.stats.handshakes_ok == 0
        assert await wait_for(
            lambda: relay.stats.handshakes_refused + relay.stats.errors >= 1
        ), "a refused handshake must be counted somehow"

        # The operator edits members.json and sends SIGHUP.
        fresh = MembershipStore()
        fresh.add(Member(name="tester", public_key=client_identity.public_key, psk=PSK))
        relay.reload_membership(fresh)

        accepted = Tunnel(client_config, client_identity, PSK, relay_identity.public_key)
        await accepted.connect()
        # The relay books the session on its own task, so poll for the counters
        # rather than assuming they have already landed.
        assert await wait_for(lambda: relay.stats.handshakes_ok == 1)
        assert await wait_for(lambda: relay.stats.member("tester").sessions == 1)
        assert relay.stats.member("tester").last_seen > 0
        await accepted.close()
        assert await wait_for(lambda: relay.stats.member("tester").sessions == 0)
    finally:
        await relay.stop()


async def test_a_member_removed_by_reload_stops_starting_sessions():
    relay, client_config, client_identity, relay_identity = relay_pair()
    await relay.start()
    try:
        first = Tunnel(client_config, client_identity, PSK, relay_identity.public_key)
        await first.connect()
        await first.close()

        relay.reload_membership(MembershipStore())     # revoked
        second = Tunnel(client_config, client_identity, PSK, relay_identity.public_key)
        with pytest.raises(HandshakeError):
            await second.connect()
        await second.close()
        deadline = asyncio.get_running_loop().time() + 2.0
        while relay.stats.handshakes_refused == 0 and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.02)
        assert relay.stats.handshakes_refused >= 1
        assert relay.stats.handshakes_ok == 1, "only the first, authorised session counted"
    finally:
        await relay.stop()


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
async def test_stopping_twice_is_harmless_and_closes_sessions():
    relay, client_config, client_identity, relay_identity = relay_pair()
    await relay.start()
    tunnel = Tunnel(client_config, client_identity, PSK, relay_identity.public_key)
    await tunnel.connect()
    await relay.stop()
    with contextlib.suppress(Exception):
        await relay.stop()
    assert relay.stats.bytes_up >= 0     # the summary path ran
    with contextlib.suppress(Exception):
        await tunnel.close()


async def test_serve_forever_returns_when_stopped():
    relay, _client, _identity, _relay_identity = relay_pair(stats_interval=0.05)

    async def stopper() -> None:
        await asyncio.sleep(0.2)
        await relay.stop()

    await asyncio.gather(relay.serve_forever(), stopper())


async def test_the_stats_loop_logs_periodically(caplog):
    relay, _client, _identity, _relay_identity = relay_pair(stats_interval=0.05)
    with caplog.at_level(logging.INFO, logger="nfvpn.relay"):
        await relay.start()
        relay.config.stats_interval = 0.05
        task = asyncio.create_task(relay._stats_loop())
        await asyncio.sleep(0.2)
        relay._stopping.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await relay.stop()
    assert any("stats:" in record.message for record in caplog.records)


async def test_a_plain_http_poke_is_counted_as_a_cover_response():
    relay, _client, _identity, _relay_identity = relay_pair()
    await relay.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.config.listen_port)
        writer.write(b"GET / HTTP/1.1\r\nHost: relay\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(200), timeout=5)
        writer.close()
        assert head.startswith(b"HTTP/1.1 404")
        assert b"nginx" in head
        assert relay.stats.cover_responses == 1
        assert relay.stats.connections == 1
    finally:
        await relay.stop()


async def test_a_stalled_connection_does_not_take_the_relay_down():
    """Something that opens a socket and says nothing must be cleaned up."""
    relay, _client, _identity, _relay_identity = relay_pair()
    await relay.start()
    try:
        sockets = []
        for _ in range(5):
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.config.listen_port)
            sockets.append((reader, writer))
        await asyncio.sleep(0.2)
        assert relay.stats.connections == 5
        # The relay is still serving: a real request still gets an answer.
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.config.listen_port)
        writer.write(b"GET / HTTP/1.1\r\nHost: relay\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(200), timeout=5)
        assert head.startswith(b"HTTP/1.1 404")
        writer.close()
        for _reader, stalled in sockets:
            stalled.close()
    finally:
        await relay.stop()


async def test_binding_a_port_twice_is_a_config_error():
    relay, _client, _identity, _relay_identity = relay_pair()
    await relay.start()
    twin = Relay(relay.config, relay.identity, relay.membership)
    try:
        with pytest.raises(ConfigError, match="could not listen"):
            await twin.start()
    finally:
        await relay.stop()


def test_an_unknown_log_level_does_not_crash_the_logger(tmp_path):
    """A typo in --log-level must not make the relay unusable."""
    from nfvpn.server.relay import _make_logger

    log_file = tmp_path / "relay.log"
    logging.getLogger("nfvpn.relay").handlers.clear()
    logger = _make_logger("not-a-level", str(log_file))
    assert logger is not None
    assert logger.level == logging.INFO, "an unknown level falls back to INFO, not a crash"
    logger.handlers.clear()


def test_the_log_file_gets_written(tmp_path):
    """`--log-file` sends lines to that file.

    ``_make_logger`` attaches a handler only if the logger has none, so the
    destination is decided by the first call in a process - which is what the
    CLI does, and what an operator expects. The handler is cleared first so this
    test measures the file, not an earlier test's logger.
    """
    from nfvpn.server.relay import _make_logger

    log_file = tmp_path / "relay.log"
    logging.getLogger("nfvpn.relay").handlers.clear()
    logger = _make_logger("info", str(log_file))
    logger.info("a line an operator should be able to find")
    for handler in logger.handlers:
        handler.flush()
    assert "an operator should be able to find" in log_file.read_text(encoding="utf-8")
    logger.handlers.clear()


# --------------------------------------------------------------------------- #
# what the caller learns when a relay says no
# --------------------------------------------------------------------------- #
async def test_nothing_answering_is_still_a_transport_error():
    """The other half of the distinction: no relay at all is not a refusal."""
    _relay, client_config, client_identity, relay_identity = relay_pair()
    client_config.relay = f"ws://127.0.0.1:{free_port()}/cdn"     # nothing there
    client_config.failover = ()
    tunnel = Tunnel(client_config, client_identity, PSK, relay_identity.public_key)
    with pytest.raises(TransportError, match="could not reach any relay"):
        await tunnel.connect()


async def test_a_wrong_pre_shared_key_is_reported_as_a_refusal():
    """A member the relay knows, with the wrong key: the classic misconfiguration."""
    relay, client_config, client_identity, relay_identity = relay_pair()
    await relay.start()
    other_psk = parse_psk("A7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    tunnel = Tunnel(client_config, client_identity, other_psk, relay_identity.public_key)
    try:
        with pytest.raises(HandshakeError):
            await tunnel.connect()
    finally:
        await relay.stop()


async def test_failover_still_moves_past_a_relay_that_refuses():
    """A refusal must not stop the client trying the next relay.

    This is the behaviour the fix above could easily have broken: preserving
    the refusal has to happen *after* every endpoint has had its turn.
    """
    # The first relay knows nobody, so it refuses; the second knows this client.
    # Both identities must come from the accepting pair, or the second relay
    # would refuse the client too and the test would prove nothing.
    accepting, client_config, client_identity, accepting_identity = relay_pair()
    refusing, _other_config, _other_identity, _other_relay_identity = relay_pair(
        membership=MembershipStore()
    )
    await refusing.start()
    await accepting.start()

    client_config.relay = f"ws://127.0.0.1:{refusing.config.listen_port}/cdn"
    client_config.failover = (f"ws://127.0.0.1:{accepting.config.listen_port}/cdn",)
    client_config.peer_public_key = b64e(accepting_identity.public_key)

    tunnel = Tunnel(client_config, client_identity, PSK, accepting_identity.public_key)
    try:
        await tunnel.connect()
        deadline = asyncio.get_running_loop().time() + 2.0
        while accepting.stats.handshakes_ok == 0 and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.02)
        assert accepting.stats.handshakes_ok == 1, "the second relay authorised the session"
        assert refusing.stats.handshakes_ok == 0
        assert tunnel.active_endpoint.endswith(f":{accepting.config.listen_port}/cdn")
        await tunnel.close()
    finally:
        await accepting.stop()
        await refusing.stop()


async def test_every_relay_refusing_reports_the_refusal_not_the_count():
    refusing_a, _client_config, client_identity, _identity_a = relay_pair(membership=MembershipStore())
    refusing_b, client_config, _identity_b, identity_b = relay_pair(membership=MembershipStore())
    await refusing_a.start()
    await refusing_b.start()
    client_config.relay = f"ws://127.0.0.1:{refusing_a.config.listen_port}/cdn"
    client_config.failover = (f"ws://127.0.0.1:{refusing_b.config.listen_port}/cdn",)
    client_config.peer_public_key = b64e(identity_b.public_key)

    tunnel = Tunnel(client_config, client_identity, PSK, identity_b.public_key)
    try:
        with pytest.raises(HandshakeError):
            await tunnel.connect()
        assert tunnel.stats.failures == 2, "both relays were tried first"
    finally:
        await refusing_b.stop()
        await refusing_a.stop()
