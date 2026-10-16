"""The tunnel's resilience rules: failover order, a single retry, clean teardown.

These are the rules a user's uptime depends on, and they are invisible in the
happy path that ``test_end_to_end.py`` covers: which endpoint is tried first
after a failover, what happens when every relay is down but one of them refuses
you, whether a dead carrier leaks a socket, and which stream failures are worth
retrying automatically.

Dialling is faked, so each of those cases can be produced on demand; the tunnel
logic itself is the real code.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest
from nfvpn.client.tunnel import Tunnel, TunnelStats
from nfvpn.config import ClientConfig
from nfvpn.core.encoding import b64e
from nfvpn.core.keys import Identity
from nfvpn.errors import ConfigError, HandshakeError, TransportError
from nfvpn.framing.constants import CloseReason
from nfvpn.session.streams import StreamClosedError

PSK = b"p" * 32


def client_config(**overrides) -> ClientConfig:
    values: dict = {
        "relay": "ws://first.example:443/healthz",
        "failover": ("ws://second.example:443/healthz",),
        "peer_public_key": b64e(Identity.generate("relay").public_key),
        "psk": b64e(PSK),
        "listen_host": "127.0.0.1",
        "listen_port": 1080,
        "profile": "balanced",
        "log_level": "critical",
    }
    values.update(overrides)
    return ClientConfig(**values)


def make_tunnel(**overrides) -> Tunnel:
    return Tunnel(client_config(**overrides), Identity.generate("client"), PSK, b"k" * 32)


class FakeStreams:
    """Records what was asked for and can be told to fail a given number of times."""

    def __init__(self, failures: int = 0, error: BaseException | None = None) -> None:
        self.failures = failures
        self.error = error or TransportError("carrier died")
        self.calls: list[tuple[str, int]] = []

    async def open(self, host: str, port: int, *, timeout: float = 15.0):
        self.calls.append((host, port))
        if self.failures > 0:
            self.failures -= 1
            raise self.error
        return _Stream()


@dataclass
class _Stream:
    stream_id: int = 1


@dataclass
class FakeSession:
    streams: FakeStreams = field(default_factory=FakeStreams)
    closed: bool = False
    closes: int = 0

    async def close(self) -> None:
        self.closed = True
        self.closes += 1

    async def wait_closed(self) -> None:
        while not self.closed:
            await asyncio.sleep(0.01)

    def describe(self) -> str:
        return "session with a fake carrier"


class FakeTransport:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


@dataclass
class Dialer:
    """Stands in for ``dial`` + ``establish_initiator``, per endpoint."""

    outcomes: dict[str, object] = field(default_factory=dict)
    default: object = "session"
    dialled: list[str] = field(default_factory=list)
    transports: list[FakeTransport] = field(default_factory=list)
    sessions: list[FakeSession] = field(default_factory=list)
    #: Stream failures given to every session this dialer builds, for tests
    #: about what happens when the relay is up but every stream fails.
    stream_failures: int = 0
    stream_error: BaseException | None = None

    async def dial(self, endpoint, **kwargs):
        self.dialled.append(endpoint.url())
        outcome = self.outcomes.get(endpoint.url(), self.default)
        if isinstance(outcome, BaseException):
            raise outcome
        transport = FakeTransport()
        self.transports.append(transport)
        return transport

    async def establish(self, transport, identity, peer_key, psk, **kwargs):
        session = FakeSession(
            streams=FakeStreams(failures=self.stream_failures, error=self.stream_error)
        )
        self.sessions.append(session)
        return session


async def _temporary_attribute(monkeypatch, name, value):
    monkeypatch.setattr(f"nfvpn.client.tunnel.{name}", value)


# --------------------------------------------------------------------------- #
# endpoint selection
# --------------------------------------------------------------------------- #
def test_the_relay_and_its_failover_list_become_ordered_endpoints():
    tunnel = make_tunnel()
    assert [endpoint.url() for endpoint in tunnel._endpoints] == [
        "ws://first.example:443/healthz",
        "ws://second.example:443/healthz",
    ]
    assert tunnel.active_endpoint == "ws://first.example:443/healthz"


def test_a_blanks_in_the_failover_list_are_skipped():
    tunnel = make_tunnel(failover=("", "ws://second.example:443/healthz", ""))
    assert len(tunnel._endpoints) == 2


def test_a_tunnel_with_no_relay_at_all_is_refused():
    with pytest.raises(ConfigError, match="no relay"):
        make_tunnel(relay="", failover=())


def test_a_tls_endpoint_builds_a_context_and_a_plain_one_does_not():
    assert make_tunnel()._tls_context is None
    assert make_tunnel(relay="wss://first.example:443/healthz")._tls_context is not None


def test_a_failover_endpoint_over_tls_needs_the_context_too():
    """Half the list being wss:// is enough to need a TLS context."""
    tunnel = make_tunnel(failover=("wss://backup.example:443/healthz",))
    assert tunnel._tls_context is not None


# --------------------------------------------------------------------------- #
# connect: failover
# --------------------------------------------------------------------------- #
async def test_the_first_endpoint_that_answers_wins(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    session = await tunnel.connect()
    assert isinstance(session, FakeSession)
    assert dialer.dialled == ["ws://first.example:443/healthz"]
    assert tunnel.stats.connects == 1
    assert tunnel.stats.failures == 0
    assert tunnel.active_endpoint == "ws://first.example:443/healthz"
    assert tunnel.connected is True


async def test_a_dead_first_relay_moves_the_tunnel_to_the_second(monkeypatch):
    dialer = Dialer(outcomes={"ws://first.example:443/healthz": OSError("connection refused")})
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    await tunnel.connect()
    assert dialer.dialled == [
        "ws://first.example:443/healthz",
        "ws://second.example:443/healthz",
    ]
    assert tunnel.stats.failures == 1
    assert tunnel.active_endpoint == "ws://second.example:443/healthz", "the working one is shown"


async def test_the_relay_that_worked_is_tried_first_next_time(monkeypatch):
    """Failover must not cost a timeout on every reconnect afterwards."""
    dialer = Dialer(outcomes={"ws://first.example:443/healthz": OSError("down")})
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    await tunnel.connect()
    dialer.dialled.clear()

    await tunnel.reconnect()
    assert dialer.dialled[0] == "ws://second.example:443/healthz", "the preferred relay goes first"


async def test_every_relay_being_unreachable_names_how_many_were_tried(monkeypatch):
    dialer = Dialer(
        outcomes={
            "ws://first.example:443/healthz": OSError("no route to host"),
            "ws://second.example:443/healthz": TimeoutError("timed out"),
        }
    )
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    with pytest.raises(TransportError) as caught:
        await tunnel.connect()
    assert "2 tried" in str(caught.value)
    assert tunnel.stats.failures == 2
    assert tunnel.stats.connects == 0


async def test_a_refusal_outranks_an_unreachable_relay(monkeypatch):
    """One relay saying no is more informative than another saying nothing."""
    dialer = Dialer(
        outcomes={
            "ws://first.example:443/healthz": OSError("no route to host"),
            "ws://second.example:443/healthz": HandshakeError("the pre-shared key is wrong"),
        }
    )
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    with pytest.raises(HandshakeError, match="pre-shared key"):
        await tunnel.connect()


async def test_a_second_connect_is_free(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    first = await tunnel.connect()
    second = await tunnel.connect()
    assert first is second
    assert len(dialer.dialled) == 1, "no second handshake for a healthy tunnel"


async def test_a_closed_session_is_replaced_rather_than_returned(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    session = await tunnel.connect()
    session.closed = True
    assert tunnel.connected is False, "a closed session is not a connection"

    replacement = await tunnel.connect()
    assert replacement is not session
    assert tunnel.connected is True


async def test_a_failed_handshake_does_not_leak_the_carrier(monkeypatch):
    """A carrier that fails the handshake is closed before the next dial."""
    dialer = Dialer(default=FakeTransport())

    async def establish(transport, *args, **kwargs):
        if len(dialer.transports) == 1:
            raise HandshakeError("refused")
        return FakeSession()

    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", establish)

    tunnel = make_tunnel()
    assert await tunnel.connect() is not None, "the second relay carried the tunnel"
    assert dialer.transports[0].closed is True, "the refused carrier was left open"
    assert dialer.transports[1].closed is False, "the live one stays open"


async def test_every_relay_refusing_closes_every_carrier(monkeypatch):
    dialer = Dialer(default=FakeTransport())

    async def establish(transport, *args, **kwargs):
        raise HandshakeError("the pre-shared key is wrong")

    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", establish)

    tunnel = make_tunnel()
    with pytest.raises(HandshakeError):
        await tunnel.connect()
    assert len(dialer.transports) == 2
    assert all(transport.closed for transport in dialer.transports), "no half-open sockets"
    assert tunnel.stats.failures == 2


async def test_reconnect_counts_and_drops_the_old_session(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    old = await tunnel.connect()
    new = await tunnel.reconnect()
    assert tunnel.stats.reconnects == 1
    assert old.closed is True
    assert new is not old
    assert tunnel.stats.connects == 2


async def test_closing_twice_and_waiting_without_a_session_is_fine(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    await tunnel.close()  # nothing to close yet
    await tunnel.wait_closed()
    assert "disconnected" in tunnel.describe()

    session = await tunnel.connect()
    await tunnel.close()
    await tunnel.close()
    assert session.closes == 1, "close is idempotent"
    assert tunnel.session is None
    assert "disconnected" in tunnel.describe()


async def test_describe_reports_the_live_session(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)
    tunnel = make_tunnel()
    await tunnel.connect()
    assert tunnel.describe() == "session with a fake carrier"


# --------------------------------------------------------------------------- #
# open: the single retry
# --------------------------------------------------------------------------- #
async def test_opening_connects_first_if_it_has_to(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    stream = await tunnel.open("example.com", 443)
    assert stream is not None
    assert tunnel.stats.connects == 1
    assert tunnel.stats.streams == 1


async def test_a_stream_on_a_dead_carrier_is_retried_once_after_reconnecting(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    session = await tunnel.connect()
    session.streams = FakeStreams(failures=1)  # the first attempt fails

    stream = await tunnel.open("example.com", 443)
    assert stream is not None
    assert tunnel.stats.reconnects == 1, "the tunnel was rebuilt"
    assert tunnel.stats.streams == 1


async def test_a_second_failure_is_not_retried_forever(monkeypatch):
    """The relay is reachable but cannot open streams: one retry, then tell the caller."""
    dialer = Dialer(stream_failures=99)
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    await tunnel.connect()
    with pytest.raises(TransportError):
        await tunnel.open("example.com", 443)
    assert tunnel.stats.reconnects == 1, "exactly one retry, as documented"
    assert tunnel.stats.streams == 0, "a failed open is not a stream"
    assert len(dialer.sessions) == 2, "the retry really did reconnect"
    assert len(dialer.sessions[1].streams.calls) == 1, "and tried exactly once"


async def test_a_refusal_from_the_relay_is_not_retried(monkeypatch):
    """It would be identical the second time: a policy does not change."""
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    session = await tunnel.connect()
    session.streams = FakeStreams(failures=9, error=StreamClosedError(CloseReason.DENIED))

    with pytest.raises(StreamClosedError) as caught:
        await tunnel.open("blocked.example", 25)
    assert caught.value.reason is CloseReason.DENIED
    assert tunnel.stats.reconnects == 0
    assert session.streams.calls == [("blocked.example", 25)], "asked exactly once"


async def test_retry_can_be_turned_off(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    session = await tunnel.connect()
    session.streams = FakeStreams(failures=1)
    with pytest.raises(TransportError):
        await tunnel.open("example.com", 443, retry=False)
    assert tunnel.stats.reconnects == 0


async def test_an_open_timeout_is_retried_like_a_broken_carrier(monkeypatch):
    dialer = Dialer()
    monkeypatch.setattr("nfvpn.client.tunnel.dial", dialer.dial)
    monkeypatch.setattr("nfvpn.client.tunnel.establish_initiator", dialer.establish)

    tunnel = make_tunnel()
    session = await tunnel.connect()
    session.streams = FakeStreams(failures=1, error=TimeoutError("the relay never answered"))
    assert await tunnel.open("example.com", 443) is not None
    assert tunnel.stats.reconnects == 1


async def test_the_stats_summary_reads_like_a_status_line():
    tunnel = make_tunnel()
    tunnel.stats.connects = 2
    tunnel.stats.reconnects = 1
    tunnel.stats.failures = 3
    tunnel.stats.streams = 17
    summary = tunnel.stats.summary()
    assert "2 connect(s)" in summary
    assert "17 stream(s)" in summary
    assert TunnelStats().summary().startswith("0 connect(s)")
