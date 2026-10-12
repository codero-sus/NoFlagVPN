"""The client's tunnel: one carrier, one handshake, many streams.

Resilience rules
----------------
The tunnel is shared by every connection the local proxy serves, so it must
survive the two things that actually happen in the field: a carrier connection
that dies, and a relay that stops answering.

* Opening a stream that fails because the tunnel died reconnects once and
  retries. The application sees a slow connection, not a broken one.
* Relays are tried in order, with the last one that worked remembered, so a
  failover list costs nothing while the primary is healthy.
* A reconnect is a fresh handshake, which means fresh ephemeral keys — losing
  the carrier does not weaken the session that replaces it.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field

from nfvpn.config import ClientConfig
from nfvpn.core.keys import Identity
from nfvpn.errors import ConfigError, HandshakeError, TransportError
from nfvpn.session.session import Session, establish_initiator
from nfvpn.session.streams import Stream, StreamClosedError
from nfvpn.traffic.shaper import Shaper, get_profile
from nfvpn.transport import Endpoint, client_context, dial

__all__ = ["Tunnel", "TunnelStats"]


@dataclass
class TunnelStats:
    """Counters the local UI can show."""

    connects: int = 0
    failures: int = 0
    reconnects: int = 0
    streams: int = 0
    last_connect: float = 0.0
    active_endpoint: str = ""

    def summary(self) -> str:
        return (
            f"{self.connects} connect(s), {self.reconnects} reconnect(s), "
            f"{self.failures} failure(s), {self.streams} stream(s) opened"
        )


@dataclass
class Tunnel:
    """A resilient client-side tunnel to a relay."""

    config: ClientConfig
    identity: Identity
    psk: bytes
    peer_public_key: bytes

    _session: Session | None = field(default=None, init=False, repr=False)
    _connecting: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    stats: TunnelStats = field(default_factory=TunnelStats, init=False)
    _endpoints: list[Endpoint] = field(default_factory=list, init=False, repr=False)
    _preferred: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        candidates = [self.config.relay, *self.config.failover]
        endpoints = []
        for candidate in candidates:
            if not candidate:
                continue
            endpoints.append(Endpoint.parse(candidate))
        if not endpoints:
            raise ConfigError("no relay configured")
        self._endpoints = endpoints
        self._shaper = Shaper(get_profile(self.config.profile))
        self._tls_context = None
        if any(endpoint.uses_tls for endpoint in endpoints):
            self._tls_context, _ = client_context(
                ca_file=self.config.ca_file, insecure=self.config.insecure_tls
            )

    # -- connection management --------------------------------------------
    @property
    def session(self) -> Session | None:
        if self._session is not None and self._session.closed:
            return None
        return self._session

    @property
    def connected(self) -> bool:
        return self.session is not None

    @property
    def active_endpoint(self) -> str:
        return self._endpoints[self._preferred].url() if self._endpoints else ""

    async def connect(self) -> Session:
        """Dial a relay and complete the handshake, trying each endpoint once."""
        async with self._connecting:
            existing = self.session
            if existing is not None:
                return existing
            if self._session is not None:
                with contextlib.suppress(Exception):
                    await self._session.close()
                self._session = None

            order = list(range(len(self._endpoints)))
            if self._preferred:
                order.remove(self._preferred)
                order.insert(0, self._preferred)

            last_error: BaseException | None = None
            for index in order:
                endpoint = self._endpoints[index]
                try:
                    self._session = await self._establish(endpoint)
                except (TransportError, HandshakeError, OSError, asyncio.TimeoutError) as exc:
                    last_error = exc
                    self.stats.failures += 1
                    continue
                session = self._session
                assert session is not None  # _establish returned one or raised
                self._preferred = index
                self.stats.connects += 1
                self.stats.last_connect = time.time()
                self.stats.active_endpoint = endpoint.url()
                return session

            raise TransportError(
                f"could not reach any relay ({len(self._endpoints)} tried): {last_error}"
            )

    async def _establish(self, endpoint: Endpoint) -> Session:
        transport = await dial(
            endpoint,
            timeout=self.config.connect_timeout,
            tls_context=self._tls_context,
            encoding=self.config.encoding,
        )
        try:
            return await establish_initiator(
                transport,
                self.identity,
                self.peer_public_key,
                self.psk,
                peer_name=self.config.peer_name,
                shaper=self._shaper,
                cover_traffic=self.config.cover_traffic,
                handshake_timeout=self.config.handshake_timeout,
                window=self.config.window,
                max_streams=self.config.max_streams,
            )
        except BaseException:
            await transport.close()
            raise

    async def reconnect(self) -> Session:
        """Drop the current session and build a new one."""
        self.stats.reconnects += 1
        if self._session is not None:
            with contextlib.suppress(Exception):
                await self._session.close()
            self._session = None
        return await self.connect()

    async def close(self) -> None:
        if self._session is not None:
            with contextlib.suppress(Exception):
                await self._session.close()
            self._session = None

    # -- streams -----------------------------------------------------------
    async def open(
        self, host: str, port: int, *, timeout: float = 20.0, retry: bool = True
    ) -> Stream:
        """Open a stream to ``host:port`` through the relay.

        Reconnects once if the tunnel turns out to be dead, which is the only
        failure worth retrying automatically: a refusal from the relay's egress
        policy would be identical the second time.
        """
        session = self.session or await self.connect()
        try:
            stream = await session.streams.open(host, port, timeout=timeout)
        except (TransportError, asyncio.TimeoutError):
            if not retry:
                raise
            session = await self.reconnect()
            stream = await session.streams.open(host, port, timeout=timeout)
        except StreamClosedError:
            raise
        self.stats.streams += 1
        return stream

    async def wait_closed(self) -> None:
        if self._session is not None:
            await self._session.wait_closed()

    def describe(self) -> str:
        if self.session is None:
            return f"disconnected from {self.active_endpoint or 'no relay'}"
        return f"{self.session.describe()}"
