"""The relay daemon.

One process, one listening port, and four jobs:

1. accept carrier connections and look like whatever the carrier looks like
   (WebSocket over TLS, with a real 404 for anything that is not an upgrade),
2. authenticate the peer and, if that fails, behave exactly like a relay that
   did not (see :mod:`nfvpn.session.session`),
3. dial the destinations an authenticated peer asks for, subject to
   :mod:`nfvpn.server.egress`,
4. move bytes and keep honest counters.

There is no remote administration interface, no status endpoint and no version
string anywhere a prober can reach.  Management happens by editing files on the
host and reloading the process.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field

from nfvpn.config import ServerConfig
from nfvpn.core.keys import Identity, MembershipStore
from nfvpn.errors import ConfigError, NoFlagVPNError, TransportError
from nfvpn.framing.constants import CloseReason
from nfvpn.server.egress import Decision, EgressPolicy
from nfvpn.session.handshake import SeenNonceCache
from nfvpn.session.session import DEFAULT_IDLE_TIMEOUT, Session, establish_responder
from nfvpn.session.streams import OpenRequest, Stream
from nfvpn.traffic.shaper import Shaper, get_profile
from nfvpn.transport import accept_transport, server_context

__all__ = ["MemberStats", "Relay", "RelayStats"]

#: Read chunk size for the relay-side half of a proxied connection.
_PUMP_CHUNK = 64 * 1024


@dataclass
class MemberStats:
    """Per-member counters, shown by ``nfvpn status`` on the relay host."""

    name: str
    sessions: int = 0
    streams: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    refused: int = 0
    last_seen: float = 0.0


@dataclass
class RelayStats:
    """Everything the relay has seen since it started."""

    started_at: float = field(default_factory=time.time)
    connections: int = 0
    handshakes_ok: int = 0
    handshakes_refused: int = 0
    cover_responses: int = 0
    streams_opened: int = 0
    streams_refused: int = 0
    egress_denied: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    errors: int = 0
    members: dict[str, MemberStats] = field(default_factory=dict)

    def member(self, name: str) -> MemberStats:
        if name not in self.members:
            self.members[name] = MemberStats(name=name)
        return self.members[name]

    @property
    def uptime(self) -> float:
        return time.time() - self.started_at

    def summary(self) -> str:
        return (
            f"{self.handshakes_ok} authorized / {self.handshakes_refused} refused, "
            f"{self.cover_responses} cover responses, {self.streams_opened} streams, "
            f"{self.bytes_up / 1048576:.1f} MiB out, {self.bytes_down / 1048576:.1f} MiB in, "
            f"up {self.uptime / 60:.0f} min"
        )


class TokenBucket:
    """A simple bandwidth limiter, in bytes per second.

    Present so that a relay can be shared without becoming somebody's
    file-hosting backend.  ``None`` means unlimited.
    """

    def __init__(self, rate_per_second: float | None) -> None:
        self.rate = rate_per_second
        self.tokens = rate_per_second or 0.0
        self.updated = time.monotonic()

    async def consume(self, amount: int) -> None:
        if not self.rate:
            return
        while True:
            now = time.monotonic()
            self.tokens = min(self.rate, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens >= amount:
                self.tokens -= amount
                return
            await asyncio.sleep(min(0.25, (amount - self.tokens) / self.rate))


class Relay:
    """The daemon object; :meth:`serve_forever` runs the accept loop."""

    def __init__(
        self,
        config: ServerConfig,
        identity: Identity,
        membership: MembershipStore,
        *,
        logger=None,
    ) -> None:
        self.config = config
        self.identity = identity
        self.membership = membership
        self.stats = RelayStats()
        self.started_at = time.time()
        self._nonce_cache = SeenNonceCache()
        self._servers: list[asyncio.AbstractServer] = []
        self._sessions: set[Session] = set()
        self._session_tasks: set[asyncio.Task] = set()
        self._stopping = asyncio.Event()
        self._stats_task: asyncio.Task | None = None
        self._logger = logger or _make_logger(config.log_level, config.log_file)
        self._shaper = Shaper(get_profile(config.profile))
        self._buckets: dict[str, TokenBucket] = {}
        self._tls_context = server_context(cert_file=config.tls_cert, key_file=config.tls_key)

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> list[str]:
        """Bind the listening socket(s).  Returns the addresses bound."""
        try:
            server = await asyncio.start_server(
                self._on_connection,
                self.config.listen_host,
                self.config.listen_port,
                ssl=self._tls_context,
                limit=1 << 20,
                reuse_address=True,
            )
        except OSError as exc:
            raise ConfigError(
                f"could not listen on {self.config.listen_host}:{self.config.listen_port}: {exc}"
            ) from exc
        self._servers.append(server)
        bound = [f"{sock.getsockname()[0]}:{sock.getsockname()[1]}" for sock in server.sockets or []]
        self._logger.info(
            "relay listening on %s%s (%s, profile %s, %d member(s))",
            ", ".join(bound),
            " over TLS" if self._tls_context else "",
            self.config.encoding,
            self.config.profile,
            len(self.membership),
        )
        if not len(self.membership):
            self._logger.warning(
                "the membership list is empty: every handshake will be refused "
                "(that is safe, but nothing will work either)"
            )
        return bound

    async def serve_forever(self) -> None:
        """Accept connections until :meth:`stop` is called."""
        if not self._servers:
            await self.start()
        if self.config.stats_interval:
            # Runs for the lifetime of the relay; keep a reference to it.
            self._stats_task = asyncio.create_task(self._stats_loop(), name="nfvpn-relay-stats")
        await self._stopping.wait()

    async def stop(self) -> None:
        """Stop listening, close every session, then return."""
        self._logger.info("shutting down: %s", self.stats.summary())
        for server in self._servers:
            server.close()
        for server in self._servers:
            with contextlib.suppress(Exception):
                await server.wait_closed()
        self._servers.clear()
        for session in list(self._sessions):
            with contextlib.suppress(Exception):
                await session.close()
        for task in list(self._session_tasks):
            task.cancel()
        self._stopping.set()

    def reload_membership(self, membership: MembershipStore) -> None:
        """Swap in a freshly loaded allowlist (SIGHUP).

        Existing sessions keep their keys — a member you remove stops being able
        to *start* a session, which is what revocation means in practice for a
        tunnel that is already up.
        """
        self.membership = membership
        self._logger.info("reloaded membership: %d member(s)", len(membership))

    async def _stats_loop(self) -> None:
        while not self._stopping.is_set():
            await asyncio.sleep(self.config.stats_interval)
            self._logger.info("stats: %s", self.stats.summary())

    # -- connections -------------------------------------------------------
    async def _on_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.stats.connections += 1
        task = asyncio.current_task()
        if task is not None:
            self._session_tasks.add(task)
        try:
            await self._handle_connection(reader, writer)
        except (TransportError, NoFlagVPNError, ConnectionError, OSError) as exc:
            self.stats.errors += 1
            self._logger.debug("connection ended: %s", exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.stats.errors += 1
            self._logger.warning("unexpected error on a connection: %r", exc)
        finally:
            if task is not None:
                self._session_tasks.discard(task)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            transport = await accept_transport(
                reader,
                writer,
                is_websocket=True,
                encrypted=self._tls_context is not None,
                encoding=self.config.encoding,
                server_handshake_timeout=self.config.handshake_timeout,
                cover_body=self.config.cover_body(),
                server_header=self.config.server_header,
            )
        except TransportError:
            # Not a WebSocket upgrade: the cover page has already been served.
            self.stats.cover_responses += 1
            with contextlib.suppress(Exception):
                writer.close()
            return

        session = await establish_responder(
            transport,
            self.identity,
            self.membership,
            shaper=self._shaper,
            cover_traffic=self.config.cover_traffic,
            handshake_timeout=self.config.handshake_timeout,
            idle_timeout=self.config.idle_timeout or DEFAULT_IDLE_TIMEOUT,
            nonce_cache=self._nonce_cache,
            rekey_seconds=self.config.rekey_seconds,
            window=self.config.window,
            max_streams=self.config.max_streams,
        )
        if session is None:
            # Refused — and the peer was told nothing, which is the idea.
            self.stats.handshakes_refused += 1
            self._logger.info(
                "refused a handshake from %s (key not in the membership list, "
                "expired, revoked, or a bad pre-shared key)",
                transport.info.peer,
            )
            return

        self.stats.handshakes_ok += 1
        member = self.stats.member(session.info.peer_name)
        member.sessions += 1
        member.last_seen = time.time()
        self._logger.info("session up: %s", session.info.describe())

        session.streams.set_open_handler(
            lambda stream, request: self._handle_stream(session, stream, request)
        )
        self._sessions.add(session)
        try:
            await session.run()
        finally:
            self._sessions.discard(session)
            member.sessions = max(0, member.sessions - 1)
            self.stats.bytes_up += session.stats.bytes_sent
            self.stats.bytes_down += session.stats.bytes_received
            self._logger.info(
                "session down: %s (%s)",
                session.info.peer_name,
                session.stats.summary(),
            )

    # -- one proxied stream ------------------------------------------------
    async def _handle_stream(
        self, session: Session, stream: Stream, request: OpenRequest
    ) -> None:
        """Serve one inbound stream: authorize the destination, then pump bytes."""
        decision = await self._authorize(request)
        member = self.stats.member(session.info.peer_name)
        if not decision.allowed or not decision.addresses:
            self.stats.egress_denied += 1
            member.refused += 1
            self._logger.warning(
                "denied %s for %s: %s",
                request.label(),
                member.name,
                decision.as_message(),
            )
            await session.streams.refuse(stream, CloseReason.DENIED)
            return

        writer = None
        try:
            reader, writer = await self._dial(decision, request)
        except (OSError, TimeoutError, asyncio.TimeoutError) as exc:
            self._logger.info("could not reach %s: %s", request.label(), exc)
            await session.streams.refuse(stream, CloseReason.REFUSED)
            return

        self.stats.streams_opened += 1
        member.streams += 1
        await session.streams.accept(stream)
        self._logger.debug("stream %s -> %s", stream.stream_id, request.label())

        bucket = self._buckets.setdefault(
            member.name, TokenBucket((self.config.limit_mbps or 0) * 125000 or None)
        )
        try:
            await self._pump(stream, reader, writer, bucket)
        finally:
            member.streams = max(0, member.streams - 1)
            session.streams.detach(stream)
            if writer is not None:
                with contextlib.suppress(Exception):
                    writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    async def _authorize(self, request: OpenRequest) -> Decision:
        return await self.config.egress.authorize(request.host, request.port)

    async def _dial(self, decision: Decision, request: OpenRequest):
        """Connect to an already-authorized address.

        The address comes from the authorization decision rather than a fresh
        resolution: resolving twice would let a name that answered with a public
        address the first time answer with a private one the second time.
        """
        last_error: Exception | None = None
        for address in decision.addresses:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(address, request.port, limit=1 << 20),
                    timeout=self.config.connect_timeout,
                )
            except (OSError, TimeoutError, asyncio.TimeoutError) as exc:
                last_error = exc
                continue
        if last_error is not None:
            raise last_error
        raise ConfigError("the egress decision carried no address to dial")

    async def _pump(
        self,
        stream: Stream,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        bucket: TokenBucket,
    ) -> None:
        """Shovel bytes both ways until either side is done."""

        async def upstream() -> None:
            try:
                while True:
                    chunk = await reader.read(_PUMP_CHUNK)
                    if not chunk:
                        break
                    await bucket.consume(len(chunk))
                    await stream.send(chunk)
            except (TransportError, NoFlagVPNError, ConnectionError, OSError):
                pass
            finally:
                with contextlib.suppress(TransportError, NoFlagVPNError):
                    await stream.close(CloseReason.NORMAL)

        async def downstream() -> None:
            try:
                while True:
                    chunk = await stream.receive()
                    if chunk is None:
                        break
                    await bucket.consume(len(chunk))
                    writer.write(chunk)
                    await writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    writer.write_eof()

        await asyncio.gather(upstream(), downstream(), return_exceptions=True)

    # -- introspection -----------------------------------------------------
    @property
    def egress(self) -> EgressPolicy:
        return self.config.egress

    def describe(self) -> str:
        return (
            f"relay {self.identity.name} ({self.identity.short_id}) on "
            f"{self.config.listen_host}:{self.config.listen_port}, "
            f"{len(self.membership)} member(s), profile {self.config.profile}"
        )


def _make_logger(level: str, log_file: str | None):
    import logging

    logger = logging.getLogger("nfvpn.relay")
    if not logger.handlers:
        handler: logging.Handler
        if log_file:
            handler = logging.FileHandler(log_file, encoding="utf-8")
        else:
            handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    return logger
