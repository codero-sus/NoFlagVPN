"""Establishing and running a session.

A session is the whole thing: a carrier, a handshake, a secure channel, and a
multiplexer full of streams.  Both sides of the tunnel end up with the same
object; only ``initiator`` differs.

The relay's refusal path
------------------------
When a handshake fails — unknown key, expired key, wrong pre-shared key, replayed
nonce, a scanner poking the port with 128 random bytes — the relay still answers
with a well-formed 128-byte handshake reply, still waits for a confirmation
record, still emits a record-shaped reply of the same size a real confirmation
would have produced, and only then closes the connection.  Nothing about the
bytes it sends, their sizes, or their sequence differs from a successful
handshake by an unauthenticated peer.  A prober cannot map the relays of this
network, because "go away" and "hello" are the same message.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
import time
from dataclasses import dataclass, field

from nfvpn.core.keys import Identity, MembershipStore, SessionKeys
from nfvpn.errors import HandshakeError, NoFlagVPNError, TransportError
from nfvpn.framing.constants import (
    CTRL_CONFIRM,
    CTRL_PING,
    HEADER_SIZE,
    TAG_SIZE,
    CloseReason,
    RecordType,
)
from nfvpn.session.channel import SecureChannel
from nfvpn.session.handshake import (
    HANDSHAKE_SIZE,
    HandshakeInitiator,
    HandshakeResponder,
    SeenNonceCache,
)
from nfvpn.session.streams import DEFAULT_MAX_STREAMS, DEFAULT_WINDOW, StreamMultiplexer
from nfvpn.traffic.shaper import Shaper

__all__ = ["Session", "SessionInfo", "establish_initiator", "establish_responder"]

#: How long we wait for the peer during the handshake.
DEFAULT_HANDSHAKE_TIMEOUT = 20.0

#: After a refusal, how long the relay keeps the socket before hanging up. The
#: point is that it is not instant: an instant close is a signal.
DECOY_LINGER = 4.0

#: A session with no traffic at all for this long is considered dead.  Cover
#: traffic keeps real sessions well inside this, so it only fires on the
#: refusing path or a carrier that has silently died.
DEFAULT_IDLE_TIMEOUT = 300.0

_CONFIRM_PAYLOAD = 1 + 32  # control code plus the confirmation tag


@dataclass
class SessionInfo:
    """What we know about the other end."""

    peer_name: str
    peer_public_key: bytes
    initiator: bool
    carrier: str
    started_at: float = field(default_factory=time.time)
    member_psk: bytes = field(default=b"", repr=False)

    def describe(self) -> str:
        role = "client" if self.initiator else "relay"
        return f"session as {role} with {self.peer_name} over {self.carrier}"


def _confirmation_record_size(shaper: Shaper | None) -> int:
    """On-wire size of the record that carries a confirmation tag."""
    plaintext = _CONFIRM_PAYLOAD
    if shaper is not None:
        plaintext = max(plaintext, shaper.padded_plaintext(_CONFIRM_PAYLOAD))
    else:
        plaintext = max(plaintext, _CONFIRM_PAYLOAD)
    return HEADER_SIZE + TAG_SIZE + plaintext


def _decoy_record(record_type: RecordType = RecordType.CTRL, size: int = 0) -> bytes:
    """A record-shaped blob that decrypts to nothing because it is random.

    Well-formed header, random body: it parses exactly like a real record to
    anyone who does not hold the session keys (which is everyone except the two
    ends of a successful handshake).
    """
    from nfvpn.core.primitives import random_bytes

    header = struct.pack(">BBHIQ", int(record_type), 0, 0, 0, 0)
    return header + random_bytes(max(size - HEADER_SIZE, TAG_SIZE))


class Session:
    """A live tunnel: one carrier, one channel, many streams."""

    def __init__(
        self,
        channel: SecureChannel,
        streams: StreamMultiplexer,
        info: SessionInfo,
        *,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    ) -> None:
        self.channel = channel
        self.streams = streams
        self.info = info
        self.idle_timeout = idle_timeout
        self._read_task: asyncio.Task[None] | None = None
        self._closed = False
        self._closing = asyncio.Event()
        self.last_error: BaseException | None = None

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        """Start the channel sender and the read loop."""
        await self.channel.start()
        if self._read_task is None:
            self._read_task = asyncio.create_task(self._read_loop(), name="nfvpn-session-reader")

    async def run(self) -> None:
        """Run until the session ends.  Returns normally on a clean shutdown."""
        await self.start()
        assert self._read_task is not None
        with contextlib.suppress(asyncio.CancelledError):
            await self._read_task

    async def close(self, reason: CloseReason = CloseReason.LOCAL_SHUTDOWN) -> None:
        """Tear the session down: streams, channel, carrier."""
        if self._closed:
            return
        self._closed = True
        self._closing.set()
        with contextlib.suppress(Exception):
            await self.streams.close_all(reason)
        with contextlib.suppress(Exception):
            await self.channel.flush()
        await self.channel.close()
        if self._read_task is not None and not self._read_task.done():
            self._read_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._read_task
        with contextlib.suppress(Exception):
            await self.channel.transport.close()

    async def _read_loop(self) -> None:
        """Decode records and hand them to the multiplexer."""
        try:
            while not self._closed:
                try:
                    record = await asyncio.wait_for(
                        self.channel.receive(), timeout=self.idle_timeout
                    )
                except (TimeoutError, asyncio.TimeoutError):
                    self.last_error = TransportError(
                        f"no traffic for {self.idle_timeout:.0f}s; assuming the carrier died"
                    )
                    return
                if self.channel.failure is not None:
                    self.last_error = self.channel.failure
                    return
                await self.streams.handle_record(record)
        except asyncio.CancelledError:
            raise
        except (TransportError, NoFlagVPNError) as exc:
            self.last_error = exc
        finally:
            self._closed = True
            self._closing.set()

    # -- helpers -----------------------------------------------------------
    async def ping(self) -> None:
        """Ask the peer to acknowledge (the peer's pong is absorbed silently)."""
        await self.channel.send(RecordType.CTRL, 0, bytes([CTRL_PING]))

    async def wait_closed(self) -> None:
        await self._closing.wait()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def stats(self):
        return self.channel.stats

    def describe(self) -> str:
        return f"{self.info.describe()}; {self.stats.summary()}"

    async def __aenter__(self) -> Session:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()


async def _await_handshake_message(transport, timeout: float, what: str) -> bytes:
    try:
        message = await asyncio.wait_for(transport.receive_message(), timeout=timeout)
    except (TimeoutError, asyncio.TimeoutError) as exc:
        raise HandshakeError(f"timed out waiting for {what}") from exc
    if len(message) != HANDSHAKE_SIZE:
        raise HandshakeError(
            f"{what} must be {HANDSHAKE_SIZE} bytes, got {len(message)}"
        )
    return message


async def _exchange_confirmations(
    channel: SecureChannel, own_confirmation: bytes, *, timeout: float
) -> None:
    """Send our confirmation and verify the peer's.

    The AEAD already proves key agreement — a record only opens if both sides
    derived the same keys — so this is a second, explicit check that also fails
    loudly if a peer ever accepts a record under a stale key generation.
    """
    await channel.send(
        RecordType.CTRL, 0, bytes([CTRL_CONFIRM]) + own_confirmation
    )
    await channel.flush()

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HandshakeError("the peer never confirmed the session")
        record = await asyncio.wait_for(channel.receive(), timeout=remaining)
        if record.type is not RecordType.CTRL or not record.payload:
            raise HandshakeError("expected a confirmation record, got something else")
        if record.payload[0] != CTRL_CONFIRM:
            raise HandshakeError(f"unexpected control code {record.payload[0]} during handshake")
        HandshakeResponder.verify_confirmation(own_confirmation, record.payload[1:])
        return


async def establish_initiator(
    transport,
    identity: Identity,
    peer_static_public: bytes,
    psk: bytes,
    *,
    peer_name: str = "relay",
    shaper: Shaper | None = None,
    cover_traffic: bool = True,
    handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    rekey_bytes: int | None = None,
    rekey_seconds: float | None = None,
    window: int | None = None,
    max_streams: int | None = None,
) -> Session:
    """Run the client side of the handshake over an open carrier."""
    initiator = HandshakeInitiator(identity, peer_static_public, psk)
    await transport.send_message(initiator.hello())

    response = await _await_handshake_message(transport, handshake_timeout, "the relay's reply")
    keys, confirmation = initiator.finish(response)

    channel = _build_channel(
        keys,
        transport,
        initiator=True,
        shaper=shaper,
        cover_traffic=cover_traffic,
        rekey_bytes=rekey_bytes,
        rekey_seconds=rekey_seconds,
    )
    # The sender task must exist before the confirmation, which is itself a
    # record and therefore goes through the queue.
    await channel.start()
    await _exchange_confirmations(channel, confirmation, timeout=handshake_timeout)

    session = Session(
        channel,
        StreamMultiplexer(
            channel,
            initiator=True,
            window=window or DEFAULT_WINDOW,
            max_streams=max_streams or DEFAULT_MAX_STREAMS,
        ),
        SessionInfo(
            peer_name=peer_name,
            peer_public_key=peer_static_public,
            initiator=True,
            carrier=transport.info.describe(),
            member_psk=psk,
        ),
        idle_timeout=idle_timeout,
    )
    await session.start()
    return session


async def establish_responder(
    transport,
    identity: Identity,
    membership: MembershipStore,
    *,
    shaper: Shaper | None = None,
    cover_traffic: bool = True,
    handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    nonce_cache: SeenNonceCache | None = None,
    rekey_bytes: int | None = None,
    rekey_seconds: float | None = None,
    window: int | None = None,
    max_streams: int | None = None,
) -> Session | None:
    """Run the relay side of the handshake.

    Returns ``None`` when the peer failed to authenticate — after behaving, byte
    for byte and second for second, exactly like a relay that accepted it.  The
    caller should treat ``None`` as "close quietly and log locally".
    """
    responder = HandshakeResponder(identity, membership, nonce_cache=nonce_cache)
    init = await _await_handshake_message(transport, handshake_timeout, "the client's hello")
    answer = responder.answer(init)
    await transport.send_message(answer.message)

    if not answer.authorized or answer.keys is None or answer.confirmation is None:
        # Same shape, same size, same waiting as the success path.
        await transport.send_message(_decoy_record(size=_confirmation_record_size(shaper)))
        with contextlib.suppress(
            TimeoutError, asyncio.TimeoutError, TransportError, NoFlagVPNError
        ):
            await asyncio.wait_for(transport.receive_message(), timeout=DECOY_LINGER)
        await transport.close()
        return None

    channel = _build_channel(
        answer.keys,
        transport,
        initiator=False,
        shaper=shaper,
        cover_traffic=cover_traffic,
        rekey_bytes=rekey_bytes,
        rekey_seconds=rekey_seconds,
    )
    await channel.start()
    await _exchange_confirmations(channel, answer.confirmation, timeout=handshake_timeout)

    session = Session(
        channel,
        StreamMultiplexer(
            channel,
            initiator=False,
            window=window or DEFAULT_WINDOW,
            max_streams=max_streams or DEFAULT_MAX_STREAMS,
        ),
        SessionInfo(
            peer_name=answer.peer_name,
            peer_public_key=answer.peer_public_key or b"",
            initiator=False,
            carrier=transport.info.describe(),
            member_psk=b"",
        ),
        idle_timeout=idle_timeout,
    )
    await session.start()
    return session


def _build_channel(
    keys: SessionKeys,
    transport,
    *,
    initiator: bool,
    shaper: Shaper | None,
    cover_traffic: bool,
    rekey_bytes: int | None,
    rekey_seconds: float | None,
) -> SecureChannel:
    from nfvpn.session.channel import (
        DEFAULT_REKEY_BYTES,
        DEFAULT_REKEY_SECONDS,
    )

    return SecureChannel(
        keys,
        transport,
        initiator=initiator,
        shaper=shaper,
        cover_traffic=cover_traffic,
        rekey_bytes=DEFAULT_REKEY_BYTES if rekey_bytes is None else rekey_bytes,
        rekey_seconds=DEFAULT_REKEY_SECONDS if rekey_seconds is None else rekey_seconds,
    )

