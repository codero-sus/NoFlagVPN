"""The authenticated key exchange, and what it refuses to reveal.

Messages
--------
Both handshake messages are exactly 128 bytes::

    INIT   ver(1) flags(1) initiator_static(32) initiator_ephemeral(32)
           nonce(16) timestamp(8) padding(22) mac(16)
    RESP   ver(1) flags(1) responder_static(32) responder_ephemeral(32)
           nonce(16) timestamp(8) padding(22) mac(16)

Fixed sizes are the whole point.  An observer (or an active prober) can weigh
every response without learning whether the peer was known, unknown, expired or
lying, because all four produce the same number of bytes.  The MACs are HMACs
under the peer's pre-shared key, so a prober who does not have one cannot tell a
correct response from the decoy the relay sends it.

Why a PSK and not just public keys
----------------------------------
Public keys decide *who* you are; the PSK decides whether a given relay will
carry your traffic.  Without it, anyone who observes or guesses a relay's public
key could use it, and a seized relay would be usable by whoever seized it.  With
it, a relay answers probes and payers identically, and refusing service is
indistinguishable from not being a relay at all.

Forward secrecy comes from the ephemeral keys: ``psk ‖ dh1 ‖ dh2 ‖ dh3 ‖ dh4``
feeds HKDF, so recovering a long-term key later does not decrypt recorded
sessions.
"""

from __future__ import annotations

import contextlib
import hmac
import os
import struct
import time
from collections import deque
from dataclasses import dataclass
from hashlib import sha256

from nfvpn.core.keys import (
    Identity,
    MembershipStore,
    SessionKeys,
    derive_session_keys,
    derive_transcript,
)
from nfvpn.core.primitives import (
    constant_time_equals,
    generate_x25519_private_key,
    public_key_for,
    random_bytes,
    x25519,
)
from nfvpn.errors import HandshakeError, ProtocolError
from nfvpn.framing.constants import PROTOCOL_VERSION

__all__ = [
    "HANDSHAKE_SIZE",
    "MAX_CLOCK_SKEW",
    "HandshakeInitiator",
    "HandshakeMessage",
    "HandshakeResponder",
    "ResponderAnswer",
    "SeenNonceCache",
]

#: Every handshake message is exactly this long.  See the module docstring.
HANDSHAKE_SIZE = 128

#: Bytes before the MAC; also what the MAC covers.
_AUTHENTICATED_SIZE = HANDSHAKE_SIZE - 16

#: How far a peer's clock may drift before the handshake is refused.  Generous,
#: because the failure mode of a too-strict window is "the tunnel stops working
#: on a laptop that just woke up from suspend".
MAX_CLOCK_SKEW = 300.0

_LABEL_INIT = b"nfvpn v1 init"
_LABEL_RESP = b"nfvpn v1 resp"

_HEADER = struct.Struct(">BB")
_U64 = struct.Struct(">Q")


@dataclass(frozen=True)
class HandshakeMessage:
    """One 128-byte handshake message."""

    version: int
    flags: int
    static_public: bytes
    ephemeral_public: bytes
    nonce: bytes
    timestamp: int
    padding: bytes
    mac: bytes

    def pack(self) -> bytes:
        return b"".join(
            (
                _HEADER.pack(self.version, self.flags),
                self.static_public,
                self.ephemeral_public,
                self.nonce,
                _U64.pack(self.timestamp),
                self.padding,
                self.mac,
            )
        )

    def authenticated_part(self) -> bytes:
        """The 112 bytes the MAC is computed over."""
        return self.pack()[:_AUTHENTICATED_SIZE]

    @classmethod
    def unpack(cls, raw: bytes) -> HandshakeMessage:
        if len(raw) != HANDSHAKE_SIZE:
            raise ProtocolError(
                f"handshake message must be exactly {HANDSHAKE_SIZE} bytes, got {len(raw)}"
            )
        version, flags = _HEADER.unpack_from(raw, 0)
        return cls(
            version=version,
            flags=flags,
            static_public=raw[2:34],
            ephemeral_public=raw[34:66],
            nonce=raw[66:82],
            timestamp=_U64.unpack_from(raw, 82)[0],
            padding=raw[90:112],
            mac=raw[112:128],
        )


def _mac(psk: bytes, label: bytes, *parts: bytes) -> bytes:
    digest = hmac.new(psk, label, sha256)
    for part in parts:
        digest.update(part)
    return digest.digest()[:16]


def _decoy_message(static_public: bytes) -> bytes:
    """A handshake reply indistinguishable from a real one.

    It carries the relay's *real* static key — that value is public (it rides in
    every response) — and random bytes everywhere else: a fresh ephemeral key, a
    random nonce, a random timestamp, random padding and a random MAC.  A prober
    learns nothing that a legitimate peer would not have shown it, and a
    legitimate peer with the wrong pre-shared key sees exactly this too.
    """
    body = b"".join(
        (
            bytes([PROTOCOL_VERSION, 0]),
            static_public,
            random_bytes(32),   # ephemeral public key never used for anything
            random_bytes(16),   # nonce
            random_bytes(8),    # timestamp
            random_bytes(_AUTHENTICATED_SIZE - 2 - 32 - 32 - 16 - 8),
        )
    )
    assert len(body) == _AUTHENTICATED_SIZE
    return body + random_bytes(16)


def _burn_key_agreement_work() -> None:
    """Spend the same CPU time a real handshake would, then throw it away.

    A refusal that returns in a microsecond while an acceptance takes thirty
    milliseconds is a distinguishing signal, and "how long until the reply"
    is trivially measurable by anyone with a socket.  With the pure-Python
    X25519 implementation the four key agreements dominate the handshake, so the
    decoy path performs four of them against random keys and drops the result.
    """
    for _ in range(4):
        # Deliberately discarded: the point is the time it takes, not the result.
        with contextlib.suppress(Exception):
            x25519(generate_x25519_private_key(), generate_x25519_private_key())


class SeenNonceCache:
    """Remembers handshake nonces so a replayed INIT is not treated as fresh.

    Small and bounded on purpose: a relay only needs to remember the recent
    past, because anything older is outside the clock-skew window anyway.
    """

    def __init__(self, capacity: int = 4096) -> None:
        self._seen: deque[tuple[bytes, bytes]] = deque(maxlen=capacity)
        self._set: set[tuple[bytes, bytes]] = set()

    def check_and_add(self, static_public: bytes, nonce: bytes) -> bool:
        """``True`` if this nonce is new.  Replays return ``False``."""
        key = (static_public, nonce)
        if key in self._set:
            return False
        if len(self._seen) == self._seen.maxlen:
            self._set.discard(self._seen[0])
        self._seen.append(key)
        self._set.add(key)
        return True

    def __len__(self) -> int:
        return len(self._set)


class HandshakeInitiator:
    """Client side of the handshake: one message out, one in, one confirm out."""

    def __init__(
        self,
        identity: Identity,
        peer_static_public: bytes,
        psk: bytes,
        *,
        ephemeral_private: bytes | None = None,
        clock_skew: bool = False,
        now: float | None = None,
    ) -> None:
        self.identity = identity
        self.peer_static_public = peer_static_public
        self.psk = psk
        self.ephemeral_private = ephemeral_private or generate_x25519_private_key()
        self.ephemeral_public = public_key_for(self.ephemeral_private)
        self.session_nonce = random_bytes(16)
        self.timestamp = int(now if now is not None else time.time())
        self._clock_skew = clock_skew
        self._init_bytes: bytes | None = None
        self._keys: SessionKeys | None = None
        self.confirmation: bytes | None = None

    def hello(self) -> bytes:
        """Build the INIT message to send to the relay."""
        message = HandshakeMessage(
            version=PROTOCOL_VERSION,
            flags=0,
            static_public=self.identity.public_key,
            ephemeral_public=self.ephemeral_public,
            nonce=self.session_nonce,
            timestamp=self.timestamp,
            padding=random_bytes(_AUTHENTICATED_SIZE - 2 - 32 - 32 - 16 - 8),
            mac=b"\x00" * 16,
        )
        body = message.authenticated_part()
        self._init_bytes = body + _mac(self.psk, _LABEL_INIT, body)
        return self._init_bytes

    def finish(self, response: bytes) -> tuple[SessionKeys, bytes]:
        """Verify the relay's answer and derive the session keys.

        Returns ``(keys, confirmation)`` where ``confirmation`` is the tag to put
        in the CONFIRM record that completes the handshake.

        Raises:
            HandshakeError: the response is malformed or not authentic.
        """
        if self._init_bytes is None:
            raise HandshakeError("hello() must be sent before finish()")
        try:
            message = HandshakeMessage.unpack(response)
        except ProtocolError as exc:
            raise HandshakeError(str(exc)) from exc

        if message.version != PROTOCOL_VERSION:
            raise HandshakeError(
                f"relay speaks protocol version {message.version}, we speak {PROTOCOL_VERSION}"
            )
        if message.static_public != self.peer_static_public:
            raise HandshakeError(
                "relay identified itself with a different key than the one we pinned; "
                "refusing (this is what a man-in-the-middle looks like)"
            )

        expected = _mac(
            self.psk, _LABEL_RESP, self._init_bytes[:_AUTHENTICATED_SIZE], response[:_AUTHENTICATED_SIZE]
        )
        if not constant_time_equals(expected, message.mac):
            raise HandshakeError(
                "the relay's handshake MAC did not verify: the pre-shared key is wrong, "
                "or the relay is not the peer you pinned"
            )

        transcript = derive_transcript(self._init_bytes, response)
        keys, confirmation = derive_session_keys(
            psk=self.psk,
            static_private=self.identity.private_key,
            peer_static_public=message.static_public,
            ephemeral_private=self.ephemeral_private,
            peer_ephemeral_public=message.ephemeral_public,
            transcript=transcript,
            initiator=True,
        )
        self._keys = keys
        self.confirmation = confirmation
        return keys, confirmation


@dataclass
class ResponderAnswer:
    """What the relay decides to send back, and whether it means anything."""

    message: bytes
    """Always 128 bytes, always worth sending — see the module docstring."""

    authorized: bool
    """``True`` only when the peer proved knowledge of a valid pre-shared key."""

    keys: SessionKeys | None = None
    confirmation: bytes | None = None
    peer_name: str = ""
    peer_public_key: bytes | None = None
    reason: str = ""
    """Why the handshake was refused, for the relay's own logs.  Never sent."""


class HandshakeResponder:
    """Relay side of the handshake."""

    def __init__(
        self,
        identity: Identity,
        membership: MembershipStore,
        *,
        nonce_cache: SeenNonceCache | None = None,
        ephemeral_private: bytes | None = None,
        max_clock_skew: float = MAX_CLOCK_SKEW,
    ) -> None:
        self.identity = identity
        self.membership = membership
        self.nonce_cache = nonce_cache or SeenNonceCache()
        self.ephemeral_private = ephemeral_private or generate_x25519_private_key()
        self.ephemeral_public = public_key_for(self.ephemeral_private)
        self.max_clock_skew = max_clock_skew

    def _decoy(self) -> bytes:
        """Build a refusal reply, doing the same work a real one would."""
        _burn_key_agreement_work()
        return _decoy_message(self.identity.public_key)

    def answer(self, init_bytes: bytes, *, now: float | None = None) -> ResponderAnswer:
        """Process an INIT and produce the reply to send.

        The reply is generated identically for good and bad handshakes.  When the
        handshake fails, ``authorized`` is ``False`` and the caller is expected to
        send ``message`` and then keep talking to the peer exactly as if nothing
        had gone wrong.
        """
        timestamp_now = now if now is not None else time.time()

        try:
            message = HandshakeMessage.unpack(init_bytes)
        except ProtocolError as exc:
            return ResponderAnswer(
                message=self._decoy(), authorized=False, reason=f"malformed init: {exc}"
            )

        if message.version != PROTOCOL_VERSION:
            return ResponderAnswer(
                message=self._decoy(),
                authorized=False,
                reason=f"protocol version {message.version} is not {PROTOCOL_VERSION}",
            )

        if abs(timestamp_now - message.timestamp) > self.max_clock_skew:
            return ResponderAnswer(
                message=self._decoy(),
                authorized=False,
                reason="init outside the accepted clock window",
            )

        if not self.nonce_cache.check_and_add(message.static_public, message.nonce):
            return ResponderAnswer(
                message=self._decoy(), authorized=False, reason="replayed handshake nonce"
            )

        member = self.membership.lookup(message.static_public, now=timestamp_now)
        if member is None:
            return ResponderAnswer(
                message=self._decoy(),
                authorized=False,
                reason="unknown, expired or revoked peer key",
            )

        expected = _mac(member.psk, _LABEL_INIT, init_bytes[:_AUTHENTICATED_SIZE])
        if not constant_time_equals(expected, message.mac):
            return ResponderAnswer(
                message=self._decoy(),
                authorized=False,
                reason=f"bad handshake MAC for member {member.name}",
            )

        response = HandshakeMessage(
            version=PROTOCOL_VERSION,
            flags=0,
            static_public=self.identity.public_key,
            ephemeral_public=self.ephemeral_public,
            nonce=random_bytes(16),
            timestamp=int(timestamp_now),
            padding=random_bytes(_AUTHENTICATED_SIZE - 2 - 32 - 32 - 16 - 8),
            mac=b"\x00" * 16,
        )
        body = response.authenticated_part()
        mac = _mac(
            member.psk,
            _LABEL_RESP,
            init_bytes[:_AUTHENTICATED_SIZE],
            body,
        )
        response_bytes = body + mac

        transcript = derive_transcript(init_bytes, response_bytes)
        keys, confirmation = derive_session_keys(
            psk=member.psk,
            static_private=self.identity.private_key,
            peer_static_public=message.static_public,
            ephemeral_private=self.ephemeral_private,
            peer_ephemeral_public=message.ephemeral_public,
            transcript=transcript,
            initiator=False,
        )
        return ResponderAnswer(
            message=response_bytes,
            authorized=True,
            keys=keys,
            confirmation=confirmation,
            peer_name=member.name,
            peer_public_key=message.static_public,
            reason="authorized",
        )

    @staticmethod
    def verify_confirmation(expected: bytes, received: bytes) -> None:
        """Check the initiator's confirm tag.

        Raises:
            HandshakeError: the tag does not match, meaning the peer never
                derived the same keys (wrong PSK, a spliced session, or a probe).
        """
        if not constant_time_equals(expected, received):
            raise HandshakeError("handshake confirmation did not verify")


def random_padding(size: int) -> bytes:
    """Cryptographically random padding (kept for callers that build messages)."""
    return os.urandom(size)
