"""Sessions: the handshake, the secure channel, and the streams inside it."""

from __future__ import annotations

from nfvpn.session.channel import ChannelStats, SecureChannel
from nfvpn.session.handshake import (
    HANDSHAKE_SIZE,
    HandshakeInitiator,
    HandshakeMessage,
    HandshakeResponder,
    ResponderAnswer,
    SeenNonceCache,
)
from nfvpn.session.session import (
    Session,
    SessionInfo,
    establish_initiator,
    establish_responder,
)
from nfvpn.session.streams import (
    DEFAULT_MAX_STREAMS,
    DEFAULT_WINDOW,
    OpenRequest,
    Stream,
    StreamClosedError,
    StreamMultiplexer,
)

__all__ = [
    "DEFAULT_MAX_STREAMS",
    "DEFAULT_WINDOW",
    "HANDSHAKE_SIZE",
    "ChannelStats",
    "HandshakeInitiator",
    "HandshakeMessage",
    "HandshakeResponder",
    "OpenRequest",
    "ResponderAnswer",
    "SecureChannel",
    "SeenNonceCache",
    "Session",
    "SessionInfo",
    "Stream",
    "StreamClosedError",
    "StreamMultiplexer",
    "establish_initiator",
    "establish_responder",
]
