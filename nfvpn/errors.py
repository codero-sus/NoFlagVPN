"""Typed exception hierarchy.

Every error the user can plausibly cause has a distinct type so the CLI can
print something actionable instead of a traceback.
"""

from __future__ import annotations

__all__ = [
    "AuthenticationError",
    "ConfigError",
    "HandshakeError",
    "NoFlagVPNError",
    "PeerError",
    "ProtocolError",
    "ReplayError",
    "TransportError",
]


class NoFlagVPNError(Exception):
    """Base class for every error raised by nfvpn."""


class ConfigError(NoFlagVPNError):
    """The configuration file, key material or CLI arguments are unusable."""


class TransportError(NoFlagVPNError):
    """The carrier connection failed (handshake, socket, WebSocket framing)."""


class ProtocolError(NoFlagVPNError):
    """A peer sent something that violates the wire protocol."""


class HandshakeError(NoFlagVPNError):
    """The authenticated key exchange did not complete."""


class AuthenticationError(NoFlagVPNError):
    """A tag, signature or identity check failed."""


class ReplayError(NoFlagVPNError):
    """A frame or handshake message was seen before (possible injection)."""


class PeerError(NoFlagVPNError):
    """A peer is unknown, revoked, or attempted an action it is not allowed to take."""
