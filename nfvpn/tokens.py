"""Invite tokens: one string that carries everything a new client needs.

A relay operator normally has to communicate four things — the address, the
relay's public key, the pre-shared key, and which of them is which.  Getting any
of them wrong is a failed handshake with no useful error, which is the wrong
first experience for a tool that is supposed to just work.

So there is one token::

    nfvpn://eyJ2IjoxLCJuYW1lIjoi...

It is base64url of a small JSON object, and it is a *secret* when it contains a
PSK — treat it like a password, not like a URL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from nfvpn.core.encoding import b64d, b64e
from nfvpn.errors import ConfigError

__all__ = ["TOKEN_PREFIX", "Invite", "decode_invite", "encode_invite"]

TOKEN_PREFIX = "nfvpn://"
_TOKEN_VERSION = 1
_MAX_DECODED = 4096


@dataclass(frozen=True)
class Invite:
    """What an invite token carries."""

    relay: str
    peer_public_key: str
    psk: str
    name: str = "relay"

    def encode(self) -> str:
        """Serialise to the ``nfvpn://`` form."""
        payload = {
            "v": _TOKEN_VERSION,
            "relay": self.relay,
            "key": self.peer_public_key,
            "psk": self.psk,
            "name": self.name,
        }
        return TOKEN_PREFIX + b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    def redacted(self) -> str:
        """A copy safe to paste into a chat or an issue: the PSK is removed."""
        return (
            f"{self.relay} key={self.peer_public_key[:8]}… psk=…"
            f"{self.psk[-4:]} name={self.name}"
        )


def encode_invite(relay: str, peer_public_key: str, psk: str, name: str = "relay") -> str:
    """Build a token from its parts."""
    return Invite(relay=relay, peer_public_key=peer_public_key, psk=psk, name=name).encode()


def decode_invite(token: str, *, require_psk: bool = True) -> Invite:
    """Parse a token, with errors that say what is actually wrong."""
    text = token.strip()
    if not text.startswith(TOKEN_PREFIX):
        raise ConfigError(
            f"an invite token starts with {TOKEN_PREFIX!r}; "
            "use `nfvpn token --member NAME` on the relay to create one"
        )
    blob = text[len(TOKEN_PREFIX) :]
    try:
        raw = b64d(blob)
    except ValueError as exc:
        raise ConfigError("the invite token is not valid base64; it was probably truncated") from exc
    if len(raw) > _MAX_DECODED:
        raise ConfigError("the invite token is implausibly large")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError("the invite token does not contain valid JSON") from exc
    if not isinstance(payload, dict):
        raise ConfigError("the invite token does not contain an object")

    version = payload.get("v")
    if version != _TOKEN_VERSION:
        raise ConfigError(
            f"invite token version {version!r} is not supported (this build speaks {_TOKEN_VERSION})"
        )

    for field in ("relay", "key"):
        if not payload.get(field):
            raise ConfigError(f"the invite token is missing its {field!r} field")
    if require_psk and not payload.get("psk"):
        raise ConfigError("the invite token is missing its 'psk' field")

    return Invite(
        relay=str(payload["relay"]),
        peer_public_key=str(payload["key"]),
        psk=str(payload.get("psk") or ""),
        name=str(payload.get("name") or "relay"),
    )
