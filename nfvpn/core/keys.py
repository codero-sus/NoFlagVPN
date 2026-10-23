"""Long-term identity, pre-shared keys, membership and the key schedule.

Threat model in one paragraph
-----------------------------
The network we tunnel through is hostile: it can see every byte, drop, delay,
reorder and rewrite packets, and it can also spin up *active* probes that try to
learn whether a given host is running a NoFlagVPN relay.  Therefore:

* All user payload and all control messages are AEAD-sealed with ChaCha20-Poly1305.
* Identity is a static X25519 key; secrecy of the tunnel comes from ephemeral
  X25519 (forward secrecy) and is *authorized* by a per-peer pre-shared key, so
  seeing a public key is not enough to use a relay.
* An unknown peer never gets a distinguishable error — see
  :mod:`nfvpn.session.handshake`.  Probes learn nothing.

Key schedule
------------
Both sides derive the same :class:`SessionKeys` from the handshake transcript::

    master  = HKDF-SHA256(salt = transcript_hash,
                          ikm  = psk ‖ dh1 ‖ dh2 ‖ dh3 ‖ dh4,
                          info = "nfvpn v1 handshake")
    traffic = HKDF-SHA256(master, info = "nfvpn v1 traffic")
    key_i2r = HKDF-SHA256(master, info = "nfvpn v1 i2r")
    key_r2i = HKDF-SHA256(master, info = "nfvpn v1 r2i")
    header  = HKDF-SHA256(master, info = "nfvpn v1 header")
    confirm = HKDF-SHA256(master, info = "nfvpn v1 confirm")

The PSK is mixed into the IKM rather than used as the HKDF salt so that a wrong
PSK produces uniformly different keys, never a distinguishable MAC error.
Rekeying chains forward: ``master_{n+1} = HKDF(master_n, info = "nfvpn v1 rekey")``.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import stat
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from nfvpn.core.encoding import b64d, b64e, fingerprint, safety_number, short_id
from nfvpn.core.primitives import (
    KEY_SIZE,
    constant_time_equals,
    generate_x25519_private_key,
    hkdf_sha256,
    public_key_for,
    random_bytes,
    x25519_shared,
)
from nfvpn.errors import ConfigError

__all__ = [
    "Identity",
    "Member",
    "MembershipStore",
    "SessionKeys",
    "derive_session_keys",
    "derive_transcript",
    "generate_psk",
    "parse_psk",
    "write_private_file",
]

#: Domain separator for the handshake transcript hash.
TRANSCRIPT_LABEL = b"nfvpn v1 transcript"
HANDSHAKE_LABEL = b"nfvpn v1 handshake"
TRAFFIC_LABEL = b"nfvpn v1 traffic"
HEADER_LABEL = b"nfvpn v1 header"
CONFIRM_LABEL = b"nfvpn v1 confirm"
REKEY_LABEL = b"nfvpn v1 rekey"

_PSK_SIZE = 32


def write_private_file(path: Path, data: str) -> None:
    """Write a file that only the owner can read, creating parents as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    # os.open's mode only applies when the file is created; an existing key with
    # looser permissions must be tightened, not silently left readable.
    with contextlib.suppress(OSError):
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def generate_psk() -> str:
    """A fresh 256-bit pre-shared key, base64url encoded."""
    return b64e(random_bytes(_PSK_SIZE))


def parse_psk(text: str) -> bytes:
    """Accept base64url, hex, or a passphrase (stretched with HKDF).

    Being liberal here means a user can type a passphrase on a LAN demo and
    still get a proper 256-bit key, while ``nfvpn keygen`` output pastes cleanly.
    """
    candidate = "".join(text.split())
    if not candidate:
        raise ConfigError("empty pre-shared key")

    if len(candidate) == 64 and all(char in "0123456789abcdefABCDEF" for char in candidate):
        return bytes.fromhex(candidate)

    try:
        decoded = b64d(candidate)
    except ValueError:
        decoded = b""
    if len(decoded) == _PSK_SIZE:
        return decoded

    # Fall back to a passphrase.  A short one is weak; warn loudly instead of
    # silently accepting a brute-forceable tunnel.
    if len(text) < 16:
        raise ConfigError(
            "pre-shared key looks like a passphrase but is shorter than 16 characters; "
            "use `nfvpn keygen --psk` output instead"
        )
    return hkdf_sha256(text.encode("utf-8"), salt=b"nfvpn psk passphrase", info=b"", length=_PSK_SIZE)


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
@dataclass
class Identity:
    """A node's long-term X25519 key pair plus its display name."""

    name: str
    private_key: bytes
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if len(self.private_key) != KEY_SIZE:
            raise ConfigError(f"identity private key must be {KEY_SIZE} bytes")
        if not self.name:
            raise ConfigError("identity needs a name")

    @property
    def public_key(self) -> bytes:
        """The 32-byte X25519 public key peers pin."""
        return public_key_for(self.private_key)

    @property
    def fingerprint(self) -> str:
        """Human-readable key fingerprint (grouped hex)."""
        return fingerprint(self.public_key)

    @property
    def short_id(self) -> str:
        """Eight-character id for tables and logs."""
        return short_id(self.public_key)

    @classmethod
    def generate(cls, name: str) -> Identity:
        """Create a brand-new identity."""
        return cls(name=name, private_key=generate_x25519_private_key())

    @classmethod
    def load(cls, path: os.PathLike[str] | str) -> Identity:
        """Load from a JSON key file, refusing world-readable secrets."""
        key_path = Path(path)
        try:
            raw = json.loads(key_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError(f"identity file not found: {key_path}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"identity file is not valid UTF-8 JSON: {key_path}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"identity file must be a JSON object: {key_path}")

        mode = key_path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ConfigError(
                f"{key_path} is readable by other users (mode {stat.S_IMODE(mode):04o}); "
                f"run `chmod 600 {key_path}`"
            )
        try:
            encoded_private_key = raw["private_key"]
            if not isinstance(encoded_private_key, str):
                raise ValueError("private_key must be a string")
            private_key = b64d(encoded_private_key)
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError(f"identity file {key_path} has no usable private_key") from exc
        try:
            created_at = float(raw["created_at"]) if raw.get("created_at") is not None else time.time()
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"identity file {key_path} has invalid created_at") from exc
        if not math.isfinite(created_at):
            raise ConfigError(f"identity file {key_path} has invalid created_at")
        return cls(
            name=str(raw.get("name") or "unnamed"),
            private_key=private_key,
            created_at=created_at,
        )

    @classmethod
    def load_or_create(cls, path: os.PathLike[str] | str, name: str = "nfvpn") -> Identity:
        """Idempotent helper for demos and tests."""
        key_path = Path(path)
        if key_path.exists():
            return cls.load(key_path)
        identity = cls.generate(name)
        identity.save(key_path)
        return identity

    def save(self, path: os.PathLike[str] | str) -> None:
        """Persist with 0600 permissions."""
        payload = {
            "name": self.name,
            "private_key": b64e(self.private_key),
            "public_key": b64e(self.public_key),
            "created_at": self.created_at,
            "comment": "NoFlagVPN long-term identity. Keep secret. Share only the public_key.",
        }
        write_private_file(Path(path), json.dumps(payload, indent=2) + "\n")

    def public_dict(self) -> dict[str, Any]:
        """The shareable half."""
        return {"name": self.name, "public_key": b64e(self.public_key), "short_id": self.short_id}

    def agrees(self, peer_public_key: bytes) -> str:
        """Symmetric safety number against a peer key."""
        return safety_number(self.public_key, peer_public_key)


# --------------------------------------------------------------------------- #
# Membership
# --------------------------------------------------------------------------- #
@dataclass
class Member:
    """A peer that is allowed to use a relay, plus its per-peer authorization."""

    name: str
    public_key: bytes
    psk: bytes
    added_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    enabled: bool = True
    #: Free-form tags, e.g. {"egress": "restricted", "note": "kid's laptop"}
    tags: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.public_key) != KEY_SIZE:
            raise ConfigError("member public key must be 32 bytes")
        if len(self.psk) != _PSK_SIZE:
            raise ConfigError(f"member PSK must be {_PSK_SIZE} bytes")
        if (
            isinstance(self.added_at, bool)
            or not isinstance(self.added_at, (int, float))
            or not math.isfinite(self.added_at)
        ):
            raise ConfigError("member added_at must be a finite timestamp")
        if self.expires_at is not None and (
            isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, (int, float))
            or not math.isfinite(self.expires_at)
        ):
            raise ConfigError("member expires_at must be a finite timestamp")

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)

    @property
    def short_id(self) -> str:
        return short_id(self.public_key)

    def is_usable(self, now: float | None = None) -> bool:
        """Enabled and not expired."""
        if not self.enabled:
            return False
        if self.expires_at is None:
            return True
        return (now if now is not None else time.time()) < self.expires_at

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["public_key"] = b64e(self.public_key)
        payload["psk"] = b64e(self.psk)
        return payload

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Member:
        enabled = raw.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError("member entry enabled must be a boolean")
        tags = raw.get("tags", {})
        if tags is None:
            tags = {}
        if not isinstance(tags, dict):
            raise ConfigError("member entry tags must be an object")
        try:
            return cls(
                name=str(raw["name"]),
                public_key=b64d(str(raw["public_key"])),
                psk=b64d(str(raw["psk"])),
                added_at=(
                    float(raw["added_at"]) if raw.get("added_at") is not None else time.time()
                ),
                expires_at=(
                    float(raw["expires_at"]) if raw.get("expires_at") is not None else None
                ),
                enabled=enabled,
                tags={str(k): str(v) for k, v in tags.items()},
            )
        except KeyError as exc:
            raise ConfigError(f"member entry is missing {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"member entry is malformed: {exc}") from exc


@dataclass
class MembershipStore:
    """The relay's allowlist: who may connect, and with which PSK.

    Closed by default.  A relay with an empty store answers every handshake with
    the same silence it would give a port scanner, so there is nothing to
    enumerate.
    """

    members: dict[str, Member] = field(default_factory=dict)  # keyed by base64 public key
    path: Path | None = None

    @staticmethod
    def _key(public_key: bytes) -> str:
        return b64e(public_key)

    def add(self, member: Member, *, replace: bool = False) -> Member:
        """Add a member; refuses to clobber an existing key unless told to."""
        key = self._key(member.public_key)
        if key in self.members and not replace:
            raise ConfigError(
                f"a member with this public key already exists ({self.members[key].name}); "
                "pass replace=True to overwrite"
            )
        self.members[key] = member
        return member

    def remove(self, public_key: bytes) -> bool:
        """Delete a member outright. Returns whether anything was removed."""
        return self.members.pop(self._key(public_key), None) is not None

    def revoke(self, public_key: bytes) -> bool:
        """Disable a member without forgetting the key (keeps the audit trail)."""
        member = self.lookup(public_key)
        if member is None:
            return False
        member.enabled = False
        return True

    def lookup(self, public_key: bytes, *, now: float | None = None) -> Member | None:
        """Return the member for this key if it is currently usable."""
        member = self.members.get(self._key(public_key))
        if member is None or not member.is_usable(now):
            return None
        return member

    def get(self, name: str) -> Member | None:
        """Look a member up by display name."""
        for member in self.members.values():
            if member.name == name:
                return member
        return None

    def __len__(self) -> int:
        return len(self.members)

    def __iter__(self) -> Iterator[Member]:
        return iter(self.members.values())

    def active(self, now: float | None = None) -> list[Member]:
        """Members that would currently be accepted."""
        return [member for member in self.members.values() if member.is_usable(now)]

    def to_dict(self) -> dict[str, Any]:
        return {"version": 1, "members": [member.to_dict() for member in self.members.values()]}

    @classmethod
    def from_dict(cls, raw: dict[str, Any], path: Path | None = None) -> MembershipStore:
        if not isinstance(raw, dict):
            raise ConfigError("membership file must contain a JSON object")
        entries = raw.get("members", [])
        if not isinstance(entries, list):
            raise ConfigError("membership file members must be a list")
        store = cls(path=path)
        for entry in entries:
            if not isinstance(entry, dict):
                raise ConfigError("each membership entry must be a JSON object")
            store.add(Member.from_dict(entry), replace=True)
        return store

    @classmethod
    def load(cls, path: os.PathLike[str] | str) -> MembershipStore:
        """Load the allowlist; a missing file means an empty (closed) store."""
        store_path = Path(path)
        if not store_path.exists():
            return cls(path=store_path)
        try:
            raw = json.loads(store_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"membership file is not valid UTF-8 JSON: {store_path}") from exc

        mode = store_path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ConfigError(
                f"{store_path} is readable by other users (mode {stat.S_IMODE(mode):04o}); "
                f"run `chmod 600 {store_path}`"
            )
        store = cls.from_dict(raw, path=store_path)
        store.path = store_path
        return store

    def save(self, path: os.PathLike[str] | str | None = None) -> None:
        """Persist with 0600 permissions (it contains PSKs)."""
        target = Path(path) if path is not None else self.path
        if target is None:
            raise ConfigError("no path given for the membership store")
        write_private_file(target, json.dumps(self.to_dict(), indent=2) + "\n")
        self.path = target


# --------------------------------------------------------------------------- #
# Key schedule
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SessionKeys:
    """Everything two peers need to talk, derived from one handshake."""

    master: bytes
    traffic: bytes
    header: bytes
    confirm: bytes
    initiator_to_responder: bytes
    responder_to_initiator: bytes

    def rekey(self) -> SessionKeys:
        """Advance the key chain by one step (forward secrecy for long sessions)."""
        new_master = hkdf_sha256(self.master, salt=None, info=REKEY_LABEL, length=KEY_SIZE)
        return derive_from_master(new_master)


def derive_transcript(*parts: bytes, label: bytes = TRANSCRIPT_LABEL) -> bytes:
    """Hash the handshake transcript; never empty, so it is always a valid salt."""
    from hashlib import sha256

    digest = sha256()
    digest.update(label)
    for part in parts:
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()


def derive_from_master(master: bytes) -> SessionKeys:
    """Expand a master secret into the per-direction session keys."""
    return SessionKeys(
        master=master,
        traffic=hkdf_sha256(master, None, TRAFFIC_LABEL, 32),
        header=hkdf_sha256(master, None, HEADER_LABEL, 32),
        confirm=hkdf_sha256(master, None, CONFIRM_LABEL, 32),
        initiator_to_responder=hkdf_sha256(master, None, b"nfvpn v1 i2r", 32),
        responder_to_initiator=hkdf_sha256(master, None, b"nfvpn v1 r2i", 32),
    )


def derive_session_keys(
    *,
    psk: bytes,
    static_private: bytes,
    peer_static_public: bytes,
    ephemeral_private: bytes,
    peer_ephemeral_public: bytes,
    transcript: bytes,
    initiator: bool,
) -> tuple[SessionKeys, bytes]:
    """Run the full handshake KEX and return ``(keys, confirmation_tag)``.

    ``confirmation_tag`` binds the session to the exact transcript; both sides
    send it and compare, so a relay cannot splice two half-open sessions.

    The four Diffie-Hellman values are:

    ``mix1 = X25519(initiator_ephemeral, responder_static)``
    ``mix2 = X25519(initiator_static,    responder_ephemeral)``
    ``ee   = X25519(initiator_ephemeral, responder_ephemeral)``
    ``ss   = X25519(initiator_static,    responder_static)``

    Each side can only compute two of them directly: we always hold our own
    ephemeral and static keys and the peer's public halves, so a naive
    "ephemeral × peer-static" and "static × peer-ephemeral" pair comes out with
    ``mix1`` and ``mix2`` **swapped** for the responder.  Concatenating them in a
    fixed order would therefore derive two different masters.  ``initiator``
    exists to put them back in the agreed order — it is the whole reason this
    function takes a side.
    """
    if len(psk) != _PSK_SIZE:
        raise ConfigError(f"PSK must be {_PSK_SIZE} bytes, got {len(psk)}")

    own_ephemeral_with_peer_static = x25519_shared(ephemeral_private, peer_static_public)
    own_static_with_peer_ephemeral = x25519_shared(static_private, peer_ephemeral_public)
    ephemeral_ephemeral = x25519_shared(ephemeral_private, peer_ephemeral_public)
    static_static = x25519_shared(static_private, peer_static_public)

    if initiator:
        mix1, mix2 = own_ephemeral_with_peer_static, own_static_with_peer_ephemeral
    else:
        mix1, mix2 = own_static_with_peer_ephemeral, own_ephemeral_with_peer_static

    ikm = b"".join((psk, mix1, mix2, ephemeral_ephemeral, static_static))
    master = hkdf_sha256(ikm, salt=transcript, info=HANDSHAKE_LABEL, length=KEY_SIZE)
    keys = derive_from_master(master)
    return keys, hkdf_sha256(keys.confirm, None, b"self-check", 32)


def verify_confirmation(expected_tag: bytes, received_tag: bytes) -> None:
    """Raise if a peer's confirmation tag does not match."""
    from nfvpn.errors import HandshakeError

    if not constant_time_equals(expected_tag, received_tag):
        raise HandshakeError("handshake confirmation failed")
