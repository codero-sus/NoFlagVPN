"""RFC 8439 (ChaCha20-Poly1305) and RFC 7748 (X25519), implemented from scratch.

Why hand-rolled crypto?
-----------------------
NoFlagVPN is meant to be launched on machines you do not control, in networks
that try to stop it.  Requiring a wheel with native code (or any third-party
package at all) is a deployment and trust cost that this project chose not to
pay.  Everything below is standard-library-only, small enough to audit in one
sitting, and pinned to the published RFC test vectors in
``tests/test_primitives.py`` — plus cross-checked against ``cryptography``
when that package happens to be installed.

Correctness notes
-----------------
* ChaCha20-Poly1305 follows RFC 8439 §2.8 exactly: 32-bit block counter, the
  Poly1305 one-time key taken from block 0, ciphertext stream starting at
  block 1, and the AAD/CT length footer appended little-endian.
* X25519 follows RFC 7748 §5: scalar clamping, Montgomery ladder on
  ``2^255 - 19``, and rejection of the all-zero (low-order) shared secret.
* Tag comparison is constant time (``hmac.compare_digest``).

Performance
-----------
The pure-Python inner loop reaches a few MB/s, which is fine for browsing,
game traffic and control channels.  If ``cryptography`` is importable, the
:class:`CryptographyBackend` is selected automatically and gives bulk speeds
in the hundreds of MB/s; the wire format is identical either way, so the two
backends interoperate freely.  Force one with ``NFVPN_CRYPTO_BACKEND=pure``
or ``NFVPN_CRYPTO_BACKEND=cryptography``.
"""

from __future__ import annotations

import hmac
import os
import struct
from hashlib import sha256
from typing import Protocol

from nfvpn.core.chacha import (  # noqa: F401  (re-exported for callers)
    BLOCK_SIZE as CHACHA_BLOCK_SIZE,
)
from nfvpn.core.chacha import (
    KEY_SIZE,
    NONCE_SIZE,
    chacha20_block,
    chacha20_keystream,
    chacha20_xor,
)
from nfvpn.errors import AuthenticationError

__all__ = [
    "AEAD_NONCE_SIZE",
    "AEAD_TAG_SIZE",
    "KEY_SIZE",
    "AuthenticationError",
    "backend_name",
    "chacha20_block",
    "chacha20_keystream",
    "chacha20_xor",
    "constant_time_equals",
    "hkdf_expand",
    "hkdf_extract",
    "hkdf_sha256",
    "hmac_sha256",
    "open_",
    "poly1305_mac",
    "random_bytes",
    "seal",
    "use_backend",
    "x25519",
    "x25519_base",
]

AEAD_NONCE_SIZE = NONCE_SIZE
AEAD_TAG_SIZE = 16
POLY1305_KEY_SIZE = 32

# X25519 / Curve25519 field parameters (RFC 7748 §4.1).
_P25519 = (1 << 255) - 19
_A24 = 121665


def random_bytes(count: int) -> bytes:
    """Return ``count`` cryptographically secure random bytes."""
    if count < 0:
        raise ValueError("count must be non-negative")
    return os.urandom(count)


def constant_time_equals(left: bytes, right: bytes) -> bool:
    """Constant-time byte comparison; ``False`` for a length mismatch."""
    return hmac.compare_digest(left, right)


# --------------------------------------------------------------------------- #
# Poly1305 (RFC 8439 §2.5)
# --------------------------------------------------------------------------- #
def poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    """Return the 16-byte Poly1305 tag of ``message`` under ``one_time_key``."""
    if len(one_time_key) != POLY1305_KEY_SIZE:
        raise ValueError(f"Poly1305 key must be {POLY1305_KEY_SIZE} bytes")

    r = int.from_bytes(one_time_key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time_key[16:], "little")
    accumulator = 0

    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        # Append the 0x01 byte *above* the block (i.e. add 2^(8*len(block))).
        accumulator += int.from_bytes(block, "little") + (1 << (8 * len(block)))
        accumulator = (accumulator * r) % ((1 << 130) - 5)

    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    """Zero padding that brings ``len(data)`` to a multiple of 16."""
    remainder = len(data) % 16
    return b"" if remainder == 0 else b"\x00" * (16 - remainder)


def _poly1305_aead_data(aad: bytes, ciphertext: bytes) -> bytes:
    """RFC 8439 §2.8 MAC input: aad ‖ pad ‖ ct ‖ pad ‖ len(aad) ‖ len(ct)."""
    return b"".join(
        (
            aad,
            _pad16(aad),
            ciphertext,
            _pad16(ciphertext),
            struct.pack("<Q", len(aad)),
            struct.pack("<Q", len(ciphertext)),
        )
    )


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt and authenticate; returns ``ciphertext ‖ tag`` (RFC 8439 §2.8)."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"AEAD key must be {KEY_SIZE} bytes")
    if len(nonce) != AEAD_NONCE_SIZE:
        raise ValueError(f"AEAD nonce must be {AEAD_NONCE_SIZE} bytes")

    one_time_key = chacha20_block(key, 0, nonce)[:POLY1305_KEY_SIZE]
    ciphertext = chacha20_xor(key, 1, nonce, plaintext)
    tag = poly1305_mac(_poly1305_aead_data(aad, ciphertext), one_time_key)
    return ciphertext + tag


def aead_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """Verify and decrypt ``sealed``; raises :class:`AuthenticationError`."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"AEAD key must be {KEY_SIZE} bytes")
    if len(nonce) != AEAD_NONCE_SIZE:
        raise ValueError(f"AEAD nonce must be {AEAD_NONCE_SIZE} bytes")
    if len(sealed) < AEAD_TAG_SIZE:
        raise AuthenticationError("ciphertext shorter than the authentication tag")

    ciphertext, tag = sealed[:-AEAD_TAG_SIZE], sealed[-AEAD_TAG_SIZE:]
    one_time_key = chacha20_block(key, 0, nonce)[:POLY1305_KEY_SIZE]
    expected = poly1305_mac(_poly1305_aead_data(aad, ciphertext), one_time_key)
    if not constant_time_equals(expected, tag):
        raise AuthenticationError("AEAD authentication failed")
    return chacha20_xor(key, 1, nonce, ciphertext)


# --------------------------------------------------------------------------- #
# HKDF-SHA256 (RFC 5869) and HMAC
# --------------------------------------------------------------------------- #
def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256."""
    return hmac.new(key, message, sha256).digest()


def hkdf_extract(salt: bytes | None, input_key_material: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 §2.2)."""
    return hmac_sha256(salt if salt else b"\x00" * sha256().digest_size, input_key_material)


def hkdf_expand(pseudorandom_key: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 §2.3)."""
    if length < 0 or length > 255 * sha256().digest_size:
        raise ValueError("HKDF output length out of range")
    output = bytearray()
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac_sha256(pseudorandom_key, block + info + bytes([counter]))
        output += block
        counter += 1
    return bytes(output[:length])


def hkdf_sha256(secret: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    """HKDF-Extract-then-Expand in one call."""
    return hkdf_expand(hkdf_extract(salt, secret), info, length)


# --------------------------------------------------------------------------- #
# X25519 (RFC 7748)
# --------------------------------------------------------------------------- #
def _clamp_scalar(scalar: bytes) -> bytes:
    if len(scalar) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    clamped = bytearray(scalar)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return bytes(clamped)


def _x25519_scalarmult(scalar: bytes, u_coordinate: bytes) -> bytes:
    """Constant-structure Montgomery ladder on Curve25519 (RFC 7748 §5)."""
    if len(u_coordinate) != 32:
        raise ValueError("X25519 u-coordinate must be 32 bytes")

    k = int.from_bytes(_clamp_scalar(scalar), "little")
    x1 = int.from_bytes(u_coordinate, "little") & ((1 << 255) - 1)

    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for bit in range(254, -1, -1):
        current = (k >> bit) & 1
        swap ^= current
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = current

        a = (x2 + z2) % _P25519
        aa = a * a % _P25519
        b = (x2 - z2) % _P25519
        bb = b * b % _P25519
        e = (aa - bb) % _P25519
        c = (x3 + z3) % _P25519
        d = (x3 - z3) % _P25519
        da = d * a % _P25519
        cb = c * b % _P25519

        x3 = (da + cb) ** 2 % _P25519
        z3 = x1 * ((da - cb) ** 2 % _P25519) % _P25519
        x2 = aa * bb % _P25519
        z2 = e * (aa + _A24 * e) % _P25519

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    shared = x2 * pow(z2, _P25519 - 2, _P25519) % _P25519
    return shared.to_bytes(32, "little")


def x25519(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Raw X25519 scalar multiplication.

    Raises :class:`AuthenticationError` if the result is the all-zero shared
    secret, which happens exactly when the peer sent a low-order point.  That
    check is what stops a "contribute nothing" attack from pinning the derived
    keys to a value the attacker knows.
    """
    shared = _x25519_scalarmult(private_key, peer_public_key)
    if shared == b"\x00" * 32:
        raise AuthenticationError("X25519 produced an all-zero shared secret (low-order point)")
    return shared


def x25519_base(private_key: bytes) -> bytes:
    """Derive the public key for ``private_key`` (u-coordinate 9, RFC 7748 §6.1)."""
    return _x25519_scalarmult(private_key, (9).to_bytes(32, "little"))


def generate_x25519_private_key() -> bytes:
    """A fresh clamped X25519 private key."""
    return _clamp_scalar(random_bytes(32))


# --------------------------------------------------------------------------- #
# Backend selection
# --------------------------------------------------------------------------- #
class CryptoBackend(Protocol):
    """The handful of primitives the protocol actually consumes."""

    name: str

    def seal(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...

    def open(self, key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes: ...

    def x25519(self, private_key: bytes, peer_public_key: bytes) -> bytes: ...

    def x25519_base(self, private_key: bytes) -> bytes: ...


class PureBackend:
    """Reference implementation. Always available, zero dependencies."""

    name = "pure"

    def seal(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return aead_seal(key, nonce, plaintext, aad)

    def open(self, key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
        return aead_open(key, nonce, sealed, aad)

    def x25519(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        return x25519(private_key, peer_public_key)

    def x25519_base(self, private_key: bytes) -> bytes:
        return x25519_base(private_key)


class CryptographyBackend:
    """Optional acceleration via ``cryptography`` (identical wire format)."""

    name = "cryptography"

    def __init__(self) -> None:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        self._cipher = ChaCha20Poly1305
        self._invalid_tag = InvalidTag
        self._private_key = X25519PrivateKey
        self._public_key = X25519PublicKey
        self._encoding = Encoding
        self._no_encryption = NoEncryption
        self._private_format = PrivateFormat
        self._public_format = PublicFormat

    def seal(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self._cipher(key).encrypt(nonce, plaintext, aad)

    def open(self, key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
        try:
            return self._cipher(key).decrypt(nonce, sealed, aad)
        except self._invalid_tag as exc:  # pragma: no cover - exercised in tests
            raise AuthenticationError("AEAD authentication failed") from exc

    def x25519(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        private = self._private_key.from_private_bytes(private_key)
        try:
            shared = private.exchange(self._public_key.from_public_bytes(peer_public_key))
        except ValueError as exc:
            raise AuthenticationError(f"X25519 rejected the peer key: {exc}") from exc
        if shared == b"\x00" * 32:
            raise AuthenticationError(
                "X25519 produced an all-zero shared secret (low-order point)"
            )
        return shared

    def x25519_base(self, private_key: bytes) -> bytes:
        private = self._private_key.from_private_bytes(private_key)
        return private.public_key().public_bytes(
            self._encoding.Raw, self._public_format.Raw
        )


_BACKENDS: dict[str, type] = {"pure": PureBackend, "cryptography": CryptographyBackend}
_active: CryptoBackend | None = None


def _resolve_backend() -> CryptoBackend:
    requested = os.environ.get("NFVPN_CRYPTO_BACKEND", "auto").strip().lower()
    if requested in _BACKENDS:
        if requested == "pure":
            return PureBackend()
        try:
            return CryptographyBackend()
        except ImportError:  # pragma: no cover - depends on the environment
            return PureBackend()
    if requested not in ("", "auto"):
        raise ValueError(
            f"unknown NFVPN_CRYPTO_BACKEND={requested!r}; expected auto, pure or cryptography"
        )

    try:
        return CryptographyBackend()
    except ImportError:
        return PureBackend()


def get_backend() -> CryptoBackend:
    """The active backend, resolved once per process."""
    global _active
    if _active is None:
        _active = _resolve_backend()
    return _active


def backend_name() -> str:
    """Name of the active backend (``pure`` or ``cryptography``)."""
    return get_backend().name


def use_backend(name: str) -> CryptoBackend:
    """Pin the backend; mainly for tests and benchmarks."""
    if name not in _BACKENDS:
        raise ValueError(f"unknown backend {name!r}; expected one of {sorted(_BACKENDS)}")
    global _active
    _active = _BACKENDS[name]()
    return _active


# Module-level entry points that every other module should use.
def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AEAD-encrypt with the active backend."""
    return get_backend().seal(key, nonce, plaintext, aad)


def open_(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """AEAD-decrypt with the active backend.  Named ``open_`` to spare the builtin."""
    return get_backend().open(key, nonce, sealed, aad)


def x25519_shared(private_key: bytes, peer_public_key: bytes) -> bytes:
    """X25519 with the active backend (raises on low-order points)."""
    return get_backend().x25519(private_key, peer_public_key)


def public_key_for(private_key: bytes) -> bytes:
    """Public key for ``private_key`` with the active backend."""
    return get_backend().x25519_base(private_key)
