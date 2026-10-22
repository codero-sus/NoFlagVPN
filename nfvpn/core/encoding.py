"""Compact, copy-pasteable encodings used for keys, tokens and fingerprints."""

from __future__ import annotations

import base64
import binascii

from nfvpn.errors import EncodingError

__all__ = ["b64d", "b64e", "fingerprint", "group_hex", "safety_number", "short_id"]

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford-ish, no I/L/O/U


def b64e(raw: bytes) -> str:
    """URL-safe base64 without padding — the canonical encoding for keys."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    """Decode :func:`b64e` output, tolerating padding and stray whitespace."""
    cleaned = "".join(text.split())
    padding = "=" * (-len(cleaned) % 4)
    try:
        # urlsafe_b64decode() ignores every non-alphabet byte by default.  That
        # turns a corrupted key like ``Zm9v$YmFy`` into valid ``foobar`` bytes,
        # so use the same alphabet with strict validation after whitespace has
        # already been removed intentionally above.
        return base64.b64decode(cleaned + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EncodingError(
            f"not valid base64url: {text[:16]}… — check for a truncated copy/paste"
        ) from exc


def group_hex(raw: bytes, group: int = 4) -> str:
    """Lowercase hex in groups: ``a1b2 c3d4 …`` — for reading aloud."""
    digest = raw.hex()
    return " ".join(digest[i : i + group] for i in range(0, len(digest), group))


def fingerprint(raw: bytes, group: int = 4) -> str:
    """A stable, non-secret 160-bit name for a public key (full SHA-256 prefix)."""
    from hashlib import sha256

    return group_hex(sha256(b"nfvpn-fingerprint\x00" + raw).digest()[:20], group)


def short_id(raw: bytes, length: int = 8) -> str:
    """The compact form shown in tables and logs."""
    from hashlib import sha256

    digest = sha256(b"nfvpn-fingerprint\x00" + raw).digest()
    value = int.from_bytes(digest[:8], "big")
    out = []
    for _ in range(length):
        out.append(_ALPHABET[value % 32])
        value //= 32
    return "".join(out)


def safety_number(left: bytes, right: bytes, digits: int = 12) -> str:
    """A symmetric short code two people can compare out of band.

    Sorting the two key fingerprints first is what makes it symmetric: both
    sides compute the same code regardless of who dialled whom.
    """
    from hashlib import sha256

    first, second = sorted((sha256(left).digest(), sha256(right).digest()))
    digest = sha256(b"nfvpn-safety-number\x00" + first + second).digest()
    number = int.from_bytes(digest[:8], "big") % (10**digits)
    text = str(number).rjust(digits, "0")
    return " ".join(text[i : i + 4] for i in range(0, len(text), 4))
