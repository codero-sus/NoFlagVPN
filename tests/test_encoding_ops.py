"""Copy/paste encodings must be forgiving about whitespace, not corrupted bytes."""
from __future__ import annotations

import pytest
from nfvpn.core.encoding import b64d, b64e
from nfvpn.errors import EncodingError


def test_base64url_accepts_canonical_unpadded_and_padded_forms():
    payload = bytes(range(32))
    encoded = b64e(payload)
    assert b64d(encoded) == payload
    assert b64d(encoded + "=") == payload
    assert b64d("  " + encoded[:12] + " \n" + encoded[12:] + "  ") == payload


@pytest.mark.parametrize("text", ["Zm9v$YmFy", "Zm9v*YmFy", "Zm9v!YmFy"])
def test_base64url_rejects_non_alphabet_characters_instead_of_silently_ignoring_them(text):
    with pytest.raises(EncodingError, match="not valid base64url"):
        b64d(text)


def test_base64url_rejects_impossible_lengths():
    with pytest.raises(EncodingError, match="not valid base64url"):
        b64d("a")
