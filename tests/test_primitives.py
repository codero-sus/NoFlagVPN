"""Primitives against the published test vectors.

Every expected value in this file is copied from an RFC.  These are the tests
that would catch a mistake in the crypto; everything else in the project assumes
they pass.
"""

from __future__ import annotations

import os

import pytest
from nfvpn.core import primitives
from nfvpn.errors import AuthenticationError

# RFC 8439 §2.3.2 / §2.4.2 / §2.5.2 / §2.8.2 -----------------------------------

SUNSCREEN = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you "
    b"only one tip for the future, sunscreen would be it."
)


def test_chacha20_block_function_vector():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert primitives.chacha20_block(key, 1, nonce) == expected


def test_chacha20_encryption_vector():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    )
    assert primitives.chacha20_xor(key, 1, nonce, SUNSCREEN) == expected
    assert primitives.chacha20_xor(key, 1, nonce, expected) == SUNSCREEN


def test_poly1305_vector():
    key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    message = b"Cryptographic Forum Research Group"
    assert primitives.poly1305_mac(message, key).hex() == "a8061dc1305136c6c22b8baf0c0127a9"


def test_aead_vector():
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    sealed = primitives.aead_seal(key, nonce, SUNSCREEN, aad)
    ciphertext = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
    )
    assert sealed == ciphertext + bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
    assert primitives.aead_open(key, nonce, sealed, aad) == SUNSCREEN


def test_aead_rejects_tampering():
    key, nonce = os.urandom(32), os.urandom(12)
    sealed = bytearray(primitives.aead_seal(key, nonce, b"payload", b"header"))
    sealed[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        primitives.aead_open(key, nonce, bytes(sealed), b"header")


def test_aead_rejects_wrong_aad():
    key, nonce = os.urandom(32), os.urandom(12)
    sealed = primitives.aead_seal(key, nonce, b"payload", b"right")
    with pytest.raises(AuthenticationError):
        primitives.aead_open(key, nonce, sealed, b"wrong")


# RFC 7748 §5.2 -----------------------------------------------------------------


def test_x25519_vectors():
    alice_private = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    alice_public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    bob_private = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    bob_public = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    assert primitives.x25519_base(alice_private) == alice_public
    assert primitives.x25519_base(bob_private) == bob_public
    assert primitives.x25519(alice_private, bob_public) == shared
    assert primitives.x25519(bob_private, alice_public) == shared


def test_x25519_rejects_low_order_points():
    private = os.urandom(32)
    for low_order in (b"\x00" * 32, (1).to_bytes(32, "little")):
        with pytest.raises(AuthenticationError):
            primitives.x25519(private, low_order)


# RFC 5869 ---------------------------------------------------------------------


def test_hkdf_sha256_vector():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = primitives.hkdf_sha256(ikm, salt, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_hkdf_expand_limits():
    prk = bytes(32)
    with pytest.raises(ValueError):
        primitives.hkdf_expand(prk, b"", 255 * 32 + 1)


# backend equivalence -----------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 1024, 65536])
def test_backends_agree(size):
    key, nonce, aad = os.urandom(32), os.urandom(12), os.urandom(7)
    payload = os.urandom(size)
    primitives.use_backend("pure")
    pure_sealed = primitives.seal(key, nonce, payload, aad)
    try:
        primitives.use_backend("cryptography")
    except Exception:  # pragma: no cover - accelerated backend is optional
        pytest.skip("cryptography is not installed")
    assert primitives.seal(key, nonce, payload, aad) == pure_sealed
    assert primitives.open_(key, nonce, pure_sealed, aad) == payload
    primitives.use_backend("pure")


def test_unknown_backend_is_rejected():
    with pytest.raises(ValueError):
        primitives.use_backend("quantum")
