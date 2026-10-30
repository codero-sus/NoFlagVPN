"""Boundary contracts for the built-in crypto backends and their selector."""
from __future__ import annotations

import os

import pytest
from nfvpn.core import primitives
from nfvpn.errors import AuthenticationError


def test_random_bytes_zero_and_negative_lengths():
    assert primitives.random_bytes(0) == b""
    with pytest.raises(ValueError, match="non-negative"):
        primitives.random_bytes(-1)


def test_constant_time_equality_handles_equal_and_different_lengths():
    assert primitives.constant_time_equals(b"same", b"same")
    assert not primitives.constant_time_equals(b"same", b"diff")
    assert not primitives.constant_time_equals(b"short", b"longer")


def test_poly1305_rejects_a_wrong_key_length():
    with pytest.raises(ValueError, match="Poly1305 key must be 32 bytes"):
        primitives.poly1305_mac(b"message", b"short")


@pytest.mark.parametrize(
    ("key", "nonce", "message", "error"),
    [
        (b"k" * 31, b"n" * 12, b"payload", "AEAD key must be 32 bytes"),
        (b"k" * 32, b"n" * 11, b"payload", "AEAD nonce must be 12 bytes"),
    ],
)
def test_aead_seal_rejects_invalid_key_and_nonce(key, nonce, message, error):
    with pytest.raises(ValueError, match=error):
        primitives.aead_seal(key, nonce, message)


@pytest.mark.parametrize(
    ("key", "nonce", "sealed", "error"),
    [
        (b"k" * 31, b"n" * 12, b"x" * 16, ValueError),
        (b"k" * 32, b"n" * 11, b"x" * 16, ValueError),
        (b"k" * 32, b"n" * 12, b"short", AuthenticationError),
    ],
)
def test_aead_open_rejects_invalid_inputs(key, nonce, sealed, error):
    with pytest.raises(error):
        primitives.aead_open(key, nonce, sealed)


def test_hkdf_expand_supports_empty_output_and_rfc_maximum():
    prk = bytes(range(32))
    assert primitives.hkdf_expand(prk, b"test", 0) == b""
    assert len(primitives.hkdf_expand(prk, b"test", 255 * 32)) == 255 * 32
    with pytest.raises(ValueError, match="out of range"):
        primitives.hkdf_expand(prk, b"test", -1)


def test_x25519_rejects_wrong_scalar_and_coordinate_sizes():
    with pytest.raises(ValueError, match="scalar must be 32 bytes"):
        primitives._clamp_scalar(b"short")
    with pytest.raises(ValueError, match="u-coordinate must be 32 bytes"):
        primitives._x25519_scalarmult(b"s" * 32, b"short")


def test_x25519_public_and_shared_keys_are_symmetric():
    alice_private = bytes(range(32))
    bob_private = bytes(range(32, 64))
    alice_public = primitives.x25519_base(alice_private)
    bob_public = primitives.x25519_base(bob_private)
    assert primitives.x25519(alice_private, bob_public) == primitives.x25519(
        bob_private, alice_public
    )


def test_crypto_backend_matches_x25519_and_normalizes_invalid_peer_points():
    try:
        backend = primitives.CryptographyBackend()
    except ImportError:
        pytest.skip("cryptography is not installed")
    alice_private = os.urandom(32)
    bob_private = os.urandom(32)
    alice_public = backend.x25519_base(alice_private)
    bob_public = backend.x25519_base(bob_private)
    assert backend.x25519(alice_private, bob_public) == backend.x25519(bob_private, alice_public)
    with pytest.raises(AuthenticationError, match="X25519 rejected the peer key"):
        backend.x25519(alice_private, bytes(32))


def test_crypto_backend_maps_invalid_aead_tags_to_authentication_error():
    try:
        backend = primitives.CryptographyBackend()
    except ImportError:
        pytest.skip("cryptography is not installed")
    sealed = backend.seal(b"k" * 32, b"n" * 12, b"payload", b"aad")
    assert backend.open(b"k" * 32, b"n" * 12, sealed, b"aad") == b"payload"
    with pytest.raises(AuthenticationError, match="AEAD authentication failed"):
        backend.open(b"k" * 32, b"n" * 12, sealed[:-1] + bytes([sealed[-1] ^ 1]), b"aad")


def test_backend_resolution_honours_pure_and_rejects_unknown_environment(monkeypatch):
    monkeypatch.setenv("NFVPN_CRYPTO_BACKEND", " PURE ")
    assert isinstance(primitives._resolve_backend(), primitives.PureBackend)
    monkeypatch.setenv("NFVPN_CRYPTO_BACKEND", "quantum")
    with pytest.raises(ValueError, match="unknown NFVPN_CRYPTO_BACKEND"):
        primitives._resolve_backend()


def test_backend_resolution_uses_auto_and_requested_acceleration(monkeypatch):
    class StubBackend:
        name = "stub"

    monkeypatch.setattr(primitives, "CryptographyBackend", StubBackend)
    monkeypatch.setenv("NFVPN_CRYPTO_BACKEND", "cryptography")
    assert isinstance(primitives._resolve_backend(), StubBackend)
    monkeypatch.setenv("NFVPN_CRYPTO_BACKEND", "auto")
    assert isinstance(primitives._resolve_backend(), StubBackend)
    monkeypatch.setenv("NFVPN_CRYPTO_BACKEND", "")
    assert isinstance(primitives._resolve_backend(), StubBackend)


def test_backend_resolution_falls_back_to_pure_if_crypto_import_fails(monkeypatch):
    def unavailable():
        raise ImportError("optional module missing")

    monkeypatch.setattr(primitives, "CryptographyBackend", unavailable)
    for requested in ("cryptography", "auto", ""):
        monkeypatch.setenv("NFVPN_CRYPTO_BACKEND", requested)
        assert isinstance(primitives._resolve_backend(), primitives.PureBackend)


def test_backend_is_resolved_once_and_can_be_pinned(monkeypatch):
    monkeypatch.setattr(primitives, "_active", None)
    monkeypatch.setattr(primitives, "_resolve_backend", lambda: primitives.PureBackend())
    first = primitives.get_backend()
    assert primitives.get_backend() is first
    assert primitives.backend_name() == "pure"
    accelerated = primitives.use_backend("cryptography")
    assert accelerated.name == "cryptography"
    assert primitives.get_backend() is accelerated


def test_use_backend_rejects_unknown_names():
    with pytest.raises(ValueError, match="unknown backend 'missing'"):
        primitives.use_backend("missing")


def test_pure_backend_open_uses_the_reference_aead():
    backend = primitives.PureBackend()
    key, nonce = b"k" * 32, b"n" * 12
    sealed = backend.seal(key, nonce, b"plaintext", b"aad")
    assert backend.open(key, nonce, sealed, b"aad") == b"plaintext"


def test_crypto_backend_rejects_a_zero_shared_result_even_if_provider_returns_it():
    from types import SimpleNamespace

    backend = object.__new__(primitives.CryptographyBackend)

    class Private:
        def exchange(self, public):
            return bytes(32)

    backend._private_key = SimpleNamespace(from_private_bytes=lambda key: Private())
    backend._public_key = SimpleNamespace(from_public_bytes=lambda key: object())
    with pytest.raises(AuthenticationError, match="all-zero shared secret"):
        backend.x25519(b"p" * 32, b"q" * 32)
