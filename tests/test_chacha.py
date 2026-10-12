"""The two ChaCha20 kernels must agree, always.

The packed kernel exists purely for speed; the scalar one is the definition the
RFC vectors pin.  A difference between them would be a catastrophic, silent bug,
so the differential test below is exhaustive about the shapes that could break
the lane masking: payloads that are shorter than one batch, exactly one batch,
and longer with a tail.
"""

from __future__ import annotations

import os
import random

import pytest
from nfvpn.core import chacha

#: Lengths chosen to straddle every interesting boundary: the 64-byte block, the
#: 16-block packed batch, and awkward tails on both sides of each.
LENGTHS = [
    0,
    1,
    2,
    63,
    64,
    65,
    127,
    128,
    129,
    1023,
    1024,
    1025,
    chacha.BLOCK_SIZE * chacha.PACKED_LANES - 1,
    chacha.BLOCK_SIZE * chacha.PACKED_LANES,
    chacha.BLOCK_SIZE * chacha.PACKED_LANES + 1,
    chacha.BLOCK_SIZE * chacha.PACKED_LANES * 3 + 7,
]


def scalar_keystream(key: bytes, counter: int, nonce: bytes, length: int) -> bytes:
    blocks = (length + chacha.BLOCK_SIZE - 1) // chacha.BLOCK_SIZE
    return b"".join(
        chacha.chacha20_block(key, counter + index, nonce) for index in range(blocks)
    )[:length]


@pytest.mark.parametrize("length", LENGTHS)
def test_packed_matches_scalar(length):
    key, nonce = os.urandom(32), os.urandom(12)
    counter = random.randrange(0, 2**24)
    assert chacha.chacha20_keystream(key, counter, nonce, length) == scalar_keystream(
        key, counter, nonce, length
    )


def test_packed_matches_scalar_on_random_inputs():
    rng = random.Random(20241012)
    for _ in range(60):
        key, nonce = os.urandom(32), os.urandom(12)
        counter = rng.randrange(0, 2**32 - 4096)
        length = rng.choice([*LENGTHS, rng.randrange(1, 40000)])
        assert chacha.chacha20_keystream(key, counter, nonce, length) == scalar_keystream(
            key, counter, nonce, length
        ), (length, counter)


def test_xor_is_its_own_inverse():
    key, nonce = os.urandom(32), os.urandom(12)
    payload = os.urandom(9000)
    ciphertext = chacha.chacha20_xor(key, 1, nonce, payload)
    assert ciphertext != payload
    assert chacha.chacha20_xor(key, 1, nonce, ciphertext) == payload


def test_counter_changes_the_keystream():
    key, nonce = os.urandom(32), os.urandom(12)
    assert chacha.chacha20_block(key, 7, nonce) != chacha.chacha20_block(key, 8, nonce)


def test_forcing_the_scalar_kernel_gives_the_same_bytes(monkeypatch):
    key, nonce = os.urandom(32), os.urandom(12)
    payload = os.urandom(5000)
    packed = chacha.chacha20_xor(key, 0, nonce, payload)
    monkeypatch.setattr(chacha, "_FORCE_SCALAR", True)
    assert chacha.chacha20_xor(key, 0, nonce, payload) == packed
    assert chacha.packed_kernel_available() is False


def test_input_validation():
    key, nonce = bytes(32), bytes(12)
    with pytest.raises(ValueError):
        chacha.chacha20_block(key[:31], 0, nonce)
    with pytest.raises(ValueError):
        chacha.chacha20_block(key, 0, nonce[:11])
    with pytest.raises(ValueError):
        chacha.chacha20_block(key, -1, nonce)
    with pytest.raises(ValueError):
        chacha.chacha20_keystream(key, 2**32 - 1, nonce, 1024)
    with pytest.raises(ValueError):
        chacha.chacha20_keystream(key, 0, nonce, -5)


def test_bigint_xor_path_is_used_for_large_buffers():
    """The fast path must still be correct for sizes around its threshold."""
    key, nonce = os.urandom(32), os.urandom(12)
    for size in (255, 256, 257, 4096):
        payload = os.urandom(size)
        stream = chacha.chacha20_keystream(key, 1, nonce, size)
        expected = bytes(a ^ b for a, b in zip(payload, stream, strict=True))
        assert chacha.chacha20_xor(key, 1, nonce, payload) == expected


def test_rfc_vector_through_both_kernels():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    expected = bytes.fromhex("10f1e7e4d13b5915500fdd1fa32071c4")
    assert chacha.chacha20_block(key, 1, nonce).startswith(expected)
    assert chacha.chacha20_keystream(key, 1, nonce, 16) == expected
