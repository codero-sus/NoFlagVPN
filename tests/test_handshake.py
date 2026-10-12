"""The handshake: what it proves, and what it refuses to leak."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import pytest
from nfvpn.core.keys import Identity, Member, MembershipStore, generate_psk, parse_psk
from nfvpn.errors import HandshakeError
from nfvpn.framing.constants import PROTOCOL_VERSION
from nfvpn.session.handshake import (
    HANDSHAKE_SIZE,
    MAX_CLOCK_SKEW,
    HandshakeInitiator,
    HandshakeMessage,
    HandshakeResponder,
    ResponderAnswer,
    SeenNonceCache,
)


@pytest.fixture
def relay() -> Identity:
    return Identity.generate("relay")


@pytest.fixture
def client() -> Identity:
    return Identity.generate("client")


@pytest.fixture
def psk() -> bytes:
    return parse_psk(generate_psk())


@pytest.fixture
def membership(client: Identity, psk: bytes) -> MembershipStore:
    store = MembershipStore()
    store.add(Member(name="client", public_key=client.public_key, psk=psk))
    return store


@dataclass
class Exchange:
    """One complete handshake attempt, kept whole so tests can inspect any part."""

    initiator: HandshakeInitiator
    responder: HandshakeResponder
    init: bytes
    answer: ResponderAnswer


def do_handshake(relay, client, membership, psk, **kwargs) -> Exchange:
    initiator = HandshakeInitiator(client, relay.public_key, psk, **kwargs)
    responder = HandshakeResponder(relay, membership)
    init = initiator.hello()
    answer = responder.answer(init)
    return Exchange(initiator, responder, init, answer)


def test_happy_path_derives_the_same_keys(relay, client, membership, psk):
    exchange = do_handshake(relay, client, membership, psk)
    assert exchange.answer.authorized is True
    assert exchange.answer.peer_name == "client"
    keys, confirmation = exchange.initiator.finish(exchange.answer.message)
    assert keys == exchange.answer.keys
    assert confirmation == exchange.answer.confirmation


def test_both_messages_are_exactly_128_bytes(relay, client, membership, psk):
    exchange = do_handshake(relay, client, membership, psk)
    assert len(exchange.init) == HANDSHAKE_SIZE
    assert len(exchange.answer.message) == HANDSHAKE_SIZE
    assert len(HandshakeMessage.unpack(exchange.init).mac) == 16


def test_confirmation_tag_is_verified(relay, client, membership, psk):
    answer = do_handshake(relay, client, membership, psk).answer
    assert answer.confirmation is not None
    HandshakeResponder.verify_confirmation(answer.confirmation, answer.confirmation)
    with pytest.raises(HandshakeError):
        HandshakeResponder.verify_confirmation(answer.confirmation, os.urandom(16))


def test_unknown_peer_is_refused_but_replied_to(relay, client, membership, psk):
    stranger = Identity.generate("stranger")
    initiator = HandshakeInitiator(stranger, relay.public_key, psk)
    responder = HandshakeResponder(relay, membership)
    answer = responder.answer(initiator.hello())
    assert answer.authorized is False
    assert answer.keys is None
    # The reply is still a well-formed RESP carrying the relay's real key: a
    # prober learns "something is here", never "you were rejected".
    assert len(answer.message) == HANDSHAKE_SIZE
    message = HandshakeMessage.unpack(answer.message)
    assert message.static_public == relay.public_key


def test_wrong_psk_is_refused_with_an_indistinguishable_reply(relay, client, membership, psk):
    initiator = HandshakeInitiator(client, relay.public_key, b"\x11" * 32)
    responder = HandshakeResponder(relay, membership)
    answer = responder.answer(initiator.hello())
    assert answer.authorized is False
    assert len(answer.message) == HANDSHAKE_SIZE


def test_refusals_all_look_the_same(relay, client, membership, psk):
    """Every refusal path must produce the same shape of reply."""
    responder = HandshakeResponder(relay, membership)
    replies = []

    replies.append(responder.answer(b"\x00" * 40).message)  # malformed
    wrong_version = bytearray(HandshakeInitiator(client, relay.public_key, psk).hello())
    wrong_version[0] = PROTOCOL_VERSION + 1
    replies.append(responder.answer(bytes(wrong_version)).message)
    replies.append(responder.answer(HandshakeInitiator(Identity.generate("x"), relay.public_key, psk).hello()).message)
    replies.append(responder.answer(HandshakeInitiator(client, relay.public_key, b"\x22" * 32).hello()).message)

    assert len({len(reply) for reply in replies}) == 1
    assert all(len(reply) == HANDSHAKE_SIZE for reply in replies)


def test_clock_skew_is_bounded(relay, client, membership, psk):
    responder = HandshakeResponder(relay, membership)
    initiator = HandshakeInitiator(client, relay.public_key, psk, now=time.time() - MAX_CLOCK_SKEW - 60)
    assert responder.answer(initiator.hello()).authorized is False

    fresh = HandshakeInitiator(client, relay.public_key, psk, now=time.time() + MAX_CLOCK_SKEW - 10)
    assert responder.answer(fresh.hello()).authorized is True


def test_replayed_init_is_refused(relay, client, membership, psk):
    responder = HandshakeResponder(relay, membership)
    initiator = HandshakeInitiator(client, relay.public_key, psk)
    init = initiator.hello()
    assert responder.answer(init).authorized is True
    second = responder.answer(init)
    assert second.authorized is False
    assert "replay" in second.reason


def test_revoked_member_is_refused(relay, client, membership, psk):
    membership.revoke(client.public_key)
    answer = do_handshake(relay, client, membership, psk).answer
    assert answer.authorized is False
    assert answer.keys is None


def test_pinned_key_mismatch_is_caught_client_side(relay, client, membership, psk):
    other_relay = Identity.generate("other-relay")
    initiator = HandshakeInitiator(client, other_relay.public_key, psk)
    responder = HandshakeResponder(relay, membership)
    answer = responder.answer(initiator.hello())
    assert answer.authorized is True  # the relay is genuine...
    with pytest.raises(HandshakeError, match="pinned"):
        initiator.finish(answer.message)  # ...but not the one we pinned


def test_tampered_init_does_not_verify(relay, client, membership, psk):
    responder = HandshakeResponder(relay, membership)
    init = bytearray(HandshakeInitiator(client, relay.public_key, psk).hello())
    init[70] ^= 0x01
    assert responder.answer(bytes(init)).authorized is False


def test_seen_nonce_cache_is_bounded():
    cache = SeenNonceCache(capacity=4)
    peer = os.urandom(32)
    assert all(cache.check_and_add(peer, bytes([index]) * 16) for index in range(4))
    assert cache.check_and_add(peer, b"\x02" * 16) is False
    assert cache.check_and_add(peer, b"\x09" * 16) is True  # evicts the oldest
    assert len(cache) == 4
    assert cache.check_and_add(peer, b"\x00" * 16) is True  # evicted, so new again


def test_forward_secrecy_between_sessions(relay, client, membership, psk):
    """Two sessions between the same peers must not share key material."""
    first = do_handshake(relay, client, membership, psk).answer
    second = do_handshake(relay, client, membership, psk).answer
    assert first.keys != second.keys
    assert first.keys.initiator_to_responder != second.keys.initiator_to_responder
    assert first.message != second.message
