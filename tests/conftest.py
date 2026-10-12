"""Shared fixtures.

The point of these is that every test starts from the same shape as a real
deployment: a relay identity, a client identity, a membership list and a
pre-shared key that the two of them agree on out of band.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from dataclasses import dataclass

import pytest
from nfvpn.client.proxy import LocalProxy
from nfvpn.client.tunnel import Tunnel
from nfvpn.config import ClientConfig, ServerConfig
from nfvpn.core.encoding import b64e
from nfvpn.core.keys import Identity, Member, MembershipStore, generate_psk, parse_psk
from nfvpn.selftest import start_origin
from nfvpn.server.egress import EgressPolicy
from nfvpn.server.relay import Relay

pytest_plugins: list[str] = []


def free_port() -> int:
    """A port that was free a moment ago; good enough for loopback tests."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class Rig:
    """A running relay + client + origin, for tests that need the whole thing."""

    relay: Relay
    tunnel: Tunnel
    proxy: LocalProxy
    proxy_port: int
    relay_port: int
    origin_url: str
    origin_port: int
    client_identity: Identity
    relay_identity: Identity
    psk: bytes
    origin: asyncio.AbstractServer


@pytest.fixture
def relay_identity() -> Identity:
    return Identity.generate("test-relay")


@pytest.fixture
def client_identity() -> Identity:
    return Identity.generate("test-client")


@pytest.fixture
def psk() -> bytes:
    return parse_psk(generate_psk())


@pytest.fixture
def membership(relay_identity: Identity, client_identity: Identity, psk: bytes) -> MembershipStore:
    store = MembershipStore()
    store.add(Member(name="test-client", public_key=client_identity.public_key, psk=psk))
    return store


@pytest.fixture
def relay_config() -> ServerConfig:
    return ServerConfig(
        listen_host="127.0.0.1",
        listen_port=free_port(),
        ws_path="/healthz",
        profile="balanced",
        log_level="critical",
        # The origin in these tests is on loopback, which the default policy
        # correctly refuses; the refusal itself is covered in test_egress.py.
        egress=EgressPolicy(allow_private_literals=True),
    )


@pytest.fixture
async def rig(relay_config, relay_identity, client_identity, membership, psk):
    """Bring up relay + client + proxy + origin, and tear them down after."""
    origin, origin_url = await start_origin()
    origin_port = int(origin_url.rsplit(":", 1)[1].strip("/"))

    relay = Relay(relay_config, relay_identity, membership)
    await relay.start()

    client_config = ClientConfig(
        relay=f"ws://127.0.0.1:{relay_config.listen_port}{relay_config.ws_path}",
        peer_public_key=b64e(relay_identity.public_key),
        psk=b64e(psk),
        listen_host="127.0.0.1",
        listen_port=free_port(),
        profile="balanced",
        log_level="critical",
    )
    tunnel = Tunnel(client_config, client_identity, psk, relay_identity.public_key)
    await tunnel.connect()
    proxy = LocalProxy(tunnel, client_config)
    await proxy.start()

    rig = Rig(
        relay=relay,
        tunnel=tunnel,
        proxy=proxy,
        proxy_port=client_config.listen_port,
        relay_port=relay_config.listen_port,
        origin_url=origin_url,
        origin_port=origin_port,
        client_identity=client_identity,
        relay_identity=relay_identity,
        psk=psk,
        origin=origin,
    )
    try:
        yield rig
    finally:
        with contextlib.suppress(Exception):
            await proxy.stop()
        with contextlib.suppress(Exception):
            await tunnel.close()
        with contextlib.suppress(Exception):
            await relay.stop()
        origin.close()
        with contextlib.suppress(Exception):
            await origin.wait_closed()
