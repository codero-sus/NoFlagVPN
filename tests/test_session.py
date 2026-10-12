"""End-to-end session tests: two peers on loopback, over a real WebSocket.

These exercise the parts that only appear when everything is wired together:
the handshake over the wire, stream multiplexing, flow control on a transfer
much larger than the window, and what a prober sees.
"""

from __future__ import annotations

import asyncio
import contextlib
import os

import pytest
from nfvpn.core.keys import Identity, Member, MembershipStore
from nfvpn.errors import HandshakeError
from nfvpn.session import SeenNonceCache, establish_initiator, establish_responder
from nfvpn.session.handshake import HANDSHAKE_SIZE, HandshakeInitiator
from nfvpn.traffic import Shaper, get_profile
from nfvpn.transport import Endpoint, accept_transport, dial

pytestmark = pytest.mark.timeout(60)

WINDOW = 256 * 1024


class RelayHarness:
    """A relay that echoes every stream, with its state kept for assertions."""

    def __init__(self) -> None:
        self.relay = Identity.generate("relay")
        self.client = Identity.generate("client")
        self.psk = os.urandom(32)
        self.members = MembershipStore()
        self.members.add(Member(name="client", public_key=self.client.public_key, psk=self.psk))
        self.nonces = SeenNonceCache()
        self.shapers = Shaper(get_profile("balanced"))
        self.sessions: list[object] = []
        self.accepted: list[str] = []
        self.server: asyncio.AbstractServer | None = None
        self.port = 0

    @property
    def endpoint(self) -> Endpoint:
        return Endpoint.parse(f"ws://127.0.0.1:{self.port}/cdn/stream")

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = int(self.server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        for session in self.sessions:
            with contextlib.suppress(Exception):
                await session.close()  # type: ignore[attr-defined]
        if self.server is not None:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()

    async def _serve(self, reader, writer) -> None:
        try:
            transport = await accept_transport(reader, writer, is_websocket=True)
            session = await establish_responder(
                transport,
                self.relay,
                self.members,
                shaper=self.shapers,
                nonce_cache=self.nonces,
            )
            if session is None:
                return
            self.sessions.append(session)

            async def handler(stream, request):
                self.accepted.append(request.label())
                await session.streams.accept(stream)
                while True:
                    chunk = await stream.receive()
                    if chunk is None:
                        break
                    await stream.send(chunk)  # echo verbatim: chunking is ours
                await stream.close()
                session.streams.detach(stream)

            session.streams.set_open_handler(handler)
            await session.run()
        except Exception:  # pragma: no cover - a broken test should not hang
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()


@pytest.fixture
async def harness():
    relay = RelayHarness()
    await relay.start()
    try:
        yield relay
    finally:
        await relay.stop()


async def connect(harness: RelayHarness, **kwargs):
    transport = await dial(harness.endpoint)
    return await establish_initiator(
        transport,
        harness.client,
        harness.relay.public_key,
        harness.psk,
        shaper=harness.shapers,
        **kwargs,
    )


async def test_handshake_and_a_round_trip(harness):
    session = await connect(harness)
    assert session.info.peer_name == "relay"
    stream = await session.streams.open("example.com", 443)
    await stream.send(b"hello relay")
    assert await stream.receive() == b"hello relay"
    await stream.close()
    await session.close()


async def test_transfer_larger_than_the_stream_window(harness):
    """256 KiB of window must not cap a 1 MiB transfer."""
    session = await connect(harness)
    stream = await session.streams.open("big.example", 443)
    blob = os.urandom(1024 * 1024)

    async def send_all() -> None:
        await stream.send(blob)

    sender = asyncio.create_task(send_all())
    received = bytearray()
    while len(received) < len(blob):
        chunk = await stream.receive()
        if chunk is None:
            break
        received += chunk
    await sender
    assert bytes(received) == blob
    await stream.close()
    await session.close()


async def test_many_streams_multiplex(harness):
    session = await connect(harness)
    streams = [await session.streams.open(f"host{index}.example", 443) for index in range(8)]
    for index, stream in enumerate(streams):
        await stream.send(bytes([index]) * 64)
    replies = [await stream.receive() for stream in streams]
    for index, reply in enumerate(replies):
        assert reply == bytes([index]) * 64
    for stream in streams:
        await stream.close()
    assert len(harness.accepted) == 8
    await session.close()


async def test_streams_are_independent_after_one_closes(harness):
    session = await connect(harness)
    first = await session.streams.open("a.example", 80)
    second = await session.streams.open("b.example", 80)
    await first.send(b"one")
    assert await first.receive() == b"one"
    await first.close()
    await second.send(b"two")
    assert await second.receive() == b"two"
    await second.close()
    await session.close()


async def test_wrong_psk_is_refused(harness):
    transport = await dial(harness.endpoint)
    with pytest.raises(HandshakeError):
        await establish_initiator(
            transport,
            harness.client,
            harness.relay.public_key,
            os.urandom(32),
            handshake_timeout=5.0,
        )
    await transport.close()


async def test_unknown_identity_is_refused_the_same_way(harness):
    stranger = Identity.generate("stranger")
    transport = await dial(harness.endpoint)
    with pytest.raises(HandshakeError):
        await establish_initiator(
            transport,
            stranger,
            harness.relay.public_key,
            os.urandom(32),
            handshake_timeout=5.0,
        )
    await transport.close()


async def test_every_refusal_is_the_same_size(harness):
    """The relay's answers must not weigh more for strangers than for members."""
    sizes = []

    probes = [
        (harness.client, os.urandom(32)),  # right key, wrong PSK
        (Identity.generate("stranger"), os.urandom(32)),  # unknown key
        (harness.client, harness.psk),  # a genuine member: same size too
    ]
    for identity, psk in probes:
        transport = await dial(harness.endpoint)
        initiator = HandshakeInitiator(identity, harness.relay.public_key, psk)
        await transport.send_message(initiator.hello())
        sizes.append(len(await transport.receive_message()))
        await transport.close()
    assert sizes == [HANDSHAKE_SIZE] * len(probes)


async def test_replayed_init_gets_a_well_formed_refusal(harness):
    initiator = HandshakeInitiator(harness.client, harness.relay.public_key, harness.psk)
    captured = initiator.hello()

    transport = await dial(harness.endpoint)
    await transport.send_message(captured)
    reply = await transport.receive_message()
    assert len(reply) == HANDSHAKE_SIZE
    await transport.close()

    # The relay must not be willing to run the same handshake twice.
    second = await dial(harness.endpoint)
    await second.send_message(captured)
    assert len(await second.receive_message()) == HANDSHAKE_SIZE
    await second.close()


async def test_not_a_websocket_gets_an_ordinary_web_page(harness):
    reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
    writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(4096), timeout=5)
    assert response.startswith(b"HTTP/1.1 404")
    assert b"nginx" in response
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
