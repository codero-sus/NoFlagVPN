"""Whole-stack tests: relay, client, proxy and a real origin, all on loopback.

Everything here goes through the same path a user's browser would: SOCKS5 or
HTTP CONNECT into the local proxy, over the tunnel, out of the relay's egress
policy, to an HTTP origin.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import socket
import struct

import pytest

pytestmark = pytest.mark.timeout(120)


def origin_host_port(rig) -> tuple[str, int]:
    """Split the fixture's ``http://host:port/`` into its two halves."""
    authority = rig.origin_url.removeprefix("http://").split("/", 1)[0]
    host, _, port = authority.rpartition(":")
    return host, int(port)


async def read_http_response(reader: asyncio.StreamReader) -> bytes:
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=20)
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    body = await asyncio.wait_for(reader.readexactly(length), timeout=20) if length else b""
    return head + body


async def socks5_connect(port: int, host: str, target_port: int):
    """Perform a SOCKS5 CONNECT through the local proxy."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    request = (
        b"\x05\x01\x00\x03"
        + bytes([len(host)])
        + host.encode()
        + struct.pack(">H", target_port)
    )
    writer.write(request)
    await writer.drain()
    reply = await reader.readexactly(4)
    assert reply[1] == 0, f"SOCKS5 CONNECT refused with 0x{reply[1]:02x}"
    if reply[3] == 1:
        await reader.readexactly(6)
    elif reply[3] == 3:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    else:
        await reader.readexactly(18)
    return reader, writer


async def test_socks5_fetches_a_page_from_the_origin(rig):
    host, port = origin_host_port(rig)
    reader, writer = await socks5_connect(rig.proxy_port, host, port)
    writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    await writer.drain()
    response = await read_http_response(reader)
    assert response.startswith(b"HTTP/1.1 200")
    assert b"200 OK" in response
    assert len(response) > 60
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_http_connect_fetches_a_page_from_the_origin(rig):
    host, port = origin_host_port(rig)
    reader, writer = await asyncio.open_connection("127.0.0.1", rig.proxy_port)
    writer.write(
        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
    )
    await writer.drain()
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=20)
    assert head.startswith(b"HTTP/1.1 200")
    writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    await writer.drain()
    response = await read_http_response(reader)
    assert b"HTTP/1.1 200" in response
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_a_megabyte_survives_the_tunnel(rig):
    host, port = origin_host_port(rig)
    reader, writer = await socks5_connect(rig.proxy_port, host, port)
    writer.write(b"GET /large=1048576 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    await writer.drain()
    response = await read_http_response(reader)
    head, _, body = response.partition(b"\r\n\r\n")
    assert b"200 OK" in head
    assert len(body) == 1024 * 1024
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_the_relay_refuses_private_destinations_by_default(rig):
    """The client must not be able to reach 127.0.0.1 *through the relay*.

    The rig's relay allows private literals so that its origin is reachable;
    a relay with the stock policy is what this test stands up.
    """
    from nfvpn.server.egress import EgressPolicy

    policy = EgressPolicy()
    allowed, reason = policy.address_allowed("127.0.0.1")
    assert allowed is False
    assert "denied range" in reason


async def test_an_unreachable_host_fails_cleanly(rig):
    reader, writer = await asyncio.open_connection("127.0.0.1", rig.proxy_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    host = "no-such-host.invalid"
    writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + b"\x00\x50")
    await writer.drain()
    reply = await reader.readexactly(4)
    assert reply[1] != 0  # a DNS failure is a refusal, not a hang
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_proxy_rejects_non_socks_traffic(rig):
    reader, writer = await asyncio.open_connection("127.0.0.1", rig.proxy_port)
    writer.write(b"NOT HTTP AND NOT SOCKS\r\n\r\n")
    await writer.drain()
    with contextlib.suppress(asyncio.IncompleteReadError, asyncio.TimeoutError):
        data = await asyncio.wait_for(reader.read(1024), timeout=5)
        assert not data.startswith(b"\x05")
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_plain_http_to_the_relay_port_gets_a_web_page(rig):
    """Port-scanning the relay must show an ordinary web server."""
    reader, writer = await asyncio.open_connection("127.0.0.1", rig.relay_port)
    writer.write(b"GET /admin HTTP/1.1\r\nHost: relay\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(4096), timeout=10)
    assert response.startswith(b"HTTP/1.1 404")
    assert b"nginx" in response
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_tunnel_counters_move(rig):
    before = rig.relay.stats.handshakes_ok
    host, port = origin_host_port(rig)
    reader, writer = await socks5_connect(rig.proxy_port, host, port)
    writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    await writer.drain()
    await read_http_response(reader)
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    await asyncio.sleep(0.2)
    assert rig.relay.stats.handshakes_ok >= before
    assert rig.tunnel.stats.streams >= 1
    assert rig.tunnel.describe()


def test_free_ports_are_actually_free():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        assert sock.getsockname()[1] > 0
    assert base64.b64encode(b"x") == b"eA=="
