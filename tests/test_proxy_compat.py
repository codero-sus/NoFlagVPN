"""The request shapes that *other* software sends.

Pointing one browser at the proxy is the easy case, and ``test_end_to_end.py``
covers it with a domain-name request.  Routing a whole device is a different
story: the things that do it - redsocks under a netfilter REDIRECT, an OS proxy
setting, a browser with "proxy DNS" on - send different bytes.  A redirector has
already lost the hostname (netfilter hands it an address, not a name) and sends
an IPv4 literal; a client with no username configured still offers the
username/password method; a game asks for UDP before it does anything else.

Each test here pins the answer the proxy gives to one of those, so the routing
recipes in ``docs/ROUTING.md`` rest on something checked rather than assumed.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from urllib.parse import urlsplit

from nfvpn.client.proxy import LocalAuth, LocalProxy
from nfvpn.config import ClientConfig


def free_port() -> int:
    """A port that was free a moment ago; the same helper conftest uses."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])

SOCKS_VERSION = 0x05
AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REPLY_SUCCEEDED = 0x00
REPLY_COMMAND_UNSUPPORTED = 0x07
REPLY_ATYP_UNSUPPORTED = 0x08


async def greet(port: int, methods: bytes = b"\x00") -> bytes:
    """Send a SOCKS5 greeting and return the server's method selection."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(bytes([SOCKS_VERSION, len(methods)]) + methods)
    await writer.drain()
    try:
        return await asyncio.wait_for(reader.readexactly(2), timeout=10)
    finally:
        writer.close()


async def request(port: int, atyp: int, payload: bytes, target_port: int):
    """A bare CONNECT; returns (reply code, open stream or None)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"

    writer.write(b"\x05\x01\x00" + bytes([atyp]) + payload + struct.pack(">H", target_port))
    await writer.drain()
    head = await asyncio.wait_for(reader.readexactly(4), timeout=20)
    code = head[1]
    if head[3] == ATYP_IPV4:
        await reader.readexactly(6)
    elif head[3] == ATYP_DOMAIN:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    else:
        await reader.readexactly(18)
    if code != REPLY_SUCCEEDED:
        writer.close()
        return code, None
    return code, (reader, writer)


async def fetch(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, path: str) -> bytes:
    """One GET through an already-connected stream."""
    writer.write(f"GET {path} HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    body = await asyncio.wait_for(reader.read(), timeout=20)
    writer.close()
    return body


def origin_port_of(rig) -> int:
    return int(urlsplit(rig.origin_url).port or 80)


async def test_an_ipv4_literal_works(rig):
    """redsocks and every transparent redirect send the address they were given."""
    code, stream = await request(rig.proxy_port, ATYP_IPV4, bytes([127, 0, 0, 1]), origin_port_of(rig))
    assert code == REPLY_SUCCEEDED
    assert stream is not None
    assert b"200 OK" in (await fetch(*stream, "/")).split(b"\r\n")[0]


async def test_an_ipv6_literal_is_understood(rig):
    """ATYP 4 is parsed, not answered with "address type not supported"."""
    code, _stream = await request(rig.proxy_port, ATYP_IPV6, bytes(15) + bytes([1]), origin_port_of(rig))
    assert code != REPLY_ATYP_UNSUPPORTED, "IPv6 literals must be understood"
    # ::1 is not the origin's address here, so a clean failure is the right answer.
    assert code != REPLY_SUCCEEDED


async def test_a_domain_request_still_works(rig):
    """The browser path, asserted next to the address forms above."""
    host = "localhost"
    code, stream = await request(
        rig.proxy_port, ATYP_DOMAIN, bytes([len(host)]) + host.encode(), origin_port_of(rig)
    )
    assert code == REPLY_SUCCEEDED
    assert stream is not None
    assert b"200" in (await fetch(*stream, "/")).split(b"\r\n")[0]


async def test_udp_associate_is_refused_with_the_documented_code(rig):
    """A game asks for UDP first; it must get 0x07, not a hang."""
    reader, writer = await asyncio.open_connection("127.0.0.1", rig.proxy_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    writer.write(b"\x05\x03\x00\x01" + bytes(4) + struct.pack(">H", 0))
    await writer.drain()
    reply = await asyncio.wait_for(reader.readexactly(10), timeout=10)
    writer.close()
    assert reply[1] == REPLY_COMMAND_UNSUPPORTED


async def test_bind_is_refused_with_the_documented_code(rig):
    reader, writer = await asyncio.open_connection("127.0.0.1", rig.proxy_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    writer.write(b"\x05\x02\x00\x01" + bytes(4) + struct.pack(">H", 0))
    await writer.drain()
    reply = await asyncio.wait_for(reader.readexactly(10), timeout=10)
    writer.close()
    assert reply[1] == REPLY_COMMAND_UNSUPPORTED


async def test_a_client_offering_only_password_auth_is_refused_when_none_is_set(rig):
    """An OS set to "always send credentials" must be told no clearly, not hang."""
    assert await greet(rig.proxy_port, methods=bytes([AUTH_USERPASS])) == bytes([SOCKS_VERSION, 0xFF])


async def test_credentials_are_enforced_when_configured(rig):
    """The --expose-lan path: wrong password rejected, right one gets the page."""
    config = ClientConfig(listen_host="127.0.0.1", listen_port=free_port(), log_level="critical")
    proxy = LocalProxy(rig.tunnel, config, auth=LocalAuth("neighbour", "letmein"))
    await proxy.start()
    try:
        assert await greet(config.listen_port, methods=bytes([AUTH_USERPASS, AUTH_NONE])) == bytes(
            [SOCKS_VERSION, AUTH_USERPASS]
        )
        assert await greet(config.listen_port, methods=bytes([AUTH_NONE])) == bytes(
            [SOCKS_VERSION, 0xFF]
        )

        async def try_auth(username: str, password: str) -> bytes:
            reader, writer = await asyncio.open_connection("127.0.0.1", config.listen_port)
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            assert await reader.readexactly(2) == bytes([SOCKS_VERSION, AUTH_USERPASS])
            writer.write(
                bytes([0x01, len(username)])
                + username.encode()
                + bytes([len(password)])
                + password.encode()
            )
            await writer.drain()
            answer = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            if answer[1] == 0:
                host = "localhost"
                writer.write(
                    b"\x05\x01\x00\x03"
                    + bytes([len(host)])
                    + host.encode()
                    + struct.pack(">H", origin_port_of(rig))
                )
                await writer.drain()
                reply = await asyncio.wait_for(reader.readexactly(4), timeout=20)
                return reply[1:2] + await fetch(reader, writer, "/")
            writer.close()
            return answer

        assert await try_auth("neighbour", "wrong") == b"\x01\x01"
        assert b"200 OK" in (await try_auth("neighbour", "letmein"))[1:]
    finally:
        await proxy.stop()
