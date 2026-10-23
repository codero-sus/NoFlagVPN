"""The local proxy your applications connect to.

One port, two protocols, because that is what "point the browser at it" means in
practice: Firefox and Chrome speak SOCKS5 *and* HTTP proxies, and different
tools speak different ones.  The first byte decides — ``0x05`` is SOCKS5, a
printable ASCII letter is an HTTP request method — so both work on the same
address with no second port to explain to anyone.

Two things this deliberately does **not** do:

* It never resolves a hostname locally.  Names travel to the relay as names, so
  your DNS traffic does not leak to your ISP and a split-horizon resolver cannot
  quietly point you at a different site.  The honest cost: the relay learns the
  names you visit.
* It does not accept UDP ASSOCIATE.  SOCKS5's UDP mode would let a game use QUIC
  over the tunnel, but it also needs a whole second carrier inside the tunnel;
  it refuses cleanly with the documented reply code, and everything TCP —
  including every browser, and Bloxd.io — works.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import logging
from dataclasses import dataclass
from urllib.parse import urlsplit

from nfvpn.client.tunnel import Tunnel
from nfvpn.config import ClientConfig
from nfvpn.errors import NoFlagVPNError, TransportError
from nfvpn.framing.constants import CloseReason
from nfvpn.pump import pump_bidirectional
from nfvpn.session.streams import StreamClosedError

__all__ = ["LocalAuth", "LocalProxy"]

# SOCKS5 constants (RFC 1928 / RFC 1929).
_SOCKS_VERSION = 0x05
_AUTH_NONE = 0x00
_AUTH_USERPASS = 0x02
_AUTH_UNACCEPTABLE = 0xFF
_CMD_CONNECT = 0x01
_CMD_BIND = 0x02
_CMD_UDP = 0x03
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04

_REPLY_SUCCEEDED = 0x00
_REPLY_GENERAL_FAILURE = 0x01
_REPLY_NOT_ALLOWED = 0x02
_REPLY_HOST_UNREACHABLE = 0x04
_REPLY_REFUSED = 0x05
_REPLY_TTL_EXPIRED = 0x06
_REPLY_COMMAND_UNSUPPORTED = 0x07
_REPLY_ATYP_UNSUPPORTED = 0x08

#: How long a client may take to send its request before we hang up.
HANDSHAKE_TIMEOUT = 30.0

_HTTP_METHODS = (
    b"GET",
    b"POST",
    b"HEAD",
    b"PUT",
    b"DELETE",
    b"OPTIONS",
    b"TRACE",
    b"PATCH",
    b"CONNECT",
)


@dataclass(frozen=True)
class LocalAuth:
    """Optional username/password for the local proxy.

    Mandatory whenever the proxy is bound to something other than loopback: an
    open proxy on your LAN is a gift to the neighbours.
    """

    username: str
    password: str

    def check(self, username: str, password: str) -> bool:
        return (
            len(username) == len(self.username)
            and len(password) == len(self.password)
            and _constant_time(username, self.username)
            and _constant_time(password, self.password)
        )


def _constant_time(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


class LocalProxy:
    """SOCKS5 + HTTP CONNECT in front of a :class:`~nfvpn.client.tunnel.Tunnel`."""

    def __init__(
        self,
        tunnel: Tunnel,
        config: ClientConfig,
        *,
        auth: LocalAuth | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.tunnel = tunnel
        self.config = config
        self.auth = auth
        self.log = logger or logging.getLogger("nfvpn.proxy")
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task] = set()
        self._stopping = asyncio.Event()
        self.connections = 0
        self.denied = 0
        self.failed = 0

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> list[str]:
        """Bind the proxy port.  Returns the addresses it is listening on."""
        try:
            self._server = await asyncio.start_server(
                self._on_client,
                self.config.listen_host,
                self.config.listen_port,
                limit=1 << 20,
            )
        except OSError as exc:
            raise TransportError(
                f"could not listen on {self.config.listen_host}:{self.config.listen_port}: {exc}"
            ) from exc
        bound = [
            f"{sock.getsockname()[0]}:{sock.getsockname()[1]}"
            for sock in self._server.sockets or []
        ]
        self.log.info(
            "local proxy on %s%s",
            ", ".join(bound),
            " (with username/password)" if self.auth else "",
        )
        return bound

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        await self._stopping.wait()

    async def stop(self) -> None:
        self._stopping.set()
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        for task in list(self._tasks):
            task.cancel()
        for task in list(self._tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    async def _on_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        self.connections += 1
        try:
            await self._dispatch(reader, writer)
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.log.debug("client connection failed: %r", exc)
        finally:
            if task is not None:
                self._tasks.discard(task)
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _dispatch(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Peek one byte to decide which protocol this client speaks."""
        try:
            first = await asyncio.wait_for(reader.readexactly(1), timeout=HANDSHAKE_TIMEOUT)
        except (TimeoutError, asyncio.TimeoutError):
            return
        if first == bytes([_SOCKS_VERSION]):
            await self._serve_socks5(reader, writer)
            return
        if first.startswith(_HTTP_METHODS) or first.isalpha():
            await self._serve_http(reader, writer, first)
            return
        # Neither: say nothing, close. Same as any port that is not for you.
        self.log.debug("unrecognised client greeting: %r", first)

    # -- SOCKS5 ------------------------------------------------------------
    async def _serve_socks5(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # The version byte was consumed by the sniffer; nmethods comes next.
        nmethods = (
            await asyncio.wait_for(reader.readexactly(1), timeout=HANDSHAKE_TIMEOUT)
        )[0]
        methods = await asyncio.wait_for(
            reader.readexactly(nmethods), timeout=HANDSHAKE_TIMEOUT
        )

        if self.auth is not None:
            if _AUTH_USERPASS not in methods:
                writer.write(bytes([_SOCKS_VERSION, _AUTH_UNACCEPTABLE]))
                await writer.drain()
                self.denied += 1
                return
            writer.write(bytes([_SOCKS_VERSION, _AUTH_USERPASS]))
            await writer.drain()
            if not await self._socks_authenticate(reader, writer):
                self.denied += 1
                return
        else:
            if _AUTH_NONE not in methods:
                writer.write(bytes([_SOCKS_VERSION, _AUTH_UNACCEPTABLE]))
                await writer.drain()
                self.denied += 1
                return
            writer.write(bytes([_SOCKS_VERSION, _AUTH_NONE]))
            await writer.drain()

        header = await asyncio.wait_for(reader.readexactly(4), timeout=HANDSHAKE_TIMEOUT)
        command, address_type = header[1], header[3]
        if command != _CMD_CONNECT:
            await self._socks_reply(writer, _REPLY_COMMAND_UNSUPPORTED)
            self.log.debug("refused SOCKS command 0x%02x (only CONNECT is supported)", command)
            return
        if address_type not in (_ATYP_IPV4, _ATYP_DOMAIN, _ATYP_IPV6):
            await self._socks_reply(writer, _REPLY_ATYP_UNSUPPORTED)
            return

        host = await self._socks_read_host(reader, address_type)
        port = int.from_bytes(
            await asyncio.wait_for(reader.readexactly(2), timeout=HANDSHAKE_TIMEOUT), "big"
        )
        await self._proxy_connection(reader, writer, host, port, socks=True)

    async def _socks_authenticate(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        sub = await asyncio.wait_for(reader.readexactly(2), timeout=HANDSHAKE_TIMEOUT)
        username = (await reader.readexactly(sub[1])).decode("utf-8", "replace")
        password_length = (await reader.readexactly(1))[0]
        password = (await reader.readexactly(password_length)).decode("utf-8", "replace")
        assert self.auth is not None
        if not self.auth.check(username, password):
            writer.write(bytes([0x01, 0x01]))
            await writer.drain()
            self.log.warning("rejected SOCKS client with wrong credentials")
            return False
        writer.write(bytes([0x01, 0x00]))
        await writer.drain()
        return True

    async def _socks_read_host(self, reader: asyncio.StreamReader, address_type: int) -> str:
        if address_type == _ATYP_IPV4:
            return ".".join(str(byte) for byte in await reader.readexactly(4))
        if address_type == _ATYP_IPV6:
            # Compressed form ("2001:db8::1"), which is what the relay, the
            # egress policy and any log line will show anyway.
            return str(ipaddress.IPv6Address(await reader.readexactly(16)))
        length = (await reader.readexactly(1))[0]
        return (await reader.readexactly(length)).decode("utf-8", "replace")

    async def _socks_reply(self, writer: asyncio.StreamWriter, code: int) -> None:
        writer.write(
            bytes([_SOCKS_VERSION, code, 0x00, _ATYP_IPV4]) + b"\x00\x00\x00\x00" + b"\x00\x00"
        )
        await writer.drain()

    # -- HTTP --------------------------------------------------------------
    async def _serve_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, first_byte: bytes
    ) -> None:
        rest = await asyncio.wait_for(reader.readline(), timeout=HANDSHAKE_TIMEOUT)
        request_line = (first_byte + rest).decode("latin-1").rstrip("\r\n")
        parts = request_line.split(" ")
        if len(parts) < 3:
            await self._http_error(writer, 400, "Bad Request")
            return
        method, target, version = parts[0].upper(), parts[1], parts[2]

        headers: list[tuple[str, str]] = []
        total = 0
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=HANDSHAKE_TIMEOUT)
            total += len(line)
            if line in (b"\r\n", b"\n", b""):
                break
            if total > 65536:
                await self._http_error(writer, 431, "Request Header Fields Too Large")
                return
            name, _, value = line.decode("latin-1").partition(":")
            headers.append((name.strip(), value.strip()))

        if self.auth is not None and not self._http_authorized(headers):
            writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"nfvpn\"\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            self.denied += 1
            return

        if method == "CONNECT":
            try:
                host, port = _parse_authority(target, default_port=443)
            except ValueError:
                await self._http_error(writer, 400, "Bad CONNECT authority")
                return
            await self._proxy_connection(reader, writer, host, port, socks=False)
            return

        try:
            parsed = urlsplit(target)
            if parsed.scheme.lower() != "http" or not parsed.hostname:
                raise ValueError("expected an absolute http:// URL")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("userinfo is not valid in a proxy request target")
            host = parsed.hostname
            parsed_port = parsed.port
            port = 80 if parsed_port is None else parsed_port
            if not 1 <= port <= 65535:
                raise ValueError("port is outside the TCP port range")
        except ValueError:
            await self._http_error(
                writer, 400, "This proxy expects CONNECT or an absolute http:// URL"
            )
            return

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        await self._proxy_http_request(
            reader,
            writer,
            host,
            port,
            method,
            path,
            version,
            headers,
        )

    def _http_authorized(self, headers: list[tuple[str, str]]) -> bool:
        assert self.auth is not None
        for name, value in headers:
            if name.lower() != "proxy-authorization":
                continue
            scheme, _, token = value.partition(" ")
            if scheme.lower() != "basic":
                continue
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            username, _, password = decoded.partition(":")
            if self.auth.check(username, password):
                return True
        return False

    async def _http_error(self, writer: asyncio.StreamWriter, status: int, message: str) -> None:
        body = f"<html><body><h1>{status} {message}</h1></body></html>\r\n".encode()
        writer.write(
            f"HTTP/1.1 {status} {message}\r\n".encode()
            + b"Content-Type: text/html; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        await writer.drain()

    # -- shared tunnel plumbing -------------------------------------------
    async def _proxy_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
        *,
        socks: bool,
    ) -> None:
        """Open a tunnel stream and pump, replying in whichever dialect was used."""
        try:
            stream = await self.tunnel.open(host, port, timeout=self.config.connect_timeout * 2)
        except StreamClosedError as exc:
            self.denied += 1
            code = _socks_code_for(exc.reason)
            self.log.info("the relay refused %s:%d (%s)", host, port, exc.reason.name.lower())
            if socks:
                await self._socks_reply(writer, code)
            else:
                await self._http_error(
                    writer,
                    403 if exc.reason is CloseReason.DENIED else 502,
                    "Blocked by the relay's egress policy"
                    if exc.reason is CloseReason.DENIED
                    else "The relay could not reach the destination",
                )
            return
        except (TransportError, TimeoutError, asyncio.TimeoutError) as exc:
            self.failed += 1
            self.log.warning("could not open a stream to %s:%d: %s", host, port, exc)
            if socks:
                await self._socks_reply(writer, _REPLY_HOST_UNREACHABLE)
            else:
                await self._http_error(writer, 504, "The tunnel did not answer")
            return
        except NoFlagVPNError as exc:
            self.failed += 1
            self.log.warning("stream setup failed for %s:%d: %s", host, port, exc)
            if socks:
                await self._socks_reply(writer, _REPLY_GENERAL_FAILURE)
            else:
                await self._http_error(writer, 502, "Tunnel error")
            return

        if socks:
            await self._socks_reply(writer, _REPLY_SUCCEEDED)
        else:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

        self.log.debug("tunnelling %s:%d via %s", host, port, self.tunnel.active_endpoint)
        try:
            await pump_bidirectional(stream, reader, writer)
        finally:
            session = self.tunnel.session
            if session is not None:
                session.streams.detach(stream)

    async def _proxy_http_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
        method: str,
        path: str,
        version: str,
        headers: list[tuple[str, str]],
    ) -> None:
        """Serve a plain (non-CONNECT) HTTP request by rewriting it to origin form."""
        try:
            stream = await self.tunnel.open(host, port, timeout=self.config.connect_timeout * 2)
        except (StreamClosedError, TransportError, NoFlagVPNError, TimeoutError) as exc:
            self.failed += 1
            self.log.info("could not proxy http://%s%s: %s", host, path, exc)
            await self._http_error(writer, 502, "Bad Gateway")
            return

        try:
            request = [f"{method} {path} {version}"]
            connection_tokens = {
                token.strip().lower()
                for name, value in headers
                if name.lower() == "connection"
                for token in value.split(",")
                if token.strip()
            }
            hop_by_hop = {
                "connection",
                "keep-alive",
                "proxy-connection",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailer",
                "upgrade",
            }
            for name, value in headers:
                lowered = name.lower()
                if lowered in hop_by_hop or lowered in connection_tokens:
                    continue
                request.append(f"{name}: {value}")
            request.append("Connection: close")
            await stream.send(("\r\n".join(request) + "\r\n\r\n").encode("latin-1"))
            await pump_bidirectional(stream, reader, writer)
        finally:
            session = self.tunnel.session
            if session is not None:
                session.streams.detach(stream)


def _parse_authority(authority: str, *, default_port: int) -> tuple[str, int]:
    """Parse CONNECT's host[:port], including bracketed IPv6 literals."""
    parsed = urlsplit(f"//{authority}")
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid CONNECT authority")
    parsed_port = parsed.port
    port = default_port if parsed_port is None else parsed_port
    if not 1 <= port <= 65535:
        raise ValueError("port is outside the TCP port range")
    return parsed.hostname, port


def _socks_code_for(reason: CloseReason) -> int:
    if reason is CloseReason.DENIED:
        return _REPLY_NOT_ALLOWED
    if reason is CloseReason.REFUSED:
        return _REPLY_REFUSED
    if reason is CloseReason.TIMEOUT:
        return _REPLY_TTL_EXPIRED
    if reason is CloseReason.LIMIT:
        return _REPLY_NOT_ALLOWED
    return _REPLY_GENERAL_FAILURE
