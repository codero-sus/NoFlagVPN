"""Carriers, endpoint parsing and dialling.

Supported endpoint schemes::

    wss://relay.example/dashboard     WebSocket over TLS   (default, port 443)
    ws://relay.example:8080/ws        WebSocket, cleartext (port 80)
    tcp://relay.example:9001          length-prefixed TCP  (port 9001)
    tls://relay.example:9002          length-prefixed TCP inside TLS

Bare ``host:port`` is accepted and means ``wss://host:port/``.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass

from nfvpn.errors import ConfigError, TransportError
from nfvpn.transport.base import Transport, TransportInfo

# Re-exported so callers only need `nfvpn.transport`.
from nfvpn.transport.raw import RawTCPTransport
from nfvpn.transport.tls import DEFAULT_ALPN, client_context, server_context
from nfvpn.transport.websocket import (
    COVER_404,
    DEFAULT_USER_AGENT,
    PayloadEncoding,
    WebSocketTransport,
    compute_accept,
)

__all__ = [
    "COVER_404",
    "DEFAULT_ALPN",
    "DEFAULT_USER_AGENT",
    "Endpoint",
    "PayloadEncoding",
    "RawTCPTransport",
    "Transport",
    "TransportInfo",
    "WebSocketTransport",
    "accept_transport",
    "client_context",
    "compute_accept",
    "dial",
    "server_context",
]

_DEFAULT_PORTS = {"wss": 443, "ws": 80, "tcp": 9001, "tls": 9002}
_WEBSOCKET_SCHEMES = {"ws", "wss"}
_TLS_SCHEMES = {"wss", "tls"}


@dataclass(frozen=True)
class Endpoint:
    """A carrier address."""

    scheme: str
    host: str
    port: int
    path: str = "/"

    def __post_init__(self) -> None:
        if self.scheme not in _DEFAULT_PORTS:
            raise ConfigError(
                f"unsupported carrier scheme {self.scheme!r}; expected one of "
                f"{', '.join(sorted(_DEFAULT_PORTS))}"
            )
        if not self.host:
            raise ConfigError("endpoint host is empty")
        if not 1 <= self.port <= 65535:
            raise ConfigError(f"endpoint port {self.port} is out of range")
        if not self.path.startswith("/"):
            raise ConfigError("endpoint path must start with '/'")

    @classmethod
    def parse(cls, text: str, *, default_scheme: str = "wss") -> Endpoint:
        """Parse ``scheme://host:port/path``, ``host:port`` or ``host``."""
        raw = text.strip()
        if not raw:
            raise ConfigError("empty endpoint")

        scheme = default_scheme
        rest = raw
        if "://" in raw:
            scheme, _, rest = raw.partition("://")
            scheme = scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            raise ConfigError(f"unsupported carrier scheme {scheme!r}")

        path = "/"
        if "/" in rest:
            rest, _, path_tail = rest.partition("/")
            path = "/" + path_tail
        if rest.startswith("["):  # bracketed IPv6 literal
            host, _, tail = rest[1:].partition("]")
            rest = f"{host}{tail}"
            port = int(tail[1:]) if tail.startswith(":") and tail[1:] else _DEFAULT_PORTS[scheme]
        else:
            if ":" in rest:
                host, _, port_text = rest.rpartition(":")
            else:
                host, port_text = rest, ""
            port = int(port_text) if port_text else _DEFAULT_PORTS[scheme]

        if not host:
            raise ConfigError(f"endpoint {text!r} has no host")
        if not 0 < port < 65536:
            raise ConfigError(f"endpoint {text!r} has an out-of-range port {port}")
        return cls(scheme=scheme, host=host, port=port, path=path)

    @property
    def uses_tls(self) -> bool:
        return self.scheme in _TLS_SCHEMES

    @property
    def is_websocket(self) -> bool:
        return self.scheme in _WEBSOCKET_SCHEMES

    @property
    def authority(self) -> str:
        """``host:port``, with IPv6 literals bracketed."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.path}"

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.url()


async def dial(
    endpoint: Endpoint,
    *,
    timeout: float = 15.0,
    tls_context: ssl.SSLContext | None = None,
    server_hostname: str | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    encoding: str = PayloadEncoding.BINARY,
    subprotocol: str | None = None,
    extra_headers: dict[str, str] | None = None,
    max_message_size: int = 1 << 20,
) -> Transport:
    """Connect to ``endpoint`` and return a ready carrier.

    Raises:
        TransportError: DNS, TCP, TLS or the carrier handshake failed.
    """
    ssl_arg: ssl.SSLContext | bool | None = None
    actual_hostname = server_hostname or endpoint.host
    if endpoint.uses_tls:
        if tls_context is None:
            tls_context, override = client_context()
            actual_hostname = override or actual_hostname
        ssl_arg = tls_context

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                endpoint.host,
                endpoint.port,
                ssl=ssl_arg,
                server_hostname=actual_hostname if ssl_arg else None,
            ),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        raise TransportError(f"could not reach {endpoint.authority}: {exc}") from exc

    peer = writer.get_extra_info("peername")
    peer_text = f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else str(peer)

    if endpoint.is_websocket:
        transport: Transport = WebSocketTransport(
            reader,
            writer,
            peer=peer_text,
            encrypted=endpoint.uses_tls,
            server_side=False,
            encoding=encoding,
            max_message_size=max_message_size,
            request_path=endpoint.path,
            user_agent=user_agent,
            subprotocol=subprotocol,
            extra_headers=extra_headers,
            host_header=endpoint.authority,
            handshake_timeout=timeout,
        )
    else:
        transport = RawTCPTransport(
            reader,
            writer,
            peer=peer_text,
            encrypted=endpoint.uses_tls,
            max_message_size=max_message_size,
        )

    try:
        await transport.open()
    except BaseException:
        await transport.close()
        raise
    return transport


async def accept_transport(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    is_websocket: bool = True,
    encrypted: bool = False,
    encoding: str = PayloadEncoding.BINARY,
    server_handshake_timeout: float = 15.0,
    max_message_size: int = 1 << 20,
    cover_body: bytes = COVER_404,
    server_header: str | None = "nginx",
    subprotocol: str | None = None,
) -> Transport:
    """Wrap an accepted connection in a server-side carrier.

    Raises:
        TransportError: the peer did not complete a carrier handshake.
    """
    peer = writer.get_extra_info("peername")
    peer_text = f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else str(peer)

    transport: Transport
    if not is_websocket:
        transport = RawTCPTransport(
            reader, writer, peer=peer_text, encrypted=encrypted, max_message_size=max_message_size
        )
    else:
        transport = WebSocketTransport(
            reader,
            writer,
            peer=peer_text,
            encrypted=encrypted,
            server_side=True,
            encoding=encoding,
            max_message_size=max_message_size,
            subprotocol=subprotocol,
            handshake_timeout=server_handshake_timeout,
            cover_body=cover_body,
            server_header=server_header,
        )

    try:
        await transport.open()
    except BaseException:
        await transport.close()
        raise
    return transport
