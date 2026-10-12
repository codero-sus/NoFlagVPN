"""What a relay is willing to connect to on your behalf.

A relay is an open door into whatever network it sits in.  Two failure modes
matter more than any fingerprint:

**It becomes a weapon pointed inward.**  If a client can ask the relay for
``127.0.0.1``, ``10.0.0.1`` or ``169.254.169.254``, your relay is a
server-side-request-forgery gadget: whoever holds a pre-shared key can read the
cloud metadata service, your router's admin page and your internal wiki.  So
private, loopback, link-local, multicast and reserved ranges are refused *by
default*, and they are checked against every resolved address, not just the
hostname the client typed.

**It becomes a spam cannon.**  Port 25 out of a residential IP is how relay
networks get their address space blocked.  SMTP is denied by default too.

Everything else is a policy question, so it is a config file.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

__all__ = ["Decision", "EgressPolicy", "Verdict", "resolve_and_authorize"]


class Verdict(str, Enum):
    """Why a connection was allowed or refused."""

    ALLOWED = "allowed"
    PORT_DENIED = "port denied"
    ADDRESS_DENIED = "address range denied"
    DOMAIN_DENIED = "hostname denied"
    RESOLUTION_FAILED = "name did not resolve"
    NO_ADDRESSES = "no usable address"


#: Ranges that must never be reachable through a relay.  This is the default
#: deny list and the single most important line in this file.
DEFAULT_DENIED_NETWORKS: tuple[str, ...] = (
    "0.0.0.0/8",          # "this network"
    "10.0.0.0/8",         # RFC 1918 private
    "100.64.0.0/10",      # carrier-grade NAT
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local, including the cloud metadata service
    "172.16.0.0/12",      # RFC 1918 private
    "192.0.0.0/24",       # IETF protocol assignments
    "192.0.2.0/24",       # documentation
    "192.88.99.0/24",     # 6to4 relay anycast
    "192.168.0.0/16",     # RFC 1918 private
    "198.18.0.0/15",      # benchmarking
    "198.51.100.0/24",    # documentation
    "203.0.113.0/24",     # documentation
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # reserved / broadcast
    "::/128",             # unspecified
    "::1/128",            # loopback
    "fc00::/7",           # unique local
    "fe80::/10",          # link-local
    "ff00::/8",           # multicast
    "64:ff9b::/96",       # NAT64
    "2001:db8::/32",      # documentation
)

#: Ports a relay refuses by default: mail submission and the like, because an
#: open relay on these gets the whole network's address space blacklisted.
DEFAULT_DENIED_PORTS: tuple[int, ...] = (25, 465, 587, 2525)


@dataclass(frozen=True)
class Decision:
    """The outcome of an egress check."""

    allowed: bool
    verdict: Verdict
    detail: str = ""
    addresses: tuple[str, ...] = ()
    port: int = 0
    host: str = ""

    def as_message(self) -> str:
        target = f"{self.host}:{self.port}"
        if self.allowed:
            return f"allowed {target} ({self.detail})"
        return f"refused {target}: {self.verdict.value}{f' — {self.detail}' if self.detail else ''}"


@dataclass
class EgressPolicy:
    """A relay's outbound rules."""

    #: If non-empty, only these ports may be dialled.
    allow_ports: tuple[int, ...] = ()
    #: Always refused, even if in ``allow_ports``.
    deny_ports: tuple[int, ...] = DEFAULT_DENIED_PORTS
    #: If non-empty, only destinations inside these networks may be dialled.
    allow_networks: tuple[str, ...] = ()
    #: Extra ranges to refuse, on top of :data:`DEFAULT_DENIED_NETWORKS`.
    deny_networks: tuple[str, ...] = ()
    #: Refuse private, loopback, link-local and reserved ranges.  Leave this on.
    block_private: bool = True
    #: Hostname suffixes that may be dialled.  Empty means "any hostname".
    allow_domains: tuple[str, ...] = ()
    #: Hostname suffixes that are refused.  Applied after ``allow_domains``.
    deny_domains: tuple[str, ...] = ()
    #: How long a name resolution may take.
    resolve_timeout: float = 10.0
    #: Allow private destinations.  This exists for test rigs (where the origin
    #: is on loopback) and is deliberately the *only* way to turn the private
    #: deny list off; relays should never set it.
    allow_private_literals: bool = False

    _allow_nets: tuple = field(default=(), init=False, repr=False, compare=False)
    _deny_nets: tuple = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._allow_nets = tuple(
            ipaddress.ip_network(item, strict=False) for item in self.allow_networks
        )
        deny_specs = list(self.deny_networks)
        if self.block_private and not self.allow_private_literals:
            deny_specs = list(DEFAULT_DENIED_NETWORKS) + deny_specs
        self._deny_nets = tuple(ipaddress.ip_network(item, strict=False) for item in deny_specs)

    # -- individual checks -------------------------------------------------
    def port_allowed(self, port: int) -> tuple[bool, str]:
        if not 1 <= port <= 65535:
            return False, f"port {port} is not a valid TCP port"
        if port in self.deny_ports:
            return False, "port is on the deny list"
        if self.allow_ports and port not in self.allow_ports:
            return False, f"port is not in the allow list ({', '.join(map(str, self.allow_ports))})"
        return True, "port permitted"

    def hostname_allowed(self, host: str) -> tuple[bool, str]:
        lowered = host.strip().lower().rstrip(".")
        if self.allow_domains and not any(
            lowered == suffix or lowered.endswith("." + suffix) for suffix in self.allow_domains
        ):
            return False, "hostname is outside the allow list"
        if any(lowered == suffix or lowered.endswith("." + suffix) for suffix in self.deny_domains):
            return False, "hostname is on the deny list"
        return True, "hostname permitted"

    def address_allowed(self, address: str) -> tuple[bool, str]:
        """Check one resolved address against the network rules."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False, f"{address} is not a valid IP address"

        if any(ip in network for network in self._deny_nets):
            return False, f"{address} is inside a denied range"
        if self._allow_nets and not any(ip in network for network in self._allow_nets):
            return False, f"{address} is outside the allowed ranges"
        if not ip.is_global and not self.allow_private_literals:
            return False, f"{address} is not a globally routable address"
        if ip.is_multicast:
            return False, f"{address} is a multicast address"
        return True, f"{address} permitted"

    # -- the whole check ---------------------------------------------------
    async def authorize(self, host: str, port: int, *, resolver=None) -> Decision:
        """Resolve ``host`` and decide whether the relay may dial ``host:port``."""
        allowed, detail = self.port_allowed(port)
        if not allowed:
            return Decision(False, Verdict.PORT_DENIED, detail, port=port, host=host)

        allowed, detail = self.hostname_allowed(host)
        if not allowed:
            return Decision(False, Verdict.DOMAIN_DENIED, detail, port=port, host=host)

        literal = _as_literal(host)
        if literal is not None:
            allowed, detail = self.address_allowed(literal)
            if not allowed:
                return Decision(False, Verdict.ADDRESS_DENIED, detail, port=port, host=host)
            return Decision(True, Verdict.ALLOWED, detail, (literal,), port, host)

        return await resolve_and_authorize(host, port, self, resolver=resolver)


def _as_literal(host: str) -> str | None:
    """Return ``host`` if it is already an IP literal, else ``None``."""
    candidate = host.strip().strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


async def resolve_and_authorize(
    host: str, port: int, policy: EgressPolicy, *, resolver=None
) -> Decision:
    """Resolve ``host``, then check every address against the policy.

    **Every** address is checked, and the returned decision carries them all:
    a name that resolves to both a public and a private address (which is what a
    DNS-rebinding attack looks like) is refused outright, and the caller is
    expected to connect to one of ``decision.addresses`` rather than resolving
    again — the second resolution is where rebinding slips through.
    """
    loop = asyncio.get_running_loop()
    getaddrinfo = resolver or loop.getaddrinfo
    try:
        infos = await asyncio.wait_for(
            getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=policy.resolve_timeout
        )
    except (TimeoutError, asyncio.TimeoutError):
        return Decision(False, Verdict.RESOLUTION_FAILED, "resolution timed out", port=port, host=host)
    except (socket.gaierror, OSError) as exc:
        return Decision(False, Verdict.RESOLUTION_FAILED, str(exc), port=port, host=host)

    addresses: list[str] = []
    refusals: list[str] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = sockaddr[0]
        if address in addresses:
            continue
        allowed, detail = policy.address_allowed(address)
        if allowed:
            addresses.append(address)
        else:
            refusals.append(f"{address}: {detail}")

    if not addresses:
        return Decision(
            False,
            Verdict.ADDRESS_DENIED if refusals else Verdict.NO_ADDRESSES,
            "; ".join(refusals) or "the name resolved to nothing dialable",
            (),
            port,
            host,
        )
    if refusals:
        # Mixed public/private answers are exactly the rebinding pattern.
        return Decision(
            False,
            Verdict.ADDRESS_DENIED,
            f"name resolves to refused addresses too ({'; '.join(refusals)})",
            (),
            port,
            host,
        )
    return Decision(
        True,
        Verdict.ALLOWED,
        f"{len(addresses)} address(es) permitted",
        tuple(addresses),
        port,
        host,
    )


def networks_from_text(items: Iterable[str]) -> tuple[str, ...]:
    """Normalise a list of CIDR strings, raising on nonsense early."""
    return tuple(str(ipaddress.ip_network(item, strict=False)) for item in items)
