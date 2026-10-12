"""Egress: what a relay will and will not dial on your behalf.

This is the security boundary of the whole project.  A relay is a machine on
the public internet that will open TCP connections for its members, so the
defaults here are what keep it from being a pivot into its own network, its
cloud provider's metadata service, or its neighbours.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest
from nfvpn.server.egress import (
    DEFAULT_DENIED_NETWORKS,
    DEFAULT_DENIED_PORTS,
    Decision,
    EgressPolicy,
    Verdict,
    networks_from_text,
    resolve_and_authorize,
)


def resolver_returning(*addresses: str, family: int = socket.AF_INET):
    """A drop-in ``getaddrinfo`` replacement returning fixed addresses."""

    async def resolver(host, port=None, **kwargs):
        return [
            (family, socket.SOCK_STREAM, 6, "", (address, 0)) for address in addresses
        ]

    return resolver


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.5.4",
        "192.168.1.1",
        "169.254.169.254",  # the cloud metadata service
        "100.64.0.1",  # carrier-grade NAT
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "224.0.0.1",
    ],
)
def test_default_policy_refuses_everything_private(address):
    allowed, reason = EgressPolicy().address_allowed(address)
    assert allowed is False, f"{address} was allowed: {reason}"




@pytest.mark.parametrize("address", ["93.184.216.34", "8.8.8.8", "2606:4700::1111"])
def test_default_policy_allows_public_addresses(address):
    allowed, reason = EgressPolicy().address_allowed(address)
    assert allowed is True, reason




@pytest.mark.parametrize("port", list(DEFAULT_DENIED_PORTS))
def test_smtp_ports_are_refused_by_default(port):
    allowed, reason = EgressPolicy().port_allowed(port)
    assert allowed is False
    assert "deny list" in reason


def test_allow_port_list_is_exclusive():
    policy = EgressPolicy(allow_ports=(443, 80))
    assert policy.port_allowed(443)[0] is True
    assert policy.port_allowed(8443)[0] is False


def test_deny_beats_allow_for_ports():
    policy = EgressPolicy(allow_ports=(25, 443), deny_ports=(25,))
    assert policy.port_allowed(25)[0] is False
    assert policy.port_allowed(443)[0] is True


def test_deny_beats_allow_for_networks():
    """An explicit deny wins over the allow list.

    Reaching a private range at all takes ``allow_private_literals`` — the
    default deny list is on top of whatever the operator writes.
    """
    policy = EgressPolicy(allow_networks=("10.0.0.0/8",), deny_networks=("10.7.0.0/16",))
    assert policy.address_allowed("10.1.0.1")[0] is False  # still private by default

    rig = EgressPolicy(
        allow_networks=("10.0.0.0/8",),
        deny_networks=("10.7.0.0/16",),
        allow_private_literals=True,
    )
    assert rig.address_allowed("10.1.0.1")[0] is True
    assert rig.address_allowed("10.7.0.1")[0] is False


def test_allow_networks_is_exclusive():
    policy = EgressPolicy(allow_networks=("93.184.216.0/24",))
    assert policy.address_allowed("93.184.216.34")[0] is True
    assert policy.address_allowed("93.184.217.34")[0] is False


def test_domain_allow_and_deny_lists():
    policy = EgressPolicy(allow_domains=("example.com",), deny_domains=("evil.example.com",))
    assert policy.hostname_allowed("example.com")[0] is True
    assert policy.hostname_allowed("www.example.com")[0] is True
    assert policy.hostname_allowed("evil.example.com")[0] is False
    assert policy.hostname_allowed("example.org")[0] is False


def test_private_ranges_can_be_opened_for_a_test_rig():
    policy = EgressPolicy(allow_private_literals=True)
    assert policy.address_allowed("127.0.0.1")[0] is True
    # ...but multicast and explicitly denied ranges stay denied.
    assert policy.address_allowed("224.0.0.1")[0] is False
    strict = EgressPolicy(allow_private_literals=True, deny_networks=("10.1.0.0/16",))
    assert strict.address_allowed("10.1.2.3")[0] is False


def test_nonsense_addresses_are_refused():
    assert EgressPolicy().address_allowed("not-an-ip")[0] is False


async def test_authorize_allows_a_public_literal():
    decision = await EgressPolicy().authorize("93.184.216.34", 443)
    assert isinstance(decision, Decision)
    assert decision.allowed is True
    assert decision.verdict is Verdict.ALLOWED
    assert decision.addresses == ("93.184.216.34",)


async def test_authorize_refuses_a_private_literal_with_a_useful_message():
    decision = await EgressPolicy().authorize("169.254.169.254", 80)
    assert decision.allowed is False
    assert decision.verdict is Verdict.ADDRESS_DENIED
    assert "denied" in decision.detail
    assert "169.254.169.254:80" in decision.as_message()


async def test_authorize_refuses_the_port_before_resolving():
    decision = await EgressPolicy().authorize("example.com", 25)
    assert decision.allowed is False
    assert decision.verdict is Verdict.PORT_DENIED
    assert decision.addresses == ()


async def test_authorize_refuses_a_denied_hostname():
    policy = EgressPolicy(deny_domains=("internal.example.com",))
    decision = await policy.authorize("internal.example.com", 443)
    assert decision.allowed is False
    assert decision.verdict is Verdict.DOMAIN_DENIED


async def test_a_split_horizon_name_is_refused_entirely():
    """A name answering with both a public and a private address is a trap.

    ``localhost.example`` resolving to 93.184.216.34 *and* 10.0.0.5 is the
    classic DNS-rebinding attack on an egress filter: allow the public address
    and the second connection lands inside the network.
    """

    decision = await resolve_and_authorize(
        "localhost.example", 443, EgressPolicy(), resolver=resolver_returning("93.184.216.34", "10.0.0.5")
    )
    assert decision.allowed is False
    assert decision.verdict is Verdict.ADDRESS_DENIED
    assert "10.0.0.5" in decision.detail


async def test_resolution_failure_is_reported_not_raised():
    async def failing(host, port=None, **kwargs):
        raise OSError("name or service not known")

    decision = await resolve_and_authorize("nx.invalid", 443, EgressPolicy(), resolver=failing)
    assert decision.allowed is False
    assert decision.verdict is Verdict.RESOLUTION_FAILED
    assert "nx.invalid" in decision.as_message()


async def test_a_public_name_resolves_to_a_fixed_address_set():
    policy = EgressPolicy()
    decision = await resolve_and_authorize(
        "example.com", 443, policy, resolver=resolver_returning("93.184.216.34", "93.184.216.35")
    )
    assert decision.allowed is True
    # The caller dials exactly what was authorised, never a second lookup.
    assert set(decision.addresses) == {"93.184.216.34", "93.184.216.35"}


def test_networks_from_text_parses_and_refuses_junk():
    assert networks_from_text(["10.0.0.0/8", "192.168.0.0/24"]) == ("10.0.0.0/8", "192.168.0.0/24")
    with pytest.raises(ValueError):
        networks_from_text(["not-a-network"])


def test_default_denied_networks_are_valid_cidrs():
    for item in DEFAULT_DENIED_NETWORKS:
        assert ipaddress.ip_network(item, strict=False)
