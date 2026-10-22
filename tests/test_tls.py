"""The ``wss://`` carrier: the disguise, and what has to be true about it.

Nothing else in the suite ran the tunnel over TLS, which is the mode this tool
exists for — a relay that a middlebox sees as an ordinary HTTPS server.  These
tests generate a certificate on the fly, run the real relay behind it, and check
the parts that would be security bugs if they were wrong:

* a client that pins the relay's CA connects, tunnelled traffic included;
* a client that trusts only the public roots **refuses** that relay, because a
  TLS layer nobody can authenticate is how a censor serves you its own relay;
* ``--insecure-tls`` is the only way past that, and it is explicit;
* the certificate's ALPN list looks like a browser's, because an odd list is a
  fingerprint, which is the one thing this project cannot afford;
* the config layer refuses half-configured TLS instead of silently falling back
  to cleartext.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import ssl
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from nfvpn.client.proxy import LocalProxy
from nfvpn.client.tunnel import Tunnel
from nfvpn.config import ClientConfig, ServerConfig
from nfvpn.core.encoding import b64e
from nfvpn.core.keys import Identity, Member, MembershipStore, parse_psk
from nfvpn.errors import ConfigError, TransportError
from nfvpn.selftest import start_origin
from nfvpn.server.egress import EgressPolicy
from nfvpn.server.relay import Relay
from nfvpn.transport.tls import DEFAULT_ALPN, client_context, server_context


def free_port() -> int:
    """A port that was free a moment ago; the same helper conftest uses."""
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])

PSK = parse_psk("s7_SKalwmOc3WEsuA6bjyejEPW8a7t3VUpMZ5R83E-w")


# --------------------------------------------------------------------------- #
# a certificate, and the certificate files
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def certificate(tmp_path_factory) -> tuple[Path, Path]:
    """A self-signed certificate for localhost, valid right now."""
    directory = tmp_path_factory.mktemp("tls")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NoFlagVPN tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = directory / "relay.crt"
    key_path = directory / "relay.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


# --------------------------------------------------------------------------- #
# the contexts themselves (this module was 32% covered)
# --------------------------------------------------------------------------- #
def test_the_server_context_needs_both_halves(certificate):
    cert_path, key_path = certificate
    assert server_context(cert_file=None, key_file=None) is None
    assert server_context(cert_file=cert_path, key_file=None) is None
    assert server_context(cert_file=None, key_file=key_path) is None
    assert server_context(cert_file=cert_path, key_file=key_path) is not None


def test_a_missing_certificate_or_key_is_a_config_error(tmp_path, certificate):
    _cert, key_path = certificate
    with pytest.raises(ConfigError, match="certificate not found"):
        server_context(cert_file=tmp_path / "nope.crt", key_file=key_path)
    with pytest.raises(ConfigError, match="private key not found"):
        server_context(cert_file=certificate[0], key_file=tmp_path / "nope.key")


def test_the_server_offers_browser_alpn_and_no_old_tls(certificate):
    context = server_context(cert_file=certificate[0], key_file=certificate[1])
    assert context is not None
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert DEFAULT_ALPN == ("h2", "http/1.1"), "an unusual ALPN list is a fingerprint"


def test_pinning_a_ca_that_does_not_exist_is_refused():
    with pytest.raises(ConfigError, match="CA file not found"):
        client_context(ca_file="/nowhere/nowhere.pem")


def test_insecure_mode_is_its_own_opt_in():
    context, hostname = client_context(insecure=True)
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE
    assert hostname is None

    strict, _ = client_context()
    assert strict.check_hostname is True
    assert strict.verify_mode == ssl.CERT_REQUIRED


def test_the_config_refuses_half_configured_tls(certificate):
    with pytest.raises(ConfigError, match="together"):
        ServerConfig(listen_host="127.0.0.1", tls_cert=str(certificate[0]))
    with pytest.raises(ConfigError, match="together"):
        ServerConfig(listen_host="127.0.0.1", tls_key=str(certificate[1]))


# --------------------------------------------------------------------------- #
# the carrier, end to end
# --------------------------------------------------------------------------- #
async def _tls_rig(certificate, *, client_ca: str | None, insecure: bool):
    """A relay behind the test certificate, and a client configured for it."""
    cert_path, key_path = certificate
    relay_identity = Identity.generate("tls-relay")
    client_identity = Identity.generate("tls-client")
    membership = MembershipStore()
    membership.add(Member(name="tester", public_key=client_identity.public_key, psk=PSK))

    relay_config = ServerConfig(
        listen_host="127.0.0.1",
        listen_port=free_port(),
        ws_path="/cdn",
        profile="balanced",
        log_level="critical",
        tls_cert=str(cert_path),
        tls_key=str(key_path),
        egress=EgressPolicy(allow_private_literals=True, block_private=False),
    )
    relay = Relay(relay_config, relay_identity, membership)
    await relay.start()

    client_config = ClientConfig(
        relay=f"wss://localhost:{relay_config.listen_port}/cdn",
        peer_public_key=b64e(relay_identity.public_key),
        psk=b64e(PSK),
        listen_host="127.0.0.1",
        listen_port=free_port(),
        profile="balanced",
        log_level="critical",
        ca_file=client_ca,
        insecure_tls=insecure,
    )
    tunnel = Tunnel(client_config, client_identity, PSK, relay_identity.public_key)
    return relay, tunnel, client_config


async def test_the_tunnel_runs_over_tls_and_carries_traffic(certificate):
    relay, tunnel, client_config = await _tls_rig(
        certificate, client_ca=str(certificate[0]), insecure=False
    )
    origin, origin_url = await start_origin()
    origin_port = int(origin_url.rsplit(":", 1)[1].rstrip("/"))
    proxy = None
    try:
        await tunnel.connect()
        proxy = LocalProxy(tunnel, client_config)
        await proxy.start()

        reader, writer = await asyncio.open_connection("127.0.0.1", client_config.listen_port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        assert await reader.readexactly(2) == b"\x05\x00"
        host = b"localhost"
        writer.write(
            b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", origin_port)
        )
        await writer.drain()
        reply = await reader.readexactly(4)
        assert reply[1] == 0, f"the proxy refused over TLS: 0x{reply[1]:02x}"
        await reader.readexactly(6)

        writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        await writer.drain()
        body = await asyncio.wait_for(reader.read(), timeout=20)
        writer.close()
        assert b"200 OK" in body.split(b"\r\n")[0], body[:200]
    finally:
        if proxy is not None:
            await proxy.stop()
        await tunnel.close()
        await relay.stop()
        origin.close()


async def test_a_client_that_cannot_authenticate_the_relay_refuses_it(certificate):
    """The default trust store does not know this certificate, and must not
    wave it through: an unauthenticated carrier can be substituted."""
    relay, tunnel, _config = await _tls_rig(certificate, client_ca=None, insecure=False)
    try:
        with pytest.raises((TransportError, ConfigError, ssl.SSLError, OSError)):
            await tunnel.connect()
    finally:
        await tunnel.close()
        await relay.stop()


async def test_insecure_tls_is_the_only_way_past_that(certificate):
    relay, tunnel, _config = await _tls_rig(certificate, client_ca=None, insecure=True)
    try:
        await tunnel.connect()  # explicitly opted in, so it connects
    finally:
        await tunnel.close()
        await relay.stop()


async def test_a_plain_http_client_gets_the_cover_page_over_tls(certificate):
    """A scanner that dials the carrier with HTTPS must see an ordinary server."""
    relay, _tunnel, _client_config = await _tls_rig(
        certificate, client_ca=str(certificate[0]), insecure=False
    )
    context = ssl.create_default_context(cafile=str(certificate[0]))
    context.set_alpn_protocols(["http/1.1"])
    try:
        # Dial the relay's own port, not the local proxy: this is the scanner's
        # view of the carrier.
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", relay.config.listen_port, ssl=context, server_hostname="localhost"
        )
        writer.write(b"GET /nothing-here HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(400), timeout=20)
        writer.close()
        assert head.startswith(b"HTTP/1.1 404"), head[:80]
        assert b"nginx" in head
    finally:
        await relay.stop()


def test_an_unreadable_ca_bundle_is_a_config_error(tmp_path):
    invalid_ca = tmp_path / "ca.pem"
    invalid_ca.write_text("not a PEM certificate")
    with pytest.raises(ConfigError, match="could not load CA file"):
        client_context(ca_file=invalid_ca)


def test_an_unreadable_server_key_pair_is_a_config_error(tmp_path):
    cert = tmp_path / "relay.crt"
    key = tmp_path / "relay.key"
    cert.write_text("not a PEM certificate")
    key.write_text("not a PEM private key")
    with pytest.raises(ConfigError, match="could not load the certificate/key pair"):
        server_context(cert_file=cert, key_file=key)
