"""TLS contexts for carriers that need to look like HTTPS.

Two things are worth being clear about.

**The outer TLS is the disguise, not the security.**  The tunnel's own
authenticated encryption is what protects your traffic; the carrier's TLS is
there so that a network middlebox sees a certificate-authenticated HTTPS
connection like every other one.  Certificate validation is still on by default,
because a carrier you cannot authenticate is a carrier that can be impersonated,
and impersonation is how a censor *serves* you something.

**TLS inside TLS is normal.**  Browsing an HTTPS site through the tunnel puts the
browser's TLS inside the tunnel's payload, which itself travels over the
carrier's TLS if ``wss://`` is used.  That is how every commercial VPN that
supports HTTPS proxying works; nothing about the outer layer changes.
"""

from __future__ import annotations

import ssl
from pathlib import Path

from nfvpn.errors import ConfigError

__all__ = ["client_context", "server_context"]

#: ALPN order that matches a browser talking to a normal HTTPS server.  Offering
#: nothing unusual here matters: an odd ALPN list is a trivially observable
#: fingerprint for a passive observer that logs ClientHellos.
DEFAULT_ALPN = ("h2", "http/1.1")


def client_context(
    *,
    ca_file: str | Path | None = None,
    insecure: bool = False,
    server_hostname_override: str | None = None,
) -> tuple[ssl.SSLContext, str | None]:
    """Build the client-side TLS context.

    Returns ``(context, mandatory_hostname)``.  When ``ca_file`` is given, the
    context trusts only that CA — the right way to run a private relay with a
    self-signed certificate.
    """
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif ca_file:
        path = Path(ca_file)
        if not path.exists():
            raise ConfigError(f"CA file not found: {path}")
        context = ssl.create_default_context(cafile=str(path))
    else:
        context = ssl.create_default_context()

    try:
        context.set_alpn_protocols(list(DEFAULT_ALPN))
    except NotImplementedError:  # pragma: no cover - ancient OpenSSL
        pass
    return context, server_hostname_override


def server_context(
    *,
    cert_file: str | Path | None,
    key_file: str | Path | None,
    alpn: tuple[str, ...] = DEFAULT_ALPN,
) -> ssl.SSLContext | None:
    """Build the server-side TLS context, or ``None`` if no certificate was given."""
    if not cert_file or not key_file:
        return None
    cert_path, key_path = Path(cert_file), Path(key_file)
    if not cert_path.exists():
        raise ConfigError(f"certificate not found: {cert_path}")
    if not key_path.exists():
        raise ConfigError(f"private key not found: {key_path}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    except ssl.SSLError as exc:
        raise ConfigError(f"could not load the certificate/key pair: {exc}") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.set_alpn_protocols(list(alpn))
    except NotImplementedError:  # pragma: no cover
        pass
    return context
