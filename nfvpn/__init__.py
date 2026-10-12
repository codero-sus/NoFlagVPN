"""NoFlagVPN — a censorship-resistant, traffic-shaped peer-to-peer tunnel.

The package is organised in layers, each of which can be tested on its own:

``nfvpn.core``       cryptographic primitives and key material (stdlib only)
``nfvpn.framing``    the encrypted record format that carries user payload
``nfvpn.traffic``    what the carrier looks like on the wire (shaping/jitter)
``nfvpn.transport``  carriers: RFC 6455 WebSocket, over TLS or cleartext
``nfvpn.session``    the authenticated handshake and the per-peer stream
``nfvpn.server``     the relay daemon: membership, switching, egress policy
``nfvpn.client``     the local side: socks5 HTTP CONNECT and peer selection
``nfvpn.detect``     local measurement of how fingerprintable our own traffic is
``nfvpn.cli``        ``python -m nfvpn``
"""

from __future__ import annotations

from nfvpn.version import __version__

__all__ = ["__version__"]
