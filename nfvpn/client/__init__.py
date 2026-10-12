"""The client side: a resilient tunnel and the local proxy applications use."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from nfvpn.client.proxy import LocalAuth, LocalProxy
    from nfvpn.client.tunnel import Tunnel, TunnelStats

__all__ = ["LocalAuth", "LocalProxy", "Tunnel", "TunnelStats"]

_LAZY = {
    "LocalAuth": "nfvpn.client.proxy",
    "LocalProxy": "nfvpn.client.proxy",
    "Tunnel": "nfvpn.client.tunnel",
    "TunnelStats": "nfvpn.client.tunnel",
}


def __getattr__(name: str) -> Any:
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    return getattr(import_module(module_name), name)


def __dir__() -> list[str]:  # pragma: no cover - introspection aid
    return sorted(__all__)
