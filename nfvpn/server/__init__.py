"""The relay side: egress policy, the daemon and its counters.

The names below are resolved lazily (PEP 562) so that importing a submodule such
as :mod:`nfvpn.server.egress` does not drag in the daemon — which imports the
configuration module, which imports the egress policy.  A package ``__init__``
that eagerly imports everything is a reliable way to build an import cycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from nfvpn.server.egress import Decision, EgressPolicy, Verdict
    from nfvpn.server.relay import MemberStats, Relay, RelayStats

__all__ = ["Decision", "EgressPolicy", "MemberStats", "Relay", "RelayStats", "Verdict"]

_LAZY = {
    "Decision": "nfvpn.server.egress",
    "EgressPolicy": "nfvpn.server.egress",
    "Verdict": "nfvpn.server.egress",
    "MemberStats": "nfvpn.server.relay",
    "Relay": "nfvpn.server.relay",
    "RelayStats": "nfvpn.server.relay",
}


def __getattr__(name: str) -> Any:
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    return getattr(import_module(module_name), name)


def __dir__() -> list[str]:  # pragma: no cover - introspection aid
    return sorted(__all__)
