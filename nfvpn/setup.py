"""First-run initialization for a relay deployment."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from nfvpn.config import ServerConfig
from nfvpn.core.keys import Identity, MembershipStore
from nfvpn.errors import ConfigError


@dataclass(frozen=True)
class ServerSetup:
    """Paths and public identity details created by :func:`initialize_server`."""

    config_path: Path
    identity_path: Path
    membership_path: Path
    public_key: str


def initialize_server(config_path: str | Path = "config.json") -> ServerSetup:
    """Create a safe local-only server config and its private state files.

    Existing config files are never overwritten. The generated relay listens on
    loopback without TLS and has an empty membership list, so first-run setup
    cannot accidentally expose an unauthenticated public relay.
    """
    target = Path(config_path).expanduser()
    if target.exists():
        raise ConfigError(f"config already exists: {target}")

    root = target.parent.resolve()
    identity_path = root / "data" / "relay.key"
    membership_path = root / "data" / "members.json"
    identity_path.parent.mkdir(parents=True, exist_ok=True)

    identity = Identity.load_or_create(identity_path, name="relay")
    membership = MembershipStore.load(membership_path)
    if not membership_path.exists():
        membership.save(membership_path)

    config = ServerConfig(
        listen_host="127.0.0.1",
        listen_port=8443,
        ws_path="/",
        tls_cert=None,
        tls_key=None,
        identity_file=str(identity_path),
        membership_file=str(membership_path),
    )
    saved_path = config.save(target)
    return ServerSetup(
        config_path=saved_path,
        identity_path=identity_path,
        membership_path=membership_path,
        public_key=identity.public_dict()["public_key"],
    )
