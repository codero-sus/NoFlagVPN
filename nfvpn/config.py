"""Configuration files, defaults and the place we keep keys.

Layout (all overridable with ``NFVPN_CONFIG_DIR``)::

    ~/.config/nfvpn/
        identity.key        this machine's long-term X25519 identity (0600)
        members.json        a relay's allowlist: names, public keys, PSKs (0600)
        relay.json          relay settings
        client.json         client settings

Everything a relay can be told is a file, and every file is a plain mapping, so
a relay can be provisioned by copying two files and no daemon needs a control
API.  There deliberately is no remote management interface: an administrative
port would be a much more attractive target than the tunnel itself.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from nfvpn.core.keys import Identity, write_private_file
from nfvpn.errors import ConfigError
from nfvpn.server.egress import EgressPolicy
from nfvpn.traffic.shaper import DEFAULT_PROFILE, profile_names
from nfvpn.transport.websocket import PayloadEncoding


def check_booleans(config: Any, names: Iterable[str]) -> None:
    """Boolean settings must be JSON booleans, never truthy strings or integers."""
    for name in names:
        if not isinstance(getattr(config, name), bool):
            raise ConfigError(f"{name} must be a boolean")


def check_numbers(
    config: Any, *, positive: Iterable[str], non_negative: Iterable[str] = ()
) -> None:
    """Numeric fields must be sane.  Shared by both configs.

    A zero or negative window is not a smaller tunnel, it is a hang: the sender
    waits for credit that can never be granted.  An interval of zero means "off"
    for the fields where that is documented, and nothing at all where it is not.
    Better to refuse the value at the door than to debug it at three in the
    morning.
    """
    for name in positive:
        value = getattr(config, name)
        if value <= 0:
            raise ConfigError(f"{name} must be greater than zero, not {value:g}")
    for name in non_negative:
        value = getattr(config, name)
        if value < 0:
            raise ConfigError(f"{name} cannot be negative, got {value:g}")


__all__ = [
    "ClientConfig",
    "ServerConfig",
    "check_identity_name",
    "config_dir",
    "default_membership_path",
    "identity_path",
    "load_json",
    "save_json",
]

DEFAULT_CONFIG_DIR_NAME = "nfvpn"


def config_dir() -> Path:
    """Where nfvpn keeps its keys and settings."""
    override = os.environ.get("NFVPN_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":  # pragma: no cover - platform specific
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "nfvpn"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base_path = Path(xdg) if xdg else Path.home() / ".config"
    return base_path / DEFAULT_CONFIG_DIR_NAME


#: Identity file names: one component of a file name, nothing more.  A name
#: such as ``../../etc/passwd`` would otherwise write a key outside the config
#: directory, which is a surprise nobody wants from ``nfvpn keygen --name``.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_NAME_LENGTH = 64


def check_identity_name(name: str) -> str:
    """Return ``name`` if it is usable as an identity file name, else raise.

    Deliberately strict: letters, digits, dot, dash and underscore, starting
    with a letter or digit.  ``.`` and ``..`` fall out of that rule, so a name
    can never escape the config directory or resolve to a directory.
    """
    if not _NAME_RE.match(name):
        raise ConfigError(
            f"invalid name {name!r}: use letters, digits, dot, dash or underscore "
            f"(up to {_NAME_LENGTH} characters, starting with a letter or digit)"
        )
    return name


def identity_path(name: str = "identity") -> Path:
    return config_dir() / f"{check_identity_name(name)}.key"


def default_membership_path() -> Path:
    return config_dir() / "members.json"


def config_file(name: str, explicit: os.PathLike[str] | str | None = None) -> Path:
    """Find a settings file: the one the user named, or the config dir's default.

    ``nfvpn serve`` and ``nfvpn connect`` take ``--config``, but the layout this
    module documents is ``~/.config/nfvpn/relay.json`` and ``client.json``, and
    ``nfvpn doctor`` reads exactly those.  Requiring ``--config`` for them meant
    a user who wrote the documented file got a daemon running on defaults with
    nothing said about it.

    A path the user typed that does not exist is an error rather than a silent
    fallback to defaults: starting a relay with the wrong egress policy because
    of a typo in a file name is precisely the kind of surprise this project
    should not have.
    """
    if explicit:
        path = Path(explicit).expanduser()
        if not path.exists():
            raise ConfigError(f"no such config file: {path}")
        return path
    return config_dir() / name


def load_json(path: os.PathLike[str] | str) -> dict[str, Any]:
    """Read a JSON object, with a clear error when it is not one."""
    file_path = Path(path)
    if not file_path.exists():
        return {}
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{file_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{file_path} must contain a JSON object")
    return data


def save_json(
    path: os.PathLike[str] | str, data: dict[str, Any], *, private: bool = True
) -> Path:
    """Write a JSON object; ``private`` means mode 0600."""
    file_path = Path(path)
    text = json.dumps(data, indent=2, sort_keys=False) + "\n"
    if private:
        write_private_file(file_path, text)
    else:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(text, encoding="utf-8")
    return file_path


def _as_tuple(value: Any, cast=str) -> tuple:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (cast(value),)
    return tuple(cast(item) for item in value)


@dataclass
class ServerConfig:
    """Everything a relay needs to know about itself."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 8443
    ws_path: str = "/"
    encoding: str = PayloadEncoding.BINARY
    server_header: str | None = "nginx"
    #: HTML file served to anything that is not a WebSocket upgrade.  Empty means
    #: the default nginx 404 page, which is the most ordinary answer available.
    cover_page: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    profile: str = DEFAULT_PROFILE
    cover_traffic: bool = True
    identity_file: str | Path = field(default_factory=lambda: identity_path("relay"))
    membership_file: str | Path = field(default_factory=default_membership_path)
    max_streams: int = 256
    window: int = 256 * 1024
    idle_timeout: float = 300.0
    handshake_timeout: float = 20.0
    connect_timeout: float = 15.0
    rekey_seconds: float = 900.0
    stats_interval: float = 0.0
    limit_mbps: float | None = None
    log_level: str = "info"
    log_file: str | None = None
    egress: EgressPolicy = field(default_factory=EgressPolicy)

    #: Cached cover body, so a probe does not hit the disk.
    _cover_cache: bytes | None = field(default=None, init=False, repr=False, compare=False)

    # -- validation --------------------------------------------------------
    def __post_init__(self) -> None:
        check_booleans(self, ("cover_traffic",))
        if self.encoding not in (PayloadEncoding.BINARY, PayloadEncoding.TEXT):
            raise ConfigError(
                f"encoding must be '{PayloadEncoding.BINARY}' or '{PayloadEncoding.TEXT}'"
            )
        if self.profile not in profile_names():
            raise ConfigError(
                f"unknown shaping profile {self.profile!r}; expected one of "
                f"{', '.join(profile_names())}"
            )
        if not self.ws_path.startswith("/"):
            raise ConfigError("ws_path must start with '/'")
        if not isinstance(self.egress, EgressPolicy):
            # Without this, a bad egress only explodes later inside asdict()
            # with a dataclasses TypeError, far from whoever set it.
            raise ConfigError(
                f"egress must be an EgressPolicy, not {type(self.egress).__name__}"
            )
        if bool(self.tls_cert) != bool(self.tls_key):
            raise ConfigError("tls_cert and tls_key must be set together")
        if not 1 <= self.listen_port <= 65535:
            raise ConfigError(f"listen_port {self.listen_port} is out of range")
        check_numbers(
            self,
            positive=(
                "max_streams",
                "window",
                "rekey_seconds",
                "idle_timeout",
                "handshake_timeout",
                "connect_timeout",
            ),
            non_negative=("stats_interval",),
        )
        if self.limit_mbps is not None and self.limit_mbps <= 0:
            raise ConfigError(
                f"limit_mbps must be greater than zero or left out entirely (meaning no "
                f"limit), not {self.limit_mbps:g}"
            )

    def cover_body(self) -> bytes:
        """The bytes served for non-upgrade requests (defaults to nginx's 404)."""
        from nfvpn.transport.websocket import COVER_404

        if not self.cover_page:
            return COVER_404
        if self._cover_cache is None:
            path = Path(self.cover_page).expanduser()
            if not path.exists():
                raise ConfigError(f"cover_page not found: {path}")
            self._cover_cache = path.read_bytes()
        return self._cover_cache

    # -- (de)serialisation -------------------------------------------------
    def to_mapping(self, *, include_secrets: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "ws_path": self.ws_path,
            "encoding": self.encoding,
            "server_header": self.server_header,
            "cover_page": self.cover_page,
            "tls_cert": self.tls_cert,
            "tls_key": self.tls_key,
            "profile": self.profile,
            "cover_traffic": self.cover_traffic,
            "max_streams": self.max_streams,
            "window": self.window,
            "idle_timeout": self.idle_timeout,
            "connect_timeout": self.connect_timeout,
            "rekey_seconds": self.rekey_seconds,
            "stats_interval": self.stats_interval,
            "limit_mbps": self.limit_mbps,
            "log_level": self.log_level,
            "log_file": self.log_file,
            "egress": asdict(self.egress, dict_factory=lambda items: {
                key: value for key, value in items if not key.startswith("_")
            }),
        }
        if include_secrets:
            # str() on purpose: these may be Path objects, and JSON only has
            # strings — a config that cannot round-trip is worse than useless.
            payload["identity_file"] = str(self.identity_file)
            payload["membership_file"] = str(self.membership_file)
        return payload

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> ServerConfig:
        known = set(cls.__dataclass_fields__)
        unknown = set(raw) - known
        if unknown:
            raise ConfigError(
                f"unknown relay setting(s): {', '.join(sorted(unknown))} "
                f"(known: {', '.join(sorted(known))})"
            )
        egress_raw = raw.get("egress", {})
        if egress_raw is None:
            egress_raw = {}
        if not isinstance(egress_raw, dict):
            raise ConfigError("egress must be a JSON object")
        egress = EgressPolicy(
            allow_ports=tuple(int(item) for item in _as_tuple(egress_raw.get("allow_ports"))),
            deny_ports=tuple(
                int(item)
                for item in _as_tuple(egress_raw.get("deny_ports"))
                or EgressPolicy().deny_ports
            ),
            allow_networks=_as_tuple(egress_raw.get("allow_networks")),
            deny_networks=_as_tuple(egress_raw.get("deny_networks")),
            block_private=egress_raw.get("block_private", True),
            allow_domains=_as_tuple(egress_raw.get("allow_domains")),
            deny_domains=_as_tuple(egress_raw.get("deny_domains")),
            resolve_timeout=float(egress_raw.get("resolve_timeout", 10.0)),
            allow_private_literals=egress_raw.get("allow_private_literals", False),
        )
        kwargs = {key: value for key, value in raw.items() if key != "egress"}
        return cls(egress=egress, **kwargs)

    @classmethod
    def load(cls, path: os.PathLike[str] | str) -> ServerConfig:
        return cls.from_mapping(load_json(path))

    def save(self, path: os.PathLike[str] | str) -> Path:
        return save_json(path, self.to_mapping())

    def load_identity(self, path: str | None = None) -> Identity:
        """Load the relay's identity, creating one on first run."""
        return Identity.load_or_create(Path(path or self.identity_file), name="relay")


@dataclass
class ClientConfig:
    """Everything a client needs to reach a relay."""

    relay: str = ""
    peer_public_key: str = ""
    psk: str = ""
    identity_file: str = field(default_factory=lambda: str(identity_path("client")))
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    profile: str = DEFAULT_PROFILE
    cover_traffic: bool = True
    connect_timeout: float = 15.0
    handshake_timeout: float = 20.0
    max_streams: int = 256
    window: int = 256 * 1024
    peer_name: str = "relay"
    failover: tuple[str, ...] = ()
    insecure_tls: bool = False
    ca_file: str | None = None
    encoding: str = PayloadEncoding.BINARY
    log_level: str = "info"
    expose_lan: bool = False
    """Bind the local proxy to the LAN instead of loopback.  Off by default:
    an open proxy on your laptop is exactly the thing you are hiding from."""

    def __post_init__(self) -> None:
        check_booleans(self, ("cover_traffic", "insecure_tls", "expose_lan"))
        if self.profile not in profile_names():
            raise ConfigError(
                f"unknown shaping profile {self.profile!r}; expected one of "
                f"{', '.join(profile_names())}"
            )
        if self.encoding not in (PayloadEncoding.BINARY, PayloadEncoding.TEXT):
            raise ConfigError(f"unknown encoding {self.encoding!r}")
        if not 1 <= self.listen_port <= 65535:
            raise ConfigError(f"listen_port {self.listen_port} is out of range")
        check_numbers(self, positive=("max_streams", "window"))
        if self.insecure_tls and self.ca_file:
            raise ConfigError("insecure_tls and ca_file are mutually exclusive")

    def to_mapping(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["failover"] = list(self.failover)
        return payload

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> ClientConfig:
        known = set(cls.__dataclass_fields__)
        unknown = set(raw) - known
        if unknown:
            raise ConfigError(f"unknown client setting(s): {', '.join(sorted(unknown))}")
        payload = dict(raw)
        payload["failover"] = _as_tuple(payload.get("failover"))
        return cls(**payload)

    @classmethod
    def load(cls, path: os.PathLike[str] | str) -> ClientConfig:
        return cls.from_mapping(load_json(path))

    def save(self, path: os.PathLike[str] | str) -> Path:
        return save_json(path, self.to_mapping())

    def load_identity(self, path: str | None = None) -> Identity:
        key_path = Path(path or self.identity_file)
        return Identity.load_or_create(key_path, name="client")
