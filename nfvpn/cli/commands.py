"""Implementations of the ``nfvpn`` subcommands.

Kept separate from argument parsing so that every command is a plain function of
its options, and so the parser can stay readable.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import platform
import signal
import socket
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from nfvpn.client.proxy import LocalAuth, LocalProxy
from nfvpn.client.tunnel import Tunnel
from nfvpn.config import (
    ClientConfig,
    ServerConfig,
    config_dir,
    identity_path,
    load_json,
    save_json,
)
from nfvpn.core.encoding import b64d, b64e, fingerprint
from nfvpn.core.keys import Identity, Member, MembershipStore, generate_psk, parse_psk
from nfvpn.core.primitives import backend_name, use_backend
from nfvpn.detect.probe import format_report, probe_endpoint
from nfvpn.errors import ConfigError, HandshakeError, NoFlagVPNError
from nfvpn.framing.constants import CloseReason
from nfvpn.server.egress import EgressPolicy
from nfvpn.server.relay import Relay
from nfvpn.session.handshake import HandshakeInitiator
from nfvpn.tokens import Invite, decode_invite
from nfvpn.traffic import get_profile, profile_names
from nfvpn.transport import Endpoint, dial
from nfvpn.version import __version__

__all__ = [
    "cmd_connect",
    "cmd_doctor",
    "cmd_demo",
    "cmd_keygen",
    "cmd_member",
    "cmd_probe",
    "cmd_selftest",
    "cmd_serve",
    "cmd_token",
    "configure_logging",
]

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def configure_logging(level: str, *, quiet: bool = False) -> None:
    """Set up the root logger once, in a shape that reads well in a terminal."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO) if not quiet else logging.ERROR,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
        force=True,
    )
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def parse_bind(text: str, default_port: int) -> tuple[str, int]:
    """Parse ``host:port``, ``:port``, ``[::1]:port`` or a bare host."""
    value = text.strip()
    if value.startswith("["):
        host, _, tail = value[1:].partition("]")
        port = int(tail[1:]) if tail.startswith(":") and tail[1:] else default_port
        return host, port
    if value.startswith(":"):
        return "0.0.0.0", int(value[1:] or default_port)
    host, separator, port_text = value.rpartition(":")
    if separator and port_text.isdigit():
        return host or "0.0.0.0", int(port_text)
    return value or "0.0.0.0", default_port


def _is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost")


def _print(message: str = "") -> None:
    print(message)


def _as_json(data: dict) -> None:
    print(json.dumps(data, indent=2, sort_keys=False))


def _install_signals(loop, *, on_stop, on_reload=None) -> bool:
    """Wire SIGINT/SIGTERM (and SIGHUP) into the event loop.

    Returns ``False`` on platforms without ``add_signal_handler`` (Windows),
    where the caller falls back to ``KeyboardInterrupt``.
    """
    installed = True
    with contextlib.suppress(NotImplementedError, AttributeError, ValueError):
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, on_stop)
        if on_reload is not None and hasattr(signal, "SIGHUP"):
            loop.add_signal_handler(signal.SIGHUP, on_reload)
        return True
    return not installed


# --------------------------------------------------------------------------- #
# keygen / token / member
# --------------------------------------------------------------------------- #
def cmd_keygen(args) -> int:
    """Create a long-term identity, and optionally a pre-shared key."""
    target = Path(args.out).expanduser() if args.out else identity_path(args.name or "identity")
    if target.exists() and not args.force:
        raise ConfigError(f"{target} already exists (use --force to overwrite)")

    name = args.name or socket.gethostname().split(".")[0] or "nfvpn"
    identity = Identity.generate(name)
    identity.save(target)

    result = {
        "name": identity.name,
        "public_key": b64e(identity.public_key),
        "fingerprint": identity.fingerprint,
        "short_id": identity.short_id,
        "private_key_file": str(target),
    }
    if args.psk:
        result["psk"] = generate_psk()

    if args.json:
        _as_json(result)
        return EXIT_OK

    _print(f"identity      {identity.name}")
    _print(f"public key    {result['public_key']}")
    _print(f"fingerprint   {result['fingerprint']}")
    _print(f"private key   {target}  (mode 0600 — never share this)")
    if "psk" in result:
        _print(f"pre-shared key {result['psk']}")
    return EXIT_OK


def _load_membership(args) -> MembershipStore:
    config_path = Path(args.config).expanduser() if args.config else None
    path = config_path or (config_dir() / "members.json")
    return MembershipStore.load(path)


def cmd_member(args) -> int:
    """Add, list, revoke or remove members of a relay's allowlist."""
    store = _load_membership(args)

    if args.member_command == "list":
        rows = [
            {
                "name": member.name,
                "short_id": member.short_id,
                "fingerprint": member.fingerprint,
                "enabled": member.enabled,
                "expires_at": member.expires_at,
                "tags": member.tags,
            }
            for member in store
        ]
        if args.json:
            _as_json({"members": rows, "file": str(store.path)})
            return EXIT_OK
        if not rows:
            _print(f"no members in {store.path} — every handshake will be refused")
            return EXIT_OK
        for row in rows:
            state = "enabled" if row["enabled"] else "revoked"
            expiry = (
                time.strftime("%Y-%m-%d", time.localtime(row["expires_at"]))
                if row["expires_at"]
                else "never"
            )
            _print(f"{row['name']:<20} {row['short_id']:<10} {state:<8} expires {expiry}")
        return EXIT_OK

    if args.member_command == "add":
        public_key: bytes
        psk: bytes
        if args.token:
            invite = decode_invite(args.token)
            public_key = b64d(invite.peer_public_key)
            psk = parse_psk(invite.psk)
            name = args.name or invite.name
        else:
            if not args.key:
                raise ConfigError("member add needs --key (the client's public key) or --token")
            public_key = b64d(args.key)
            psk = parse_psk(args.psk) if args.psk else None  # type: ignore[assignment]
            name = args.name or "peer"
        generated = psk is None
        if generated:
            psk = b64d(generate_psk())
        expires_at = time.time() + args.expires * 86400 if args.expires else None
        member = Member(
            name=name,
            public_key=public_key,
            psk=psk,
            expires_at=expires_at,
            tags=dict(args.tag or []),
        )
        store.add(member, replace=args.replace)
        store.save()

        result = {
            "name": member.name,
            "public_key": b64e(member.public_key),
            "short_id": member.short_id,
            "psk": b64e(member.psk),
            "psk_generated": generated,
            "expires_at": member.expires_at,
            "membership_file": str(store.path),
        }
        if args.json:
            _as_json(result)
            return EXIT_OK
        _print(f"added {member.name} ({member.short_id}) to {store.path}")
        if generated:
            _print(f"generated pre-shared key: {result['psk']}")
            _print("hand this to the client, or use `nfvpn token --member` for a single string")
        return EXIT_OK

    if args.member_command in ("revoke", "remove"):
        key_bytes = b64d(args.key) if args.key else None
        if key_bytes is None and args.name:
            found = store.get(args.name)
            if found is None:
                raise ConfigError(f"no member named {args.name!r}")
            key_bytes = found.public_key
        if key_bytes is None:
            raise ConfigError("say which member: --key <public key> or --name <name>")
        changed = (
            store.revoke(key_bytes)
            if args.member_command == "revoke"
            else store.remove(key_bytes)
        )
        if not changed:
            raise ConfigError("no member matched that key")
        store.save()
        _print(f"{args.member_command}d; {len(store)} member(s) remain in {store.path}")
        return EXIT_OK

    raise ConfigError(f"unknown member subcommand {args.member_command!r}")


def cmd_token(args) -> int:
    """Produce one string containing everything a client needs."""
    server_config_path = Path(args.config).expanduser() if args.config else None
    if args.relay and args.key and args.psk:
        invite = Invite(relay=args.relay, peer_public_key=args.key, psk=args.psk, name=args.name)
    else:
        config = ServerConfig.load(server_config_path) if server_config_path else ServerConfig()
        identity = Identity.load(Path(args.identity_file or config.identity_file).expanduser())
        if not args.member:
            raise ConfigError(
                "name the member whose pre-shared key the token should carry: "
                "`nfvpn token --member NAME`"
            )
        store = MembershipStore.load(
            Path(args.membership_file or config.membership_file).expanduser()
        )
        member = store.get(args.member)
        if member is None:
            raise ConfigError(f"no member named {args.member!r} in {store.path}")
        if not member.is_usable():
            raise ConfigError(f"member {args.member!r} is revoked or expired")
        host = args.host or ("relay.local" if config.listen_host == "0.0.0.0" else config.listen_host)
        relay = args.relay or f"{'wss' if config.tls_cert else 'ws'}://{host}:{config.listen_port}{config.ws_path}"
        invite = Invite(
            relay=relay,
            peer_public_key=b64e(identity.public_key),
            psk=b64e(member.psk),
            name=identity.name,
        )
        if args.name:
            invite = replace(invite, name=args.name)

    token = invite.encode()
    if args.json:
        _as_json(
            {
                "token": token,
                "relay": invite.relay,
                "peer_public_key": invite.peer_public_key,
                "fingerprint": fingerprint(b64d(invite.peer_public_key)),
                "name": invite.name,
            }
        )
        return EXIT_OK
    _print(token)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# serve / connect
# --------------------------------------------------------------------------- #
def _apply_server_overrides(config: ServerConfig, args) -> ServerConfig:
    changes: dict = {}
    if getattr(args, "listen", None):
        changes["listen_host"], changes["listen_port"] = parse_bind(args.listen, config.listen_port)
    if getattr(args, "ws_path", None):
        changes["ws_path"] = args.ws_path
    if getattr(args, "profile", None):
        changes["profile"] = args.profile
    if getattr(args, "encoding", None):
        changes["encoding"] = args.encoding
    if getattr(args, "tls_cert", None):
        changes["tls_cert"] = args.tls_cert
    if getattr(args, "tls_key", None):
        changes["tls_key"] = args.tls_key
    if getattr(args, "no_cover", False):
        changes["cover_traffic"] = False
    if getattr(args, "stats_interval", None) is not None:
        changes["stats_interval"] = args.stats_interval
    if getattr(args, "limit_mbps", None) is not None:
        changes["limit_mbps"] = args.limit_mbps
    if getattr(args, "log_level", None):
        changes["log_level"] = args.log_level
    if getattr(args, "identity_file", None):
        changes["identity_file"] = args.identity_file
    if getattr(args, "membership_file", None):
        changes["membership_file"] = args.membership_file
    if getattr(args, "server_header", None) is not None:
        changes["server_header"] = args.server_header or None
    if getattr(args, "cover_page", None):
        changes["cover_page"] = args.cover_page
    if getattr(args, "max_streams", None):
        changes["max_streams"] = args.max_streams
    if getattr(args, "idle_timeout", None):
        changes["idle_timeout"] = args.idle_timeout

    egress_changes: dict = {}
    if getattr(args, "allow_port", None):
        egress_changes["allow_ports"] = tuple(args.allow_port)
    if getattr(args, "deny_port", None):
        egress_changes["deny_ports"] = tuple(args.deny_port)
    if getattr(args, "allow_network", None):
        egress_changes["allow_networks"] = tuple(args.allow_network)
    if getattr(args, "deny_network", None):
        egress_changes["deny_networks"] = tuple(args.deny_network)
    if getattr(args, "allow_private", False):
        egress_changes["allow_private_literals"] = True

    if changes:
        config = replace(config, **changes)
    if egress_changes:
        config = replace(config, egress=replace(config.egress, **egress_changes))
    return config


def cmd_serve(args) -> int:
    """Run the relay."""
    config = ServerConfig.load(Path(args.config).expanduser()) if args.config else ServerConfig()
    config = _apply_server_overrides(config, args)
    configure_logging(config.log_level, quiet=args.quiet)

    identity = config.load_identity()
    membership = MembershipStore.load(Path(config.membership_file).expanduser())

    log = logging.getLogger("nfvpn.cli")
    log.info("relay identity: %s (%s)", identity.name, identity.short_id)
    log.info("public key: %s", b64e(identity.public_key))
    if config.egress.allow_private_literals:
        log.warning(
            "--allow-private is set: this relay will dial private addresses, "
            "including cloud metadata endpoints.  Only do this on a test rig."
        )
    if not config.tls_cert:
        log.warning(
            "no TLS certificate configured: the carrier is cleartext. "
            "A censor sees the WebSocket handshake; run behind a TLS terminator "
            "or pass --tls-cert/--tls-key for anything that matters."
        )

    async def main() -> int:
        relay = Relay(config, identity, membership)
        await relay.start()
        loop = asyncio.get_running_loop()
        stopping = asyncio.Event()

        def on_reload() -> None:
            try:
                reloaded = MembershipStore.load(Path(config.membership_file).expanduser())
            except NoFlagVPNError as exc:  # pragma: no cover - operator error
                log.error("membership reload failed: %s", exc)
                return
            relay.reload_membership(reloaded)

        def on_stop() -> None:
            stopping.set()

        try:
            loop.add_signal_handler(signal.SIGHUP, on_reload)
        except (NotImplementedError, AttributeError, ValueError):  # pragma: no cover
            pass
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, on_stop)
        except (NotImplementedError, AttributeError, ValueError):  # pragma: no cover
            pass

        await stopping.wait()
        await relay.stop()
        return EXIT_OK

    try:
        return asyncio.run(main())
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return EXIT_OK


def _apply_client_overrides(config: ClientConfig, args) -> ClientConfig:
    changes: dict = {}
    if getattr(args, "relay", None):
        changes["relay"] = args.relay
    if getattr(args, "peer_key", None):
        changes["peer_public_key"] = args.peer_key
    if getattr(args, "psk", None):
        changes["psk"] = args.psk
    if getattr(args, "listen", None):
        changes["listen_host"], changes["listen_port"] = parse_bind(args.listen, config.listen_port)
    if getattr(args, "profile", None):
        changes["profile"] = args.profile
    if getattr(args, "no_cover", False):
        changes["cover_traffic"] = False
    if getattr(args, "max_streams", None):
        changes["max_streams"] = args.max_streams
    if getattr(args, "insecure_tls", False):
        changes["insecure_tls"] = True
    if getattr(args, "ca_file", None):
        changes["ca_file"] = args.ca_file
    if getattr(args, "identity_file", None):
        changes["identity_file"] = args.identity_file
    if getattr(args, "peer_name", None):
        changes["peer_name"] = args.peer_name
    if getattr(args, "encoding", None):
        changes["encoding"] = args.encoding
    if getattr(args, "log_level", None):
        changes["log_level"] = args.log_level
    return replace(config, **changes) if changes else config


def cmd_connect(args) -> int:
    """Run the local proxy that tunnels through a relay."""
    config = ClientConfig.load(Path(args.config).expanduser()) if args.config else ClientConfig()

    if getattr(args, "token", None):
        invite = decode_invite(args.token)
        config = replace(
            config,
            relay=invite.relay,
            peer_public_key=invite.peer_public_key,
            psk=invite.psk,
            peer_name=invite.name,
        )
    config = _apply_client_overrides(config, args)
    configure_logging(config.log_level, quiet=args.quiet)

    if not config.relay:
        raise ConfigError("no relay configured: pass --relay/--token or set 'relay' in the config")
    if not config.peer_public_key:
        raise ConfigError("no relay public key configured: pass --peer-key or use an invite token")
    if not config.psk:
        raise ConfigError("no pre-shared key configured: pass --psk or use an invite token")

    auth: LocalAuth | None = None
    if getattr(args, "proxy_auth", None):
        username, separator, password = args.proxy_auth.partition(":")
        if not separator or not username:
            raise ConfigError("--proxy-auth expects USER:PASSWORD")
        auth = LocalAuth(username=username, password=password)

    expose = bool(getattr(args, "expose_lan", False))
    if expose and auth is None:
        raise ConfigError(
            "--expose-lan would publish an open proxy to your network; "
            "add --proxy-auth USER:PASSWORD (or leave the bind address on loopback)"
        )
    if expose:
        config = replace(config, listen_host="0.0.0.0", expose_lan=True)

    identity = config.load_identity()
    psk = parse_psk(config.psk)

    async def main() -> int:
        tunnel = Tunnel(config, identity, psk, b64d(config.peer_public_key))
        proxy = LocalProxy(tunnel, config, auth=auth)

        log = logging.getLogger("nfvpn.cli")
        log.info("client identity: %s (%s)", identity.name, identity.short_id)
        log.info("connecting to %s", config.relay)
        try:
            await tunnel.connect()
        except (NoFlagVPNError, OSError) as exc:
            log.error("could not establish the tunnel: %s", exc)
            return EXIT_FAILURE
        log.info("%s", tunnel.describe())

        bound = await proxy.start()
        if not expose and not _is_loopback(config.listen_host):
            log.warning(
                "the proxy is bound to %s, which is not loopback: anyone who can reach "
                "it can use your tunnel",
                config.listen_host,
            )
        _print("")
        _print(f"  NoFlagVPN is up.  Point your browser or game at:")
        for address in bound:
            _print(f"      SOCKS5 / HTTP proxy   {address}")
        _print("")
        _print(f"  relay: {config.relay}   profile: {config.profile}")
        _print("  press Ctrl+C to stop")
        _print("")

        loop = asyncio.get_running_loop()
        stopping = asyncio.Event()

        def on_stop() -> None:
            stopping.set()

        _install_signals(loop, on_stop=on_stop)
        if getattr(args, "stats_interval", 0):
            async def stats_loop() -> None:
                while not stopping.is_set():
                    await asyncio.sleep(args.stats_interval)
                    log.info("tunnel: %s", tunnel.describe())

            asyncio.create_task(stats_loop())

        await stopping.wait()
        log.info("shutting down: %s", tunnel.stats.summary())
        await proxy.stop()
        await tunnel.close()
        return EXIT_OK

    try:
        return asyncio.run(main())
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return EXIT_OK


# --------------------------------------------------------------------------- #
# probe / selftest / doctor / demo
# --------------------------------------------------------------------------- #
def cmd_probe(args) -> int:
    """Look at an endpoint the way a network scanner would."""
    report = asyncio.run(
        probe_endpoint(
            args.target,
            path=args.path or "/",
            timeout=args.timeout,
            rounds=args.rounds,
            insecure=args.insecure,
        )
    )
    if args.json:
        _as_json(report.as_dict())
    else:
        _print(format_report(report))
    warnings = [item for item in report.findings() if item[0] == "warn"]
    return EXIT_OK if not warnings else EXIT_FAILURE


def cmd_selftest(args) -> int:
    """End-to-end check: relay + client + proxy + origin, all on loopback."""
    from nfvpn.selftest import run_selftest

    return asyncio.run(run_selftest(verbose=not args.quiet, json_output=args.json))


def cmd_doctor(args) -> int:
    """Report on this machine's setup and on how our traffic looks."""
    from nfvpn.detect.audit import run_doctor

    return run_doctor(json_output=args.json)


def cmd_demo(args) -> int:
    """Run a relay and a client together on this machine, for a first look."""
    work = Path(args.directory).expanduser() if args.directory else Path(
        tempfile.mkdtemp(prefix="nfvpn-demo-")
    )
    work.mkdir(parents=True, exist_ok=True)
    configure_logging(args.log_level, quiet=False)

    relay_identity = Identity.load_or_create(work / "relay.key", "demo-relay")
    client_identity = Identity.load_or_create(work / "client.key", "demo-client")
    membership_path = work / "members.json"
    membership = MembershipStore.load(membership_path)
    psk_b64 = b64e(b64d(generate_psk()))
    if membership.get("demo-client") is None:
        membership.add(
            Member(name="demo-client", public_key=client_identity.public_key, psk=b64d(psk_b64)),
            replace=True,
        )
        membership.save(membership_path)

    relay_port = args.relay_port
    # The origin lives on loopback, so the demo relay has to be allowed to dial it.
    relay_config = ServerConfig(
        listen_host="127.0.0.1",
        listen_port=relay_port,
        identity_file=str(work / "relay.key"),
        membership_file=str(membership_path),
        profile=args.profile,
        egress=EgressPolicy(allow_private_literals=True),
        log_level=args.log_level,
    )
    client_config = ClientConfig(
        relay=f"ws://127.0.0.1:{relay_port}/",
        peer_public_key=b64e(relay_identity.public_key),
        psk=psk_b64,
        identity_file=str(work / "client.key"),
        listen_host="127.0.0.1",
        listen_port=args.proxy_port,
        profile=args.profile,
        log_level=args.log_level,
    )

    async def main() -> int:
        from nfvpn.selftest import start_origin

        origin, origin_url = await start_origin()
        relay = Relay(relay_config, relay_identity, membership)
        await relay.start()
        tunnel = Tunnel(client_config, client_identity, b64d(psk_b64), relay_identity.public_key)
        await tunnel.connect()
        proxy = LocalProxy(tunnel, client_config)
        await proxy.start()

        _print("")
        _print("  NoFlagVPN demo is running.")
        _print(f"    relay        ws://127.0.0.1:{relay_port}/          (localhost only)")
        _print(f"    proxy        SOCKS5 + HTTP on 127.0.0.1:{args.proxy_port}")
        _print(f"    test origin  {origin_url}")
        _print("")
        _print("  Try it:")
        _print(f"    curl --socks5-hostname 127.0.0.1:{args.proxy_port} {origin_url}")
        _print(f"    curl --proxy http://127.0.0.1:{args.proxy_port} {origin_url}")
        _print("")
        _print("  Set your browser's SOCKS5 proxy to 127.0.0.1:%d and load a game." % args.proxy_port)
        _print("  Press Ctrl+C to stop.")
        _print("")

        loop = asyncio.get_running_loop()
        stopping = asyncio.Event()
        _install_signals(loop, on_stop=stopping.set)
        await stopping.wait()
        await proxy.stop()
        await tunnel.close()
        await relay.stop()
        origin.close()
        return EXIT_OK

    try:
        return asyncio.run(main())
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return EXIT_OK


def cmd_version(args) -> int:
    """Print version and environment details."""
    data = {
        "version": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()}",
        "crypto_backend": backend_name(),
        "config_dir": str(config_dir()),
        "profiles": profile_names(),
    }
    if args.json:
        _as_json(data)
        return EXIT_OK
    _print(f"nfvpn {data['version']}")
    _print(f"python {data['python']} on {data['platform']}")
    _print(f"crypto backend: {data['crypto_backend']}")
    _print(f"config dir: {data['config_dir']}")
    return EXIT_OK
