"""``python -m nfvpn`` — the command line.

Every command is a plain function in :mod:`nfvpn.cli.commands`; this module only
builds the parser and turns exceptions into exit codes, because a tool that
prints a traceback for "you typed the wrong key" is a tool people stop using.
"""

from __future__ import annotations

import argparse
import sys

from nfvpn.cli import commands
from nfvpn.errors import ConfigError, NoFlagVPNError
from nfvpn.traffic import profile_names
from nfvpn.version import __version__

__all__ = ["build_parser", "main"]

_ENCODINGS = ("binary", "text")


def _add_server_options(
    parser: argparse.ArgumentParser,
    *,
    log_level_default: str | None = "info",
    include_allow_private: bool = False,
    include_quiet: bool = False,
) -> None:
    """Attach the common one-line relay settings to configure and serve."""
    parser.add_argument("--config", help="relay config file")
    parser.add_argument(
        "--listen",
        help="host:port, or 'auto' to bind all interfaces and auto-detect the invite IP",
    )
    parser.add_argument("--ws-path", help="URL path clients dial (default /)")
    parser.add_argument("--profile", choices=profile_names(), help="traffic shaping profile")
    parser.add_argument("--encoding", choices=_ENCODINGS, help="record encoding")
    parser.add_argument("--tls-cert", help="TLS certificate file")
    parser.add_argument("--tls-key", help="TLS private key file")
    parser.add_argument("--no-tls", action="store_true", help="disable TLS explicitly")
    parser.add_argument("--no-cover", action="store_true", help="do not send padding while idle")
    parser.add_argument("--cover", action="store_true", help="enable padding while idle")
    parser.add_argument("--cover-page", help="HTML file served to non-WebSocket requests")
    parser.add_argument("--server-header", help="Server: header to send ('' to omit)")
    parser.add_argument("--stats-interval", type=float, help="log counters every N seconds")
    parser.add_argument("--limit-mbps", type=float, help="cap each member's bandwidth")
    parser.add_argument("--max-streams", type=int)
    parser.add_argument("--idle-timeout", type=float)
    parser.add_argument("--handshake-timeout", type=float)
    parser.add_argument("--connect-timeout", type=float)
    parser.add_argument("--rekey-seconds", type=float)
    parser.add_argument("--window", type=int, help="flow-control window in bytes")
    parser.add_argument("--identity-file")
    parser.add_argument("--membership-file")
    parser.add_argument("--allow-port", type=int, action="append", help="restrict egress ports")
    parser.add_argument("--deny-port", type=int, action="append", help="refuse an egress port")
    parser.add_argument("--allow-network", action="append", help="restrict egress destinations")
    parser.add_argument("--deny-network", action="append", help="refuse an egress range")
    parser.add_argument("--allow-domain", action="append", help="restrict egress hostnames")
    parser.add_argument("--deny-domain", action="append", help="refuse an egress hostname suffix")
    if include_allow_private:
        parser.add_argument(
            "--allow-private",
            action="store_true",
            help="let the relay dial private addresses (test rigs only)",
        )
    parser.add_argument("--log-level", default=log_level_default)
    parser.add_argument("--log-file")
    if include_quiet:
        parser.add_argument("--quiet", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    """The whole command tree."""
    parser = argparse.ArgumentParser(
        prog="nfvpn",
        description=(
            "NoFlagVPN — a censorship-resistant tunnel that is hard to tell apart "
            "from ordinary web traffic."
        ),
        epilog="Run `nfvpn selftest` after installing to check the whole thing end to end.",
    )
    parser.add_argument("--version", action="version", version=f"nfvpn {__version__}")
    parser.add_argument(
        "--config", dest="global_config", help="config path (before a command, e.g. nfvpn --config relay.json serve)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- init --------------------------------------------------------------
    init = subparsers.add_parser("init", help="create a safe, local-only relay setup")
    init.add_argument("--config", help="where to write the relay config (default: config.json)")
    init.add_argument("--json", action="store_true", help="print created paths as JSON")
    init.set_defaults(func=commands.cmd_init)

    # -- keygen ------------------------------------------------------------
    keygen = subparsers.add_parser("keygen", help="create this machine's long-term identity")
    keygen.add_argument(
        "--name",
        help=(
            "label for the identity, and the file it is written to "
            "(default: hostname; use 'relay' on the relay and 'client' on the client)"
        ),
    )
    keygen.add_argument("--out", help="where to write the private key")
    keygen.add_argument("--force", action="store_true", help="overwrite an existing file")
    keygen.add_argument("--psk", action="store_true", help="also print a fresh pre-shared key")
    keygen.add_argument("--json", action="store_true")
    keygen.set_defaults(func=commands.cmd_keygen)

    # -- token -------------------------------------------------------------
    token = subparsers.add_parser("token", help="build a one-line invite for a client")
    token.add_argument("--config", help="relay config file to read defaults from")
    token.add_argument("--identity-file")
    token.add_argument("--membership-file")
    token.add_argument("--member", help="member whose pre-shared key to embed")
    token.add_argument("--relay", help="relay URL to put in the token")
    token.add_argument("--host", help="hostname clients should dial")
    token.add_argument("--key", help="relay public key (base64url)")
    token.add_argument("--psk", help="pre-shared key (base64url)")
    token.add_argument("--name", help="relay name shown to clients")
    token.add_argument("--json", action="store_true")
    token.set_defaults(func=commands.cmd_token)

    # -- member ------------------------------------------------------------
    member = subparsers.add_parser("member", help="manage a relay's allowlist")
    member.add_argument("--config", help="membership file (default: the config dir)")
    member.add_argument("--json", action="store_true")
    member_sub = member.add_subparsers(dest="member_command", required=True)
    member_add = member_sub.add_parser("add", help="authorize a new client")
    # Arguments repeated at this level use SUPPRESS so that they do not clobber
    # a value given before the subcommand ("member --config x list").
    member_add.add_argument(
        "--config", default=argparse.SUPPRESS, help="membership file (same as the parent option)"
    )
    member_add.add_argument("--name")
    member_add.add_argument("--key", help="the client's public key")
    member_add.add_argument("--psk", help="pre-shared key (default: generate one)")
    member_add.add_argument("--token", help="an invite token produced by the client's keygen")
    member_add.add_argument("--expires", type=float, help="days until this member expires")
    member_add.add_argument(
        "--tag", action="append", metavar="KEY=VALUE", help="free-form label (repeatable)"
    )
    member_add.add_argument("--replace", action="store_true")
    member_add.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    member_list = member_sub.add_parser("list", help="show every member")
    member_list.add_argument(
        "--config", default=argparse.SUPPRESS, help="membership file (same as the parent option)"
    )
    member_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    for name, help_text in (("revoke", "disable a member"), ("remove", "forget a member")):
        sub = member_sub.add_parser(name, help=help_text)
        # Accept --config after the subcommand as well as before it: both are
        # what people type, and argparse cannot share an option across levels.
        sub.add_argument(
            "--config", default=argparse.SUPPRESS, help="membership file (same as the parent option)"
        )
        sub.add_argument("--key")
        sub.add_argument("--name")
    member.set_defaults(func=commands.cmd_member)

    # -- configure / serve -----------------------------------------------
    configure = subparsers.add_parser(
        "configure", help="write relay settings from command-line options (no file editing)"
    )
    _add_server_options(configure, log_level_default=None)
    configure.set_defaults(func=commands.cmd_configure)

    serve = subparsers.add_parser("serve", help="run the relay")
    _add_server_options(serve, include_allow_private=True, include_quiet=True)
    serve.set_defaults(func=commands.cmd_serve)

    # -- connect -----------------------------------------------------------
    connect = subparsers.add_parser("connect", help="run the local proxy")
    connect.add_argument("--config", help="client config file")
    connect.add_argument("--token", help="invite token from the relay operator")
    connect.add_argument("--relay", help="relay URL (wss://host:port/path)")
    connect.add_argument("--peer-key", help="the relay's public key")
    connect.add_argument("--psk", help="pre-shared key")
    connect.add_argument("--peer-name", help="label for the relay")
    connect.add_argument(
        "--failover",
        action="append",
        metavar="URL",
        help="another relay to try when the first is unreachable (repeatable)",
    )
    connect.add_argument("--listen", help="where the local proxy listens (default 127.0.0.1:8080)")
    connect.add_argument("--profile", choices=profile_names())
    connect.add_argument("--encoding", choices=_ENCODINGS)
    connect.add_argument("--no-cover", action="store_true")
    connect.add_argument("--max-streams", type=int)
    connect.add_argument("--insecure-tls", action="store_true", help="skip certificate checks")
    connect.add_argument("--ca-file", help="trust only this CA (for self-signed relays)")
    connect.add_argument("--identity-file")
    connect.add_argument("--proxy-auth", metavar="USER:PASSWORD")
    connect.add_argument(
        "--expose-lan",
        action="store_true",
        help="listen on 0.0.0.0 (requires --proxy-auth)",
    )
    connect.add_argument("--stats-interval", type=float, default=0.0)
    connect.add_argument("--log-level", default="info")
    connect.add_argument("--quiet", action="store_true")
    connect.set_defaults(func=commands.cmd_connect)

    # -- probe / selftest / doctor / demo / version ------------------------
    probe = subparsers.add_parser(
        "probe", help="look at an endpoint the way a network scanner would"
    )
    probe.add_argument("target", help="host, host:port, or a full wss:// URL")
    probe.add_argument("--path", help="URL path to request")
    probe.add_argument("--timeout", type=float, default=6.0)
    probe.add_argument("--rounds", type=int, default=3, help="how many junk probes to send")
    probe.add_argument("--insecure", action="store_true", help="ignore TLS certificate errors")
    probe.add_argument("--json", action="store_true")
    probe.set_defaults(func=commands.cmd_probe)

    selftest = subparsers.add_parser(
        "selftest", help="run the whole stack on loopback and check every promise"
    )
    selftest.add_argument("--json", action="store_true")
    selftest.add_argument("--quiet", action="store_true")
    selftest.set_defaults(func=commands.cmd_selftest)

    doctor = subparsers.add_parser("doctor", help="check this machine's setup and traffic shape")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=commands.cmd_doctor)

    demo = subparsers.add_parser("demo", help="start a relay and a client locally, for a first look")
    demo.add_argument("--directory", help="where to keep the demo keys")
    demo.add_argument("--relay-port", type=int, default=8443)
    demo.add_argument("--proxy-port", type=int, default=8080)
    demo.add_argument("--profile", default="balanced", choices=profile_names())
    demo.add_argument("--log-level", default="warning")
    demo.set_defaults(func=commands.cmd_demo)

    version = subparsers.add_parser("version", help="print version and environment")
    version.add_argument("--json", action="store_true")
    version.set_defaults(func=commands.cmd_version)

    return parser


#: Options whose value is an opaque base64url blob.  A freshly generated key
#: starts with "-" about once in 69 keys, and argparse would read that as an
#: option name; these are re-joined as ``--opt=value`` before parsing.
_OPAQUE_VALUE_OPTIONS = frozenset(
    {"--key", "--psk", "--token", "--peer-key", "--ca-file", "--proxy-auth", "--invite"}
)


def _rejoin_opaque_values(argv: list[str]) -> list[str]:
    """Rewrite ``--key -AbC…`` as ``--key=-AbC…`` so argparse accepts it.

    Without this, one key in ~69 is unreachable from the command line through no
    fault of the person typing it.
    """
    fixed: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if (
            item in _OPAQUE_VALUE_OPTIONS
            and index + 1 < len(argv)
            and argv[index + 1].startswith("-")
            and argv[index + 1] not in ("-", "--")
        ):
            fixed.append(f"{item}={argv[index + 1]}")
            index += 2
            continue
        fixed.append(item)
        index += 1
    return fixed


def main(argv: list[str] | None = None) -> int:
    """Entry point.  Returns a process exit code."""
    parser = build_parser()
    # sys.argv[1:] rather than argv=None, so the opaque-value rewrite below
    # applies to the real command line too and not only to in-process calls.
    arguments = list(sys.argv[1:] if argv is None else argv)
    # A root-level config path followed by settings is a configure-once command:
    # `nfvpn --config relay.json --listen 127.0.0.1:8443`. An explicit command
    # still wins, as in `nfvpn --config relay.json serve`.
    if arguments and (arguments[0] == "--config" or arguments[0].startswith("--config=")):
        command_index = 2 if arguments[0] == "--config" else 1
        command_names = {
            "configure", "connect", "demo", "doctor", "init", "keygen", "member",
            "probe", "selftest", "serve", "token", "version",
        }
        if command_index >= len(arguments) or arguments[command_index] not in command_names:
            arguments.insert(command_index, "configure")
    args = parser.parse_args(_rejoin_opaque_values(arguments))
    global_config = getattr(args, "global_config", None)
    if global_config and hasattr(args, "config") and not args.config:
        args.config = global_config
    function = getattr(args, "func", None)
    if function is None:  # pragma: no cover - argparse enforces a subcommand
        parser.print_help()
        return commands.EXIT_USAGE
    try:
        return int(function(args) or 0)
    except ConfigError as exc:
        print(f"nfvpn: {exc}", file=sys.stderr)
        return commands.EXIT_USAGE
    except NoFlagVPNError as exc:
        print(f"nfvpn: {type(exc).__name__}: {exc}", file=sys.stderr)
        return commands.EXIT_FAILURE
    except KeyboardInterrupt:  # pragma: no cover - interactive
        print("", file=sys.stderr)
        return 130
    except BrokenPipeError:  # pragma: no cover - `| head`
        return commands.EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
