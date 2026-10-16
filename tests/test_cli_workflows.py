"""CLI workflows that a whole session runs through, not one command at a time.

``test_cli.py`` checks each command exists and its happy path works;
``test_cli_robustness.py`` checks that bad input produces sentences.  This file
covers the middle: the workflows an operator actually repeats (add a member,
re-key it, hand out a token, revoke it), the flag-to-config plumbing behind
``serve`` and ``connect``, and the two long-running commands, which are started
for real and signalled to stop.
"""

from __future__ import annotations

import json
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
from nfvpn.cli.commands import _apply_client_overrides, _apply_server_overrides, parse_bind
from nfvpn.cli.main import build_parser, main
from nfvpn.config import ClientConfig, ServerConfig
from nfvpn.core.encoding import b64d, b64e, fingerprint
from nfvpn.core.keys import Identity, Member, MembershipStore, parse_psk
from nfvpn.tokens import decode_invite

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path):
    monkeypatch.setenv("NFVPN_CONFIG_DIR", str(tmp_path / "config"))
    return tmp_path / "config"


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_ok(capsys, *argv: str) -> str:
    code, out, err = run(capsys, *argv)
    assert code == 0, f"{argv} failed: {err}"
    return out


def parse_args(*argv: str):
    return build_parser().parse_args(list(argv))


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# --------------------------------------------------------------------------- #
# member lifecycle
# --------------------------------------------------------------------------- #
def test_a_member_is_added_with_a_generated_key_and_a_psk(capsys, isolated_config):
    client = Identity.generate("laptop")
    out = run_ok(
        capsys,
        "member",
        "add",
        "--name",
        "laptop",
        "--key",
        b64e(client.public_key),
    )
    assert "added laptop" in out
    assert "generated pre-shared key" in out, "the operator must be told how to hand it over"
    assert "nfvpn token --member" in out, "and pointed at the one-string alternative"

    store = MembershipStore.load(isolated_config / "members.json")
    member = store.get("laptop")
    assert member is not None
    assert member.public_key == client.public_key
    assert member.is_usable()
    assert member.psk and len(member.psk) == 32


def test_member_add_json_is_the_handoff_format(capsys, isolated_config):
    client = Identity.generate("laptop")
    code, out, _err = run(
        capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key), "--json"
    )
    assert code == 0
    payload = json.loads(out)
    assert payload["psk_generated"] is True
    assert payload["membership_file"] == str(isolated_config / "members.json")
    assert isinstance(payload["expires_at"], type(None))
    # The JSON form has to carry a usable key, or it is decoration.
    assert b64d(payload["public_key"]) == client.public_key
    assert len(b64d(payload["psk"])) == 32


def test_readding_a_name_with_a_new_key_needs_replace(capsys, isolated_config):
    first = Identity.generate("laptop")
    second = Identity.generate("laptop")
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(first.public_key))

    code, _out, err = run(
        capsys, "member", "add", "--name", "laptop", "--key", b64e(second.public_key)
    )
    assert code != 0
    assert "--replace" in err, "the error must name the flag that resolves it"

    store = MembershipStore.load(isolated_config / "members.json")
    assert len(store) == 1, "the refusal must not have added anything"

    run_ok(
        capsys,
        "member",
        "add",
        "--name",
        "laptop",
        "--key",
        b64e(second.public_key),
        "--replace",
    )
    store = MembershipStore.load(isolated_config / "members.json")
    assert len(store) == 1, "re-keying is not a second laptop"
    member = store.get("laptop")
    assert member is not None and member.public_key == second.public_key


def test_adding_the_same_name_and_key_twice_is_harmless(capsys, isolated_config):
    client = Identity.generate("laptop")
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key))
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key))
    store = MembershipStore.load(isolated_config / "members.json")
    assert len(store) == 1


def test_members_can_be_added_from_an_invite_token(capsys, isolated_config):
    client = Identity.generate("laptop")
    psk = "A7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    from nfvpn.tokens import Invite

    token = Invite(
        relay="wss://relay.example/healthz",
        peer_public_key=b64e(client.public_key),
        psk=psk,
        name="laptop",
    ).encode()

    out = run_ok(capsys, "member", "add", "--token", token)
    assert "added laptop" in out, "the token carries the name"
    store = MembershipStore.load(isolated_config / "members.json")
    member = store.get("laptop")
    assert member is not None
    assert member.public_key == client.public_key
    assert member.psk == parse_psk(psk), "the token's own key is reused, not a fresh one"


def test_a_given_expiry_is_stored_and_shown(capsys, isolated_config):
    client = Identity.generate("phone")
    run_ok(
        capsys,
        "member",
        "add",
        "--name",
        "phone",
        "--key",
        b64e(client.public_key),
        "--expires",
        "7",
    )
    store = MembershipStore.load(isolated_config / "members.json")
    member = store.get("phone")
    assert member is not None and member.expires_at is not None
    assert 6.9 < (member.expires_at - time.time()) / 86400 <= 7.0

    listing = run_ok(capsys, "member", "list")
    assert "phone" in listing
    assert "expires 20" in listing, "a date, not a timestamp"
    assert "never" not in listing


@pytest.mark.parametrize("days", ["-1", "0"])
def test_expiry_days_reject_nonsense(capsys, isolated_config, days):
    """A member that expires before it is added is a typo, not a policy."""
    client = Identity.generate("phone")
    code, _out, err = run(
        capsys,
        "member",
        "add",
        "--name",
        "phone",
        "--key",
        b64e(client.public_key),
        "--expires",
        days,
    )
    assert code != 0
    assert "expires" in err
    assert len(MembershipStore.load(isolated_config / "members.json")) == 0, "nothing was added"


def test_tags_are_stored_and_listed_in_json(capsys, isolated_config):
    client = Identity.generate("laptop")
    run_ok(
        capsys,
        "member",
        "add",
        "--name",
        "laptop",
        "--key",
        b64e(client.public_key),
        "--tag",
        "owner=sam",
        "--tag",
        "device=laptop",
        "--json",
    )
    payload = json.loads(run_ok(capsys, "member", "list", "--json"))
    assert payload["members"][0]["tags"] == ["owner=sam", "device=laptop"]
    assert payload["file"].endswith("members.json")
    listing = run_ok(capsys, "member", "list")
    assert "owner=sam" in listing, "the text listing shows tags too"


def test_revoking_by_name_catches_every_member_with_that_name(capsys, isolated_config):
    """Two entries answering to one name is exactly the case that matters."""
    store = MembershipStore.load(isolated_config / "members.json")
    for _ in range(2):
        identity = Identity.generate("laptop")
        store.add(
            Member(name="laptop", public_key=identity.public_key, psk=b"p" * 32), replace=True
        )
    store.save()

    out = run_ok(capsys, "member", "revoke", "--name", "laptop")
    assert "revoked 2 member(s)" in out
    remaining = list(MembershipStore.load(isolated_config / "members.json"))
    assert len(remaining) == 2, "revoking disables; it does not forget"
    assert all(not member.enabled for member in remaining), "and it disables every match"


def test_revoking_a_member_that_does_not_exist_says_so(capsys, isolated_config):
    code, _out, err = run(capsys, "member", "revoke", "--name", "ghost")
    assert code != 0
    assert "ghost" in err


def test_removing_is_different_from_revoking(capsys, isolated_config):
    client = Identity.generate("laptop")
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key))

    out = run_ok(capsys, "member", "revoke", "--name", "laptop")
    assert "revoked 1 member(s); 1 remain" in out
    assert "revoked" in run_ok(capsys, "member", "list")
    listing = json.loads(run_ok(capsys, "member", "list", "--json"))
    assert listing["members"][0]["enabled"] is False

    out = run_ok(capsys, "member", "remove", "--name", "laptop")
    assert "removed 1 member(s); 0 remain" in out
    assert "no members in" in run_ok(capsys, "member", "list")


def test_revoking_by_key_works_and_an_unknown_key_does_not(capsys, isolated_config):
    client = Identity.generate("laptop")
    other = Identity.generate("other")
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key))

    code, _out, err = run(capsys, "member", "revoke", "--key", b64e(other.public_key))
    assert code != 0
    assert "no member matched" in err

    assert "revoked 1 member(s)" in run_ok(capsys, "member", "revoke", "--key", b64e(client.public_key))


def test_a_member_file_that_is_not_readable_says_so(capsys, isolated_config):
    isolated_config.mkdir(parents=True, exist_ok=True)
    (isolated_config / "members.json").write_text("{{{ not json")
    code, _out, err = run(capsys, "member", "list")
    assert code != 0
    assert "members.json" in err


def test_member_list_is_empty_rather_than_wrong_on_a_fresh_relay(capsys):
    out = run_ok(capsys, "member", "list")
    assert "no members" in out
    assert "refused" in out, "say what an empty allowlist means"


# --------------------------------------------------------------------------- #
# tokens
# --------------------------------------------------------------------------- #
def test_a_token_from_flags_round_trips(capsys):
    relay_key = b64e(Identity.generate("relay").public_key)
    psk = "A7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    out = run_ok(
        capsys,
        "token",
        "--relay",
        "wss://relay.example:443/healthz",
        "--key",
        relay_key,
        "--psk",
        psk,
        "--name",
        "relay.example",
    )
    token = out.strip()
    invite = decode_invite(token)
    assert invite.relay == "wss://relay.example:443/healthz"
    assert invite.peer_public_key == relay_key
    assert invite.name == "relay.example"
    assert len(token) < 400, "an invite must be pasteable"


def test_a_token_for_a_member_is_built_from_the_server_config(capsys, isolated_config):
    isolated_config.mkdir(parents=True, exist_ok=True)
    config = ServerConfig(
        listen_host="203.0.113.7",
        listen_port=443,
        ws_path="/healthz",
        identity_file=str(isolated_config / "relay.key"),
    )
    config.save(isolated_config / "relay.json")
    identity = Identity.load_or_create(isolated_config / "relay.key", "relay")

    client = Identity.generate("laptop")
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key))

    invite = decode_invite(run_ok(capsys, "token", "--member", "laptop").strip())
    assert invite.relay == "ws://203.0.113.7:443/healthz", "host and port come from the config"
    assert invite.peer_public_key == b64e(identity.public_key)
    assert invite.name == "relay"
    store = MembershipStore.load(isolated_config / "members.json")
    member = store.get("laptop")
    assert member is not None
    assert parse_psk(invite.psk) == member.psk, "the token carries the member's own key"


def test_a_tls_relay_produces_a_wss_token(capsys, isolated_config):
    isolated_config.mkdir(parents=True, exist_ok=True)
    ServerConfig(
        listen_host="relay.example",
        listen_port=443,
        tls_cert="/etc/ssl/c.pem",
        tls_key="/etc/ssl/k.pem",
    ).save(isolated_config / "relay.json")
    Identity.load_or_create(isolated_config / "relay.key", "relay")
    client = Identity.generate("laptop")
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key))
    invite = decode_invite(run_ok(capsys, "token", "--member", "laptop").strip())
    assert invite.relay.startswith("wss://"), "a TLS relay must not be handed out as ws://"


def test_a_bound_to_everything_relay_does_not_hand_out_0000(capsys, isolated_config):
    isolated_config.mkdir(parents=True, exist_ok=True)
    ServerConfig(listen_host="0.0.0.0", listen_port=8443).save(isolated_config / "relay.json")
    Identity.load_or_create(isolated_config / "relay.key", "relay")
    client = Identity.generate("laptop")
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key))

    invite = decode_invite(run_ok(capsys, "token", "--member", "laptop").strip())
    assert "0.0.0.0" not in invite.relay, "0.0.0.0 is not an address a client can dial"
    assert invite.relay.startswith("ws://relay.local:")


def test_a_token_for_an_unknown_or_revoked_member_is_refused(capsys, isolated_config):
    isolated_config.mkdir(parents=True, exist_ok=True)
    ServerConfig(listen_port=443).save(isolated_config / "relay.json")
    Identity.load_or_create(isolated_config / "relay.key", "relay")

    code, _out, err = run(capsys, "token", "--member", "ghost")
    assert code != 0
    assert "ghost" in err

    client = Identity.generate("laptop")
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key))
    run_ok(capsys, "member", "revoke", "--name", "laptop")
    code, _out, err = run(capsys, "token", "--member", "laptop")
    assert code != 0
    assert "revoked or expired" in err


def test_a_token_that_names_no_member_says_which_flag_to_use(capsys, isolated_config):
    isolated_config.mkdir(parents=True, exist_ok=True)
    ServerConfig(listen_port=443).save(isolated_config / "relay.json")
    Identity.load_or_create(isolated_config / "relay.key", "relay")
    code, _out, err = run(capsys, "token")
    assert code != 0
    assert "--member" in err


def test_a_token_json_output_is_machine_readable(capsys):
    relay_key = b64e(Identity.generate("relay").public_key)
    psk = "A7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    payload = json.loads(
        run_ok(
            capsys, "token", "--relay", "ws://r/x", "--key", relay_key, "--psk", psk, "--json"
        )
    )
    assert b64d(payload["peer_public_key"]) == b64d(relay_key)
    assert payload["fingerprint"] == fingerprint(b64d(relay_key))
    assert decode_invite(payload["token"]).relay == "ws://r/x"


# --------------------------------------------------------------------------- #
# flag → config plumbing
# --------------------------------------------------------------------------- #
def test_serve_flags_land_in_the_config():
    args = parse_args(
        "serve",
        "--listen",
        "0.0.0.0:9443",
        "--ws-path",
        "/cdn",
        "--profile",
        "paranoid",
        "--encoding",
        "text",
        "--tls-cert",
        "/tmp/c.pem",
        "--tls-key",
        "/tmp/k.pem",
        "--no-cover",
        "--stats-interval",
        "30",
        "--limit-mbps",
        "12.5",
        "--log-level",
        "debug",
        "--identity-file",
        "/tmp/relay.key",
        "--membership-file",
        "/tmp/members.json",
        "--server-header",
        "nginx",
        "--cover-page",
        "/tmp/index.html",
        "--max-streams",
        "64",
        "--idle-timeout",
        "120",
        "--allow-port",
        "443",
        "--deny-port",
        "25",
        "--allow-network",
        "10.0.0.0/8",
        "--deny-network",
        "169.254.0.0/16",
        "--allow-private",
    )
    config = _apply_server_overrides(ServerConfig(), args)

    assert (config.listen_host, config.listen_port) == ("0.0.0.0", 9443)
    assert config.ws_path == "/cdn"
    assert config.profile == "paranoid"
    assert config.encoding == "text"
    assert (config.tls_cert, config.tls_key) == ("/tmp/c.pem", "/tmp/k.pem")
    assert config.cover_traffic is False
    assert config.stats_interval == 30
    assert config.limit_mbps == 12.5
    assert config.log_level == "debug"
    assert config.identity_file == "/tmp/relay.key"
    assert config.membership_file == "/tmp/members.json"
    assert config.server_header == "nginx"
    assert config.cover_page == "/tmp/index.html"
    assert config.max_streams == 64
    assert config.idle_timeout == 120
    assert config.egress.allow_ports == (443,)
    assert config.egress.deny_ports == (25,)
    assert config.egress.allow_networks == ("10.0.0.0/8",)
    assert config.egress.deny_networks == ("169.254.0.0/16",)
    assert config.egress.allow_private_literals is True


def test_no_server_flags_leaves_the_config_exactly_alone():
    original = ServerConfig(listen_port=443, profile="balanced")
    assert _apply_server_overrides(original, parse_args("serve")) == original


def test_a_dash_server_header_means_send_none():
    """`--server-header ""` must clear it, not be ignored as an empty value."""
    config = _apply_server_overrides(ServerConfig(), parse_args("serve", "--server-header", ""))
    assert config.server_header is None


def test_zero_is_a_value_and_not_an_absent_flag():
    args = parse_args("serve", "--max-streams", "0")
    with pytest.raises(Exception) as caught:
        _apply_server_overrides(ServerConfig(), args)
    assert "max_streams" in str(caught.value)


def test_connect_flags_land_in_the_config():
    args = parse_args(
        "connect",
        "--relay",
        "wss://relay.example/cdn",
        "--peer-key",
        b64e(Identity.generate("r").public_key),
        "--psk",
        "A7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "--listen",
        "127.0.0.1:1080",
        "--profile",
        "low-latency",
        "--no-cover",
        "--max-streams",
        "32",
        "--ca-file",
        "/tmp/ca.pem",
        "--identity-file",
        "/tmp/client.key",
        "--peer-name",
        "relay.example",
        "--failover",
        "ws://second.example/x",
        "--encoding",
        "text",
        "--log-level",
        "info",
    )
    config = _apply_client_overrides(ClientConfig(), args)
    assert config.relay == "wss://relay.example/cdn"
    assert (config.listen_host, config.listen_port) == ("127.0.0.1", 1080)
    assert config.profile == "low-latency"
    assert config.cover_traffic is False
    assert config.max_streams == 32
    assert config.ca_file == "/tmp/ca.pem"
    assert config.insecure_tls is False, "one or the other, and --ca-file was given"
    assert config.identity_file == "/tmp/client.key"
    assert config.peer_name == "relay.example"
    assert config.failover == ("ws://second.example/x",)
    assert config.encoding == "text"
    assert config.log_level == "info"


def test_no_connect_flags_leaves_the_config_alone():
    original = ClientConfig(relay="ws://r/x", peer_public_key="k", psk="p")
    assert _apply_client_overrides(original, parse_args("connect")) == original


def _capturing_relay(seen: dict):
    """A stand-in Relay that records the config it was handed and stops."""

    class CapturingRelay:
        def __init__(self, config, identity, membership):
            seen["config"] = config
            seen["identity"] = identity
            seen["membership"] = membership

        async def start(self):
            import asyncio

            asyncio.get_running_loop().call_later(0.02, signal.raise_signal, signal.SIGINT)

        async def stop(self):
            pass

        def reload_membership(self, store):
            pass

    return CapturingRelay


def test_serve_reads_relay_json_from_the_config_dir(isolated_config, monkeypatch):
    """The documented layout: a settings file in the config dir is the settings."""
    isolated_config.mkdir(parents=True, exist_ok=True)
    ServerConfig(
        listen_host="127.0.0.1",
        listen_port=free_port(),
        profile="paranoid",
        server_header="nginx",
        ws_path="/cdn",
    ).save(isolated_config / "relay.json")

    seen: dict = {}
    monkeypatch.setattr("nfvpn.cli.commands.Relay", _capturing_relay(seen))
    assert main(["serve"]) == 0
    config = seen["config"]
    assert config.profile == "paranoid", "relay.json was not read"
    assert config.server_header == "nginx"
    assert config.ws_path == "/cdn"
    assert config.identity_file == str(isolated_config / "relay.key"), "keys stay in the config dir"


def test_an_explicit_config_file_still_wins(isolated_config, tmp_path, monkeypatch):
    isolated_config.mkdir(parents=True, exist_ok=True)
    ServerConfig(listen_port=free_port(), profile="paranoid").save(isolated_config / "relay.json")
    elsewhere = tmp_path / "other-relay.json"
    ServerConfig(listen_port=free_port(), profile="off").save(elsewhere)

    seen: dict = {}
    monkeypatch.setattr("nfvpn.cli.commands.Relay", _capturing_relay(seen))
    assert main(["serve", "--config", str(elsewhere)]) == 0
    assert seen["config"].profile == "off"


def test_a_config_file_that_does_not_exist_is_an_error(isolated_config, capsys):
    """A typo must not silently start a relay on defaults."""
    code, _out, err = run(capsys, "serve", "--config", "/nope/relay.json")
    assert code != 0
    assert "/nope/relay.json" in err


def test_connect_reads_client_json_from_the_config_dir(isolated_config, monkeypatch):
    isolated_config.mkdir(parents=True, exist_ok=True)
    ClientConfig(
        relay="ws://127.0.0.1:1/healthz",
        peer_public_key=b64e(Identity.generate("relay").public_key),
        psk="A7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        listen_host="127.0.0.1",
        listen_port=free_port(),
        peer_name="from-the-file",
        log_level="critical",
    ).save(isolated_config / "client.json")

    seen: dict = {}

    class Tunnel:
        def __init__(self, config, identity, psk, peer_key):
            seen["config"] = config
            self.stats = type("S", (), {"summary": lambda self: ""})()
            self.active_endpoint = config.relay
            self.session = None

        async def connect(self):
            pass

        def describe(self):
            return "tunnel"

        async def close(self):
            pass

    class Proxy:
        def __init__(self, tunnel, config, auth=None):
            pass

        async def start(self):
            import asyncio

            asyncio.get_running_loop().call_later(0.02, signal.raise_signal, signal.SIGINT)
            return ["127.0.0.1:1"]

        async def stop(self):
            pass

    monkeypatch.setattr("nfvpn.cli.commands.Tunnel", Tunnel)
    monkeypatch.setattr("nfvpn.cli.commands.LocalProxy", Proxy)
    assert main(["connect"]) == 0
    assert seen["config"].peer_name == "from-the-file", "client.json was not read"


def test_a_star_bind_means_every_interface(isolated_config, monkeypatch):
    isolated_config.mkdir(parents=True, exist_ok=True)
    seen: dict = {}
    monkeypatch.setattr("nfvpn.cli.commands.Relay", _capturing_relay(seen))
    assert main(["serve", "--listen", "*:9443"]) == 0
    assert (seen["config"].listen_host, seen["config"].listen_port) == ("0.0.0.0", 9443)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("127.0.0.1", ("127.0.0.1", 8443)),
        ("127.0.0.1:9000", ("127.0.0.1", 9000)),
        ("[::1]:9000", ("::1", 9000)),
        ("*", ("0.0.0.0", 8443)),
        ("*:9000", ("0.0.0.0", 9000)),
        ("0.0.0.0:443", ("0.0.0.0", 443)),
        ("hostname:8443", ("hostname", 8443)),
    ],
)
def test_bind_addresses_parse(text, expected):
    assert parse_bind(text, 8443) == expected


# --------------------------------------------------------------------------- #
# the long-running commands, started for real
# --------------------------------------------------------------------------- #
def test_serve_wires_up_signals_and_stops_on_sigint(isolated_config, monkeypatch, capsys):
    """The daemon path: start, install handlers, stop on SIGINT."""
    isolated_config.mkdir(parents=True, exist_ok=True)
    ServerConfig(listen_host="127.0.0.1", listen_port=free_port()).save(
        isolated_config / "relay.json"
    )

    seen = {"started": False, "stopped": False, "reloaded": None}

    class FakeRelay:
        def __init__(self, config, identity, membership):
            self.config = config
            self.identity = identity
            self.membership = membership

        async def start(self):
            seen["started"] = True
            import asyncio

            asyncio.get_running_loop().call_later(0.05, signal.raise_signal, signal.SIGINT)

        async def stop(self):
            seen["stopped"] = True

        def reload_membership(self, store):
            seen["reloaded"] = store

    monkeypatch.setattr("nfvpn.cli.commands.Relay", FakeRelay)
    code = main(["serve", "--quiet"])
    assert code == 0
    assert seen == {"started": True, "stopped": True, "reloaded": None}


def test_serve_warns_about_the_two_settings_that_really_matter(
    isolated_config, capsys, monkeypatch
):
    """--allow-private and no TLS are the two mistakes worth a log line."""
    isolated_config.mkdir(parents=True, exist_ok=True)
    client = Identity.generate("laptop")
    run_ok(capsys, "member", "add", "--name", "laptop", "--key", b64e(client.public_key))

    class StoppingRelay:
        def __init__(self, *args, **kwargs):
            pass

        async def start(self):
            import asyncio

            asyncio.get_running_loop().call_later(0.05, signal.raise_signal, signal.SIGINT)

        async def stop(self):
            pass

        def reload_membership(self, store):
            pass

    monkeypatch.setattr("nfvpn.cli.commands.Relay", StoppingRelay)

    # configure_logging() rewrites the root logger, so the warnings go to stderr
    # (not through caplog, whose handler it removes).
    code = main(["serve", "--allow-private"])
    assert code == 0
    text = capsys.readouterr().err
    assert "allow-private" in text and "metadata" in text
    assert "no TLS certificate" in text
    assert "relay identity" in text, "an operator wants to see which key is running"


def test_connect_starts_the_proxy_and_stops_on_sigint(isolated_config, monkeypatch, capsys):
    isolated_config.mkdir(parents=True, exist_ok=True)
    relay_key = Identity.generate("relay")
    psk = "A7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ClientConfig(
        relay="ws://127.0.0.1:1/healthz",
        peer_public_key=b64e(relay_key.public_key),
        psk=psk,
        listen_host="127.0.0.1",
        listen_port=free_port(),
        log_level="critical",
    ).save(isolated_config / "client.json")

    seen: dict[str, object] = {}

    class FakeTunnel:
        def __init__(self, config, identity, psk_bytes, peer_key):
            self.config = config
            self.stats = _Stats()
            self.active_endpoint = "127.0.0.1:1/healthz"
            self.session = None

        async def connect(self):
            seen["connected"] = True

        def describe(self):
            return "tunnel to 127.0.0.1:1/healthz"

        async def close(self):
            seen["tunnel_closed"] = True

    class _Stats:
        def summary(self):
            return "0 streams"

    class FakeProxy:
        def __init__(self, tunnel, config, auth=None):
            seen["auth"] = auth
            seen["proxy_port"] = config.listen_port

        async def start(self):
            import asyncio

            asyncio.get_running_loop().call_later(0.05, signal.raise_signal, signal.SIGINT)
            return [f"127.0.0.1:{seen['proxy_port']}"]

        async def stop(self):
            seen["proxy_stopped"] = True

    monkeypatch.setattr("nfvpn.cli.commands.Tunnel", FakeTunnel)
    monkeypatch.setattr("nfvpn.cli.commands.LocalProxy", FakeProxy)

    out_file = None
    code = main(["connect", "--stats-interval", "1"])
    captured = capsys.readouterr()
    assert out_file is None
    assert code == 0
    assert seen["connected"] is True
    assert seen["proxy_stopped"] is True
    assert seen["tunnel_closed"] is True
    assert "NoFlagVPN is up" in captured.out
    assert "SOCKS5 / HTTP proxy" in captured.out, "the user is told where to point the browser"
    assert "press Ctrl+C to stop" in captured.out


def test_connect_asks_the_relay_admin_to_authorize_a_refused_identity(
    isolated_config, monkeypatch, capsys
):
    """The exact hint that turns a refusal into a fix."""
    from nfvpn.errors import HandshakeError

    isolated_config.mkdir(parents=True, exist_ok=True)
    ClientConfig(
        relay="ws://127.0.0.1:1/healthz",
        peer_public_key=b64e(Identity.generate("relay").public_key),
        psk="A7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        listen_port=free_port(),
        log_level="error",
    ).save(isolated_config / "client.json")

    class RefusingTunnel:
        def __init__(self, *args, **kwargs):
            pass

        async def connect(self):
            raise HandshakeError("the relay's handshake MAC did not verify")

    monkeypatch.setattr("nfvpn.cli.commands.Tunnel", RefusingTunnel)
    code = main(["connect"])
    err = capsys.readouterr().err
    assert code == 1
    assert "member add" in err, "print the command that fixes it"
    identity = ClientConfig.load(isolated_config / "client.json").load_identity()
    assert b64e(identity.public_key) in err


def test_a_proxy_bound_beyond_loopback_without_auth_is_refused_at_startup(
    isolated_config, capsys
):
    isolated_config.mkdir(parents=True, exist_ok=True)
    ClientConfig(
        relay="ws://127.0.0.1:1/healthz",
        peer_public_key=b64e(Identity.generate("relay").public_key),
        psk="A7_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        listen_port=free_port(),
    ).save(isolated_config / "client.json")

    code, _out, err = run(capsys, "connect", "--listen", "0.0.0.0:1080", "--expose-lan")
    assert code != 0
    assert "--proxy-auth" in err

    code, _out, err = run(capsys, "connect", "--proxy-auth", "no-colon-here")
    assert code != 0
    assert "USER:PASSWORD" in err


# --------------------------------------------------------------------------- #
# version and demo
# --------------------------------------------------------------------------- #
def test_version_json_describes_the_build(capsys):
    payload = json.loads(run_ok(capsys, "version", "--json"))
    assert payload["version"]
    assert payload["crypto_backend"] in ("pure", "cryptography")
    assert "balanced" in payload["profiles"]
    assert payload["config_dir"]


def test_the_demo_serves_a_request_and_stops_cleanly(tmp_path):
    """`nfvpn demo` is the first thing a user runs; it has to actually work."""
    work = tmp_path / "demo"
    relay_port, proxy_port = free_port(), free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            "-u",  # otherwise the banner sits in a pipe buffer until exit
            "-m",
            "nfvpn",
            "demo",
            "--directory",
            str(work),
            "--relay-port",
            str(relay_port),
            "--proxy-port",
            str(proxy_port),
            "--log-level",
            "warning",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=REPO_ROOT,
    )
    try:
        origin_url = None
        deadline = time.monotonic() + 60
        lines: list[str] = []
        while time.monotonic() < deadline:
            line = process.stdout.readline()
            if not line:
                break
            lines.append(line)
            if "demo is running" in line:
                continue
            match = re.search(r"(http://127\.0\.0\.1:\d+/)", line)
            if match:
                origin_url = match.group(1)
                break
        assert origin_url, "the demo never announced its test origin:\n" + "".join(lines)

        # Fetch the origin through the demo proxy, exactly as the hint says.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
        )
        with opener.open(origin_url, timeout=20) as response:
            body = response.read()
        assert response.status == 200
        assert b"NoFlagVPN" in body or b"origin" in body.lower(), body[:200]

        process.send_signal(signal.SIGINT)
        process.wait(timeout=30)
        assert process.returncode == 0, "Ctrl+C is a clean stop, not a crash"
        assert (work / "relay.key").exists(), "the demo keys are where it said they would be"
        assert (work / "members.json").exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if process.stdout is not None:
            process.stdout.close()


def test_the_demo_in_one_process_prints_where_to_point_things(
    isolated_config, monkeypatch, capsys
):
    """The same command, driven in-process so the banner and cleanup are checked."""
    monkeypatch.setattr(
        "nfvpn.cli.commands._install_signals",
        lambda loop, *, on_stop, on_reload=None: loop.call_later(0.2, on_stop),
    )
    work = isolated_config.parent / "demo"
    code, out, _err = run(
        capsys,
        "demo",
        "--directory",
        str(work),
        "--relay-port",
        str(free_port()),
        "--proxy-port",
        str(free_port()),
        "--log-level",
        "critical",
    )
    assert code == 0
    assert "NoFlagVPN demo is running" in out
    assert "SOCKS5 + HTTP on 127.0.0.1:" in out
    assert "curl --socks5-hostname" in out, "give the reader something to paste"
    assert "Ctrl+C" in out
    assert (work / "client.key").exists(), "the demo leaves its keys where it says"
    assert MembershipStore.load(work / "members.json").get("demo-client") is not None


def test_the_demo_reuses_the_keys_it_created(tmp_path):
    """Running it twice must not silently generate a second relay identity."""
    work = tmp_path / "demo"
    work.mkdir()
    identity = Identity.load_or_create(work / "relay.key", "demo-relay")
    before = identity.public_key

    result = subprocess.run(
        [sys.executable, "-m", "nfvpn", "demo", "--help"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )
    assert result.returncode == 0
    assert "--relay-port" in result.stdout
    assert Identity.load(work / "relay.key").public_key == before, "nothing rewrote the key"


def test_the_default_window_is_worth_having():
    """A regression guard on the constant the flow-control threshold derives from."""
    from nfvpn.session.streams import DEFAULT_WINDOW as WINDOW

    assert WINDOW >= 1 << 14
