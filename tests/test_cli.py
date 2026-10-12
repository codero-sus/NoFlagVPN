"""The command line: the operator workflow, driven exactly as a person would.

Every test here runs ``main(argv)`` in-process with ``NFVPN_CONFIG_DIR`` pointed
at a temporary directory, so nothing touches the real home directory and the
exit codes are the ones a shell would see.
"""

from __future__ import annotations

import json

import pytest
from nfvpn.cli.main import build_parser, main
from nfvpn.core.encoding import b64d, fingerprint
from nfvpn.tokens import decode_invite


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path):
    monkeypatch.setenv("NFVPN_CONFIG_DIR", str(tmp_path / "config"))
    return tmp_path / "config"


def run(capsys, *argv: str) -> tuple[int, str, str]:
    """Run one command; returns (exit code, stdout, stderr).

    ``capsys.readouterr()`` clears the buffers, so the results are returned here
    and callers must not read them again.
    """
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_ok(capsys, *argv: str) -> str:
    """Run a command that must succeed, and return its stdout."""
    code, out, err = run(capsys, *argv)
    assert code == 0, f"{argv} failed: {err}"
    return out


def run_json(capsys, *argv: str) -> dict:
    return json.loads(run_ok(capsys, *argv))


def test_version_prints_something_useful(capsys):
    code, out, _err = run(capsys, "version")
    assert code == 0
    assert "nfvpn" in out.lower()
    assert "python" in out.lower()


def test_the_parser_accepts_every_documented_command():
    parser = build_parser()
    for argv in (
        ["keygen"],
        ["token", "--member", "x"],
        ["member", "list"],
        ["serve"],
        ["connect", "--token", "nfvpn://x"],
        ["probe", "example.com:443"],
        ["selftest"],
        ["doctor"],
        ["demo"],
        ["version"],
    ):
        assert parser.parse_args(argv) is not None


def test_an_unknown_command_is_a_usage_error():
    parser = build_parser()
    with pytest.raises(SystemExit) as info:
        parser.parse_args(["frobnicate"])
    assert info.value.code == 2


def test_keygen_writes_a_key_and_prints_the_public_half(capsys, isolated_config):
    payload = run_json(capsys, "keygen", "--name", "relay", "--json")
    assert payload["name"] == "relay"
    assert (isolated_config / "relay.key").exists()
    assert len(payload["public_key"]) > 20
    assert payload["fingerprint"]


def test_keygen_refuses_to_clobber_an_existing_key(capsys):
    first = run_json(capsys, "keygen", "--name", "relay", "--json")["public_key"]

    code, _out, err = run(capsys, "keygen", "--name", "relay", "--json")
    assert code == 2
    assert "already exists" in err

    # ...and says how to do it anyway, which does rotate the key.
    second = run_json(capsys, "keygen", "--name", "relay", "--force", "--json")["public_key"]
    assert second != first


def test_member_list_on_an_empty_store(capsys):
    code, out, _err = run(capsys, "member", "list")
    assert code == 0
    assert "no members" in out.lower()


def test_the_full_invite_workflow(capsys, isolated_config):
    """keygen -> member add -> token -> decode: one pass, as an operator does it."""
    relay = run_json(capsys, "keygen", "--name", "relay", "--json")
    client_key = run_json(capsys, "keygen", "--name", "laptop", "--json")["public_key"]

    store = isolated_config / "members.json"
    run_ok(capsys, "member", "add", "--config", str(store), "--name", "laptop", "--key", client_key)

    list_out = run_ok(capsys, "member", "list", "--config", str(store))
    assert "laptop" in list_out
    listed = json.loads(run_ok(capsys, "member", "list", "--config", str(store), "--json"))
    assert listed["members"][0]["name"] == "laptop"

    token_out = run_ok(
        capsys,
        "token",
        "--identity-file",
        str(isolated_config / "relay.key"),
        "--membership-file",
        str(store),
        "--member",
        "laptop",
        "--relay",
        "wss://relay.example/cdn",
    )
    invite = decode_invite(token_out.strip())
    assert invite.relay == "wss://relay.example/cdn"
    assert invite.peer_public_key == relay["public_key"]


def test_member_revoke_then_list(capsys, isolated_config):
    other = run_json(capsys, "keygen", "--name", "other", "--json")
    store = isolated_config / "members.json"
    run_ok(capsys, "member", "add", "--config", str(store), "--name", "k", "--key", other["public_key"])

    listed = json.loads(run_ok(capsys, "member", "list", "--config", str(store), "--json"))
    assert listed["members"][0]["enabled"] is True

    run_ok(capsys, "member", "revoke", "--config", str(store), "--name", "k")
    listed = json.loads(run_ok(capsys, "member", "list", "--config", str(store), "--json"))
    assert listed["members"][0]["enabled"] is False

    run_ok(capsys, "member", "remove", "--config", str(store), "--name", "k")
    listed = json.loads(run_ok(capsys, "member", "list", "--config", str(store), "--json"))
    assert listed["members"] == []


def test_a_key_that_starts_with_a_dash_is_accepted(capsys, isolated_config):
    """One generated key in ~69 starts with "-", and argparse would eat it.

    A leading dash is ordinary base64url, so it must be read as the value of the
    option in front of it rather than as a new option.
    """
    generated = run_json(capsys, "keygen", "--name", "dash", "--json")["public_key"]
    assert set(generated) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )

    store = isolated_config / "members.json"
    key = "-" + generated[1:]
    run_ok(capsys, "member", "add", "--config", str(store), "--name", "dash", "--key", key)

    listed = json.loads(run_ok(capsys, "member", "list", "--config", str(store), "--json"))
    assert listed["members"][0]["fingerprint"] == fingerprint(b64d(key))

    # The same applies wherever a key is passed straight through.
    token = decode_invite(
        run_ok(capsys, "token", "--relay", "ws://relay.example/cdn", "--key", key, "--psk", "shared").strip()
    )
    assert token.peer_public_key == key


def test_tokens_without_an_identity_fail_clearly(capsys):
    code, _out, err = run(capsys, "token", "--member", "nobody")
    assert code == 2
    assert "nfvpn" in err.lower()


def test_a_bad_token_is_refused_before_anything_is_dialled(capsys):
    code, _out, err = run(capsys, "connect", "--token", "not-a-token")
    assert code == 2
    assert err


def test_probe_reports_and_does_not_hang(capsys):
    code, out, _err = run(capsys, "probe", "ws://127.0.0.1:1", "--timeout", "1", "--rounds", "1")
    assert code == 1  # nothing is listening, so the probe says so
    assert "127.0.0.1:1" in out


def test_probe_json_mode_is_machine_readable(capsys):
    code, out, _err = run(
        capsys, "probe", "ws://127.0.0.1:1", "--timeout", "1", "--rounds", "1", "--json"
    )
    assert code == 1
    payload = json.loads(out)
    assert payload["target"].startswith("ws://")
    assert payload["reachable"] is False


def test_doctor_runs_on_a_clean_machine(capsys):
    code, out, _err = run(capsys, "doctor")
    assert code in (0, 1)
    assert "findings" in out.lower()


def test_doctor_json(capsys):
    code, out, _err = run(capsys, "doctor", "--json")
    assert code in (0, 1)
    payload = json.loads(out)
    assert "facts" in payload
    assert "findings" in payload


def test_selftest_passes_on_loopback(capsys):
    code, out, _err = run(capsys, "selftest")
    assert code == 0, out
    assert "checks passed" in out
    assert "FAIL" not in out


def test_serve_refuses_to_bind_a_bad_port(capsys):
    code, _out, err = run(capsys, "serve", "--listen", "127.0.0.1:99999")
    assert code == 2
    assert err


def test_connect_requires_something_to_connect_to(capsys):
    code, _out, err = run(capsys, "connect")
    assert code == 2
    assert err
    assert "token" in err.lower() or "relay" in err.lower()


def test_expose_lan_without_auth_is_refused(capsys, isolated_config):
    """Publishing an unauthenticated proxy to the LAN is refused, not warned about."""
    from nfvpn.core.encoding import b64e
    from nfvpn.tokens import Invite

    token = Invite(
        relay="ws://127.0.0.1:1/x", peer_public_key=b64e(b"\x01" * 32), psk=b64e(b"\x02" * 32)
    ).encode()
    code, _out, err = run(capsys, "connect", "--token", token, "--expose-lan")
    assert code == 2
    assert "auth" in err.lower()

    # With an authenticated proxy the same flags are accepted (nothing is
    # dialled: the relay address is a dead port, so this still fails, but on
    # the network rather than on the policy).
    code, _out, err = run(
        capsys, "connect", "--token", token, "--expose-lan", "--proxy-auth", "u:p", "--stats-interval", "0"
    )
    assert code == 1
    assert "auth" not in err.lower()


def test_demo_help_exists():
    parser = build_parser()
    assert parser.parse_args(["demo"]).func is not None
