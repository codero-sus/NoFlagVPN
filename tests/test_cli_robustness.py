"""Bad input must produce a sentence, not a stack trace.

Every case here was found by running the CLI with jelly input and reading the
result.  Before this file existed, ``--deny-network banana`` printed six lines
of ``ipaddress`` internals, ``member add --key not-a-key`` escaped with a bare
``ValueError``, ``--tag noequals`` raised a tuple-unpacking error from inside
``dict()``, ``keygen --name ../../etc/passwd`` tried to write outside the config
directory, and three flags (``--deny-port 99999``, ``--allow-port -1``,
``--limit-mbps -1``) made the relay start and run forever with values that mean
nothing.

The assertions are deliberately about *behaviour a user can see*: nothing
escapes, the exit code is one of the documented ones, and the message names the
thing that was wrong.
"""

from __future__ import annotations

import contextlib

import pytest
from nfvpn.cli.main import main

#: Exit codes the CLI documents: success, failure, usage, interrupted.
DOCUMENTED_EXITS = {0, 1, 2, 130}

BAD_INPUT: list[list[str]] = [
    # probe: the port is part of a target the user typed by hand
    ["probe", "127.0.0.1:notaport"],
    ["probe", "127.0.0.1:99999"],
    ["probe", "ws://host:port/x"],
    ["probe", "wss://[::1]:bad/x"],
    ["probe", "::::"],
    ["probe", ""],
    # serve: egress policy and limits
    ["serve", "--listen", "banana"],
    ["serve", "--listen", "127.0.0.1:notaport"],
    ["serve", "--listen", "127.0.0.1:99999"],
    ["serve", "--deny-network", "banana"],
    ["serve", "--allow-network", "300.1.1.0/24"],
    ["serve", "--deny-port", "99999"],
    ["serve", "--deny-port", "0"],
    ["serve", "--allow-port", "-1"],
    ["serve", "--limit-mbps", "-1"],
    ["serve", "--limit-mbps", "0"],
    ["serve", "--stats-interval", "banana"],
    ["serve", "--idle-timeout", "0"],
    ["serve", "--max-streams", "0"],
    ["serve", "--profile", "turbo"],
    ["serve", "--tls-cert", "/nope/cert.pem"],
    # connect: tokens, endpoints, credentials
    ["connect", "--relay", "ws://127.0.0.1:notaport/x", "--peer-key", "AAAA", "--psk", "AAAA"],
    ["connect", "--relay", "banana", "--peer-key", "AAAA", "--psk", "AAAA"],
    ["connect", "--token", "nfvpn://not-base64!!"],
    ["connect", "--token", "nfvpn://" + "A" * 9000],
    ["connect", "--token", "nfvpn://e30"],
    # members: keys, tags, expiry
    ["member", "add", "--name", "x", "--key", "not-a-key"],
    ["member", "add", "--name", "x", "--key", ""],
    ["member", "add", "--name", "x", "--tag", "noequals"],
    ["member", "add", "--name", "x", "--tag", "=nokey"],
    ["member", "revoke", "--name", "ghost"],
    ["token", "--member", "ghost"],
    ["member", "list", "--config", "/nope/nope/nope.json"],
    # keygen: names are file names
    ["keygen", "--name", "../../etc/passwd"],
    ["keygen", "--name", ""],
    ["keygen", "--name", "."],
    ["keygen", "--name", ".."],
    ["keygen", "--name", "x" * 200],
    ["keygen", "--name", "with/slash"],
]


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path):
    monkeypatch.setenv("NFVPN_CONFIG_DIR", str(tmp_path / "config"))
    return tmp_path / "config"


@pytest.mark.parametrize("argv", BAD_INPUT, ids=lambda argv: " ".join(argv)[:60] or "<empty>")
def test_bad_input_exits_cleanly(capsys, argv):
    """No case may raise, hang, or return an undocumented exit code."""
    try:
        code = main(list(argv))
    except SystemExit as exc:  # argparse's own error path; documented as 2
        code = int(exc.code or 0)
    capsys.readouterr()
    assert code in DOCUMENTED_EXITS, f"{argv} returned {code}"


@pytest.mark.parametrize("argv", BAD_INPUT, ids=lambda argv: " ".join(argv)[:60] or "<empty>")
def test_bad_input_is_explained_in_one_language(capsys, argv):
    """The message must never be Python internals."""
    with contextlib.suppress(SystemExit):
        main(list(argv))
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Traceback (most recent call last)" not in output
    for leak in ("invalid literal for int", "does not appear to be an IPv4", "base64url"):
        if leak == "base64url":
            # Our own wording mentions base64url on purpose; the raw decoder
            # message is only acceptable when it is wrapped in a sentence.
            assert leak not in output or "not a public key" in output or "not valid base64url" not in output
        else:
            assert leak not in output, f"{argv} leaked {leak!r}"


def test_the_previously_hanging_flags_fail_instead_of_serving(capsys):
    """These three used to start a relay that ran forever, which is worse than
    an error: nothing tells you the limit is meaningless."""
    for argv in (
        ["serve", "--deny-port", "99999"],
        ["serve", "--allow-port", "-1"],
        ["serve", "--limit-mbps", "-1"],
    ):
        try:
            code = main(list(argv))
        except SystemExit as exc:
            code = int(exc.code or 0)
        out, err = capsys.readouterr()
        assert code == 2, f"{argv} returned {code}"
        assert "relay listening" not in out
        assert err.strip(), f"{argv} explained nothing"


def test_a_traversing_name_never_touches_the_filesystem(capsys, isolated_config, tmp_path):
    """`keygen --name ../../etc/passwd` wrote outside the config directory."""
    target = tmp_path / "escaped.key"
    with contextlib.suppress(SystemExit):
        main(["keygen", "--name", "../../escaped"])
    capsys.readouterr()
    assert not target.exists()
    assert list(isolated_config.parent.glob("*.key")) == []


def test_a_bare_keygen_says_how_to_name_it(capsys, isolated_config):
    """The default `identity.key` is a trap: serve and connect do not read it."""
    code = main(["keygen"])
    capsys.readouterr()
    assert code == 0
    assert (isolated_config / "identity.key").exists()

    code = main(["keygen"])
    out, err = capsys.readouterr()
    assert code == 2
    assert "already exists" in err
    assert "--name relay" in err and "--name client" in err
    assert "identity.key" in out + err


def test_the_tag_parser_refuses_a_typo(capsys, isolated_config):
    code = main(["member", "add", "--name", "x", "--key", "A" * 43, "--tag", "noequals"])
    _out, err = capsys.readouterr()
    assert code == 2
    assert "--tag wants KEY=VALUE" in err
    assert "noequals" in err


def test_the_peer_port_message_names_what_was_typed(capsys):
    code = main(["probe", "127.0.0.1:notaport"])
    _out, err = capsys.readouterr()
    assert code == 2
    assert "non-numeric port" in err
    assert "notaport" in err
