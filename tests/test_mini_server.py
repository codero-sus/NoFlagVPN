"""The relay-only zipapp is small, executable and works without installation."""

from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path

from nfvpn.cli.main import main as cli_main
from nfvpn.config import ServerConfig
from nfvpn.mini_server import main as mini_server_main
from tools.build_mini_server import build_mini_server


def test_mini_server_initializes_missing_config_before_serving(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    calls = []

    def fake_cli(args):
        calls.append(args)
        if args[0] == "init":
            return cli_main(args)
        return 0

    monkeypatch.setattr("nfvpn.mini_server.cli_main", fake_cli)

    assert mini_server_main(["--listen", "127.0.0.1:8443"]) == 0
    assert calls == [
        ["init", "--config", "config.json"],
        ["serve", "--config", "config.json", "--listen", "127.0.0.1:8443"],
    ]
    assert Path("config.json").is_file()
    assert Path("data/relay.key").is_file()
    assert Path("data/members.json").is_file()


def test_mini_server_respects_explicit_config_path(monkeypatch):
    calls = []
    monkeypatch.setattr("nfvpn.mini_server.cli_main", lambda args: calls.append(args) or 0)

    assert mini_server_main(["--config=server.json"]) == 0
    assert calls == [["serve", "--config=server.json"]]


def test_starter_config_is_local_only_and_uses_private_egress_defaults():
    config = ServerConfig.load(Path(__file__).parents[1] / "config.json")
    assert config.listen_host == "127.0.0.1"
    assert config.tls_cert is None
    assert config.tls_key is None
    assert config.egress.allow_private_literals is False
    assert config.membership_file == "./data/members.json"


def test_mini_server_builds_a_compact_executable_zipapp(tmp_path):
    artifact = build_mini_server(tmp_path / "nfvpn-mini-server.pyz")

    assert zipfile.is_zipfile(artifact)
    assert artifact.stat().st_size < 2_000_000, "the relay app should remain a compact bundle"
    if os.name != "nt":
        assert os.access(artifact, os.X_OK)
        assert artifact.read_bytes().startswith(b"#!/usr/bin/env python3\n")

    with zipfile.ZipFile(artifact) as archive:
        names = archive.namelist()
    assert "__main__.py" in names
    assert any(name.startswith("nfvpn/") for name in names)
    assert not any(name.startswith("tests/") for name in names)


def test_mini_server_zipapp_runs_relay_help_without_an_install(tmp_path):
    artifact = build_mini_server(tmp_path / "nfvpn-mini-server.pyz")
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(artifact), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        cwd=tmp_path,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    assert "nfvpn serve" in result.stdout
    assert "--membership-file" in result.stdout
    assert "--tls-cert" in result.stdout


def test_mini_server_builder_creates_missing_output_directory(tmp_path):
    destination = tmp_path / "new" / "nested" / "server.pyz"
    artifact = build_mini_server(destination, interpreter="")
    assert artifact == destination
    assert artifact.is_file()
    assert not artifact.read_bytes().startswith(b"#!")
