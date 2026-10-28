"""The relay-only zipapp is small, executable and works without installation."""

from __future__ import annotations

import os
import subprocess
import sys
import zipfile

from tools.build_mini_server import build_mini_server


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
