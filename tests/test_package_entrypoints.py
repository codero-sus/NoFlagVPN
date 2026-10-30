"""Public import and ``python -m nfvpn`` entrypoint compatibility."""
from __future__ import annotations

import json
import runpy
import sys

import pytest
from nfvpn import client, server


def test_client_lazy_exports_resolve_and_dir_lists_the_public_api():
    for name in client.__all__:
        assert getattr(client, name) is not None
    assert dir(client) == sorted(client.__all__)


def test_client_unknown_lazy_export_is_a_normal_attribute_error():
    name = "Missing"
    with pytest.raises(AttributeError, match=name):
        getattr(client, name)


def test_server_lazy_exports_resolve_and_dir_lists_the_public_api():
    for name in server.__all__:
        assert getattr(server, name) is not None
    assert dir(server) == sorted(server.__all__)


def test_server_unknown_lazy_export_is_a_normal_attribute_error():
    name = "Missing"
    with pytest.raises(AttributeError, match=name):
        getattr(server, name)


def test_python_m_entrypoint_passes_through_the_cli_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["nfvpn", "version", "--json"])
    exit_codes: list[int] = []
    monkeypatch.setattr(sys, "exit", exit_codes.append)

    runpy.run_module("nfvpn", run_name="__main__")

    assert exit_codes == [0]
    assert json.loads(capsys.readouterr().out)["version"] == "0.1.0"
