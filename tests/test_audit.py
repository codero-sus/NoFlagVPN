"""``nfvpn doctor``: the checks, the arithmetic behind its numbers, its exit code.

The doctor is the one command whose whole job is to be right: a user reads it to
decide whether their setup leaks.  So these tests check the findings themselves
(what is warned about, and what is deliberately *not* warned about) and the
numbers in the facts block, which are computed rather than measured.
"""

from __future__ import annotations

import json
import random
import stat
import sys

import pytest
from nfvpn.config import ClientConfig, ServerConfig
from nfvpn.core.primitives import backend_name
from nfvpn.detect.audit import (
    Audit,
    _permission_findings,
    _policy_findings,
    _shape_findings,
    benchmark_backends,
    run_doctor,
)
from nfvpn.framing.constants import HEADER_SIZE, TAG_SIZE
from nfvpn.traffic import Shaper, ShapingProfile, get_profile


def levels(audit: Audit) -> list[str]:
    return [level for level, _title, _detail in audit.findings]


def titles(audit: Audit) -> str:
    return "\n".join(f"{level} {title} {detail}" for level, title, detail in audit.findings)


# --------------------------------------------------------------------------- #
# the findings container
# --------------------------------------------------------------------------- #
def test_findings_are_grouped_and_counted():
    audit = Audit()
    audit.add("ok", "all good")
    audit.add("info", "for your information")
    audit.add("warn", "fix me", "this is why")

    assert [item[1] for item in audit.warnings] == ["fix me"]
    rendered = audit.render()
    assert "[  ok  ] all good" in rendered
    assert "[ info ] for your information" in rendered
    assert "[ warn ] fix me" in rendered
    assert "this is why" in rendered
    assert "1 thing(s) worth fixing." in rendered
    assert "environment" not in rendered, "no facts yet, so no facts block"


def test_nothing_alarming_is_said_plainly():
    audit = Audit()
    audit.add("ok", "fine")
    assert "Nothing alarming found." in audit.render()


def test_facts_are_rendered_and_exported():
    audit = Audit(facts={"python": "3.11.0", "config directory": "/tmp/x"})
    audit.add("warn", "thing")
    rendered = audit.render()
    assert rendered.index("environment") < rendered.index("findings")
    assert "python" in rendered and "3.11.0" in rendered

    exported = audit.as_dict()
    assert exported["facts"]["python"] == "3.11.0"
    assert exported["warnings"] == 1
    assert exported["findings"] == [{"level": "warn", "title": "thing", "detail": ""}]
    assert json.loads(json.dumps(exported)) == exported, "must be JSON-serialisable"


# --------------------------------------------------------------------------- #
# key file permissions
# --------------------------------------------------------------------------- #
def test_no_configuration_directory_is_merely_informative(tmp_path):
    audit = Audit()
    _permission_findings(audit, tmp_path / "absent")
    assert levels(audit) == ["info"]
    assert not audit.warnings


def test_a_directory_without_key_material_says_so(tmp_path):
    (tmp_path / "readme.txt").write_text("hi")
    audit = Audit()
    _permission_findings(audit, tmp_path)
    assert levels(audit) == ["info"]
    assert "no key material" in titles(audit)


def test_group_or_world_readable_keys_are_a_warning_with_the_fix(tmp_path):
    exposed = tmp_path / "client.json"
    exposed.write_text("{}")
    exposed.chmod(0o644)
    hidden = tmp_path / "relay.key"
    hidden.write_text("x")
    hidden.chmod(0o600)

    audit = Audit()
    _permission_findings(audit, tmp_path)
    assert levels(audit) == ["warn"]
    detail = audit.findings[0][2]
    assert "0644" in detail
    assert f"chmod 600 {exposed}" in detail, "the warning must carry the command that fixes it"
    assert str(hidden) not in detail, "the private one is not part of the problem"


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_keys_nobody_else_can_read_are_reported_ok(tmp_path, mode):
    key = tmp_path / "client.key"
    key.write_text("x")
    key.chmod(mode)
    audit = Audit()
    _permission_findings(audit, tmp_path)
    assert levels(audit) == ["ok"]
    assert "1 file(s)" in audit.findings[0][2]
    assert stat.S_IMODE(key.stat().st_mode) == mode


# --------------------------------------------------------------------------- #
# configured policy
# --------------------------------------------------------------------------- #
def test_a_relay_that_dials_private_addresses_is_the_first_warning(tmp_path):
    egress = ServerConfig().egress.__class__(allow_private_literals=True)
    ServerConfig(listen_port=443, egress=egress).save(tmp_path / "relay.json")
    audit = Audit()
    _policy_findings(audit, tmp_path)
    assert "allow_private_literals is on" in audit.findings[0][2]
    assert audit.findings[0][0] == "warn"


def test_a_restrictive_relay_reports_its_deny_lists(tmp_path):
    ServerConfig(
        listen_port=443, tls_cert="/etc/ssl/cert.pem", tls_key="/etc/ssl/key.pem"
    ).save(tmp_path / "relay.json")
    audit = Audit()
    _policy_findings(audit, tmp_path)
    assert "ranges denied" in titles(audit)
    assert "ports denied" in titles(audit)
    assert "not using TLS" not in titles(audit)
    assert not audit.warnings


def test_a_relay_without_tls_is_warned_about(tmp_path):
    ServerConfig(listen_port=443).save(tmp_path / "relay.json")
    audit = Audit()
    _policy_findings(audit, tmp_path)
    assert "not using TLS" in titles(audit)
    assert "tls_cert/tls_key" in titles(audit)


def test_a_relay_config_that_cannot_be_read_is_reported_not_raised(tmp_path):
    (tmp_path / "relay.json").write_text("{ this is not json")
    audit = Audit()
    _policy_findings(audit, tmp_path)
    assert "relay.json could not be read" in titles(audit)
    assert levels(audit)[0] == "warn"


def test_a_client_config_that_cannot_be_read_is_reported_not_raised(tmp_path):
    (tmp_path / "client.json").write_text("[]")
    audit = Audit()
    _policy_findings(audit, tmp_path)
    assert "client.json could not be read" in titles(audit)


def test_missing_configs_are_informative(tmp_path):
    audit = Audit()
    _policy_findings(audit, tmp_path)
    assert levels(audit) == ["info", "info"]


def test_a_proxy_on_every_interface_is_warned_about(tmp_path):
    ClientConfig(relay="ws://r/healthz", peer_public_key="k", psk="p", listen_host="0.0.0.0").save(
        tmp_path / "client.json"
    )
    audit = Audit()
    _policy_findings(audit, tmp_path)
    assert "bound beyond loopback" in titles(audit)
    assert "--proxy-auth" in titles(audit), "say what to do about it"


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_a_loopback_proxy_is_reported_ok(tmp_path, host):
    ClientConfig(
        relay="ws://r/healthz", peer_public_key="k", psk="p", listen_host=host
    ).save(tmp_path / "client.json")
    audit = Audit()
    _policy_findings(audit, tmp_path)
    assert "stays on loopback" in titles(audit)


def test_disabled_certificate_validation_is_warned_about(tmp_path):
    ClientConfig(
        relay="ws://r/healthz", peer_public_key="k", psk="p", insecure_tls=True
    ).save(tmp_path / "client.json")
    audit = Audit()
    _policy_findings(audit, tmp_path)
    assert "certificate validation is disabled" in titles(audit)
    assert "--ca" in titles(audit)


# --------------------------------------------------------------------------- #
# traffic shape arithmetic
# --------------------------------------------------------------------------- #
def test_the_overhead_number_matches_the_shaper():
    """``doctor`` prints an overhead; it must be the overhead, not an estimate."""
    audit = Audit()
    _shape_findings(audit, "balanced")

    shaper = Shaper(get_profile("balanced"), random.Random(7))
    payload = 1400
    expected = HEADER_SIZE + TAG_SIZE + shaper.padded_plaintext(payload)
    assert f"{expected}" in validate_shape(audit, payload), "the fact matches the shaper"


def validate_shape(audit: Audit, payload: int) -> str:
    """Recompute the wire size of one payload the way the record layer does."""
    shaper = Shaper(get_profile(audit.facts["shaping profile"]), random.Random(7))
    return str(HEADER_SIZE + TAG_SIZE + shaper.padded_plaintext(payload))


def test_the_size_class_count_is_a_real_count():
    audit = Audit()
    _shape_findings(audit, "balanced")
    reported = int(audit.facts["wire sizes seen"].split()[0])
    assert reported >= 4, "a profile worth shipping has several size classes"
    assert "distinct wire sizes" in titles(audit)


def test_shaping_off_is_warned_about_because_sizes_leak():
    audit = Audit()
    _shape_findings(audit, "off")
    assert "traffic shaping is off" in titles(audit)
    assert audit.warnings


def test_cover_traffic_and_timing_are_described_when_configured():
    audit = Audit()
    _shape_findings(audit, "balanced")
    assert "cover traffic is scheduled" in titles(audit)
    paranoid = Audit()
    _shape_findings(paranoid, "paranoid")
    assert "timing is shaped" in titles(paranoid), "a delayed profile must say it costs latency"


def test_a_profile_with_one_size_class_is_warned_about(monkeypatch):
    """A single size bucket is itself a fingerprint, and the audit must say so."""
    coarse = ShapingProfile(name="coarse", buckets=(1 << 20,))
    monkeypatch.setattr("nfvpn.detect.audit.get_profile", lambda _name: coarse)
    audit = Audit()
    _shape_findings(audit, "coarse")
    assert "few size classes" in titles(audit)


# --------------------------------------------------------------------------- #
# the benchmark and the command
# --------------------------------------------------------------------------- #
def test_the_backend_benchmark_measures_and_restores_the_backend():
    results = benchmark_backends(payload_size=1 << 12, rounds=2)
    assert results["active"] in ("pure", "cryptography")
    assert results["python"]
    assert results["pure_mb_per_second"] > 0
    assert backend_name() == "pure", "the doctor must not change how the process encrypts"


def test_doctor_is_clean_on_a_fresh_machine(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("nfvpn.detect.audit.config_dir", lambda: tmp_path)
    monkeypatch.setenv("NFVPN_PROFILE", "balanced")
    code = run_doctor()
    output = capsys.readouterr().out
    assert "environment" in output and "findings" in output
    assert code == 0, "nothing to fix on a machine with no configuration at all"


def test_doctor_reports_json_when_asked(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("nfvpn.detect.audit.config_dir", lambda: tmp_path)
    monkeypatch.setenv("NFVPN_PROFILE", "off")
    code = run_doctor(json_output=True)
    payload = json.loads(capsys.readouterr().out)
    assert code == 1, "shaping off is a warning, and warnings set the exit code"
    assert payload["warnings"] >= 1
    assert payload["facts"]["shaping profile"] == "off"
    assert any(item["title"] == "traffic shaping is off" for item in payload["findings"])


def test_doctor_exit_code_follows_the_warnings(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("nfvpn.detect.audit.config_dir", lambda: tmp_path)
    monkeypatch.setenv("NFVPN_PROFILE", "balanced")

    ServerConfig(listen_port=443).save(tmp_path / "relay.json")
    exposed = tmp_path / "client.key"
    exposed.write_text("x")
    exposed.chmod(0o666)

    assert run_doctor() == 1, "an exposed key file is worth a non-zero exit"
    output = capsys.readouterr().out
    assert "key material is readable by other users" in output
    assert "not using TLS" in output
    assert "thing(s) worth fixing." in output


def test_doctor_mentions_the_python_it_is_running_on(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("nfvpn.detect.audit.config_dir", lambda: tmp_path)
    monkeypatch.setenv("NFVPN_PROFILE", "balanced")
    run_doctor(json_output=True)
    payload = json.loads(capsys.readouterr().out)
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    assert version in payload["facts"]["python"]
    assert "profiles" in payload["facts"], "the user should learn what they can choose"
    assert "balanced" in payload["facts"]["profiles"]
