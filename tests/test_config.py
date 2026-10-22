"""Configuration, identities, the membership list and invite tokens.

All of it is on-disk state that a user edits by hand at 2am, so the tests care
about two things above all: nothing silently accepts a typo, and nothing writes
a secret with the wrong permissions.
"""

from __future__ import annotations

import json
import stat
import time

import pytest
from nfvpn.config import ClientConfig, ServerConfig, config_dir, load_json, save_json
from nfvpn.core.encoding import b64d, b64e, fingerprint, short_id
from nfvpn.core.keys import (
    Identity,
    Member,
    MembershipStore,
    generate_psk,
    parse_psk,
)
from nfvpn.errors import ConfigError
from nfvpn.tokens import Invite, decode_invite, encode_invite

# identities --------------------------------------------------------------------


def test_identity_survives_a_round_trip(tmp_path):
    path = tmp_path / "identity.key"
    original = Identity.generate("relay")
    original.save(path)
    loaded = Identity.load(path)
    assert loaded.public_key == original.public_key
    assert loaded.name == "relay"


def test_identity_file_is_private(tmp_path):
    path = tmp_path / "identity.key"
    Identity.generate("relay").save(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & 0o077 == 0, f"private key is readable by others ({oct(mode)})"


def test_load_or_create_is_idempotent(tmp_path):
    path = tmp_path / "identity.key"
    first = Identity.load_or_create(path, name="relay")
    second = Identity.load_or_create(path, name="relay")
    assert first.public_key == second.public_key


def test_a_corrupt_key_file_says_so(tmp_path):
    path = tmp_path / "identity.key"
    path.write_text("not a key")
    with pytest.raises(ConfigError):
        Identity.load(path)


def test_a_key_that_does_not_exist_says_so(tmp_path):
    with pytest.raises(ConfigError):
        Identity.load(tmp_path / "missing.key")


def test_fingerprints_are_stable_and_human(tmp_path):
    identity = Identity.generate("relay")
    assert identity.fingerprint == fingerprint(identity.public_key)
    assert identity.short_id == short_id(identity.public_key)
    assert len(identity.short_id) == 8
    assert " " in identity.fingerprint  # grouped, so it can be read aloud


def test_identity_file_is_not_world_readable_after_re_save(tmp_path):
    path = tmp_path / "identity.key"
    identity = Identity.generate("relay")
    identity.save(path)
    path.chmod(0o644)
    identity.save(path)
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


# psks --------------------------------------------------------------------------


def test_psk_round_trip():
    text = generate_psk()
    assert len(parse_psk(text)) == 32
    assert parse_psk(b64e(parse_psk(text))) == parse_psk(text)


def test_psk_of_the_wrong_size_is_refused():
    with pytest.raises(ConfigError):
        parse_psk(b64e(b"short"))


# membership --------------------------------------------------------------------


@pytest.fixture
def member() -> Member:
    return Member(name="laptop", public_key=Identity.generate("laptop").public_key, psk=b"\x07" * 32)


def test_membership_round_trip(tmp_path, member):
    path = tmp_path / "members.json"
    store = MembershipStore(path=path)
    store.add(member)
    store.save()
    reloaded = MembershipStore.load(path)
    assert len(reloaded) == 1
    assert reloaded.get("laptop") is not None
    assert reloaded.lookup(member.public_key).name == "laptop"


def test_membership_file_is_private(tmp_path, member):
    path = tmp_path / "members.json"
    store = MembershipStore(path=path)
    store.add(member)
    store.save()
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def test_duplicate_members_need_an_explicit_replace(member):
    store = MembershipStore()
    store.add(member)
    with pytest.raises(ConfigError):
        store.add(member)
    assert store.add(member, replace=True).name == "laptop"
    assert len(store) == 1


def test_unknown_members_are_not_found():
    assert MembershipStore().lookup(b"\x00" * 32) is None


def test_revoked_members_stop_looking_up(member):
    store = MembershipStore()
    store.add(member)
    assert store.lookup(member.public_key) is not None
    store.revoke(member.public_key)
    assert store.lookup(member.public_key) is None
    assert len(store.active()) == 0


def test_expired_members_stop_looking_up(member):
    member.expires_at = time.time() - 60
    store = MembershipStore()
    store.add(member)
    assert store.lookup(member.public_key) is None


def test_removed_members_disappear(member):
    store = MembershipStore()
    store.add(member)
    assert store.remove(member.public_key) is True
    assert store.remove(member.public_key) is False
    assert len(store) == 0


def test_membership_file_with_junk_is_refused(tmp_path):
    path = tmp_path / "members.json"
    path.write_text(json.dumps({"members": [{"name": "x"}]}))
    with pytest.raises(ConfigError):
        MembershipStore.load(path)


# configs -----------------------------------------------------------------------


def test_server_config_round_trips(tmp_path):
    config = ServerConfig(
        listen_port=9443, tls_cert="/tmp/cert.pem", tls_key="/tmp/key.pem", ws_path="/cdn"
    )
    path = config.save(tmp_path / "server.json")
    reloaded = ServerConfig.load(path)
    assert reloaded.listen_port == 9443
    assert reloaded.ws_path == "/cdn"
    assert reloaded.tls_cert == "/tmp/cert.pem"


def test_server_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "server.json"
    path.write_text(json.dumps({"listen_port": 1, "lissten_port": 8443}))
    with pytest.raises(ConfigError, match="unknown"):
        ServerConfig.load(path)


def test_server_config_validates_obvious_nonsense():
    with pytest.raises(ConfigError):
        ServerConfig(listen_port=0)
    with pytest.raises(ConfigError):
        ServerConfig(profile="not-a-profile")
    with pytest.raises(ConfigError):
        ServerConfig(ws_path="no-leading-slash")


def test_the_cover_body_is_a_real_web_page(tmp_path):
    config = ServerConfig()
    body = config.cover_body()
    assert b"404" in body
    assert b"nginx" in body
    assert len(body) < 2048


def test_a_custom_cover_page_is_used_verbatim(tmp_path):
    page = tmp_path / "index.html"
    page.write_text("<h1>hello</h1>")
    config = ServerConfig(cover_page=str(page))
    assert config.cover_body() == b"<h1>hello</h1>"


def test_a_missing_cover_page_is_an_error_not_a_crash(tmp_path):
    config = ServerConfig(cover_page=str(tmp_path / "nope.html"))
    with pytest.raises(ConfigError):
        config.cover_body()


def test_client_config_round_trips(tmp_path):
    config = ClientConfig(
        relay="wss://relay.example/cdn",
        peer_public_key=b64e(b"\x01" * 32),
        psk=b64e(b"\x02" * 32),
        listen_port=1080,
        failover=("wss://backup.example/cdn",),
    )
    path = config.save(tmp_path / "client.json")
    reloaded = ClientConfig.load(path)
    assert reloaded.listen_port == 1080
    assert reloaded.failover == ("wss://backup.example/cdn",)


def test_client_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "client.json"
    path.write_text(json.dumps({"proxy_port": 1080}))
    with pytest.raises(ConfigError):
        ClientConfig.load(path)


def test_client_config_validates_tls_options():
    with pytest.raises(ConfigError):
        ClientConfig(insecure_tls=True, ca_file="/tmp/ca.pem")


def test_config_dir_honours_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("NFVPN_CONFIG_DIR", str(tmp_path / "custom"))
    assert config_dir() == tmp_path / "custom"
    # It is a path, not a side effect: the directory appears when something is
    # actually saved there.
    assert not config_dir().exists()
    Identity.generate("x").save(config_dir() / "x.key")
    assert config_dir().is_dir()


def test_config_files_are_private(tmp_path):
    path = save_json(tmp_path / "thing.json", {"secret": "yes"})
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
    assert load_json(path) == {"secret": "yes"}


def test_broken_json_is_reported_clearly(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    with pytest.raises(ConfigError):
        load_json(path)


# invite tokens -----------------------------------------------------------------


def test_token_round_trip():
    psk = generate_psk()
    token = encode_invite("wss://relay.example/cdn", b64e(b"\x03" * 32), psk, name="relay")
    assert token.startswith("nfvpn://")
    invite = decode_invite(token)
    assert invite.relay == "wss://relay.example/cdn"
    assert invite.psk == psk
    assert invite.name == "relay"
    assert parse_psk(invite.psk) == parse_psk(psk)


def test_token_redaction_hides_the_psk():
    psk = generate_psk()
    invite = Invite("wss://relay.example/cdn", b64e(b"\x03" * 32), psk)
    redacted = invite.redacted()
    assert psk not in redacted
    assert "wss://relay.example/cdn" in redacted


@pytest.mark.parametrize(
    "token",
    [
        "",
        "hello",
        "https://example.com",
        "nfvpn://not base64!!",
        "nfvpn://" + b64e(b"{}"),
        "nfvpn://" + b64e(json.dumps({"v": 99, "relay": "x", "key": "y", "psk": "z"}).encode()),
        "nfvpn://" + b64e(json.dumps({"v": 1, "relay": "wss://x/"}).encode()),
    ],
)
def test_bad_tokens_are_rejected_with_a_reason(token):
    with pytest.raises(ConfigError) as info:
        decode_invite(token)
    assert str(info.value)


def test_a_token_without_a_psk_can_be_read_but_not_used():
    token = "nfvpn://" + b64e(
        json.dumps({"v": 1, "relay": "wss://x/", "key": b64e(b"\x01" * 32)}).encode()
    )
    invite = decode_invite(token, require_psk=False)
    assert invite.psk == ""
    with pytest.raises(ConfigError):
        decode_invite(token)


def test_an_enormous_token_is_refused():
    with pytest.raises(ConfigError):
        decode_invite("nfvpn://" + "A" * 100_000)


def test_token_psk_is_usable_as_a_key():
    psk = parse_psk(generate_psk())
    assert b64d(b64e(psk)) == psk
    assert len(psk) == 32


def test_membership_load_refuses_psk_files_readable_by_other_users(tmp_path, member):
    path = tmp_path / "members.json"
    store = MembershipStore(path=path)
    store.add(member)
    store.save()
    path.chmod(0o644)
    with pytest.raises(ConfigError, match="readable by other users"):
        MembershipStore.load(path)


def test_membership_load_accepts_owner_read_only_files(tmp_path, member):
    path = tmp_path / "members.json"
    store = MembershipStore(path=path)
    store.add(member)
    store.save()
    path.chmod(0o400)
    assert MembershipStore.load(path).get("laptop") is not None


def test_member_store_does_not_treat_string_false_as_an_enabled_member(member):
    raw = member.to_dict()
    raw["enabled"] = "false"
    with pytest.raises(ConfigError, match="enabled must be a boolean"):
        Member.from_dict(raw)


def test_member_store_rejects_non_object_json(tmp_path):
    path = tmp_path / "members.json"
    path.write_text("[]")
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="JSON object"):
        MembershipStore.load(path)


def test_member_store_rejects_a_non_list_members_field(tmp_path):
    path = tmp_path / "members.json"
    path.write_text('{"members": {"not": "a list"}}')
    path.chmod(0o600)
    with pytest.raises(ConfigError, match="members must be a list"):
        MembershipStore.load(path)
