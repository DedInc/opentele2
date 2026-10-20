"""Tests of the MTP config, ``TData.migrate`` and Telethon session file
exports of opentele2._native against crates/opentele2-core/tests/
{tdata_read,tdata_write,session}.rs and the tdata vectors.

Key material is compared with ``assert_same``, which never prints the bytes.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from opentele2 import _native
from opentele2._native import Account, CoreError, TData

if TYPE_CHECKING:
    from opentele2._native import Endpoint

VECTORS = Path(__file__).resolve().parents[3] / "crates" / "opentele2-core" / "tests" / "vectors"
KEY = b"\x09" * 256

# The MTP config of crates/opentele2-core/tests/{session,tdata_read}.rs: DC 2
# has IPv4 TCP 203.0.113.2:443 first and IPv6 TCP 2001:db8::2 first, DC 1
# 198.51.100.1 and 2001:db8::1, DC 3 only the CDN IPv4 198.51.100.3.
CUSTOM_CONFIG = bytes.fromhex(
    "000000010000000000000149fffffffe000000080000000200000005000001bb0000000b323030313a64"
    "62383a3a32000000000000000200000000000001bb0000000b3230332e302e3131332e32000000000000"
    "000200000400000020fb0000000b3230332e302e3131332e33000000100102030405060708090a0b0c0d"
    "0e0f100000000200000002000000500000000b3230332e302e3131332e34000000000000000200000011"
    "000001bb0000000c323030313a6462383a3a3232000000000000000100000010000001bb0000000c3139"
    "382e35312e3130302e31000000000000000100000401000001bb0000000b323030313a6462383a3a3100"
    "000020abababababababababababababababababababababababababababababababab00000003000000"
    "08000001bb0000000c3139382e35312e3130302e330000000000000001000000cb000000030102030000"
    "00030100010000014100002710000000640001d4c00000138800007530000003e8000493e00000753000"
    "0005dc000000c80002a3000002a3000002a300000000010000001e000000050000000500000064000000"
    "1a00680074007400700073003a002f002f0074002e006d0065002f00093a8000004e2000015f90000075"
    "300000271000000004000000000000000100000000000004000000000227648000000000000005ffffff"
    "f90000000800670069006600730000000c00760065006e007500650073"
)
# The address text of the built-in table per production DC, as (IPv4, IPv6).
TABLE_TEXT = {
    1: ("149.154.175.50", "2001:0b28:f23d:f001:0000:0000:0000:000a"),
    2: ("149.154.167.51", "2001:067c:04e8:f002:0000:0000:0000:000a"),
    3: ("149.154.175.100", "2001:0b28:f23d:f003:0000:0000:0000:000a"),
    4: ("149.154.167.91", "2001:067c:04e8:f004:0000:0000:0000:000a"),
    5: ("149.154.171.5", "2001:0b28:f23f:f005:0000:0000:0000:000a"),
}
IPV6 = _native.MTP_FLAG_IPV6
MEDIA = _native.MTP_FLAG_MEDIA_ONLY
TCPO = _native.MTP_FLAG_TCPO_ONLY
CDN = _native.MTP_FLAG_CDN
STATIC = _native.MTP_FLAG_STATIC
SECRET = _native.MTP_FLAG_SECRET


def assert_same(actual: bytes, expected: bytes, label: str) -> None:
    """Fails without showing either value, so key bytes never reach the log."""
    if actual != expected:
        raise AssertionError(f"{label} differs") from None


def manifest() -> Any:
    with (VECTORS / "tdata.json").open(encoding="utf-8") as handle:
        return json.load(handle)["folders"]


def account(main_dc: int, config: bytes | None = None) -> Account:
    return Account(0, 77, main_dc, [(main_dc, KEY)], config=config)


def ep(dc_id: int, flags: int, ip: str, port: int = 443, secret: bytes = b"") -> Endpoint:
    return {"id": dc_id, "flags": flags, "ip": ip, "port": port, "secret": secret}


# ---------------------------------------------------------------- MTP config


def test_mtp_flags_are_tdesktop_values() -> None:
    flags = [IPV6, MEDIA, TCPO, CDN, STATIC, _native.MTP_FLAG_THIS_PORT_ONLY, SECRET]
    assert flags == [1, 2, 4, 8, 16, 32, 1024]


def test_production_default_config_and_endpoints() -> None:
    production = _native.account_mtp_config(account(2))
    assert production["environment"] == "production"
    assert [dc["dc_id"] for dc in production["dcs"]] == [1, 2, 3, 4, 5]
    assert production["fields"]["chat_size_max"] == 200
    assert production["fields"]["web_file_dc_id"] == 4
    assert production["fields"]["txt_domain_string"] == "apv3.stel.com"
    assert production["fields"]["reaction_default_custom"] == 0
    assert len(production["fields"]) == 35
    assert production["cdn_public_keys"] == []

    dc2 = _native.account_endpoints(account(2))
    assert dc2 is not None
    assert [e["ip"] for e in dc2["ipv4"]["tcp"]] == ["149.154.167.51", "95.161.76.100"]
    assert dc2["ipv4"]["http"] == dc2["ipv4"]["tcp"]
    assert dc2["ipv6"]["tcp"] == [ep(2, STATIC | IPV6, "2001:067c:04e8:f002:0000:0000:0000:000a")]
    assert dc2["selected_ipv4"] == dc2["ipv4"]["tcp"][0]
    assert dc2["selected_ipv6"] == dc2["ipv6"]["tcp"][0]
    assert _native.account_endpoints(account(2), 2) == dc2
    assert _native.account_endpoints(account(2), 6) is None
    assert _native.account_endpoints(account(2), 0) is None
    # Bytes that do not parse fall back to the production default.
    assert _native.account_mtp_config(account(2, b"\x00\x00\x00\x01")) == production
    assert account(2).config is None
    assert account(2, CUSTOM_CONFIG).config == CUSTOM_CONFIG

    # The configs files of the vector folders are that same default.
    stored = TData.load(VECTORS / "tdata_plain" / "performance_off")
    for loaded in stored.accounts:
        assert isinstance(loaded.config, bytes), "performance_off stores configs"
        assert _native.account_mtp_config(loaded) == production
    plain = TData.load(VECTORS / "tdata_plain" / "performance_on")
    assert all(loaded.config is None for loaded in plain.accounts)


def test_stored_custom_config_reads_back() -> None:
    config = _native.account_mtp_config(account(2, CUSTOM_CONFIG))
    assert config["environment"] == "production"
    # DCs in first-seen order; 1001 is not stored.
    assert [dc["dc_id"] for dc in config["dcs"]] == [2, 1, 3]
    assert config["cdn_public_keys"] == [{"dc_id": 203, "n": b"\x01\x02\x03", "e": b"\x01\x00\x01"}]
    fields = config["fields"]
    assert fields["chat_size_max"] == 321
    assert fields["revoke_private_inbox"] is True
    assert fields["txt_domain_string"] == ""
    assert fields["reaction_default_emoji"] == "❤"
    assert fields["reaction_default_custom"] == (1 << 63) + 5
    assert fields["rating_decay"] == -7
    assert fields["gif_search_username"] == "gifs"
    assert fields["venue_search_username"] == "venues"

    secret = bytes(range(1, 17))
    dc1 = _native.account_endpoints(account(2, CUSTOM_CONFIG), 1)
    assert dc1 is not None
    assert dc1["ipv4"]["tcp"] == [ep(1, STATIC, "198.51.100.1")]
    assert dc1["ipv4"]["http"] == dc1["ipv4"]["tcp"]
    assert dc1["ipv6"]["tcp"] == [ep(1, IPV6 | SECRET, "2001:db8::1", 443, b"\xab" * 32)]
    assert dc1["ipv6"]["http"] == []

    dc2 = _native.account_endpoints(account(2, CUSTOM_CONFIG))
    assert dc2 is not None
    plain = ep(2, 0, "203.0.113.2")
    media = ep(2, MEDIA, "203.0.113.4", 80)
    v6_static = ep(2, IPV6 | STATIC, "2001:db8::22")
    assert dc2["ipv4"]["tcp"] == [plain, ep(2, SECRET, "203.0.113.3", 8443, secret), media]
    assert dc2["ipv4"]["http"] == [plain, media]
    assert dc2["ipv6"]["tcp"] == [ep(2, IPV6 | TCPO, "2001:db8::2"), v6_static]
    assert dc2["ipv6"]["http"] == [v6_static]

    dc3 = _native.account_endpoints(account(3, CUSTOM_CONFIG))
    assert dc3 is not None
    assert dc3["ipv4"]["tcp"] == [ep(3, CDN, "198.51.100.3")]
    assert dc3["ipv6"] == {"tcp": [], "http": []}
    selected = dc3["selected_ipv6"]
    assert selected is not None
    assert selected["ip"] == "198.51.100.3", "falls back to IPv4"
    for dc_id, ip4, ip6 in (
        (1, "198.51.100.1", "2001:db8::1"),
        (2, "203.0.113.2", "2001:db8::2"),
        (3, "198.51.100.3", "198.51.100.3"),
    ):
        endpoints = _native.account_endpoints(account(2, CUSTOM_CONFIG), dc_id)
        assert endpoints is not None
        v4, v6 = endpoints["selected_ipv4"], endpoints["selected_ipv6"]
        assert v4 is not None
        assert v6 is not None
        assert (v4["ip"], v6["ip"]) == (ip4, ip6), dc_id
    assert _native.account_endpoints(account(5, CUSTOM_CONFIG)) is None


# ---------------------------------------------------------------- migrate


def key_file_wraps(folder: Path) -> bytes:
    """The salt, open wrap and trailer of a key file: everything a save keeps."""
    data = (folder / "key_datas").read_bytes()
    payload = data[8:-16]
    parts = []
    at = 0
    for _ in range(3):
        (length,) = struct.unpack_from(">I", payload, at)
        size = 0 if length == 0xFFFFFFFF else length
        parts.append(payload[at : at + 4 + size])
        at += 4 + size
    # The accounts info (parts[2]) is encrypted afresh by every save.
    return parts[0] + parts[1] + payload[at:]


@pytest.mark.parametrize("name", ["plain", "passcode"])
def test_migrate_keeps_one_migration_across_saves(name: str, tmp_path: Path) -> None:
    entry = manifest()[f"tdata_legacy/{name}"]
    legacy = TData.load(VECTORS / "tdata_legacy" / name, entry["passcode"])
    assert legacy.legacy_key_file is True
    assert legacy.key_file == "data"

    # Unmigrated, every save writes a fresh wrap.
    first, second, third, fourth = (tmp_path / str(n) for n in range(4))
    legacy.save(first)
    legacy.save(second)
    assert key_file_wraps(first) != key_file_wraps(second), "unmigrated saves share a wrap"
    assert legacy.legacy_key_file is True

    assert legacy.migrate() is True
    assert legacy.legacy_key_file is False
    assert legacy.migrate() is False, "a migrated folder migrates again"
    legacy.save(third)
    legacy.save(fourth)
    assert key_file_wraps(third) == key_file_wraps(fourth), "migrated saves differ in their wrap"

    # The saved folder opens with the same passcode only.
    reloaded = TData.load(third, entry["passcode"])
    assert reloaded.legacy_key_file is False
    assert [(a.index, a.user_id, a.main_dc) for a in reloaded.accounts] == [
        (a.index, a.user_id, a.main_dc) for a in legacy.accounts
    ]
    main = reloaded.main_account
    assert main is not None
    assert main.index == entry["main_account_index"]
    if entry["passcode"]:
        with pytest.raises(CoreError) as wrong:
            TData.load(third)
        assert wrong.value.code == "TDATA_BAD_DECRYPT_KEY"


def test_migrate_leaves_a_7_3_folder_alone() -> None:
    tdata = TData.load(VECTORS / "tdata_plain" / "performance_on")
    assert tdata.legacy_key_file is False
    assert tdata.migrate() is False


# ---------------------------------------------------------------- Telethon files


def test_schema_and_statements_of_the_telethon_file() -> None:
    schema = _native.telethon_schema()
    assert [table["name"] for table in schema] == [
        "version",
        "sessions",
        "entities",
        "sent_files",
        "update_state",
    ]
    assert schema[0] == {
        "name": "version",
        "ddl": "create table version (version integer primary key)",
        "columns": ["version"],
    }
    assert schema[1] == {
        "name": "sessions",
        "ddl": "create table sessions (dc_id integer primary key, server_address text, "
        "port integer, auth_key blob, takeout_id integer, tmp_auth_key blob)",
        "columns": ["dc_id", "server_address", "port", "auth_key", "takeout_id", "tmp_auth_key"],
    }
    assert schema[3]["ddl"] == (
        "create table sent_files (md5_digest blob, file_size integer, type integer, "
        "id integer, hash integer, primary key(md5_digest, file_size, type))"
    )
    for table in schema:
        assert table["ddl"].startswith(f"create table {table['name']} ("), table["name"]
    assert _native.TELETHON_SESSION_VERSION == 8
    assert _native.TELETHON_DELETE_VERSION == "delete from version"
    assert _native.TELETHON_INSERT_VERSION == "insert into version values (?)"
    assert _native.TELETHON_DELETE_SESSIONS == "delete from sessions"
    assert _native.TELETHON_INSERT_SESSION == "insert into sessions values (?, ?, ?, ?, ?, ?)"
    assert _native.TELETHON_INSERT_SESSION.count("?") == len(schema[1]["columns"])
    assert _native.TELETHON_SESSION_SUFFIX == ".session"
    assert _native.TELETHON_JSON_SUFFIX == ".json"


@pytest.mark.parametrize("folder", ["tdata_plain/performance_on", "tdata_plain/performance_off"])
def test_session_rows_of_vector_accounts(folder: str) -> None:
    entry = manifest()[folder]
    tdata = TData.load(VECTORS / folder)
    for loaded, want in zip(tdata.accounts, entry["accounts"]):
        for family, text in enumerate(TABLE_TEXT[want["main_dc"]]):
            rows = _native.telethon_session_rows(loaded, family == 1)
            assert rows["dc_id"] == want["main_dc"], folder
            assert rows["server_address"] == text, folder
            assert rows["port"] == 443
            assert rows["takeout_id"] is None
            assert_same(rows["auth_key"], bytes.fromhex(want["auth_key"]), f"{folder} rows key")
        assert _native.telethon_session_rows(loaded) == _native.telethon_session_rows(loaded, False)


def test_session_rows_keep_the_stored_config_text_and_errors() -> None:
    for ipv6, text in ((False, "203.0.113.2"), (True, "2001:db8::2")):
        rows = _native.telethon_session_rows(account(2, CUSTOM_CONFIG), ipv6)
        assert (rows["dc_id"], rows["server_address"], rows["port"]) == (2, text, 443)
        assert_same(rows["auth_key"], KEY, "rows key")
    rows = _native.telethon_session_rows(account(3, CUSTOM_CONFIG), True)
    assert rows["server_address"] == "198.51.100.3"
    with pytest.raises(CoreError) as missing:
        _native.telethon_session_rows(account(5, CUSTOM_CONFIG))
    assert missing.value.code == "TDATA_BAD_CONFIG_DATA"
    # The string sessions take the stored config's endpoint too.
    assert _native.telethon_string_session(
        account(2, CUSTOM_CONFIG)
    ) != _native.telethon_string_session(account(2))
    with pytest.raises(CoreError) as unknown:
        _native.telethon_session_rows(Account(0, 1, 7, [(7, KEY)]))
    assert unknown.value.code == "TDATA_BAD_CONFIG_DATA"


def test_session_pair_paths_and_session_path() -> None:
    cases = [
        ("acc", "acc.session", "acc.json"),
        ("acc.session", "acc.session", "acc.json"),
        ("acc.json", "acc.session", "acc.json"),
        ("acc.session.json", "acc.session.session", "acc.session.json"),
        ("acc.json.session", "acc.session", "acc.json"),
        ("dir/acc.session", "dir/acc.session", "dir/acc.json"),
        ("acc.SESSION", "acc.SESSION.session", "acc.SESSION.json"),
        (".session", ".session", ".json"),
        ("acc.sessions", "acc.sessions.session", "acc.sessions.json"),
        ("a.session.session", "a.session.session", "a.session.json"),
        ("a.json.json", "a.json.session", "a.json.json"),
        ("", ".session", ".json"),
        ("dir/", "dir/.session", "dir/.json"),
        ("acc.session/", "acc.session/.session", "acc.session/.json"),
    ]
    for base, session, companion in cases:
        assert _native.session_pair_paths(base) == (session, companion), repr(base)
    assert _native.session_pair_paths(Path("acc.session")) == ("acc.session", "acc.json")
    for given, full in (
        ("acc", "acc.session"),
        ("acc.session", "acc.session"),
        ("acc.json", "acc.json.session"),
        ("acc.SESSION", "acc.SESSION.session"),
    ):
        assert _native.session_path(given) == full


def test_session_companion_json_is_the_session_json_with_extra_keys() -> None:
    profile = _native.profile("TelegramDesktop")
    companion = _native.session_companion_json(profile, {"session_file": "acc", "id": 77})
    assert companion == _native.profile_to_session_json(profile, {"session_file": "acc", "id": 77})
    assert companion["session_file"] == "acc"
    assert companion["id"] == 77
    assert list(companion) == list(_native.profile_to_session_json(profile))
    assert json.dumps(_native.session_companion_json(profile)) == json.dumps(
        _native.profile_to_session_json(profile)
    )
