"""Tests of the 1.5.0 compatibility data opentele2._native exposes from the
core: ``CoreError.legacy_message``, the session JSON tables,
``format_app_version``, the device catalog listings, ``format_table``,
``TDF_MAGIC`` and ``draw_plan``.

Expected values are the literals of crates/opentele2-core/tests/
{legacy_messages,api,devices,auth,tdata_write}.rs, which were captured by
running 1.5.0.
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from opentele2 import _native
from opentele2._native import Account, CoreError, TData

VECTORS = Path(__file__).resolve().parents[3] / "crates" / "opentele2-core" / "tests" / "vectors"

# The 256-byte key `bytes(range(256))` the core captures used.
COUNTING_KEY = bytes(range(256))


def core_error(call: Any, *args: Any) -> CoreError:
    with pytest.raises(CoreError) as caught:
        call(*args)
    return caught.value


# ---------------------------------------------------------------- legacy messages


def test_core_error_keeps_its_legacy_message() -> None:
    plain = CoreError("SOME_CODE", "some text")
    assert plain.legacy_message == "some text"
    assert plain.args == ("SOME_CODE", "some text")

    error = CoreError("TDATA_INVALID_MAGIC", "tdata file has an invalid magic", "Invalid magic")
    assert error.code == "TDATA_INVALID_MAGIC"
    assert error.message == "tdata file has an invalid magic"
    assert error.legacy_message == "Invalid magic"
    assert str(error) == "TDATA_INVALID_MAGIC: tdata file has an invalid magic"
    copy = pickle.loads(pickle.dumps(error))
    assert (copy.code, copy.message, copy.legacy_message) == (
        error.code,
        error.message,
        error.legacy_message,
    )


def _with_key_file(folder: Path, content: bytes) -> Path:
    folder.mkdir()
    (folder / "key_datas").write_bytes(content)
    return folder


def test_read_file_messages_match_1_5_0(tmp_path: Path) -> None:
    missing = core_error(TData.load, tmp_path / "missing")
    assert missing.code == "TFILE_NOT_FOUND"
    assert missing.message == "tdata file not found"
    assert missing.legacy_message == "Could not open key_data"

    cases = [
        (b"ABCD", "Invalid magic b'ABCD' in file key_data"),
        (b"T'\x00\xff", r"""Invalid magic b"T'\x00\xff" in file key_data"""),
        (b"'\"\\\n", r"""Invalid magic b'\'"\\\n' in file key_data"""),
        (b"\t\r\x7f~", r"Invalid magic b'\t\r\x7f~' in file key_data"),
    ]
    for n, (magic, expected) in enumerate(cases):
        folder = _with_key_file(tmp_path / f"magic{n}", magic + bytes(30))
        error = core_error(TData.load, folder)
        assert error.code == "TDATA_INVALID_MAGIC"
        assert error.legacy_message == expected
        # The magic is spelled as Python's own bytes repr.
        assert error.legacy_message == f"Invalid magic {magic!r} in file key_data"

    content = b"TDF$" + (7003001).to_bytes(4, "little") + b"hello world" + bytes(16)
    error = core_error(TData.load, _with_key_file(tmp_path / "checksum", content))
    assert error.code == "TDATA_INVALID_CHECKSUM"
    assert error.legacy_message == (
        "Invalid checksum 78e20993e8b2d57b5f190eb51b1e8d63 in file key_data"
    )


def test_load_many_errors_carry_the_legacy_message(tmp_path: Path) -> None:
    [missing] = _native.load_many([tmp_path / "missing"])
    assert isinstance(missing, CoreError)
    assert missing.code == "TFILE_NOT_FOUND"
    assert missing.legacy_message == "Could not open key_data"


def test_decrypt_local_messages_match_1_5_0() -> None:
    assert (
        core_error(_native.decrypt_local, bytes(16), COUNTING_KEY).legacy_message
        == "Bad encrypted part size: 16"
    )
    assert (
        core_error(_native.decrypt_local, bytes(33), COUNTING_KEY).legacy_message
        == "Bad encrypted part size: 33"
    )
    bad_key = core_error(_native.decrypt_local, bytes(48), COUNTING_KEY)
    assert bad_key.code == "TDATA_BAD_DECRYPT_KEY"
    assert bad_key.legacy_message == "Bad decrypt key, data not decrypted - incorrect password?"

    # A correctly keyed plaintext whose length header says 2.
    plain = (2).to_bytes(4, "little") + bytes(28)
    msg_key = hashlib.sha1(plain).digest()[:16]
    aes_key, aes_iv = _native.prepare_aes_oldmtp(COUNTING_KEY, msg_key, False)
    forged = msg_key + _native.aes_ige_encrypt(plain, aes_key, aes_iv)
    error = core_error(_native.decrypt_local, forged, COUNTING_KEY)
    assert error.code == "TDATA_BAD_DECRYPTED_DATA_SIZE"
    assert error.legacy_message == "Bad decrypted part size: 48, fullLen: 32, decrypted size: 32"


def test_wrong_passcode_message_matches_1_5_0() -> None:
    error = core_error(TData.load, VECTORS / "tdata_plain" / "performance_on", "opentele2")
    assert error.code == "TDATA_BAD_DECRYPT_KEY"
    assert error.legacy_message == "Bad decrypt key, data not decrypted - incorrect password?"


def test_account_limit_message_matches_1_5_0() -> None:
    accounts = [Account(index, 1, 2, [(2, bytes(256))]) for index in range(6)]
    tdata = TData.new(accounts)
    error = core_error(tdata.add_account, 1, 2, bytes(256))
    assert error.code == "MAX_ACCOUNT_LIMIT"
    assert error.legacy_message == "You can't have more than 6 accounts in one TDesktop client"


def test_errors_without_a_1_5_0_message_give_their_text() -> None:
    error = core_error(_native.aes_ige_encrypt, bytes(16), bytes(16), bytes(32))
    assert error.code == "BAD_LENGTH"
    assert error.legacy_message == error.message


# ---------------------------------------------------------------- session JSON and versions


def test_format_app_version_matches_1_5_0() -> None:
    cases = [
        (7_003_001, "7.3.1"),
        (7_003_000, "7.3"),
        (1_000_000, "1.0"),
        (0, "0.0"),
        (12_345_678, "12.345.678"),
        (2**32 - 1, "4294.967.295"),
        (1_002_003, "1.2.3"),
    ]
    for version, expected in cases:
        assert _native.format_app_version(version) == expected, version
    desktop = _native.platform_versions()["desktop_app_version"]
    assert _native.format_app_version(7_003_001) == desktop
    with pytest.raises(OverflowError):
        _native.format_app_version(-1)


def test_tdf_magic_is_1_5_0s() -> None:
    assert _native.TDF_MAGIC == b"TDF$"


def test_session_json_tables_match_1_5_0() -> None:
    expected_extra = json.loads(
        '[["twoFA", null], ["role", ""], ["id", null], ["phone", null], ["username", null], '
        '["date_of_birth", null], ["date_of_birth_integrity", null], ["is_premium", false], '
        '["has_profile_pic", false], ["spamblock", null], ["register_time", null], '
        '["last_check_time", null], ["avatar", null], ["first_name", ""], ["last_name", ""], '
        '["sex", null], ["proxy", null], ["ipv6", false], ["session_file", ""]]'
    )
    assert [list(item) for item in _native.DEFAULT_EXTRA_FIELDS] == expected_extra
    assert all(isinstance(item, tuple) for item in _native.DEFAULT_EXTRA_FIELDS)

    assert _native.SESSION_JSON_FIELDS == [
        ("app_id", "api_id", None, None),
        ("app_hash", "api_hash", None, None),
        ("device", "device_model", None, None),
        ("sdk", "system_version", None, None),
        ("app_version", "app_version", None, None),
        ("system_lang_pack", "system_lang_code", "en", None),
        ("system_lang_code", "system_lang_code", None, "system_lang_pack"),
        ("lang_pack", "lang_pack", "", None),
        ("lang_code", "lang_code", "en", None),
    ]

    # The writer follows the same tables.
    written = _native.profile_to_session_json(_native.profile("TelegramDesktop"))
    keys = [key for key, *_ in _native.SESSION_JSON_FIELDS]
    keys += [key for key, _ in _native.DEFAULT_EXTRA_FIELDS]
    assert list(written) == keys


# ---------------------------------------------------------------- device catalogs


def lines_digest(lines: Iterable[str]) -> str:
    """SHA-1 hex of ``lines``, each followed by a newline."""
    hasher = hashlib.sha1()
    for line in lines:
        hasher.update(line.encode("utf-8") + b"\n")
    return hasher.hexdigest()


@pytest.mark.parametrize(
    ("platform", "runs", "digest"),
    [
        ("windows", 232, "ad3775a3cc0e8a0a305aac31af80c3f5be39fb89"),
        ("linux", 3944, "d5f46c6619554458fa5b51b4f3a131086f1fbd86"),
        ("macos", 1349, "ba1531aa74ba005ed87bd4e69fce7a8bf746a368"),
        ("android", 6850, "3e20af265f8b392de686676d135c80cfa1fe0570"),
        ("ios", 1166, "77c5f221cd8683c02ba0f0a451c427029cab7740"),
    ],
)
def test_catalog_entries_list_the_1_5_0_device_lists(platform: Any, runs: int, digest: str) -> None:
    merged: list[list[Any]] = []
    for entry in _native.catalog_entries(platform):
        assert entry["weight"] > 0
        last = merged[-1] if merged else None
        if last is not None and last[0] == entry["model"] and last[1] == entry["system_version"]:
            last[2] += entry["weight"]
        else:
            merged.append([entry["model"], entry["system_version"], entry["weight"]])
    assert len(merged) == runs
    lines = (f"{model}\t{version}\t{weight}" for model, version, weight in merged)
    assert lines_digest(lines) == digest


@pytest.mark.parametrize(
    ("platform", "models", "versions"),
    [
        (
            "windows",
            (116, "5c52da02e390eac9e3753d929c3360cfabbc705a"),
            (2, "e6bb592d547ca159c19720732b2b5cbfd6adb4ba"),
        ),
        (
            "linux",
            (116, "5c52da02e390eac9e3753d929c3360cfabbc705a"),
            (34, "f248aeedf61275d7a4b90fcc3ec72d873d5eaac7"),
        ),
        (
            "macos",
            (36, "f4da4ee944ec827dbef2c3a4d60c58d318355fe3"),
            (42, "da876c68c841a5aaa2e37e32e847122642a3c28f"),
        ),
        (
            "ios",
            (33, "4e9dfe139b2110fdaa14f269b0d8a723793885be"),
            (46, "2c94f86b38782cc48e1d171fe82134039ed3efbd"),
        ),
    ],
)
def test_catalog_lists_match_1_5_0_models_and_versions(
    platform: Any, models: tuple[int, str], versions: tuple[int, str]
) -> None:
    device_models = _native.device_models(platform)
    system_versions = _native.system_versions(platform)
    assert (len(device_models), lines_digest(device_models)) == models
    assert (len(system_versions), lines_digest(system_versions)) == versions


def test_android_system_versions_are_the_sdk_range() -> None:
    assert _native.system_versions("android") == [f"SDK {sdk}" for sdk in range(29, 38)]


def test_web_catalog_entries_are_listed_for_both_clients() -> None:
    web_a = _native.catalog_entries("web_a")
    web_k = _native.catalog_entries("web_k")
    assert web_a
    for entries, client in ((web_a, "web_a"), (web_k, "web_k")):
        models = set(_native.device_models(client))
        versions = set(_native.system_versions(client))
        assert all(entry["model"] in models for entry in entries)
        assert all(entry["system_version"] in versions for entry in entries)
    assert [(e["model"], e["weight"]) for e in web_a] == [(e["model"], e["weight"]) for e in web_k]


def test_web_browser_weights_are_1_5_0s() -> None:
    weights = list(_native.WEB_BROWSER_WEIGHTS.items())
    assert weights == [("chrome", 19), ("edge", 2), ("firefox", 1)]


def test_unknown_platform_is_refused() -> None:
    bad: Any = "symbian"
    for call in (_native.catalog_entries, _native.device_models, _native.system_versions):
        with pytest.raises(ValueError, match="unknown platform"):
            call(bad)


# ---------------------------------------------------------------- format_table


def test_format_table_matches_1_5_0_pretty_table() -> None:
    assert _native.format_table(["a", "bb"], [["1", "x"], ["long value", ""]]) == (
        "|------------+----|\n|     a      | bb |\n|------------+----|\n"
        "|     1      | x  |\n| long value |    |\n|------------+----|"
    )
    assert _native.format_table(
        ["Name", "#"], [["ok", "✔"], ["Ünïcødé", "12"], ["", "3"]], [0, 2]
    ) == (
        "|---------+----|\n|  Name   | #  |\n|---------+----|\n|---------+----|\n"
        "|   ok    | ✔  |\n| Ünïcødé | 12 |\n|---------+----|\n|         | 3  |\n"
        "|---------+----|"
    )
    assert _native.format_table(["Header longer"], [["x"]], add_split=[1, 5]) == (
        "|---------------|\n| Header longer |\n|---------------|\n|       x       |\n"
        "|---------------|"
    )
    assert _native.format_table(("x", "y"), [("even", "odd"), ("ab", "abc")], (1, 1)) == (
        "|------+-----|\n|  x   |  y  |\n|------+-----|\n| even | odd |\n"
        "|------+-----|\n|  ab  | abc |\n|------+-----|"
    )


def test_format_table_pads_short_rows_and_drops_extra_cells() -> None:
    assert _native.format_table(["h1", "h2"], [["only"], ["a", "b", "ignored"]]) == (
        "|------+----|\n|  h1  | h2 |\n|------+----|\n| only |    |\n"
        "|  a   | b  |\n|------+----|"
    )


# ---------------------------------------------------------------- draw_plan


def test_draw_plan_of_new_matches_1_5_0() -> None:
    assert _native.draw_plan("new", {"has_passcode": False, "performance_mode": True}) == []
    assert _native.draw_plan("new", {"has_passcode": True, "performance_mode": True}) == [
        256,
        32,
        32,
        32,
        12,
    ]
    assert _native.draw_plan("new", {"has_passcode": False, "performance_mode": False}) == [
        256,
        32,
        32,
        12,
    ]
    # The defaults are those of TData.new.
    assert _native.draw_plan("new", {}) == []


def replayable(plan: list[int]) -> list[bytes]:
    return [os.urandom(size) for size in plan]


def test_draw_plan_matches_the_draws_of_a_save(tmp_path: Path) -> None:
    tdata = TData.load(VECTORS / "tdata_plain" / "performance_on")
    copy = TData.new(tdata.accounts)
    copy.add_account(7, 4, bytes([3]) * 256)
    for performance_mode in (True, False):
        copy.performance_mode = performance_mode
        plan = _native.draw_plan("save", copy)
        assert plan
        assert all(size > 0 for size in plan)
        # A replay of other sizes, a missing or an unused draw raises.
        copy.save(tmp_path / f"saved_{performance_mode}", draws=replayable(plan))
        with pytest.raises(ValueError, match="draws"):
            copy.save(tmp_path / f"short_{performance_mode}", draws=replayable(plan[:-1]))


def test_draw_plan_matches_the_draws_of_a_migration() -> None:
    legacy = TData.load(VECTORS / "tdata_legacy" / "plain")
    assert legacy.legacy_key_file is True
    plan = _native.draw_plan("migrate", legacy)
    assert plan
    # A save of a legacy key file migrates first.
    assert _native.draw_plan("save", legacy)[: len(plan)] == plan
    assert legacy.migrate(draws=replayable(plan)) is True
    assert _native.draw_plan("migrate", legacy) == []


def test_draw_plan_refuses_what_save_refuses() -> None:
    error = core_error(_native.draw_plan, "save", TData.new([]))
    assert error.code == "TDATA_SAVE_FAILED"


def test_draw_plan_checks_its_arguments() -> None:
    tdata = TData.new([])
    bad: Any = "delete"
    with pytest.raises(ValueError, match="unknown operation"):
        _native.draw_plan(bad, tdata)
    params: Any = {"has_passcode": True}
    with pytest.raises(TypeError, match="TData"):
        _native.draw_plan("save", params)
    folder: Any = tdata
    with pytest.raises(TypeError, match="dict"):
        _native.draw_plan("new", folder)
