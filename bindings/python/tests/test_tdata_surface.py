"""Tests of the TData key, version, performance-mode and active-index
surface of opentele2._native, and of the ``draws`` replay hook, against
crates/opentele2-core/tests/tdata_write.rs and the tdata vectors.

Every vector folder is rebuilt byte for byte by replaying the recorded
``os.urandom`` draws of tdata.json through ``new``/``save``/
``migrate``. Key material is compared with ``assert_same``, which never
prints the bytes.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

import pytest

from opentele2 import _native
from opentele2._native import Account, CoreError, TData

VECTORS = Path(__file__).resolve().parents[3] / "crates" / "opentele2-core" / "tests" / "vectors"
APP_VERSION = 7_003_001
NEW_FOLDER_ACTIVE_INDEX = -1
MODERN = [
    "tdata_plain/performance_on",
    "tdata_plain/performance_off",
    "tdata_passcode/performance_on",
    "tdata_passcode/performance_off",
]
LEGACY = ["plain", "passcode"]
# Draws a migration of a legacy key file takes: the open salt, with a
# passcode the wrap salt, then the wrap padding.
MIGRATION_DRAWS = {"plain": 2, "passcode": 3}

# The fixed performance-mode local and passcode keys, the keys
# crates/opentele2-core/src/tdata/mod.rs writes without a passcode.
PERF_LOCAL_KEY = bytes.fromhex(
    "d8745944519e0d2d71309d6c8d272dc64948f5e3eba7685324d5c691ad810c20"
    "3b31d19d29aed6ac33c014be6e09843293f6fa32dbe42b6a04e00481fae99511"
    "4caf6342bd98e96d293dd062c458689b3abd23a5cf230c75527c05bf5f90f38c"
    "d93952cf61aaac1cfeaae4608592e363ded35f8d8c45234def53231decb35592"
    "afc40d0601bbed11090969f74d9ab0cc97827546f441242d2cfb8e05a0610e97"
    "669c0da1adccb56e39e10c69e2942387ff4922f8c55dcb8890e345ef318266f4"
    "b3831430ea210c863c17624c0494cdead81f523430b5f74c15da323d766bd01c"
    "b5b88b9d2a731f6d853380ad306a8647fa614cc4017f08902c1e1f997ee12e3c"
)
PERF_PASSCODE_KEY = bytes.fromhex(
    "273e6483b313c9dbc4acd9173864c0422f172881bfe1c6649ca5538654d0bd6e"
    "bcfbcc8dabbb669717ce53b41ca8afbf9d15c23fa2b06a6e166cc61f62e99805"
    "58cd42cf1022e05b466811ea29e9359fc1f94668e5c85155bce638fe7aa42aa8"
    "80ca83e0d2e534198a0a890139c8f679a57d3ba06d75fe5faa6e250101a58bc6"
    "e42b9696604de1e34ae40f6bba144a284f3ad8843253ec9b3971863a2c409208"
    "c2563967b3587e509b42a42a6040d23ff696ad552a240084fa3f950240f499b2"
    "3cd6d27e7010cbde07daae0667a7df8a5115a60b265c58f5d9291f7a98fc3c60"
    "1e2a4a32f1881b8218c855239d7b532959609e6ab52e48ad691c2583b566c8f9"
)


def assert_same(actual: bytes, expected: bytes, label: str) -> None:
    """Fails without showing either value, so key bytes never reach the log."""
    if actual != expected:
        raise AssertionError(f"{label} differs") from None


def assert_differ(actual: bytes, expected: bytes, label: str) -> None:
    """Fails without showing either value when the two are equal."""
    if actual == expected:
        raise AssertionError(f"{label} is unchanged") from None


def entry_of(folder: str) -> Any:
    with (VECTORS / "tdata.json").open(encoding="utf-8") as handle:
        return json.load(handle)["folders"][folder]


def draws_of(entry: Any) -> list[bytes]:
    return [bytes.fromhex(draw) for draw in entry["rng_draws"]]


def label_bytes(label: str, size: int) -> bytes:
    """tdata.json's ``bytes(label, n)``: SHA-256 of the label and a counter."""
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(label.encode("utf-8") + struct.pack(">I", counter)).digest()
        counter += 1
    return out[:size]


def accounts_of(entry: Any) -> list[Account]:
    return [
        Account(
            a["index"], a["user_id"], a["main_dc"], [(a["main_dc"], bytes.fromhex(a["auth_key"]))]
        )
        for a in entry["accounts"]
    ]


def key_generation_draws(entry: Any) -> int:
    """Draws ``new`` makes: pass, salt, open salt, a wrap salt with a
    passcode, and the wrap padding; none for the fixed performance keys."""
    if entry["performance_mode"] and not entry["passcode"]:
        return 0
    return 5 if entry["passcode"] else 4


def listed_files(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())


def assert_same_folder(folder: str, written: Path) -> None:
    entry = entry_of(folder)
    assert listed_files(written) == entry["files"], f"{folder} file list"
    for name in entry["files"]:
        assert_same(
            (written / name).read_bytes(),
            (VECTORS / folder / name).read_bytes(),
            f"{folder}/{name}",
        )


# ---------------------------------------------------------------- getters


@pytest.mark.parametrize("folder", MODERN)
def test_getters_of_modern_vectors(folder: str) -> None:
    entry = entry_of(folder)
    draws = draws_of(entry)
    tdata = TData.load(VECTORS / folder, entry["passcode"])
    assert tdata.app_version == APP_VERSION
    assert tdata.active_index == NEW_FOLDER_ACTIVE_INDEX
    assert tdata.performance_mode is True, "load turns performance mode on"
    assert len(tdata.local_key) == 256
    assert len(tdata.passcode_key) == 256
    if key_generation_draws(entry) == 0:
        assert_same(tdata.local_key, PERF_LOCAL_KEY, f"{folder} local key")
        assert_same(tdata.passcode_key, PERF_PASSCODE_KEY, f"{folder} passcode key")
        return
    # The local key is create_local_key(pass, salt) of the first two draws.
    assert_same(
        tdata.local_key, _native.create_local_key(draws[0], draws[1]), f"{folder} local key"
    )
    if not entry["passcode"]:
        # The open wrap key is create_local_key("", open salt).
        assert_same(
            tdata.passcode_key, _native.create_local_key(b"", draws[2]), f"{folder} passcode key"
        )
    else:
        assert_differ(tdata.passcode_key, PERF_PASSCODE_KEY, f"{folder} passcode key")


@pytest.mark.parametrize("name", LEGACY)
def test_getters_of_legacy_vectors(name: str) -> None:
    source = f"tdata_legacy/{name}"
    entry = entry_of(source)
    tdata = TData.load(VECTORS / source, entry["passcode"])
    assert tdata.legacy_key_file is True
    assert tdata.app_version == APP_VERSION
    assert tdata.main_account is not None
    assert tdata.main_account.index == entry["main_account_index"]
    assert_same(tdata.local_key, label_bytes(f"{source}/local_key", 256), f"{source} local key")
    salt = label_bytes(f"{source}/salt", 32)
    assert_same(
        tdata.passcode_key,
        _native.create_local_key(entry["passcode"], salt),
        f"{source} passcode key",
    )

    saved = TData.load(VECTORS / f"{source}_saved", entry["passcode"])
    assert saved.legacy_key_file is False
    assert_same(saved.local_key, tdata.local_key, f"{source}_saved local key")
    if not entry["passcode"]:
        open_salt = draws_of(entry_of(f"{source}_saved"))[0]
        assert_same(
            saved.passcode_key,
            _native.create_local_key(b"", open_salt),
            f"{source}_saved passcode key",
        )


# ---------------------------------------------------------------- byte-identical replay


@pytest.mark.parametrize("folder", MODERN)
def test_new_and_save_reproduce_the_vector(folder: str, tmp_path: Path) -> None:
    entry = entry_of(folder)
    draws = draws_of(entry)
    split = key_generation_draws(entry)
    tdata = TData.new(
        accounts_of(entry), entry["passcode"], entry["performance_mode"], draws=draws[:split]
    )
    assert tdata.active_index == NEW_FOLDER_ACTIVE_INDEX
    assert tdata.app_version == APP_VERSION
    assert tdata.performance_mode is entry["performance_mode"]
    tdata.save(tmp_path, draws=draws[split:])
    assert_same_folder(folder, tmp_path)

    vector = TData.load(VECTORS / folder, entry["passcode"])
    assert_same(tdata.local_key, vector.local_key, f"{folder} local key")
    assert_same(tdata.passcode_key, vector.passcode_key, f"{folder} passcode key")


@pytest.mark.parametrize("folder", MODERN)
@pytest.mark.parametrize("how", ["setter", "argument"])
def test_load_and_save_reproduce_the_vector(folder: str, how: str, tmp_path: Path) -> None:
    entry = entry_of(folder)
    draws = draws_of(entry)[key_generation_draws(entry) :]
    tdata = TData.load(VECTORS / folder, entry["passcode"])
    if how == "setter":
        tdata.performance_mode = entry["performance_mode"]
        assert tdata.performance_mode is entry["performance_mode"]
        tdata.save(tmp_path, draws=draws)
    else:
        tdata.save(tmp_path, performance_mode=entry["performance_mode"], draws=draws)
        assert tdata.performance_mode is True, "the argument applies to that save only"
    assert_same_folder(folder, tmp_path)


@pytest.mark.parametrize("name", LEGACY)
def test_legacy_save_reproduces_the_saved_vector(name: str, tmp_path: Path) -> None:
    source = f"tdata_legacy/{name}"
    entry = entry_of(source)
    legacy = TData.load(VECTORS / source, entry["passcode"])
    legacy.save(tmp_path, draws=draws_of(entry_of(f"{source}_saved")))
    assert_same_folder(f"{source}_saved", tmp_path)
    assert legacy.legacy_key_file is True, "save leaves the folder unmigrated"


@pytest.mark.parametrize("name", LEGACY)
def test_migrate_then_saves_reproduce_the_saved_vector(name: str, tmp_path: Path) -> None:
    source = f"tdata_legacy/{name}"
    entry = entry_of(source)
    draws = draws_of(entry_of(f"{source}_saved"))
    split = MIGRATION_DRAWS[name]
    tdata = TData.load(VECTORS / source, entry["passcode"])
    local_key = tdata.local_key
    old_passcode_key = tdata.passcode_key
    assert tdata.migrate(draws=draws[:split]) is True
    assert tdata.legacy_key_file is False
    assert_same(tdata.local_key, local_key, f"{source} local key")
    assert_differ(tdata.passcode_key, old_passcode_key, f"{source} passcode key")
    saved = TData.load(VECTORS / f"{source}_saved", entry["passcode"])
    assert_same(tdata.passcode_key, saved.passcode_key, f"{source} new wrap key")
    for round_ in range(2):
        written = tmp_path / str(round_)
        tdata.save(written, draws=draws[split:])
        assert_same_folder(f"{source}_saved", written)


# ---------------------------------------------------------------- setters


def test_performance_mode_and_active_index_round_trip(tmp_path: Path) -> None:
    folder = "tdata_plain/performance_on"
    tdata = TData.load(VECTORS / folder)
    snapshot_accounts = [a.index for a in tdata.accounts]
    tdata.performance_mode = False
    tdata.active_index = 1
    assert tdata.performance_mode is False
    assert tdata.active_index == 1
    main = tdata.main_account
    assert main is not None
    assert main.index == 1
    assert [a.index for a in tdata.accounts] == snapshot_accounts
    tdata.save(tmp_path / "off")
    assert listed_files(tmp_path / "off") == entry_of("tdata_plain/performance_off")["files"]
    reloaded = TData.load(tmp_path / "off")
    assert reloaded.active_index == 1
    assert reloaded.main_account is not None
    assert reloaded.main_account.index == 1
    assert_same(reloaded.local_key, tdata.local_key, "reloaded local key")

    tdata.save(tmp_path / "on", performance_mode=True)
    assert listed_files(tmp_path / "on") == entry_of(folder)["files"]
    assert tdata.performance_mode is False

    untyped: Any = tdata
    with pytest.raises((AttributeError, TypeError)):
        del untyped.active_index
    with pytest.raises(AttributeError):
        untyped.local_key = b"\x00" * 256


def test_new_stores_the_active_index(tmp_path: Path) -> None:
    entry = entry_of("tdata_plain/performance_on")
    tdata = TData.new(accounts_of(entry), active_index=1)
    assert tdata.active_index == 1
    tdata.save(tmp_path)
    assert TData.load(tmp_path).active_index == 1
    assert TData.new(accounts_of(entry)).active_index == NEW_FOLDER_ACTIVE_INDEX


# ---------------------------------------------------------------- replay errors


def test_draws_of_another_size_missing_or_unused_raise() -> None:
    entry = entry_of("tdata_plain/performance_off")
    accounts = accounts_of(entry)
    draws = draws_of(entry)[:4]
    with pytest.raises(ValueError, match="draw 0 has 255 bytes, but 256 were drawn"):
        TData.new(accounts, performance_mode=False, draws=[draws[0][:-1], *draws[1:]])
    with pytest.raises(ValueError, match="draw 3 of 12 bytes was not given"):
        TData.new(accounts, performance_mode=False, draws=draws[:3])
    with pytest.raises(ValueError, match="1 of 5 draws were left unused"):
        TData.new(accounts, performance_mode=False, draws=[*draws, b"\x00" * 4])
    with pytest.raises(ValueError, match="1 of 1 draws were left unused"):
        TData.new(accounts, draws=[b"\x00"])
    not_bytes: Any = ["not bytes"]
    with pytest.raises(TypeError):
        TData.new(accounts, performance_mode=False, draws=not_bytes)
    assert TData.new(accounts, performance_mode=False, draws=[bytearray(d) for d in draws])


def test_save_and_migrate_reject_mismatched_draws(tmp_path: Path) -> None:
    source = "tdata_legacy/plain"
    draws = draws_of(entry_of(f"{source}_saved"))
    legacy = TData.load(VECTORS / source)
    with pytest.raises(ValueError, match="draw 1 of 12 bytes was not given"):
        legacy.migrate(draws=draws[:1])
    assert legacy.legacy_key_file is True, "a failed replay leaves the folder as it was"
    with pytest.raises(ValueError, match="left unused"):
        legacy.migrate(draws=draws)
    assert legacy.legacy_key_file is True
    with pytest.raises(ValueError, match="left unused"):
        legacy.save(tmp_path / "extra", draws=[*draws, b"\x00"])

    modern = TData.load(VECTORS / "tdata_plain/performance_on")
    with pytest.raises(ValueError, match="1 of 1 draws were left unused"):
        modern.migrate(draws=[b"\x00"])
    assert modern.migrate(draws=[]) is False


# ---------------------------------------------------------------- add_account and key_file


def core_code(error: pytest.ExceptionInfo[CoreError]) -> str:
    return str(error.value.code)


def labelled_account(index: int) -> Account:
    return Account(index, 9_000_000_000 + index, 2, [(2, label_bytes(f"account {index}", 256))])


def test_max_accounts_is_tdesktops_limit() -> None:
    assert TData.MAX_ACCOUNTS == 6
    tdata = TData.load(VECTORS / "tdata_plain/performance_on")
    assert tdata.MAX_ACCOUNTS == 6


def test_add_account_then_save_and_reload(tmp_path: Path) -> None:
    folder = "tdata_plain/performance_on"
    tdata = TData.load(VECTORS / folder)
    before = tdata.accounts
    active = tdata.active_index
    key = label_bytes("added account", 256)
    assert tdata.add_account(9_000_000_123, 3, bytearray(key)) == 2
    assert [a.index for a in before] == [0, 1], "an earlier accounts list is a snapshot"
    assert [a.index for a in tdata.accounts] == [0, 1, 2]
    assert tdata.active_index == active
    added = tdata.accounts[2]
    assert (added.user_id, added.main_dc) == (9_000_000_123, 3)
    assert_same(added.auth_key, key, "added auth key")
    assert added.config is None

    tdata.save(tmp_path)
    assert len(listed_files(tmp_path)) == len(entry_of(folder)["files"]) + 2
    reloaded = TData.load(tmp_path)
    assert [(a.index, a.user_id, a.main_dc) for a in reloaded.accounts] == [
        (a.index, a.user_id, a.main_dc) for a in tdata.accounts
    ]
    for loaded, kept in zip(reloaded.accounts, tdata.accounts):
        assert_same(loaded.auth_key, kept.auth_key, f"account {kept.index} auth key")


def test_add_account_takes_the_lowest_free_index() -> None:
    tdata = TData.new([labelled_account(0), labelled_account(2)])
    assert tdata.add_account(1, 1, label_bytes("gap", 256)) == 1
    assert tdata.add_account(3, 1, label_bytes("next", 256)) == 3
    assert [a.index for a in tdata.accounts] == [0, 2, 1, 3]


def test_add_account_refuses_more_than_max_accounts() -> None:
    tdata = TData.load(VECTORS / "tdata_plain/performance_on")
    added = [tdata.add_account(n, 2, label_bytes(f"fill {n}", 256)) for n in range(4)]
    assert added == [2, 3, 4, 5]
    with pytest.raises(CoreError) as error:
        tdata.add_account(7, 2, label_bytes("seventh", 256))
    assert core_code(error) == "MAX_ACCOUNT_LIMIT"
    assert [a.index for a in tdata.accounts] == [0, 1, 2, 3, 4, 5], "a refused add changes nothing"

    full = TData.new([labelled_account(n) for n in range(TData.MAX_ACCOUNTS)])
    with pytest.raises(CoreError) as error:
        full.add_account(7, 2, label_bytes("seventh", 256))
    assert core_code(error) == "MAX_ACCOUNT_LIMIT"


def test_add_account_rejects_a_bad_key() -> None:
    tdata = TData.load(VECTORS / "tdata_plain/performance_on")
    with pytest.raises(CoreError) as error:
        tdata.add_account(7, 2, b"\x00" * 255)
    assert core_code(error) == "BAD_LENGTH"
    assert len(tdata.accounts) == 2
    not_bytes: Any = "not bytes"
    with pytest.raises(TypeError):
        tdata.add_account(7, 2, not_bytes)


def test_setting_accounts_keeps_the_keys(tmp_path: Path) -> None:
    folder = "tdata_plain/performance_off"
    tdata = TData.load(VECTORS / folder)
    local_key = tdata.local_key
    passcode_key = tdata.passcode_key
    kept = tdata.accounts[0]
    before = tdata.accounts
    tdata.accounts = [kept, labelled_account(3)]
    assert [a.index for a in before] == [0, 1], "an earlier accounts list is a snapshot"
    assert [a.index for a in tdata.accounts] == [0, 3]
    assert_same(tdata.local_key, local_key, "local key")
    assert_same(tdata.passcode_key, passcode_key, "passcode key")

    tdata.save(tmp_path)
    reloaded = TData.load(tmp_path)
    assert_same(reloaded.local_key, local_key, "reloaded local key")
    assert [(a.index, a.user_id) for a in reloaded.accounts] == [
        (0, kept.user_id),
        (3, 9_000_000_003),
    ]


def test_setting_accounts_refuses_a_list_the_folder_cannot_hold() -> None:
    tdata = TData.load(VECTORS / "tdata_plain/performance_on")
    with pytest.raises(CoreError) as error:
        tdata.accounts = [labelled_account(n) for n in range(TData.MAX_ACCOUNTS + 1)]
    assert core_code(error) == "MAX_ACCOUNT_LIMIT"
    with pytest.raises(CoreError) as repeated:
        tdata.accounts = [labelled_account(2), labelled_account(0), labelled_account(2)]
    assert core_code(repeated) == "TDATA_SAVE_FAILED"
    assert [a.index for a in tdata.accounts] == [0, 1], "a refused list changes nothing"
    tdata.accounts = [labelled_account(n) for n in range(TData.MAX_ACCOUNTS)]
    assert len(tdata.accounts) == TData.MAX_ACCOUNTS
    tdata.accounts = []
    assert tdata.accounts == []
    not_accounts: Any = "not accounts"
    with pytest.raises(TypeError):
        tdata.accounts = not_accounts


def test_setting_accounts_keeps_a_loaded_seven_account_folder_writable(tmp_path: Path) -> None:
    # A folder listing seven accounts loads, and an edited list of them saves
    # under the same local key.
    TData.new([labelled_account(n) for n in range(7)]).save(tmp_path / "seven")
    tdata = TData.load(tmp_path / "seven")
    local_key = tdata.local_key
    tdata.accounts = [labelled_account(n) for n in reversed(range(7))]
    assert [a.index for a in tdata.accounts] == [6, 5, 4, 3, 2, 1, 0]
    assert_same(tdata.local_key, local_key, "local key")
    with pytest.raises(CoreError) as error:
        tdata.accounts = [labelled_account(n) for n in range(8)]
    assert core_code(error) == "MAX_ACCOUNT_LIMIT"
    assert len(tdata.accounts) == 7, "a refused list changes nothing"


def test_key_file_rename_then_save_and_reload(tmp_path: Path) -> None:
    folder = "tdata_plain/performance_on"
    tdata = TData.load(VECTORS / folder)
    snapshot = TData.load(VECTORS / folder)
    tdata.key_file = "custom"
    assert tdata.key_file == "custom"
    assert snapshot.key_file == "data"
    tdata.save(tmp_path)
    files = listed_files(tmp_path)
    assert "key_customs" in files
    assert "key_datas" not in files
    assert len(files) == len(entry_of(folder)["files"])
    assert not set(files) & (set(entry_of(folder)["files"]) - {"key_datas"}), (
        "account files are renamed with the key file"
    )

    with pytest.raises(CoreError) as error:
        TData.load(tmp_path)
    assert core_code(error) == "TFILE_NOT_FOUND"
    reloaded = TData.load(tmp_path, key_file="custom")
    assert reloaded.key_file == "custom"
    assert [(a.index, a.user_id) for a in reloaded.accounts] == [
        (a.index, a.user_id) for a in tdata.accounts
    ]
    for loaded, kept in zip(reloaded.accounts, tdata.accounts):
        assert_same(loaded.auth_key, kept.auth_key, f"account {kept.index} auth key")
    assert_same(reloaded.local_key, tdata.local_key, "reloaded local key")


def test_key_file_rejects_an_empty_name() -> None:
    tdata = TData.load(VECTORS / "tdata_plain/performance_on")
    with pytest.raises(CoreError) as error:
        tdata.key_file = ""
    assert core_code(error) == "TDATA_SAVE_FAILED"
    assert tdata.key_file == "data"
    untyped: Any = tdata
    with pytest.raises(TypeError):
        untyped.key_file = 1
    with pytest.raises((AttributeError, TypeError)):
        del untyped.key_file
