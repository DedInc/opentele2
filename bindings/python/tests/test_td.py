"""Tests of the 1.5.0 ``opentele2.td`` facades (TDesktop, Account, AuthKey,
AuthKeyType) over opentele2._native, ported from the public tdata
assertions of 1.5.0's tests/test_full.py, tests/tdata_test.py and
tests/test_tdata_*.py, on the vector folders of
crates/opentele2-core/tests/vectors.

Saves replay the recorded 1.5.0 ``os.urandom`` draws of tdata.json through
the ``draws`` hook and are compared with the vectors byte for byte. Key
material is compared with ``assert_same``, which never prints the bytes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

import opentele2.td
from opentele2 import _native
from opentele2._native import CoreError, TData
from opentele2.api import API, APIData
from opentele2.exception import (
    OpenTeleException,
    TDAccountNotLoaded,
    TDataBadDecryptKey,
    TDataSaveFailed,
    TFileNotFound,
)
from opentele2.td import Account, AuthKey, AuthKeyType, TDesktop

VECTORS = Path(__file__).resolve().parents[3] / "crates" / "opentele2-core" / "tests" / "vectors"
APP_VERSION = 7_003_001
PASSCODE = "opentele2"
MODERN = [
    "tdata_plain/performance_on",
    "tdata_plain/performance_off",
    "tdata_passcode/performance_on",
    "tdata_passcode/performance_off",
]
LEGACY = ["tdata_legacy/plain", "tdata_legacy/passcode"]
ALL_FOLDERS = [*MODERN, *LEGACY, "tdata_legacy/plain_saved", "tdata_legacy/passcode_saved"]
PASSCODE_FOLDERS = ["tdata_passcode/performance_on", "tdata_passcode/performance_off"]
PASSCODE_FOLDERS += ["tdata_legacy/passcode"]
BAD_DECRYPT_NO_PASSCODE = (
    "The tdata folder is password-encrypted, please the set the argument 'passcode' to decrypt it"
)
BAD_DECRYPT_WRONG_PASSCODE = "Failed to decrypt tdata folder because of invalid passcode"
SAVE_FAILED = "Could not save tdata, something went wrong"


def assert_same(actual: bytes, expected: bytes, label: str) -> None:
    """Fails without showing either value, so key bytes never reach the log."""
    if actual != expected:
        raise AssertionError(f"{label} differs") from None


def entry_of(folder: str) -> Any:
    with (VECTORS / "tdata.json").open(encoding="utf-8") as handle:
        return json.load(handle)["folders"][folder]


def draws_of(folder: str) -> list[bytes]:
    return [bytes.fromhex(draw) for draw in entry_of(folder)["rng_draws"]]


def key_draws(entry: Any) -> int:
    """The draws 1.5.0 made for a new local key: pass, salt, open salt, a
    wrap salt with a passcode, and the wrap padding; none for the fixed
    performance-mode keys."""
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


def load(folder: str) -> TDesktop:
    return TDesktop(str(VECTORS / folder), passcode=entry_of(folder)["passcode"])


@pytest.fixture
def performance_mode(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Sets TDesktop.kPerformanceMode for one test."""

    def set_mode(enabled: bool) -> None:
        monkeypatch.setattr(TDesktop, "kPerformanceMode", enabled)

    return set_mode


# ---------------------------------------------------------------- public surface


def test_td_exports_the_1_5_0_public_classes_only() -> None:
    assert opentele2.td.__all__ == ["Account", "AuthKey", "AuthKeyType", "TDesktop"]
    for internal in ("MTP", "MapData", "Serialize", "Storage", "StorageAccount"):
        assert not hasattr(opentele2.td, internal), internal
    assert TDesktop.kMaxAccounts == 6
    assert TDesktop.kDefaultKeyFile == "data"
    assert TDesktop.kPerformanceMode is True
    assert Account.kWideIdsTag == -1
    assert AuthKey.kSize == 256
    assert [(t.name, int(t)) for t in AuthKeyType] == [
        ("Generated", 0),
        ("Temporary", 1),
        ("ReadFromFile", 2),
        ("Local", 3),
    ]


def test_tdesktop_empty_init() -> None:
    tdesk = TDesktop()
    assert not tdesk.isLoaded()
    assert tdesk.accountsCount == 0
    assert tdesk.accounts == []
    assert tdesk.mainAccount is None
    assert tdesk.localKey is None
    assert tdesk.passcodeKey is None
    assert tdesk.AppVersion is None
    assert tdesk.basePath is None
    assert tdesk.keyFile == "data"
    assert tdesk.passcode == ""
    assert isinstance(tdesk.api, APIData)
    assert tdesk.api == API.TelegramDesktop()
    custom = TDesktop(api=API.TelegramAndroid, passcode="пароль-密码", keyFile="other")
    assert (custom.passcode, custom.keyFile) == ("пароль-密码", "other")
    assert custom.api == API.TelegramAndroid()


def test_performance_mode_classmethod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(TDesktop, "kPerformanceMode", True)
    TDesktop.PerformanceMode(False)
    assert TDesktop.kPerformanceMode is False
    assert TDesktop().kPerformanceMode is False
    TDesktop.PerformanceMode()
    assert TDesktop.kPerformanceMode is True


# ---------------------------------------------------------------- loading


@pytest.mark.parametrize("folder", ALL_FOLDERS)
def test_every_vector_loads_as_1_5_0(folder: str) -> None:
    entry = entry_of(folder)
    tdesk = load(folder)
    path = str(VECTORS / folder)
    assert tdesk.isLoaded()
    assert tdesk.basePath == os.path.abspath(path)
    assert tdesk.keyFile == entry["key_file"]
    assert tdesk.passcode == entry["passcode"]
    assert tdesk.AppVersion == APP_VERSION
    assert tdesk.accountsCount == len(entry["accounts"])
    assert tdesk.accounts is tdesk.accounts

    native = TData.load(path, entry["passcode"])
    assert tdesk.localKey is not None
    assert tdesk.passcodeKey is not None
    assert_same(tdesk.localKey.key, native.local_key, f"{folder} local key")
    assert_same(tdesk.passcodeKey.key, native.passcode_key, f"{folder} passcode key")

    for account, want in zip(tdesk.accounts, entry["accounts"]):
        assert account.owner is tdesk
        assert account.isLoaded()
        assert not account.isAuthorized()
        assert account.index == want["index"]
        assert account.UserId == want["user_id"]
        assert account.MainDcId == want["main_dc"]
        assert account.basePath == os.path.abspath(path)
        assert account.keyFile == "data"
        assert account.api is tdesk.api
        assert account.localKey is tdesk.localKey
        auth_key = account.authKey
        assert auth_key is not None
        assert auth_key.type is AuthKeyType.ReadFromFile
        assert auth_key.dcId == want["main_dc"]
        assert len(auth_key.key) == 256
        assert_same(auth_key.key, bytes.fromhex(want["auth_key"]), f"{folder} auth key")

    main = tdesk.mainAccount
    assert main is not None
    assert main is tdesk.accounts[entry["main_account_index"]]


def test_main_account_follows_the_stored_active_index(tmp_path: Path) -> None:
    accounts = TData.load(VECTORS / "tdata_plain/performance_on").accounts
    TData.new(accounts, active_index=1).save(tmp_path)
    tdesk = TDesktop(str(tmp_path))
    assert tdesk.mainAccount is tdesk.accounts[1]


@pytest.mark.parametrize("folder", PASSCODE_FOLDERS)
def test_wrong_passcode_raises_bad_decrypt_key_with_1_5_0_message(folder: str) -> None:
    path = str(VECTORS / folder)
    with pytest.raises(TDataBadDecryptKey) as missing:
        TDesktop(path)
    assert missing.value.message == BAD_DECRYPT_NO_PASSCODE
    assert isinstance(missing.value.__cause__, CoreError)
    with pytest.raises(TDataBadDecryptKey) as wrong:
        TDesktop(path, passcode="not-" + PASSCODE)
    assert wrong.value.message == BAD_DECRYPT_WRONG_PASSCODE

    tdesk = TDesktop()
    with pytest.raises(OpenTeleException, match="No folder provided"):
        tdesk.LoadTData()
    retry = TDesktop(path, passcode=PASSCODE)
    with pytest.raises(TDataBadDecryptKey) as reloaded:
        retry.LoadTData(passcode="")
    assert reloaded.value.message == BAD_DECRYPT_NO_PASSCODE
    assert retry.accountsCount == 0, "a failed load leaves no accounts"
    retry.LoadTData(passcode=PASSCODE)
    assert retry.accountsCount == 2


def test_missing_folder_or_key_file_raises_tfile_not_found(tmp_path: Path) -> None:
    with pytest.raises(TFileNotFound) as missing:
        TDesktop(str(tmp_path / "nonexistent" / "tdata"))
    assert missing.value.message == "Could not open key_data"
    with pytest.raises(TFileNotFound):
        TDesktop(str(tmp_path))
    with pytest.raises(TFileNotFound) as other_key:
        TDesktop(str(VECTORS / "tdata_plain/performance_on"), keyFile="other")
    assert other_key.value.message == "Could not open key_other"


def test_a_key_file_without_account_files_loads_no_account(tmp_path: Path) -> None:
    shutil.copy(VECTORS / "tdata_plain/performance_on" / "key_datas", tmp_path / "key_datas")
    with pytest.raises(OpenTeleException, match="No account has been loaded"):
        TDesktop(str(tmp_path))


def test_more_accounts_than_7_3_1_allows_are_loaded_with_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    key = bytes(range(256))
    accounts = [_native.Account(i, 1000 + i, 2, [(2, key)]) for i in range(7)]
    TData.new(accounts).save(tmp_path / "seven")
    TData.new(accounts[:6]).save(tmp_path / "six")
    with caplog.at_level(logging.WARNING, logger="opentele2.td.tdesktop"):
        six = TDesktop(str(tmp_path / "six"))
        assert caplog.records == []
        seven = TDesktop(str(tmp_path / "seven"))
    assert six.accountsCount == TDesktop.kMaxAccounts
    assert seven.accountsCount == 7
    assert [a.UserId for a in seven.accounts] == [1000 + i for i in range(7)]
    assert [r.getMessage() for r in caplog.records] == [
        "tdata lists 7 accounts, above the 6 known to Telegram Desktop 7.3.1; loading them anyway"
    ]


# ---------------------------------------------------------------- byte-identical saves


@pytest.mark.parametrize("folder", MODERN)
def test_load_and_save_reproduce_the_vector(
    folder: str, tmp_path: Path, performance_mode: Any
) -> None:
    entry = entry_of(folder)
    performance_mode(entry["performance_mode"])
    tdesk = load(folder)
    local_key = tdesk.localKey
    assert tdesk.SaveTData(str(tmp_path), draws=draws_of(folder)[key_draws(entry) :]) is True
    assert_same_folder(folder, tmp_path)
    assert tdesk.localKey is local_key, "saving a loaded folder keeps its local key"
    assert tdesk.basePath == os.path.abspath(str(VECTORS / folder))

    # Account.SaveTData saves the owner's folder.
    account = tdesk.accounts[0]
    account.SaveTData(str(tmp_path / "account"), draws=draws_of(folder)[key_draws(entry) :])
    assert_same_folder(folder, tmp_path / "account")


@pytest.mark.parametrize("folder", MODERN)
def test_a_passcode_change_rekeys_into_the_vector(
    folder: str, tmp_path: Path, performance_mode: Any
) -> None:
    entry = entry_of(folder)
    performance_mode(entry["performance_mode"])
    tdesk = load(folder)
    main = tdesk.mainAccount
    other = "" if entry["passcode"] else PASSCODE
    tdesk.SaveTData(str(tmp_path / "other"), passcode=other)
    assert tdesk.passcode == other
    reloaded = TDesktop(str(tmp_path / "other"), passcode=other)
    assert [a.UserId for a in reloaded.accounts] == [a.UserId for a in tdesk.accounts]

    old_local_key = tdesk.localKey
    tdesk.SaveTData(str(tmp_path / "back"), passcode=entry["passcode"], draws=draws_of(folder))
    assert_same_folder(folder, tmp_path / "back")
    assert tdesk.localKey is not old_local_key
    assert tdesk.mainAccount is main
    for account in tdesk.accounts:
        assert account.localKey is tdesk.localKey


def test_a_rekey_keeps_the_loaded_active_index(tmp_path: Path) -> None:
    accounts = TData.load(VECTORS / "tdata_plain/performance_on").accounts
    TData.new(accounts, active_index=1).save(tmp_path / "source")
    tdesk = TDesktop(str(tmp_path / "source"))
    tdesk.SaveTData(str(tmp_path / "rekeyed"), passcode="hunter2")
    rekeyed = TData.load(tmp_path / "rekeyed", "hunter2")
    assert rekeyed.active_index == 1
    assert TDesktop(str(tmp_path / "rekeyed"), passcode="hunter2").mainAccount is not None


@pytest.mark.parametrize("folder", LEGACY)
def test_legacy_saves_migrate_once_into_the_saved_vector(
    folder: str, tmp_path: Path, performance_mode: Any
) -> None:
    performance_mode(True)
    entry = entry_of(folder)
    saved = f"{folder}_saved"
    draws = draws_of(saved)
    wrap = 3 if entry["passcode"] else 2
    tdesk = load(folder)
    local_key = tdesk.localKey
    old_passcode_key = tdesk.passcodeKey
    assert local_key is not None
    assert old_passcode_key is not None

    tdesk.SaveTData(str(tmp_path / "first"), draws=draws)
    assert_same_folder(saved, tmp_path / "first")
    assert tdesk.localKey is local_key, "migration keeps the local key"
    new_passcode_key = tdesk.passcodeKey
    assert new_passcode_key is not None
    assert new_passcode_key.key != old_passcode_key.key, "migration installs a new wrap"
    assert_same(
        new_passcode_key.key,
        TData.load(VECTORS / saved, entry["passcode"]).passcode_key,
        f"{saved} passcode key",
    )

    # The second save keeps the migrated wrap: only the save's own draws.
    tdesk.SaveTData(str(tmp_path / "second"), draws=draws[wrap:])
    assert_same_folder(saved, tmp_path / "second")
    assert TDesktop(str(tmp_path / "second"), passcode=entry["passcode"]).accountsCount == 2


@pytest.mark.parametrize("enabled", [True, False])
def test_performance_mode_picks_the_configs_files(
    enabled: bool, tmp_path: Path, performance_mode: Any
) -> None:
    performance_mode(enabled)
    tdesk = load("tdata_plain/performance_on")
    tdesk.SaveTData(str(tmp_path))
    want = "tdata_plain/performance_on" if enabled else "tdata_plain/performance_off"
    assert listed_files(tmp_path) == entry_of(want)["files"]
    assert TDesktop(str(tmp_path)).accountsCount == 2


# ---------------------------------------------------------------- save failures


def test_save_without_folder_or_accounts_fails_as_1_5_0(tmp_path: Path) -> None:
    with pytest.raises(OpenTeleException, match="No folder provided"):
        TDesktop().SaveTData()
    empty = TDesktop()
    with pytest.raises(TDataSaveFailed) as failed:
        empty.SaveTData(str(tmp_path), draws=[])
    assert failed.value.message == SAVE_FAILED
    assert isinstance(failed.value.__cause__, OpenTeleException)
    assert empty.isLoaded(), "1.5.0 generates the local key before writing"
    assert empty.localKey is not None
    assert empty.basePath == os.path.abspath(str(tmp_path))
    assert listed_files(tmp_path) == []


def test_save_failure_lists_no_replayed_draw(tmp_path: Path, performance_mode: Any) -> None:
    performance_mode(False)
    marker = bytes(range(32, 64))
    with pytest.raises(TDataSaveFailed) as failed:
        TDesktop().SaveTData(str(tmp_path), draws=[b"\x00" * 256, marker, marker, b"\x00" * 12])
    # An OpenTeleException keeps the arguments of the frame that raised it.
    arguments = failed.value._caller_method_params
    assert failed.value._caller_method == "SaveTData"
    assert "draws=None" in arguments
    assert str(marker) not in arguments
    assert "SaveTData()" in str(failed.value)


def test_mismatched_draws_raise_value_error(tmp_path: Path) -> None:
    tdesk = load("tdata_plain/performance_on")
    with pytest.raises(ValueError, match="left unused"):
        tdesk.SaveTData(str(tmp_path), draws=[*draws_of("tdata_plain/performance_on"), b"\x00"])


def test_saving_under_another_key_file_renames_it(tmp_path: Path) -> None:
    tdesk = load("tdata_plain/performance_on")
    assert tdesk.SaveTData(str(tmp_path), keyFile="other") is True
    assert tdesk.keyFile == "other"
    files = listed_files(tmp_path)
    assert "key_others" in files
    assert "key_datas" not in files
    renamed = TDesktop(str(tmp_path), keyFile="other")
    assert [(a.index, a.UserId) for a in renamed.accounts] == [
        (a.index, a.UserId) for a in tdesk.accounts
    ]


def test_an_empty_key_file_name_fails_the_save(tmp_path: Path) -> None:
    tdesk = load("tdata_plain/performance_on")
    with pytest.raises(TDataSaveFailed, match=SAVE_FAILED):
        tdesk.SaveTData(str(tmp_path), keyFile="")
    assert listed_files(tmp_path) == []


def test_saves_write_the_accounts_list_as_1_5_0(tmp_path: Path) -> None:
    # TDesktop(...).SaveTData after editing tdesk.accounts, reloaded, in 1.5.0.
    tdesk = load("tdata_plain/performance_on")
    removed = tdesk.accounts.pop(1)
    assert removed.index == 1
    tdesk.SaveTData(str(tmp_path / "removed"))
    reloaded = TDesktop(str(tmp_path / "removed"))
    assert [(a.index, a.UserId, a.MainDcId) for a in reloaded.accounts] == [(0, 100000001, 2)]
    main = reloaded.mainAccount
    assert main is not None
    assert main.index == 0

    key = bytes(range(256))
    TData.new([_native.Account(2, 4242, 4, [(4, key)])]).save(tmp_path / "two")
    tdesk = load("tdata_plain/performance_on")
    tdesk.accounts.append(TDesktop(str(tmp_path / "two")).accounts[0])
    tdesk.SaveTData(str(tmp_path / "added"))
    reloaded = TDesktop(str(tmp_path / "added"))
    assert [(a.index, a.UserId, a.MainDcId) for a in reloaded.accounts] == [
        (0, 100000001, 2),
        (1, 5000000123, 4),
        (2, 4242, 4),
    ]
    added = reloaded.accounts[2].authKey
    assert added is not None
    assert_same(added.key, key, "appended account auth key")
    for account in tdesk.accounts:
        assert account.localKey is tdesk.localKey


def test_mtp_config_reads_the_account_config_as_1_5_0() -> None:
    # TDesktop(folder).accounts[0].MtpConfig of 1.5.0: the production default,
    # and endpoints(MainDcId) sorted by address family and protocol.
    dc2_ipv4 = [
        {"id": 2, "flags": 16, "ip": "149.154.167.51", "port": 443, "secret": b""},
        {"id": 2, "flags": 16, "ip": "95.161.76.100", "port": 443, "secret": b""},
    ]
    dc2_ipv6 = [
        {
            "id": 2,
            "flags": 17,
            "ip": "2001:067c:04e8:f002:0000:0000:0000:000a",
            "port": 443,
            "secret": b"",
        }
    ]
    for folder in ("tdata_plain/performance_on", "tdata_plain/performance_off"):
        account = load(folder).accounts[0]
        config = account.MtpConfig
        assert config.environment == "production"
        assert not config.isTestMode()
        options = config.dcOptions
        assert sorted(options) == [1, 2, 3, 4, 5]
        assert options[2] == [*dc2_ipv4, *dc2_ipv6]
        assert options[1][0]["ip"] == "149.154.175.50"
        assert config.cdnPublicKeys == []
        fields = config.fields
        assert (fields["web_file_dc_id"], fields["txt_domain_string"]) == (4, "apv3.stel.com")
        assert fields["chat_size_max"] == 200
        endpoints = config.endpoints(account.MainDcId)
        assert endpoints is not None
        assert endpoints["ipv4"] == {"tcp": dc2_ipv4, "http": dc2_ipv4}
        assert endpoints["ipv6"] == {"tcp": dc2_ipv6, "http": dc2_ipv6}
        assert config.endpoints() == endpoints
        options[2].clear()
        assert len(config.dcOptions[2]) == 3, "a read returns a copy"

    with pytest.raises(TDAccountNotLoaded):
        _ = Account(TDesktop()).MtpConfig


def test_api_reaches_every_account() -> None:
    tdesk = load("tdata_plain/performance_on")
    android = API.TelegramAndroid()
    tdesk.api = android
    assert all(account.api is android for account in tdesk.accounts)
    ios = API.TelegramIOS()
    tdesk.accounts[0].api = ios
    assert tdesk.api is ios


# ---------------------------------------------------------------- AuthKey


def test_auth_key_fields_and_key_id() -> None:
    blank = AuthKey()
    assert (blank.key, blank.type, blank.dcId) == (b"", AuthKeyType.Generated, 0)
    with pytest.raises(ValueError, match="expected 256, got 0"):
        _ = blank.keyId
    key = bytes(range(256))
    auth_key = AuthKey(key, AuthKeyType.ReadFromFile, 4)
    assert (auth_key.type, auth_key.dcId) == (AuthKeyType.ReadFromFile, 4)
    # 1.5.0's __countKeyId.
    want = int.from_bytes(hashlib.sha1(key).digest()[12:20], "little")
    assert auth_key.keyId == want


def test_prepare_aes_oldmtp_matches_the_crypto_vectors() -> None:
    with (VECTORS / "crypto.json").open(encoding="utf-8") as handle:
        cases = json.load(handle)["prepare_aes_oldmtp"]
    for n, case in enumerate(cases):
        auth_key = AuthKey(bytes.fromhex(case["auth_key"]))
        msg_key = bytes.fromhex(case["msg_key"])
        aes_key, aes_iv = auth_key.prepareAES_oldmtp(msg_key + b"\xff" * 4, case["send"])
        assert_same(aes_key, bytes.fromhex(case["aes_key"]), f"aes_key case {n}")
        assert_same(aes_iv, bytes.fromhex(case["aes_iv"]), f"aes_iv case {n}")


# ---------------------------------------------------------------- real folder


@pytest.mark.skipif(
    not os.environ.get("OPENTELE2_REAL_TDATA"),
    reason="set OPENTELE2_REAL_TDATA to a real tdata folder (and the passcode in "
    "OPENTELE2_REAL_TDATA_PASSCODE) to run",
)
def test_real_tdata_folder_round_trips(tmp_path: Path) -> None:
    path = os.environ["OPENTELE2_REAL_TDATA"]
    passcode = os.environ.get("OPENTELE2_REAL_TDATA_PASSCODE", "")
    tdesk = TDesktop(path, passcode=passcode)
    assert tdesk.isLoaded()
    assert tdesk.accountsCount > 0
    main = tdesk.mainAccount
    assert main is not None
    assert main.isLoaded()
    assert main.UserId > 0
    assert 1 <= main.MainDcId <= 5
    assert main.authKey is not None
    assert len(main.authKey.key) == 256

    tdesk.SaveTData(str(tmp_path))
    saved = TDesktop(str(tmp_path), passcode=passcode, keyFile=tdesk.keyFile)
    assert [(a.index, a.UserId, a.MainDcId) for a in saved.accounts] == [
        (a.index, a.UserId, a.MainDcId) for a in tdesk.accounts
    ]
    for before, after in zip(tdesk.accounts, saved.accounts):
        assert before.authKey is not None
        assert after.authKey is not None
        assert_same(after.authKey.key, before.authKey.key, f"account {before.index} auth key")
