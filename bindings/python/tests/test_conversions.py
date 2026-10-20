"""The tdata <-> Telethon conversions of ``opentele2.td`` and ``opentele2.tl``,
their saves and loads and the client checks, on the vector folders of
crates/opentele2-core/tests/vectors.

The default tests are offline: ``UseCurrentSession`` conversions never
connect. The flows that log in (``CreateNewSession``, QR login, 2FA) need a
real account and the network, and carry the ``live`` marker.

Key material is compared with ``assert_same``, which never prints the bytes.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest
from telethon.sessions import StringSession
from telethon.sessions.memory import MemorySession
from telethon.sessions.sqlite import SQLiteSession

from opentele2 import _native
from opentele2._native import Account as CoreAccount
from opentele2._native import TData
from opentele2.api import API, CreateNewSession, LoginFlag, UseCurrentSession
from opentele2.exception import (
    LoginFlagInvalid,
    MaxAccountLimit,
    OpenTeleException,
    TDAccountNotLoaded,
    TDataAuthKeyNotFound,
    TDesktopHasNoAccount,
    TDesktopNotLoaded,
    TFileNotFound,
)
from opentele2.td import Account, TDesktop
from opentele2.tl import TelegramClient

VECTORS = Path(__file__).resolve().parents[3] / "crates" / "opentele2-core" / "tests" / "vectors"
PLAIN = "tdata_plain/performance_on"
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
# sqlite3 iterdump() of the session file written for DC 2, 149.154.167.51:443
# (crates/opentele2-core/tests/session.rs WRITTEN_DUMP).
WRITTEN_DUMP = [
    "BEGIN TRANSACTION;",
    "CREATE TABLE entities (id integer primary key, hash integer not null, username text, "
    "phone integer, name text, date integer);",
    "CREATE TABLE sent_files (md5_digest blob, file_size integer, type integer, id integer, "
    "hash integer, primary key(md5_digest, file_size, type));",
    "CREATE TABLE sessions (dc_id integer primary key, server_address text, port integer, "
    "auth_key blob, takeout_id integer, tmp_auth_key blob);",
    "INSERT INTO \"sessions\" VALUES(2,'149.154.167.51',443,X'<KEY>',NULL,NULL);",
    "CREATE TABLE update_state (id integer primary key, pts integer, qts integer, date integer, "
    "seq integer);",
    "CREATE TABLE version (version integer primary key);",
    'INSERT INTO "version" VALUES(8);',
    "COMMIT;",
]
MAX_ACCOUNTS = "You can't have more than 6 accounts in one TDesktop client"


def assert_same(actual: bytes, expected: bytes, label: str) -> None:
    """Fails without showing either value, so key bytes never reach the log."""
    if actual != expected:
        raise AssertionError(f"{label} differs") from None


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def entry_of(folder: str) -> Any:
    with (VECTORS / "tdata.json").open(encoding="utf-8") as handle:
        return json.load(handle)["folders"][folder]


def listed_files(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())


def load(folder: str = PLAIN) -> TDesktop:
    return TDesktop(str(VECTORS / folder), passcode=entry_of(folder)["passcode"])


def main_of(tdesk: TDesktop) -> Account:
    account = tdesk.mainAccount
    assert account is not None
    return account


def key_of(account: Account) -> bytes:
    assert account.authKey is not None
    return account.authKey.key


def session_key(client: TelegramClient) -> bytes:
    auth_key = client.session.auth_key
    assert auth_key is not None
    return auth_key.key


def close(client: TelegramClient) -> None:
    client.session.close()


def dump(path: str, key: bytes) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        lines = list(conn.iterdump())
    finally:
        conn.close()
    blob = f"X'{key.hex().upper()}'"
    if not any(blob in line for line in lines):
        raise AssertionError("dump holds no blob of the key") from None
    return [line.replace(blob, "X'<KEY>'") for line in lines]


def config_folder(tmp_path: Path, main_dc: int) -> TDesktop:
    """A folder whose one account stores CUSTOM_CONFIG (saved without
    performance mode, so the configs file is written)."""
    account = CoreAccount(0, 77, main_dc, [(main_dc, KEY)], config=CUSTOM_CONFIG)
    path = tmp_path / f"config_{main_dc}"
    TData.new([account], performance_mode=False).save(path)
    return TDesktop(str(path))


@pytest.fixture
def performance_mode(monkeypatch: pytest.MonkeyPatch) -> Any:
    def set_mode(enabled: bool) -> None:
        monkeypatch.setattr(TDesktop, "kPerformanceMode", enabled)

    return set_mode


# ---------------------------------------------------------------- tdata -> Telethon


def test_tdata_to_telethon_uses_the_main_account(tmp_path: Path) -> None:
    tdesk = load()
    main = main_of(tdesk)
    want = entry_of(PLAIN)["accounts"][0]

    client = run(
        tdesk.ToTelethon(
            session=str(tmp_path / "acc"), flag=UseCurrentSession, api=API.TelegramDesktop
        )
    )
    try:
        assert isinstance(client, TelegramClient)
        assert isinstance(client.session, SQLiteSession)
        assert client.session.dc_id == main.MainDcId == want["main_dc"]
        assert client.session.server_address == "149.154.167.51"
        assert client.session.port == 443
        assert_same(session_key(client), key_of(main), "session key")
        assert_same(session_key(client), bytes.fromhex(want["auth_key"]), "vector key")
        assert client.UserId == main.UserId == want["user_id"]
        assert client.api_id == API.TelegramDesktop.api_id
        # The Telethon string session of the conversion is the core's.
        core = main._core
        assert core is not None
        assert StringSession.save(client.session) == _native.telethon_string_session(core)
    finally:
        close(client)


def test_every_account_converts_and_ipv6_follows_use_ipv6() -> None:
    tdesk = load()
    for account, want in zip(tdesk.accounts, entry_of(PLAIN)["accounts"]):
        ipv4 = run(account.ToTelethon(flag=UseCurrentSession))
        ipv6 = run(account.ToTelethon(flag=UseCurrentSession, use_ipv6=True))
        core = account._core
        assert core is not None
        for client, use_ipv6 in ((ipv4, False), (ipv6, True)):
            rows = _native.telethon_session_rows(core, use_ipv6)
            assert client.session.dc_id == rows["dc_id"] == want["main_dc"]
            assert client.session.server_address == rows["server_address"]
            assert client.session.port == rows["port"] == 443
            assert_same(session_key(client), rows["auth_key"], "session key")
            assert client.UserId == want["user_id"]
            assert StringSession.save(client.session) == _native.telethon_string_session(
                core, use_ipv6
            )
            close(client)
        assert ipv6.session.server_address.startswith("2001:")


def test_stored_config_picks_the_endpoint(tmp_path: Path) -> None:
    for main_dc, ipv4, ipv6 in (
        (2, "203.0.113.2", "2001:db8::2"),
        (3, "198.51.100.3", "198.51.100.3"),
    ):
        tdesk = config_folder(tmp_path, main_dc)
        for use_ipv6, text in ((False, ipv4), (True, ipv6)):
            client = run(
                TelegramClient.FromTDesktop(tdesk, flag=UseCurrentSession, use_ipv6=use_ipv6)
            )
            assert (client.session.dc_id, client.session.server_address) == (main_dc, text)
            assert_same(session_key(client), KEY, "session key")
            close(client)

    tdesk = config_folder(tmp_path, 5)
    with pytest.raises(
        OpenTeleException, match="Couldn't find endpoint for this account, something went wrong"
    ):
        run(TelegramClient.FromTDesktop(tdesk, flag=UseCurrentSession))


def test_session_choice_follows_the_flag(tmp_path: Path) -> None:
    session = MemorySession()
    assert TelegramClient._createAuthSession(None, CreateNewSession) is not session
    assert isinstance(TelegramClient._createAuthSession("x", CreateNewSession), MemorySession)
    assert TelegramClient._createAuthSession(session, UseCurrentSession) is session
    sqlite = TelegramClient._createAuthSession(str(tmp_path / "s"), UseCurrentSession)
    assert isinstance(sqlite, SQLiteSession)
    sqlite.close()
    bogus: Any = 42
    with pytest.raises(TypeError, match=r"The given session must be a str or a Session instance\."):
        TelegramClient._createAuthSession(bogus, UseCurrentSession)


def test_to_telethon_refusals() -> None:
    with pytest.raises(TDesktopNotLoaded, match="load accounts from a tdata folder first"):
        run(TDesktop().ToTelethon(flag=UseCurrentSession))
    with pytest.raises(TDesktopNotLoaded):
        run(TelegramClient.FromTDesktop(TDesktop(), flag=UseCurrentSession))
    with pytest.raises(TDAccountNotLoaded, match="Account not loaded yet"):
        run(Account(TDesktop()).ToTelethon(flag=UseCurrentSession))
    with pytest.raises(LoginFlagInvalid, match="LoginFlag invalid"):
        run(TelegramClient.FromTDesktop(load(), flag=LoginFlag))
    with pytest.raises(TDataAuthKeyNotFound, match="The account has no authKey loaded"):
        run(TelegramClient.FromTDesktop(Account(TDesktop()), flag=UseCurrentSession))


def test_from_tdesktop_without_auth_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    tdesk = load()
    monkeypatch.setattr(main_of(tdesk), "_Account__authKey", None)
    with pytest.raises(TDataAuthKeyNotFound):
        run(TelegramClient.FromTDesktop(tdesk, flag=UseCurrentSession))


def test_resolve_account_without_main_account_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    tdesk = load()
    monkeypatch.setattr(tdesk, "_TDesktop__mainAccount", None)
    with pytest.raises(TDesktopHasNoAccount, match="no main account"):
        TelegramClient._resolveTDesktopAccount(tdesk)
    assert TelegramClient._resolveTDesktopAccount(load().accounts[1]).index == 1


def test_unofficial_api_with_the_current_session_warns() -> None:
    unofficial: Any = 12345
    with pytest.warns(UserWarning, match="Telegram might ban your account"):
        client = run(TelegramClient.FromTDesktop(load(), flag=UseCurrentSession, api=unofficial))
    close(client)


def test_the_account_api_reaches_the_client() -> None:
    android = API.TelegramAndroid()
    tdesk = TDesktop(str(VECTORS / PLAIN), api=android)
    client = run(tdesk.ToTelethon(flag=UseCurrentSession))
    try:
        assert client.api_id == android.api_id
        assert client._init_request.device_model == android.device_model
    finally:
        close(client)


# ---------------------------------------------------------------- Telethon -> tdata


def test_round_trip_tdesk_telethon_tdesk() -> None:
    tdesk = load()
    main = main_of(tdesk)
    client = run(tdesk.ToTelethon(flag=UseCurrentSession, api=API.TelegramDesktop))

    tdesk2 = run(TDesktop.FromTelethon(client, flag=UseCurrentSession, api=API.TelegramDesktop))
    assert tdesk2.isLoaded()
    assert tdesk2.accountsCount == 1
    main2 = main_of(tdesk2)
    assert main2.isLoaded()
    assert main2.index == 0
    assert_same(key_of(main2), key_of(main), "auth key")
    assert main2.MainDcId == main.MainDcId
    assert main2.UserId == main.UserId
    assert main2.owner is tdesk2
    # A new folder in performance mode takes the fixed local key.
    assert tdesk2.localKey is not None
    assert tdesk.localKey is not None
    assert_same(tdesk2.localKey.key, tdesk.localKey.key, "performance local key")
    assert main2.localKey is tdesk2.localKey
    # And back again: the same session.
    again = run(tdesk2.ToTelethon(flag=UseCurrentSession))
    assert StringSession.save(again.session) == StringSession.save(client.session)
    close(client)
    close(again)


def test_telethon_to_tdata_reproduces_the_vector(tmp_path: Path, performance_mode: Any) -> None:
    """Both vector accounts through Telethon and back, saved with the
    recorded draws: byte for byte the vector folder."""
    performance_mode(True)
    tdesk = load()
    clients = [run(account.ToTelethon(flag=UseCurrentSession)) for account in tdesk.accounts]

    rebuilt = run(clients[0].ToTDesktop(flag=UseCurrentSession))
    second = run(Account.FromTelethon(clients[1], flag=UseCurrentSession, owner=rebuilt))
    assert second.index == 1
    assert rebuilt.accountsCount == 2
    assert main_of(rebuilt).index == 0

    draws = [bytes.fromhex(draw) for draw in entry_of(PLAIN)["rng_draws"]]
    assert rebuilt.SaveTData(str(tmp_path), draws=draws) is True
    assert listed_files(tmp_path) == entry_of(PLAIN)["files"]
    for name in entry_of(PLAIN)["files"]:
        assert_same(
            (tmp_path / name).read_bytes(), (VECTORS / PLAIN / name).read_bytes(), f"{name}"
        )
    for client in clients:
        close(client)


def test_save_and_reload(tmp_path: Path) -> None:
    tdesk = load()
    main = main_of(tdesk)
    client = run(tdesk.ToTelethon(session=str(tmp_path / "save_test"), flag=UseCurrentSession))
    tdesk2 = run(TDesktop.FromTelethon(client, flag=UseCurrentSession))
    close(client)

    save_path = tmp_path / "saved_tdata"
    os.makedirs(save_path, exist_ok=True)
    assert tdesk2.SaveTData(str(save_path)) is True

    tdesk3 = TDesktop(str(save_path))
    assert tdesk3.isLoaded()
    assert_same(key_of(main_of(tdesk3)), key_of(main), "auth key")
    assert main_of(tdesk3).UserId == main.UserId
    assert main_of(tdesk3).MainDcId == main.MainDcId


def test_account_from_telethon_without_owner(tmp_path: Path) -> None:
    client = run(load().accounts[1].ToTelethon(flag=UseCurrentSession))
    want = entry_of(PLAIN)["accounts"][1]
    android = API.TelegramAndroid()

    account = run(Account.FromTelethon(client, flag=UseCurrentSession, api=android))
    close(client)
    owner = account.owner
    assert isinstance(owner, TDesktop)
    # The new owner holds the account without a local key until saved.
    assert not owner.isLoaded()
    assert owner.accounts == [account]
    assert owner.mainAccount is account
    assert account.localKey is None
    assert (account.index, account.UserId, account.MainDcId) == (
        0,
        want["user_id"],
        want["main_dc"],
    )
    assert account.api is android
    assert owner.api is android
    assert_same(key_of(account), bytes.fromhex(want["auth_key"]), "auth key")

    assert owner.SaveTData(str(tmp_path)) is True
    assert owner.isLoaded()
    reloaded = TDesktop(str(tmp_path))
    assert [(a.index, a.UserId, a.MainDcId) for a in reloaded.accounts] == [
        (0, want["user_id"], want["main_dc"])
    ]


def test_user_id_comes_from_the_client() -> None:
    client = run(load().ToTelethon(flag=UseCurrentSession))
    client.UserId = 31337
    tdesk = run(TDesktop.FromTelethon(client, flag=UseCurrentSession))
    close(client)
    assert main_of(tdesk).UserId == 31337


def test_from_telethon_refusals() -> None:
    client = run(load().ToTelethon(flag=UseCurrentSession))
    with pytest.raises(LoginFlagInvalid):
        run(TDesktop.FromTelethon(client, flag=LoginFlag))
    with pytest.raises(LoginFlagInvalid):
        run(Account.FromTelethon(client, flag=LoginFlag))

    owner = run(TDesktop.FromTelethon(client, flag=UseCurrentSession))
    for _ in range(5):
        run(Account.FromTelethon(client, flag=UseCurrentSession, owner=owner))
    assert [account.index for account in owner.accounts] == [0, 1, 2, 3, 4, 5]
    with pytest.raises(MaxAccountLimit, match=MAX_ACCOUNTS):
        run(Account.FromTelethon(client, flag=UseCurrentSession, owner=owner))
    assert owner.accountsCount == 6
    close(client)


# ---------------------------------------------------------------- .session + .json


def test_tdesktop_save_session_json_writes_the_pair(tmp_path: Path) -> None:
    tdesk = load()
    main = main_of(tdesk)
    session_file, json_file = run(tdesk.SaveSessionJson(str(tmp_path / "acc")))
    assert (session_file, json_file) == (str(tmp_path / "acc.session"), str(tmp_path / "acc.json"))
    assert dump(session_file, key_of(main)) == WRITTEN_DUMP

    expected = API.TelegramDesktop().to_json({"session_file": "acc", "id": main.UserId})
    text = Path(json_file).read_text(encoding="utf-8")
    assert text == json.dumps(expected, ensure_ascii=False, indent=2)

    ios = API.TelegramIOS()
    _, ios_json = run(tdesk.SaveSessionJson(str(tmp_path / "ios"), api=ios))
    written = json.loads(Path(ios_json).read_text(encoding="utf-8"))
    assert written == ios.to_json({"session_file": "ios", "id": main.UserId})


def test_tdesktop_from_session_json_round_trips(tmp_path: Path) -> None:
    tdesk = load()
    main = main_of(tdesk)
    android = API.TelegramAndroid()
    run(tdesk.SaveSessionJson(str(tmp_path / "acc"), api=android))

    loaded = run(TDesktop.FromSessionJson(str(tmp_path / "acc.session")))
    assert loaded.isLoaded()
    account = main_of(loaded)
    assert_same(key_of(account), key_of(main), "auth key")
    assert (account.UserId, account.MainDcId) == (main.UserId, main.MainDcId)
    assert account.api == android
    assert loaded.api == android

    ios = API.TelegramIOS()
    chosen = run(TDesktop.FromSessionJson(str(tmp_path / "acc"), api=ios))
    assert main_of(chosen).api is ios


def test_tdesktop_session_json_refusals(tmp_path: Path) -> None:
    with pytest.raises(TDesktopNotLoaded):
        run(TDesktop().SaveSessionJson(str(tmp_path / "acc")))


# ---------------------------------------------------------------- key file rename


def test_saving_under_another_key_file_renames_it(tmp_path: Path) -> None:
    tdesk = load()
    assert tdesk.SaveTData(str(tmp_path), keyFile="other") is True
    assert tdesk.keyFile == "other"
    files = listed_files(tmp_path)
    assert "key_others" in files
    assert "key_datas" not in files
    assert len(files) == len(entry_of(PLAIN)["files"])

    renamed = TDesktop(str(tmp_path), keyFile="other")
    assert [(a.index, a.UserId, a.MainDcId) for a in renamed.accounts] == [
        (a.index, a.UserId, a.MainDcId) for a in tdesk.accounts
    ]
    for before, after in zip(tdesk.accounts, renamed.accounts):
        assert_same(key_of(after), key_of(before), f"account {before.index} auth key")
    with pytest.raises(TFileNotFound, match="Could not open key_data"):
        TDesktop(str(tmp_path))


def test_a_new_instance_saves_under_its_key_file(tmp_path: Path) -> None:
    client = run(load().ToTelethon(flag=UseCurrentSession))
    tdesk = run(TDesktop.FromTelethon(client, flag=UseCurrentSession))
    close(client)
    tdesk.SaveTData(str(tmp_path / "custom"), keyFile="custom")
    assert (tmp_path / "custom" / "key_customs").is_file()
    assert TDesktop(str(tmp_path / "custom"), keyFile="custom").accountsCount == 1
    # The renamed folder keeps its name on later saves.
    tdesk.SaveTData(str(tmp_path / "again"))
    assert (tmp_path / "again" / "key_customs").is_file()


# ---------------------------------------------------------------- live

X1 = "!DedInc#opentele"
X2 = "opentele#DedInc!"
PROFILE = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / (f"test_profile{sys.version_info.major}.{sys.version_info.minor}")
)


def _live_profile() -> str:
    if not (PROFILE / f"key_{X2}s").is_file():
        raise pytest.skip.Exception(f"Test profile not found: {PROFILE}")
    return str(PROFILE)


async def _tdata_to_telethon(profile: str) -> None:
    api_ios = API.TelegramIOS.Generate(X1)
    api_android = API.TelegramAndroid.Generate()

    tdesk = TDesktop(profile, api_ios, X1, X2)
    assert tdesk.isLoaded()

    oldClient = await tdesk.ToTelethon(flag=UseCurrentSession, api=api_ios)
    tdesk = await oldClient.ToTDesktop(UseCurrentSession, api=api_ios)

    await oldClient.connect()
    assert await oldClient.is_user_authorized()
    await oldClient.PrintSessions()

    newClient = await oldClient.QRLoginToNewClient(api=api_android, password=X1)
    await newClient.connect()
    assert await newClient.is_user_authorized()
    await newClient.PrintSessions()

    tdesk = await oldClient.ToTDesktop(UseCurrentSession, api=api_ios)
    oldClient = await tdesk.ToTelethon(flag=UseCurrentSession, api=api_ios)
    tdesk = await oldClient.ToTDesktop(UseCurrentSession, api=api_ios)
    tdesk.SaveTData(profile, X1, X2)

    await oldClient.disconnect()
    await newClient.disconnect()


async def _check_telegramclient(profile: str) -> None:
    api_ios = API.TelegramIOS.Generate(X1)
    tdesk = TDesktop(profile, api_ios, X1, X2)
    oldClient = await TelegramClient.FromTDesktop(tdesk, flag=UseCurrentSession, api=api_ios)

    await oldClient.connect()
    assert await oldClient.is_user_authorized()
    assert await oldClient.is_official_app()
    assert await oldClient.GetCurrentSession()
    await Account.FromTelethon(oldClient, flag=UseCurrentSession, api=api_ios)
    assert await oldClient.TerminateAllSessions()
    await oldClient.disconnect()


@pytest.mark.live
def test_live_tdata_telethon_flows() -> None:
    profile = _live_profile()
    run(_tdata_to_telethon(profile))
    run(_check_telegramclient(profile))


@pytest.mark.live
def test_live_create_new_session_from_tdata(tmp_path: Path) -> None:
    profile = _live_profile()

    async def scenario() -> None:
        tdesk = TDesktop(profile, API.TelegramIOS.Generate(X1), X1, X2)
        new_client = await tdesk.ToTelethon(
            session=str(tmp_path / "new"), flag=CreateNewSession, password=X1
        )
        try:
            assert await new_client.is_user_authorized()
            await new_client.SaveSessionJson(str(tmp_path / "export"), fetch_user_info=True)
            data = json.loads((tmp_path / "export.json").read_text(encoding="utf-8"))
            assert data.get("id") is not None
        finally:
            await new_client.disconnect()

    run(scenario())
