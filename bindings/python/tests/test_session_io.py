"""The Telethon version 8 ``.session`` writer and the ``.session`` + ``.json``
pair, ported from 1.5.0 tests/test_session_io.py and compared with the
``sqlite3`` dump of a file 1.5.0 wrote (crates/opentele2-core/tests/
session.rs) and the Telethon-written core fixture. Offline: no client
connects.

Dumps mask the auth key blob, so key bytes never reach the log.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import shutil
import sqlite3
from typing import Any

import pytest
from telethon.crypto import AuthKey
from telethon.sessions.sqlite import CURRENT_VERSION, SQLiteSession

from opentele2 import _native
from opentele2.api import API, APIData, LoginFlag, UseCurrentSession
from opentele2.exception import LoginFlagInvalid, SessionFileInvalid, SessionFileNotFound
from opentele2.tl.session_io import (
    SESSION_VERSION,
    from_session_json,
    save_session_json,
    write_session_file,
)
from opentele2.tl.telethon import TelegramClient

AUTH_KEY = bytes(range(256))
CORE_TESTS = pathlib.Path(__file__).resolve().parents[3] / "crates" / "opentele2-core" / "tests"
TELETHON_FIXTURE = CORE_TESTS / "fixtures" / "telethon_v8.session"
# The synthetic key of the fixture: byte i is 255 - i.
FIXTURE_KEY = bytes(255 - i for i in range(256))

# sqlite3 iterdump() of the file 1.5.0 write_session_file wrote for DC 2,
# 149.154.167.51:443 (crates/opentele2-core/tests/session.rs V150_DUMP).
V150_DUMP = [
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


def dump(path: str | pathlib.Path, key: bytes) -> list[str]:
    """``iterdump()`` of ``path`` with the blob of ``key`` masked; fails when
    the dump holds no blob of ``key``."""
    conn = sqlite3.connect(str(path))
    try:
        lines = list(conn.iterdump())
    finally:
        conn.close()
    blob = f"X'{key.hex().upper()}'"
    if not any(blob in line for line in lines):
        raise AssertionError("dump holds no blob of the key") from None
    return [line.replace(blob, "X'<KEY>'") for line in lines]


def inserts(lines: list[str]) -> list[str]:
    return [line for line in lines if line.startswith("INSERT")]


def creates(lines: list[str]) -> list[str]:
    return [line for line in lines if line.startswith("CREATE")]


def _make_pre_v8_session(path: str) -> None:
    """Write the narrow pre-version-8 Telethon schema at ``path``."""
    conn = sqlite3.connect(path)
    try:
        c = conn.cursor()
        c.execute("create table version (version integer primary key)")
        c.execute("insert into version values (1)")
        c.execute(
            "create table sessions (dc_id integer primary key, "
            "server_address text, port integer, auth_key blob)"
        )
        c.execute("insert into sessions values (1, '149.154.175.50', 443, x'00')")
        c.execute(
            "create table entities (id integer primary key, hash integer not null, "
            "username text, phone integer, name text)"
        )
        c.execute(
            "create table sent_files (md5_digest blob, file_size integer, "
            "type integer, id integer, hash integer, "
            "primary key(md5_digest, file_size, type))"
        )
        c.execute(
            "create table update_state (id integer primary key, pts integer, "
            "qts integer, date integer, seq integer)"
        )
        conn.commit()
    finally:
        conn.close()


def _columns(path: str, table: str) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return [row[1] for row in conn.execute(f"pragma table_info({table})")]
    finally:
        conn.close()


def _version(path: str) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("select version from version").fetchone()[0]
    finally:
        conn.close()


def assert_session(base: str, dc_id: int, address: str, key: bytes) -> None:
    session = SQLiteSession(base)
    try:
        assert session.dc_id == dc_id
        assert session.server_address == address
        assert session.port == 443
        assert session.auth_key is not None
        if session.auth_key.key != key:
            raise AssertionError("auth key differs") from None
    finally:
        session.close()


# ---------------------------------------------------------------- write_session_file


def test_fresh_write_round_trips_through_sqlite_session(tmp_path: pathlib.Path) -> None:
    base = str(tmp_path / "fresh")
    full_path = write_session_file(base, 2, "149.154.167.51", 443, AUTH_KEY)

    assert full_path == base + ".session"
    assert _version(full_path) == CURRENT_VERSION == SESSION_VERSION
    assert_session(base, 2, "149.154.167.51", AUTH_KEY)


def test_written_file_dumps_as_1_5_0_writes_it(tmp_path: pathlib.Path) -> None:
    path = write_session_file(str(tmp_path / "v150"), 2, "149.154.167.51", 443, AUTH_KEY)
    assert dump(path, AUTH_KEY) == V150_DUMP
    # A path already ending in .session is used as it is.
    again = write_session_file(path, 2, "149.154.167.51", 443, AUTH_KEY)
    assert again == path
    assert dump(path, AUTH_KEY) == V150_DUMP


def test_schema_and_statements_come_from_the_core(tmp_path: pathlib.Path) -> None:
    path = write_session_file(str(tmp_path / "schema"), 2, "149.154.167.51", 443, AUTH_KEY)
    for table in _native.telethon_schema():
        assert _columns(path, table["name"]) == table["columns"]
        body = table["ddl"][len("create table ") :]
        assert f"CREATE TABLE {body};" in V150_DUMP


def test_write_over_pre_v8_session_rebuilds_schema(tmp_path: pathlib.Path) -> None:
    base = str(tmp_path / "legacy")
    full_path = base + ".session"
    _make_pre_v8_session(full_path)
    assert _columns(full_path, "sessions") == ["dc_id", "server_address", "port", "auth_key"]

    # Regression: this used to leave the narrow table stamped as version 8 and
    # raise "table sessions has 4 columns but 6 values supplied".
    write_session_file(base, 4, "149.154.167.91", 443, AUTH_KEY)

    assert _columns(full_path, "sessions") == [
        "dc_id",
        "server_address",
        "port",
        "auth_key",
        "takeout_id",
        "tmp_auth_key",
    ]
    assert _version(full_path) == CURRENT_VERSION
    assert_session(base, 4, "149.154.167.91", AUTH_KEY)


def test_pre_v8_file_is_rebuilt_as_1_5_0_does(tmp_path: pathlib.Path) -> None:
    path = str(tmp_path / "old.session")
    _make_pre_v8_session(path)
    write_session_file(path, 2, "149.154.167.51", 443, AUTH_KEY)
    assert dump(path, AUTH_KEY) == V150_DUMP


def test_pre_v8_file_is_never_stamped_v8_with_old_schema(tmp_path: pathlib.Path) -> None:
    """The stamp and the layout must move together, never independently."""
    base = str(tmp_path / "stamp")
    full_path = base + ".session"
    _make_pre_v8_session(full_path)
    write_session_file(base, 1, "149.154.175.50", 443, AUTH_KEY)

    conn = sqlite3.connect(full_path)
    try:
        version = conn.execute("select version from version").fetchone()[0]
        row = conn.execute("select * from sessions").fetchone()
    finally:
        conn.close()

    assert version == CURRENT_VERSION
    assert len(row) == 6
    # takeout_id and tmp_auth_key stay NULL: telethon 1.44.0 unpacks them in
    # the opposite order to its own DDL, so NULL keeps that harmless.
    assert row[4] is None
    assert row[5] is None


def test_rewrite_of_current_schema_preserves_entities(tmp_path: pathlib.Path) -> None:
    base = str(tmp_path / "keep")
    full_path = write_session_file(base, 2, "149.154.167.51", 443, AUTH_KEY)

    conn = sqlite3.connect(full_path)
    try:
        conn.execute("insert into entities values (7, 11, 'u', NULL, 'n', 0)")
        conn.commit()
    finally:
        conn.close()

    write_session_file(base, 5, "91.108.56.100", 443, AUTH_KEY)

    conn = sqlite3.connect(full_path)
    try:
        assert conn.execute("select count(*) from entities").fetchone()[0] == 1
        assert conn.execute("select count(*) from sessions").fetchone()[0] == 1
    finally:
        conn.close()

    assert_session(base, 5, "91.108.56.100", AUTH_KEY)


def test_writing_over_the_telethon_fixture_keeps_its_schema(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "over.session"
    shutil.copyfile(TELETHON_FIXTURE, path)
    telethon_schema = creates(dump(path, FIXTURE_KEY))
    assert any("\n" in line for line in telethon_schema), "Telethon writes multi-line DDL"

    address = "2001:067c:04e8:f002:0000:0000:0000:000a"
    write_session_file(str(path), 2, address, 443, AUTH_KEY)
    lines = dump(path, AUTH_KEY)
    assert creates(lines) == telethon_schema, "schema kept"
    # 1.5.0 write_session_file on a copy of the fixture, same values.
    assert inserts(lines) == [
        f"INSERT INTO \"sessions\" VALUES(2,'{address}',443,X'<KEY>',NULL,NULL);",
        'INSERT INTO "version" VALUES(8);',
    ]
    assert_session(str(tmp_path / "over"), 2, address, AUTH_KEY)


def test_write_leaves_no_open_handle(tmp_path: pathlib.Path) -> None:
    """The writer's connection is closed before the path is handed onward."""
    base = str(tmp_path / "handle")
    full_path = write_session_file(base, 2, "149.154.167.51", 443, AUTH_KEY)

    session = SQLiteSession(base)
    session.set_dc(2, "149.154.167.51", 443)
    session.save()
    session.close()

    pathlib.Path(full_path).unlink()
    assert not pathlib.Path(full_path).exists()


def test_telegram_client_writer_is_the_session_io_writer(tmp_path: pathlib.Path) -> None:
    base = str(tmp_path / "static")
    path = TelegramClient._write_session_file(base, 2, "149.154.167.51", 443, AUTH_KEY)
    assert path == base + ".session"
    assert dump(path, AUTH_KEY) == V150_DUMP


# ---------------------------------------------------------------- .session + .json


def _write_pair(base: pathlib.Path, data: Any) -> None:
    write_session_file(str(base), 2, "149.154.167.51", 443, AUTH_KEY)
    (base.parent / (base.name + ".json")).write_text(json.dumps(data), encoding="utf-8")


def _close(client: TelegramClient) -> None:
    client.session.close()


def test_from_session_json_with_the_current_session(tmp_path: pathlib.Path) -> None:
    api = API.TelegramAndroid()
    _write_pair(tmp_path / "acc", api.to_json({"session_file": "acc", "id": 777}))

    async def load(path: str) -> TelegramClient:
        return await from_session_json(path)

    for given in ("acc", "acc.session", "acc.json"):
        client = asyncio.run(load(str(tmp_path / given)))
        try:
            assert client._api_data == api
            assert client.api_id == api.api_id
            assert client._init_request.device_model == api.device_model
            assert client._init_request.lang_pack == api.lang_pack
            assert client.UserId == 777
            assert client.session.dc_id == 2
            assert client.session.server_address == "149.154.167.51"
            assert client.session.auth_key is not None
            if client.session.auth_key.key != AUTH_KEY:
                raise AssertionError("auth key differs") from None
        finally:
            _close(client)


def test_from_session_json_takes_an_explicit_json_path(tmp_path: pathlib.Path) -> None:
    api = API.TelegramIOS()
    write_session_file(str(tmp_path / "acc"), 2, "149.154.167.51", 443, AUTH_KEY)
    other = tmp_path / "meta.json"
    other.write_text(json.dumps(api.to_json()), encoding="utf-8")

    client = asyncio.run(TelegramClient.FromSessionJson(str(tmp_path / "acc"), str(other)))
    try:
        assert client._api_data == api
        assert client.UserId is None
    finally:
        _close(client)


def test_from_session_json_errors(tmp_path: pathlib.Path) -> None:
    base = tmp_path / "acc"

    def load(*args: Any) -> TelegramClient:
        return asyncio.run(from_session_json(*args))

    with pytest.raises(LoginFlagInvalid, match="LoginFlag invalid"):
        load(str(base), None, LoginFlag)
    with pytest.raises(SessionFileNotFound, match=r"Session file not found: .*acc\.session"):
        load(str(base))
    write_session_file(str(base), 2, "149.154.167.51", 443, AUTH_KEY)
    with pytest.raises(SessionFileNotFound, match=r"JSON file not found: .*acc\.json"):
        load(str(base))

    companion = tmp_path / "acc.json"
    companion.write_text("{not json", encoding="utf-8")
    with pytest.raises(SessionFileInvalid, match="Invalid JSON file: "):
        load(str(base))
    for field in ("app_id", "app_hash"):
        data = API.TelegramDesktop().to_json()
        data[field] = None
        companion.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(SessionFileInvalid, match=f"Missing required field '{field}' in JSON"):
            load(str(base))


def test_save_session_json_writes_the_1_5_0_pair(tmp_path: pathlib.Path) -> None:
    api = API.TelegramMacOS()

    async def save() -> tuple[str, str]:
        client = TelegramClient(None, api=api)
        client.session.set_dc(2, "149.154.167.51", 443)
        client.session.auth_key = AuthKey(AUTH_KEY)
        client.UserId = 4242
        return await save_session_json(client, str(tmp_path / "out.session"))

    session_file, json_file = asyncio.run(save())
    assert session_file == str(tmp_path / "out.session")
    assert json_file == str(tmp_path / "out.json")
    assert dump(session_file, AUTH_KEY) == V150_DUMP
    expected = api.to_json({"session_file": "out", "id": 4242})
    text = pathlib.Path(json_file).read_text(encoding="utf-8")
    assert text == json.dumps(expected, ensure_ascii=False, indent=2)
    assert expected == _native.session_companion_json(
        _native.profile("TelegramMacOS"), {"session_file": "out", "id": 4242}
    )


def test_save_session_json_api_choice_and_missing_key(tmp_path: pathlib.Path) -> None:
    async def save(api: type[APIData] | APIData | None, key: bytes | None) -> dict[str, Any]:
        client = TelegramClient(None, api=API.TelegramIOS)
        client.session.set_dc(2, "149.154.167.51", 443)
        client.session.auth_key = None if key is None else AuthKey(key)
        _, json_file = await client.SaveSessionJson(str(tmp_path / "acc"), api=api)
        return json.loads(pathlib.Path(json_file).read_text(encoding="utf-8"))

    assert asyncio.run(save(None, AUTH_KEY))["app_id"] == API.TelegramIOS.api_id
    assert asyncio.run(save(API.TelegramAndroid, AUTH_KEY))["app_id"] == API.TelegramAndroid.api_id
    custom = APIData(1234, "hash", "Device", "1.0", "2.0", "en", "en", "tdesktop")
    written = asyncio.run(save(custom, AUTH_KEY))
    assert (written["app_id"], written["app_hash"], written["device"]) == (1234, "hash", "Device")
    # Without a user id the account key keeps its default.
    assert written["id"] == API.TelegramIOS().to_json()["id"]
    with pytest.raises(SessionFileInvalid, match="Session has no auth_key"):
        asyncio.run(save(None, None))


def test_from_session_json_round_trips_save_session_json(tmp_path: pathlib.Path) -> None:
    api = API.TelegramAndroidX()

    async def round_trip() -> TelegramClient:
        client = TelegramClient(None, api=api)
        client.session.set_dc(4, "149.154.167.91", 443)
        client.session.auth_key = AuthKey(AUTH_KEY)
        client.UserId = 99
        await client.SaveSessionJson(str(tmp_path / "rt"))
        return await TelegramClient.FromSessionJson(str(tmp_path / "rt"), flag=UseCurrentSession)

    loaded = asyncio.run(round_trip())
    try:
        assert loaded._api_data == api
        assert loaded.UserId == 99
        assert (loaded.session.dc_id, loaded.session.server_address) == (4, "149.154.167.91")
    finally:
        _close(loaded)
