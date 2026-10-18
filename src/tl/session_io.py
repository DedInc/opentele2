from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import typing
from typing import TYPE_CHECKING

from ..api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from ..exception import (
    Expects,
    LoginFlagInvalid,
    SessionFileInvalid,
    SessionFileNotFound,
)

if TYPE_CHECKING:
    from .telethon import TelegramClient

from telethon.sessions.sqlite import SQLiteSession

logger = logging.getLogger(__name__)


def _normalize_base_path(path: str) -> str:
    base = path
    if base.endswith(".session"):
        base = base[: -len(".session")]
    if base.endswith(".json"):
        base = base[: -len(".json")]
    return base


def _read_json(path: str) -> typing.Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: str, data: typing.Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


SESSION_VERSION = 8

_V8_SCHEMA: dict[str, tuple[str, tuple[str, ...]]] = {
    "version": (
        "version (version integer primary key)",
        ("version",),
    ),
    "sessions": (
        (
            "sessions (dc_id integer primary key, server_address text, "
            "port integer, auth_key blob, takeout_id integer, tmp_auth_key blob)"
        ),
        ("dc_id", "server_address", "port", "auth_key", "takeout_id", "tmp_auth_key"),
    ),
    "entities": (
        (
            "entities (id integer primary key, hash integer not null, "
            "username text, phone integer, name text, date integer)"
        ),
        ("id", "hash", "username", "phone", "name", "date"),
    ),
    "sent_files": (
        (
            "sent_files (md5_digest blob, file_size integer, type integer, "
            "id integer, hash integer, primary key(md5_digest, file_size, type))"
        ),
        ("md5_digest", "file_size", "type", "id", "hash"),
    ),
    "update_state": (
        (
            "update_state (id integer primary key, pts integer, qts integer, "
            "date integer, seq integer)"
        ),
        ("id", "pts", "qts", "date", "seq"),
    ),
}


def _schema_is_current(c: sqlite3.Cursor) -> bool:
    """True only when every table owned here already has the version 8 layout.

    A pre-v8 file keeps a narrower ``sessions`` table. Stamping version 8 over
    it makes Telethon skip ``_upgrade_database``, after which the six-value
    INSERT fails or the ``select *`` unpack raises ``ValueError``.
    """
    c.execute("select name from sqlite_master where type='table'")
    present = {row[0] for row in c.fetchall()}
    if not set(_V8_SCHEMA) <= present:
        return False
    for table, (_ddl, columns) in _V8_SCHEMA.items():
        c.execute(f"pragma table_info({table})")
        if tuple(row[1] for row in c.fetchall()) != columns:
            return False
    return True


def write_session_file(
    path: str,
    dc_id: int,
    server_address: str,
    port: int,
    auth_key_bytes: bytes,
) -> str:
    """Write a Telethon ``CURRENT_VERSION = 8`` session file.

    Any schema that is not already the version 8 layout is dropped and rebuilt,
    so version 8 is never stamped onto an older table set. ``takeout_id`` and
    ``tmp_auth_key`` are both written as NULL: Telethon 1.44.0 unpacks
    ``select *`` in the opposite order to its own DDL while 1.45.0 follows the
    DDL, and NULL in both columns reads back the same under either order.
    """
    full_path = path if path.endswith(".session") else path + ".session"
    conn = sqlite3.connect(full_path)
    try:
        c = conn.cursor()
        if not _schema_is_current(c):
            for table in _V8_SCHEMA:
                c.execute(f"drop table if exists {table}")
            for ddl, _columns in _V8_SCHEMA.values():
                c.execute("create table " + ddl)
        c.execute("delete from version")
        c.execute("insert into version values (?)", (SESSION_VERSION,))
        c.execute("delete from sessions")
        c.execute(
            "insert into sessions values (?, ?, ?, ?, ?, ?)",
            (dc_id, server_address, port, auth_key_bytes, None, None),
        )
        conn.commit()
    finally:
        conn.close()
    return full_path


async def from_session_json(
    session_path: str,
    json_path: str | None = None,
    flag: type[LoginFlag] = UseCurrentSession,
    password: str | None = None,
    **kwargs: object,
) -> TelegramClient:
    from .telethon import TelegramClient

    Expects(
        (flag == CreateNewSession) or (flag == UseCurrentSession),
        LoginFlagInvalid("LoginFlag invalid"),
    )

    base = _normalize_base_path(session_path)
    session_file = base + ".session"
    json_file = json_path if json_path else base + ".json"

    Expects(
        os.path.isfile(session_file),
        exception=SessionFileNotFound(f"Session file not found: {session_file}"),
    )
    Expects(
        os.path.isfile(json_file),
        exception=SessionFileNotFound(f"JSON file not found: {json_file}"),
    )

    try:
        data = await asyncio.to_thread(_read_json, json_file)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise SessionFileInvalid(f"Invalid JSON file: {e}")

    required = ["app_id", "app_hash"]
    for field in required:
        Expects(
            field in data and data[field] is not None,
            exception=SessionFileInvalid(f"Missing required field '{field}' in JSON"),
        )

    api_data = APIData.from_json(data)
    session = SQLiteSession(base)
    client = TelegramClient(session, api=api_data, **kwargs)

    if flag == UseCurrentSession:
        user_id = data.get("id")
        if user_id is not None:
            client.UserId = user_id
        return client

    try:
        await client.connect()
        return await client.QRLoginToNewClient(
            api=api_data, password=password, **kwargs
        )
    finally:
        await TelegramClient._disconnect_client(client, close_session=True)


async def save_session_json(
    client: TelegramClient,
    session_path: str,
    api: type[APIData] | APIData | None = None,
    fetch_user_info: bool = False,
) -> tuple[str, str]:
    base = _normalize_base_path(session_path)
    session_file = base + ".session"
    json_file = base + ".json"

    api_data = _resolve_api_data(api, client)

    ss = client.session
    Expects(
        ss.auth_key is not None,
        exception=SessionFileInvalid("Session has no auth_key"),
    )

    write_session_file(base, ss.dc_id, ss.server_address, ss.port, ss.auth_key.key)

    extra: dict[str, typing.Any] = {}
    extra["session_file"] = os.path.basename(base)

    if fetch_user_info and client.is_connected():
        try:
            me = await client.get_me()
            if me:
                extra["id"] = me.id
                extra["phone"] = getattr(me, "phone", None)
                extra["username"] = getattr(me, "username", None)
                extra["first_name"] = getattr(me, "first_name", "") or ""
                extra["last_name"] = getattr(me, "last_name", "") or ""
                extra["is_premium"] = bool(getattr(me, "premium", False))
        except Exception:
            # User details are optional in the JSON; the session still saves.
            logger.debug("Could not fetch user info for the JSON", exc_info=True)

    if client.UserId and "id" not in extra:
        extra["id"] = client.UserId

    json_data = api_data.to_json(extra)
    await asyncio.to_thread(_write_json, json_file, json_data)

    return (session_file, json_file)


def _resolve_api_data(
    api: type[APIData] | APIData | None,
    client: TelegramClient,
) -> APIData:
    if api is not None:
        if isinstance(api, APIData):
            return api
        if isinstance(api, type) and issubclass(api, APIData):
            return api()
    if client._api_data is not None:
        return client._api_data
    return API.TelegramDesktop()
