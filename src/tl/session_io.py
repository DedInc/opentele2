"""Session file I/O utilities for opentele2.

Handles reading and writing .session (SQLite) + .json metadata files.
These are standalone functions that the TelegramClient delegates to.
"""

from __future__ import annotations

import json
import os
import sqlite3
import typing
from typing import TYPE_CHECKING, Type, Union

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


def _normalize_base_path(path: str) -> str:
    base = path
    if base.endswith(".session"):
        base = base[: -len(".session")]
    if base.endswith(".json"):
        base = base[: -len(".json")]
    return base


def write_session_file(
    path: str,
    dc_id: int,
    server_address: str,
    port: int,
    auth_key_bytes: bytes,
) -> str:
    """Write a standalone .session SQLite file.

    Args:
        path: File path without .session extension.
        dc_id: Data center ID.
        server_address: DC IP address.
        port: DC port.
        auth_key_bytes: 256-byte auth key.

    Returns:
        Full path to the created .session file.
    """
    full_path = path if path.endswith(".session") else path + ".session"
    conn = sqlite3.connect(full_path)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS version (version integer primary key)")
    c.execute("DELETE FROM version")
    c.execute("INSERT INTO version VALUES (7)")
    c.execute(
        "CREATE TABLE IF NOT EXISTS sessions ("
        "dc_id integer primary key, server_address text, "
        "port integer, auth_key blob, takeout_id integer)"
    )
    c.execute("DELETE FROM sessions")
    c.execute(
        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
        (dc_id, server_address, port, auth_key_bytes, None),
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS entities ("
        "id integer primary key, hash integer not null, "
        "username text, phone integer, name text, date integer)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS sent_files ("
        "md5_digest blob, file_size integer, type integer, "
        "id integer, hash integer, "
        "primary key(md5_digest, file_size, type))"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS update_state ("
        "id integer primary key, pts integer, qts integer, "
        "date integer, seq integer)"
    )
    conn.commit()
    conn.close()
    return full_path


async def from_session_json(
    session_path: str,
    json_path: str = None,
    flag: Type[LoginFlag] = UseCurrentSession,
    password: str = None,
    **kwargs,
) -> TelegramClient:
    """Create a TelegramClient from .session + .json files.

    Args:
        session_path: Path to the .session file (with or without extension).
        json_path: Path to the .json metadata file. If None, derived from
                   session_path by replacing .session with .json.
        flag: UseCurrentSession (default) or CreateNewSession.
        password: 2FA password if CreateNewSession is used.
        **kwargs: Additional arguments passed to the TelegramClient constructor.

    Returns:
        A TelegramClient with the session loaded and API configured.

    Raises:
        SessionFileNotFound: If .session or .json file doesn't exist.
        SessionFileInvalid: If the JSON is malformed or missing required fields.
    """
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
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
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

    await client.connect()
    return await client.QRLoginToNewClient(api=api_data, password=password, **kwargs)


async def save_session_json(
    client: TelegramClient,
    session_path: str,
    api: Union[Type[APIData], APIData] = None,
    fetch_user_info: bool = False,
) -> typing.Tuple[str, str]:
    """Save a client's session to .session + .json files.

    Args:
        client: The TelegramClient whose session to save.
        session_path: Output path (with or without .session extension).
        api: APIData to write to JSON. If None, uses the API from
             when the client was created.
        fetch_user_info: If True and client is connected, fetch user info
                        (phone, username, is_premium, etc.) from the server.

    Returns:
        Tuple of (session_file_path, json_file_path).

    Raises:
        SessionFileInvalid: If the session has no auth_key.
    """
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

    extra = {}
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
            pass

    if client.UserId and "id" not in extra:
        extra["id"] = client.UserId

    json_data = api_data.to_json(extra)
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    return (session_file, json_file)


def _resolve_api_data(
    api: Union[Type[APIData], APIData, None],
    client: TelegramClient,
) -> APIData:
    if api is not None:
        if isinstance(api, APIData):
            return api
        if isinstance(api, type) and APIData.__subclasscheck__(api):
            return api()
    if client._api_data is not None:
        return client._api_data
    return API.TelegramDesktop()
