from __future__ import annotations

import os
import sqlite3
import time
from typing import TYPE_CHECKING

from ..api import APIData
from ..exception import Expects, SessionFileInvalid, SessionFileNotFound
from .configs import PYRO_SCHEMA_VERSION

if TYPE_CHECKING:
    from ..tl.telethon import TelegramClient


def _normalize_path(path: str) -> str:
    """Strip .session suffix if present."""
    return path[: -len(".session")] if path.endswith(".session") else path

def write_pyrogram_session(
    path: str,
    dc_id: int,
    auth_key: bytes,
    api_id: int,
    user_id: int | None = None,
    is_bot: bool = False,
    test_mode: bool = False,
) -> str:
    """
    Create (or overwrite) a Pyrogram SQLite session file.

    Returns the full path written (always ends with .session).
    """
    full_path = path if path.endswith(".session") else path + ".session"

    conn = sqlite3.connect(full_path)
    c = conn.cursor()

    c.execute("CREATE TABLE IF NOT EXISTS version (number INTEGER PRIMARY KEY)")
    c.execute("DELETE FROM version")
    c.execute("INSERT INTO version VALUES (?)", (PYRO_SCHEMA_VERSION,))

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            dc_id     INTEGER PRIMARY KEY,
            api_id    INTEGER,
            test_mode INTEGER,
            auth_key  BLOB,
            date      INTEGER NOT NULL,
            user_id   INTEGER,
            is_bot    INTEGER
        )
        """
    )
    c.execute("DELETE FROM sessions")
    c.execute(
        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            dc_id,
            api_id,
            int(test_mode),
            auth_key,
            int(time.time()),
            user_id,
            int(is_bot),
        ),
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS peers (
            id             INTEGER PRIMARY KEY,
            access_hash    INTEGER,
            type           INTEGER NOT NULL,
            username       TEXT,
            phone_number   TEXT,
            last_update_on INTEGER NOT NULL DEFAULT (CAST(STRFTIME('%s', 'now') AS INTEGER))
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_peers_id ON peers (id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_peers_username ON peers (username)")
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_peers_phone_number ON peers (phone_number)"
    )

    conn.commit()
    conn.close()
    return full_path

def read_pyrogram_session(path: str) -> dict:
    """
    Read dc_id, api_id, auth_key, user_id, is_bot, test_mode from a Pyrogram
    .session file.  Returns a plain dict.

    Raises SessionFileNotFound / SessionFileInvalid on bad input.
    """
    full_path = path if path.endswith(".session") else path + ".session"

    Expects(
        os.path.isfile(full_path),
        exception=SessionFileNotFound(f"Pyrogram session not found: {full_path}"),
    )

    conn = sqlite3.connect(full_path)
    try:
        c = conn.cursor()
        try:
            c.execute(
                "SELECT dc_id, api_id, test_mode, auth_key, user_id, is_bot "
                "FROM sessions LIMIT 1"
            )
        except sqlite3.OperationalError as e:
            raise SessionFileInvalid(
                f"Not a valid Pyrogram session (missing sessions table): {e}"
            ) from e

        row = c.fetchone()
        Expects(
            row is not None,
            exception=SessionFileInvalid("Pyrogram sessions table is empty"),
        )

        dc_id, api_id, test_mode, auth_key, user_id, is_bot = row

        _auth_key_len = len(auth_key) if isinstance(auth_key, (bytes, bytearray)) else 0
        Expects(
            isinstance(auth_key, (bytes, bytearray)) and len(auth_key) == 256,
            exception=SessionFileInvalid(
                f"auth_key has unexpected length {_auth_key_len}, "
                "expected 256 bytes"
            ),
        )

        return {
            "dc_id": dc_id,
            "api_id": api_id,
            "test_mode": bool(test_mode),
            "auth_key": bytes(auth_key),
            "user_id": user_id,
            "is_bot": bool(is_bot),
        }
    finally:
        conn.close()

async def save_pyrogram_session(
    client: TelegramClient,
    session_path: str,
    api: type[APIData] | APIData | None = None,
    fetch_user_info: bool = False,
) -> str:
    """
    Export the authenticated Telethon client as a Pyrogram .session file.

    Returns the full path of the written file.
    """
    from ..tl.session_io import _resolve_api_data

    ss = client.session
    Expects(
        ss.auth_key is not None,
        exception=SessionFileInvalid("Telethon session has no auth_key"),
    )

    api_data = _resolve_api_data(api, client)

    user_id: int | None = None
    is_bot: bool = False
    if fetch_user_info and client.is_connected():
        try:
            me = await client.get_me()
            if me:
                user_id = me.id
                is_bot = bool(getattr(me, "is_bot", False))
        except Exception:
            pass

    if user_id is None and client.UserId:
        user_id = client.UserId

    return write_pyrogram_session(
        _normalize_path(session_path),
        dc_id=ss.dc_id,
        auth_key=ss.auth_key.key,
        api_id=api_data.api_id,
        user_id=user_id,
        is_bot=is_bot,
    )

async def from_pyrogram_session(
    session_path: str,
    api: type[APIData] | APIData | None = None,
    output_session: str | None = None,
    **kwargs: object,
) -> TelegramClient:
    """
    Load a Pyrogram .session file and return an authenticated TelegramClient.

    Parameters
    ----------
    session_path:
        Path to the Pyrogram .session file (with or without the extension).
    api:
        API preset to use.  Defaults to ``API.TelegramAndroid`` when the
        Pyrogram session was created with api_id=6, otherwise a plain
        ``APIData(api_id, api_hash)`` with only api_id filled in.
        Pass an explicit ``APIData`` instance to override api_hash.
    output_session:
        Path for the resulting Telethon .session file.  If *None*, an
        in-memory session is used.
    **kwargs:
        Forwarded to ``TelegramClient.__init__``.
    """
    from .client import _resolve_api_from_id, _build_telethon_session

    data = read_pyrogram_session(session_path)
    api_data = _resolve_api_from_id(data.get("api_id"), api)
    client = _build_telethon_session(data, api_data, output_session, **kwargs)
    return client
