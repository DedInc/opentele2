from __future__ import annotations

import base64
import struct

from ..exception import Expects, SessionFileInvalid
from .configs import (
    SESSION_STRING_FORMAT,
    SESSION_STRING_FORMAT_OLD,
    SESSION_STRING_SIZE,
    SESSION_STRING_SIZE_OLD,
)


def encode_session_string(
    dc_id: int,
    api_id: int,
    auth_key: bytes,
    user_id: int = 0,
    is_bot: bool = False,
    test_mode: bool = False,
) -> str:
    """Pack session data into a Pyrogram session string.

    Returns
    -------
    str
        URL-safe base64 string (no ``=`` padding).
    """
    Expects(
        isinstance(auth_key, (bytes, bytearray)) and len(auth_key) == 256,
        exception=SessionFileInvalid(
            f"auth_key must be exactly 256 bytes, got {len(auth_key) if auth_key else 0}"
        ),
    )

    packed = struct.pack(
        SESSION_STRING_FORMAT,
        dc_id,
        api_id,
        test_mode,
        auth_key,
        user_id or 0,
        is_bot,
    )
    return base64.urlsafe_b64encode(packed).decode().rstrip("=")


def decode_session_string(session_string: str) -> dict:
    """Unpack a Pyrogram session string into its components.

    Parameters
    ----------
    session_string:
        The base64 session string (with or without ``=`` padding).

    Returns
    -------
    dict
        Keys: ``dc_id``, ``api_id``, ``test_mode``, ``auth_key``,
        ``user_id``, ``is_bot``.

    Raises
    ------
    SessionFileInvalid
        If the string cannot be decoded or has an unexpected size.
    """
    # restore padding
    padded = session_string + "=" * (-len(session_string) % 4)

    try:
        data = base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise SessionFileInvalid(f"Invalid session string (base64 error): {e}") from e

    if len(data) == SESSION_STRING_SIZE:
        dc_id, api_id, test_mode, auth_key, user_id, is_bot = struct.unpack(
            SESSION_STRING_FORMAT, data
        )
    elif len(data) == SESSION_STRING_SIZE_OLD:
        # Legacy Pyrogram < 2.0 format (user_id is uint32)
        dc_id, api_id, test_mode, auth_key, user_id, is_bot = struct.unpack(
            SESSION_STRING_FORMAT_OLD, data
        )
    else:
        raise SessionFileInvalid(
            f"Session string has unexpected size {len(data)} bytes "
            f"(expected {SESSION_STRING_SIZE} or {SESSION_STRING_SIZE_OLD})"
        )

    return {
        "dc_id": dc_id,
        "api_id": api_id,
        "test_mode": bool(test_mode),
        "auth_key": bytes(auth_key),
        "user_id": user_id,
        "is_bot": bool(is_bot),
    }
