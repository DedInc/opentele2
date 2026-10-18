"""Keyword arguments opentele2 forwards to ``telethon.TelegramClient``.

One definition serves every entry point that builds a client
(``TelegramClient()``, ``FromTDesktop``, ``ToTelethon``, ``QRLoginToNewClient``)
through ``**kwargs: Unpack[...]``, so type checkers and IDEs see the same
parameters Telethon accepts.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from telethon.network.connection.connection import Connection

    from ..fingerprint import FingerprintConfig

__all__ = ["ClientKwargs", "TelethonClientKwargs"]


class TelethonClientKwargs(TypedDict, total=False):
    connection: type[Connection]
    use_ipv6: bool
    proxy: tuple | dict | None
    local_addr: str | tuple | None
    timeout: int
    request_retries: int
    connection_retries: int
    retry_delay: int
    auto_reconnect: bool
    sequential_updates: bool
    flood_sleep_threshold: int
    raise_last_call_error: bool
    loop: asyncio.AbstractEventLoop | None
    base_logger: str | logging.Logger | None
    receive_updates: bool


class ClientKwargs(TelethonClientKwargs, total=False):
    """Everything ``TelegramClient.__init__`` accepts by keyword."""

    device_model: str | None
    system_version: str | None
    app_version: str | None
    lang_code: str
    system_lang_code: str
    fingerprint_config: FingerprintConfig | None
    auto_post_login: bool
