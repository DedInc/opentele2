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
    """The keyword parameters of ``telethon.TelegramClient.__init__``.

    Names and types are the ones Telethon declares, so ``**kwargs`` of this
    type forwards to Telethon as is.
    """

    connection: type[Connection]
    use_ipv6: bool
    proxy: tuple | dict
    local_addr: str | tuple
    timeout: int
    request_retries: int
    connection_retries: int
    retry_delay: int
    auto_reconnect: bool
    sequential_updates: bool
    flood_sleep_threshold: int
    raise_last_call_error: bool
    device_model: str
    system_version: str
    app_version: str
    lang_code: str
    system_lang_code: str
    loop: asyncio.AbstractEventLoop
    base_logger: str | logging.Logger
    receive_updates: bool
    catch_up: bool
    entity_cache_limit: int


class ClientKwargs(TelethonClientKwargs, total=False):
    """Everything ``TelegramClient.__init__`` accepts by keyword."""

    fingerprint_config: FingerprintConfig | None
    auto_post_login: bool
