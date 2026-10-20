"""The initConnection ``params`` and desktop app versions; clients are built
offline (MemorySession)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import telethon
from telethon import types

from opentele2.api import API, APIData
from opentele2.fingerprint import PLATFORM_VERSIONS, tdesktop_tz_offset
from opentele2.tl.telethon import TelegramClient


def offline_client(*args: Any, **kwargs: Any) -> TelegramClient:
    """A never-connected client, built on a running loop: Telethon binds the
    current loop at construction, and on 3.8 there is none outside one."""

    async def build() -> TelegramClient:
        return TelegramClient(*args, **kwargs)

    return asyncio.run(build())


def _at(offset: timedelta) -> datetime:
    return datetime(2026, 10, 18, 12, 0, tzinfo=timezone(offset))


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (timedelta(hours=5), 18000.0),
        (timedelta(hours=5, minutes=30), 19800.0),
        (timedelta(hours=5, minutes=45), 20700.0),
        (timedelta(hours=-3, minutes=-30), -12600.0),
        (timedelta(hours=14), 50400.0),
        (timedelta(hours=-12), -43200.0),
        (timedelta(0), 0.0),
        # std::round sends halves away from zero.
        (timedelta(minutes=7, seconds=30), 900.0),
        (timedelta(minutes=-7, seconds=-30), -900.0),
        (timedelta(minutes=7), 0.0),
    ],
)
def test_tz_offset_matches_prepare_init_params(offset: timedelta, expected: float) -> None:
    assert tdesktop_tz_offset(_at(offset)) == expected


def _params(client: TelegramClient) -> dict[str, float]:
    params = client._init_request.params
    assert isinstance(params, types.JsonObject)
    return {
        item.key: item.value.value
        for item in params.value
        if isinstance(item.value, types.JsonNumber)
    }


def test_a_desktop_client_sends_tz_offset_params() -> None:
    client = offline_client(None, api=API.TelegramDesktop)

    assert client._init_request.lang_pack == "tdesktop"
    assert _params(client) == {"tz_offset": tdesktop_tz_offset()}


@pytest.mark.parametrize("api", [API.TelegramAndroid, API.TelegramIOS])
def test_other_clients_keep_telethon_params(api: type[APIData]) -> None:
    client = offline_client(None, api=api)

    assert client._init_request.params is None


@pytest.mark.parametrize(
    "api",
    [
        API.TelegramDesktop,
        API.TelegramAndroid,
        API.TelegramIOS,
        API.TelegramMacOS,
        API.TelegramWeb_A,
    ],
)
def test_lang_pack_reaches_init_connection(api: type[APIData]) -> None:
    # Telethon hardcodes lang_pack to ''; opentele2 sets the profile's.
    client = offline_client(None, api=api)
    assert client._init_request.lang_pack == (api.lang_pack or "")
    assert client._init_request.device_model == api.device_model
    assert client._init_request.app_version == api.app_version


def test_connect_refreshes_params_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def offline_connect(self: telethon.TelegramClient) -> None:
        calls.append("connect")

    async def scenario() -> TelegramClient:
        client = TelegramClient(None, api=API.TelegramDesktop, auto_post_login=False)
        client._init_request.params = None
        await client.connect()
        return client

    monkeypatch.setattr(telethon.TelegramClient, "connect", offline_connect)
    client = asyncio.run(scenario())
    assert calls == ["connect"]
    assert _params(client) == {"tz_offset": tdesktop_tz_offset()}


@pytest.mark.parametrize(
    ("system", "suffix"),
    [("windows", " x64"), ("macos", " arm64"), ("linux", "")],
)
def test_generated_desktop_apis_follow_compute_app_version(system: str, suffix: str) -> None:
    expected = PLATFORM_VERSIONS.desktop_app_version + suffix

    for unique_id in (f"device-{i}" for i in range(50)):
        api = API.TelegramDesktop.Generate(system, unique_id)
        assert api.app_version == expected, api.device_model
