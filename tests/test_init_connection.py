from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from telethon import types

from src.api import API
from src.fingerprint import PLATFORM_VERSIONS, tdesktop_tz_offset
from src.tl.telethon import TelegramClient


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
def test_tz_offset_matches_prepare_init_params(
    offset: timedelta, expected: float
) -> None:
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
    client = TelegramClient(None, api=API.TelegramDesktop)

    assert client._init_request.lang_pack == "tdesktop"
    assert _params(client) == {"tz_offset": tdesktop_tz_offset()}


@pytest.mark.parametrize("api", [API.TelegramAndroid, API.TelegramIOS])
def test_other_clients_keep_telethon_params(api: type) -> None:
    client = TelegramClient(None, api=api)

    assert client._init_request.params is None


@pytest.mark.parametrize(
    ("system", "model", "suffix"),
    [
        ("windows", "B550M DS3H AC", " x64"),
        ("linux", "HP Laptop 15", ""),
        ("macos", "Mac16,1", " arm64"),
        ("macos", "MacBookPro16,1", ""),
    ],
)
def test_desktop_app_version_suffix_follows_compute_app_version(
    system: str, model: str, suffix: str
) -> None:
    from src.api import _desktop_app_version

    assert _desktop_app_version(system, model) == (
        PLATFORM_VERSIONS.desktop_app_version + suffix
    )


@pytest.mark.parametrize("system", ["windows", "macos", "linux"])
def test_generated_desktop_apis_carry_a_platform_app_version(system: str) -> None:
    api = API.TelegramDesktop.Generate(system, "opentele")

    assert api.app_version.startswith(PLATFORM_VERSIONS.desktop_app_version)
    if system != "windows":
        assert not api.app_version.endswith(" x64")
