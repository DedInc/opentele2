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
    ("system", "suffix"),
    [("windows", " x64"), ("macos", " arm64"), ("linux", "")],
)
def test_generated_desktop_apis_follow_compute_app_version(
    system: str, suffix: str
) -> None:
    expected = PLATFORM_VERSIONS.desktop_app_version + suffix

    for unique_id in (f"device-{i}" for i in range(50)):
        api = API.TelegramDesktop.Generate(system, unique_id)
        assert api.app_version == expected, api.device_model


def test_the_mac_device_database_is_apple_silicon_only() -> None:
    # The " arm64" suffix relies on this; an Intel Mac sends no suffix.
    import json
    import pathlib
    import re

    import src

    models = json.loads(
        (pathlib.Path(src.__file__).parent / "devices" / "mac.json").read_text()
    )["models"]
    intel = re.compile(
        r"^(MacBookPro([1-9]|1[0-6])|MacBookAir[1-9]|MacBook\d|Macmini[1-8]"
        r"|iMac([1-9]|1\d|20)|iMacPro\d|MacPro[1-7]),"
    )
    assert not [m["model"] for m in models if intel.match(m["model"])]
