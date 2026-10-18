from __future__ import annotations

from typing import Any

import pytest

from src.api import API, APIData
from src.devices import AndroidDevice, DeviceInfo
from src.fingerprint import PLATFORM_VERSIONS

EXPECTED_MANUFACTURERS = {
    "samsung",
    "vivo",
    "realme",
    "OPPO",
    "OnePlus",
    "Xiaomi",
    "HONOR",
    "motorola",
    "Sony",
    "Google",
    "asus",
    "Nothing",
}


@pytest.fixture(scope="module")
def catalog() -> list[dict[str, Any]]:
    AndroidDevice._ensure_android_data()
    assert AndroidDevice._devices
    return AndroidDevice._devices


@pytest.fixture(scope="module")
def devices() -> list[DeviceInfo]:
    AndroidDevice.__gen__()
    assert AndroidDevice.deviceList
    return AndroidDevice.deviceList


def _sdk(device: DeviceInfo) -> int:
    assert device.version.startswith("SDK ")
    return int(device.version.removeprefix("SDK "))


def _versions_by_model(devices: list[DeviceInfo]) -> dict[str, set[int]]:
    by_model: dict[str, set[int]] = {}
    for device in devices:
        by_model.setdefault(device.model, set()).add(_sdk(device))
    return by_model


def test_model_is_manufacturer_concatenated_with_build_model(
    catalog: list[dict[str, Any]], devices: list[DeviceInfo]
) -> None:
    models = {device.model for device in devices}
    for entry in catalog:
        assert entry["manufacturer"] + entry["model"] in models


def test_manufacturer_never_followed_by_space(
    catalog: list[dict[str, Any]], devices: list[DeviceInfo]
) -> None:
    prefixes = tuple(
        f"{manufacturer.lower()} "
        for manufacturer in {entry["manufacturer"] for entry in catalog}
    )
    for device in devices:
        assert not device.model.lower().startswith(prefixes), device.model


def test_manufacturers_are_telegram_build_manufacturers(
    catalog: list[dict[str, Any]],
) -> None:
    manufacturers = {entry["manufacturer"] for entry in catalog}
    assert manufacturers <= EXPECTED_MANUFACTURERS


def test_sdk_36_and_37_are_emitted(devices: list[DeviceInfo]) -> None:
    sdks = {_sdk(device) for device in devices}
    assert 36 in sdks
    assert 37 in sdks


def test_sdk_32_only_for_entries_that_reported_it(
    catalog: list[dict[str, Any]], devices: list[DeviceInfo]
) -> None:
    by_model = _versions_by_model(devices)
    for entry in catalog:
        sdks = by_model[entry["manufacturer"] + entry["model"]]
        reported_12l = entry.get("sdk_32") is True or entry["min_sdk"] == 32
        in_range = entry["min_sdk"] <= 32 <= entry["max_sdk"]
        assert (32 in sdks) == (reported_12l and in_range), entry


def test_every_entry_yields_a_device(
    catalog: list[dict[str, Any]], devices: list[DeviceInfo]
) -> None:
    by_model = _versions_by_model(devices)
    for entry in catalog:
        assert by_model.get(entry["manufacturer"] + entry["model"]), entry


def test_catalog_sdk_bounds(catalog: list[dict[str, Any]]) -> None:
    for entry in catalog:
        assert 29 <= entry["min_sdk"] <= entry["max_sdk"] <= 37, entry


def test_emitted_sdks_are_within_validation_range(
    devices: list[DeviceInfo],
) -> None:
    lo, hi = PLATFORM_VERSIONS.android_sdk_range
    assert (lo, hi) == (29, 37)
    assert PLATFORM_VERSIONS.android_latest_sdk == 37
    for device in devices:
        assert lo <= _sdk(device) <= hi


def test_random_device_is_deterministic() -> None:
    first = AndroidDevice.RandomDevice("android-determinism")
    second = AndroidDevice.RandomDevice("android-determinism")
    assert (first.model, first.version) == (second.model, second.version)


@pytest.mark.parametrize("api", [API.TelegramAndroid, API.TelegramAndroidX])
def test_default_api_device_is_in_catalog(
    api: type[APIData], devices: list[DeviceInfo]
) -> None:
    assert api.device_model == "samsungSM-S938B"
    assert api.system_version == "SDK 36"
    assert (api.device_model, api.system_version) in {
        (device.model, device.version) for device in devices
    }
