from __future__ import annotations

import pytest

from src.api import API, APIData
from src.devices import AndroidDevice, DeviceInfo, IOSDevice, macOSDevice

# Apple stopped patching iOS 16/17 and macOS 13/14; nothing older may be sent.
_MIN_IOS_MAJOR = 18
_MIN_MACOS_MAJOR = 15
_MAX_ANDROID_SDK = 37
# Sept 2026 Macs whose launch builds were only assumed, not verified.
_UNVERIFIED_MAC_PREFIXES = ("Mac Studio M5", "Mac mini M5", "Mac mini M6")

_SEEDS = [f"currency-{i}" for i in range(300)]


def _major(version: str) -> int:
    return int(version.removeprefix("macOS ").split(".")[0])


@pytest.fixture(scope="module")
def ios_devices() -> list[DeviceInfo]:
    IOSDevice.__gen__()
    assert IOSDevice.deviceList
    return IOSDevice.deviceList


@pytest.fixture(scope="module")
def mac_devices() -> list[DeviceInfo]:
    macOSDevice.__gen__()
    assert macOSDevice.deviceList
    return macOSDevice.deviceList


@pytest.fixture(scope="module")
def android_devices() -> list[DeviceInfo]:
    AndroidDevice.__gen__()
    assert AndroidDevice.deviceList
    return AndroidDevice.deviceList


def test_no_unknown_iphone(ios_devices: list[DeviceInfo]) -> None:
    assert not {d.model for d in ios_devices if d.model == "Unknown iPhone"}


def test_no_unsupported_ios_major(ios_devices: list[DeviceInfo]) -> None:
    old = sorted({d.version for d in ios_devices if _major(d.version) < _MIN_IOS_MAJOR})
    assert not old


def test_no_unsupported_macos_major_in_catalog(mac_devices: list[DeviceInfo]) -> None:
    old = sorted(
        {d.version for d in mac_devices if _major(d.version) < _MIN_MACOS_MAJOR}
    )
    assert not old


@pytest.mark.parametrize("seed", _SEEDS)
def test_no_unsupported_macos_major_generated(seed: str) -> None:
    tdesktop = API.TelegramDesktop.Generate("macos", seed)
    swift = API.TelegramMacOS.Generate(seed)
    assert tdesktop.system_version is not None
    assert swift.system_version is not None
    assert tdesktop.system_version.startswith("macOS ")
    assert _major(tdesktop.system_version) >= _MIN_MACOS_MAJOR, tdesktop.system_version
    assert _major(swift.system_version) >= _MIN_MACOS_MAJOR, swift.system_version


def test_no_unverified_macs(mac_devices: list[DeviceInfo]) -> None:
    bad = {d.model for d in mac_devices if d.model.startswith(_UNVERIFIED_MAC_PREFIXES)}
    assert not bad


def test_android_max_sdk_capped(android_devices: list[DeviceInfo]) -> None:
    AndroidDevice._ensure_android_data()
    assert AndroidDevice._devices
    over = [e for e in AndroidDevice._devices if e["max_sdk"] > _MAX_ANDROID_SDK]
    assert not over
    for device in android_devices:
        assert int(device.version.removeprefix("SDK ")) <= _MAX_ANDROID_SDK


@pytest.mark.parametrize("api", [API.TelegramAndroid, API.TelegramAndroidX])
def test_android_defaults_generated_by_catalog(
    api: type[APIData], android_devices: list[DeviceInfo]
) -> None:
    pairs = {(d.model, d.version) for d in android_devices}
    assert (api.device_model, api.system_version) in pairs


def test_ios_default_generated_by_catalog(ios_devices: list[DeviceInfo]) -> None:
    pairs = {(d.model, d.version) for d in ios_devices}
    api = API.TelegramIOS
    assert (api.device_model, api.system_version) in pairs


def test_macos_default_generated_by_catalog(mac_devices: list[DeviceInfo]) -> None:
    pairs = {(d.model, d.version) for d in mac_devices}
    api = API.TelegramMacOS
    assert (api.device_model, api.system_version) in pairs
