"""Tests of opentele2.devices, ported from the 1.5.0 tests
test_{android,ios,mac,desktop,web}_devices.py and
test_device_catalog_currency.py.

1.5.0 inspected its catalogs through ``deviceList`` and ``__gen__``; the
catalogs now live in the core, so the same properties are asserted on the
devices ``RandomDevice`` picks for a fixed set of seeds, and every device of
crates/opentele2-core/tests/vectors/devices.json is checked byte for byte.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from opentele2 import _native, devices
from opentele2._compat import BaseObject
from opentele2.api import API, APIData
from opentele2.devices import (
    AndroidDevice,
    DeviceInfo,
    IOSDevice,
    LinuxDevice,
    SystemInfo,
    WebBrowserDevice,
    WindowsDevice,
    iOSDevice,
    macOSDevice,
)

VECTORS = Path(__file__).resolve().parents[3] / "crates" / "opentele2-core" / "tests" / "vectors"
SEEDS = [f"device-{n}" for n in range(300)]

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
_MAC_MODEL = re.compile(
    r"^(MacBook Pro|MacBook Air|MacBook Neo|Mac mini|iMac|Mac Studio|Mac Pro)"
    r" (M\d+( Pro| Max| Ultra)?|A\d+ Pro)$"
)
_TDESKTOP_VERSION = re.compile(r"^macOS \d+\.\d+(\.[1-9]\d*)?$")
_SWIFT_VERSION = re.compile(r"^\d+\.\d+(\.[1-9]\d*)?$")
_WINDOWS_VERSIONS = {"Windows 11 x64", "Windows 11 arm64", "Windows 10 x64", "Windows 10"}
_LINUX_VERSION = re.compile(r"^Linux( \S+)+ (Wayland|Xwayland|X11) glibc 2\.\d+$")
_GLIBC_TAIL = re.compile(r" glibc 2\.\d+$")
_KERNEL = re.compile(r"\d+\.\d+")
_DISTRO_NAMES = (
    "Ubuntu",
    "Mint",
    "Fedora",
    "Debian",
    "Arch",
    "Manjaro",
    "Pop!_OS",
    "openSUSE",
    "Zorin OS",
    "EndeavourOS",
    "elementary OS",
    "KDE neon",
    "NixOS",
)
_UNVERIFIED_MAC_PREFIXES = ("Mac Studio M5", "Mac mini M5", "Mac mini M6")


def sample(pick: Any) -> list[DeviceInfo]:
    return [pick(seed) for seed in SEEDS]


def major(version: str) -> int:
    return int(version.replace("macOS ", "", 1).split(".")[0])


def sdk(device: DeviceInfo) -> int:
    assert device.version.startswith("SDK ")
    return int(device.version[len("SDK ") :])


def test_public_names_and_hierarchy() -> None:
    assert devices.__all__ == [
        "AndroidDevice",
        "DeviceInfo",
        "IOSDevice",
        "LinuxDevice",
        "SystemInfo",
        "WebBrowserDevice",
        "WindowsDevice",
        "iOSDevice",
        "macOSDevice",
    ]
    assert iOSDevice is IOSDevice
    assert issubclass(SystemInfo, BaseObject)
    for cls in (WindowsDevice, LinuxDevice, macOSDevice):
        assert issubclass(cls, devices.GeneralDesktopDevice)
    for cls in (AndroidDevice, IOSDevice, WebBrowserDevice):
        assert cls.__bases__ == (SystemInfo,)
    device = DeviceInfo("Model X", "1.0")
    assert (device.model, device.version, str(device)) == ("Model X", "1.0", "Model X 1.0")
    with pytest.raises(NotImplementedError, match="SystemInfo device not supported"):
        SystemInfo.RandomDevice("seed")
    with pytest.raises(NotImplementedError, match="GeneralDesktopDevice device"):
        devices.GeneralDesktopDevice.RandomDevice("seed")


def test_vector_devices_are_byte_identical() -> None:
    with (VECTORS / "devices.json").open(encoding="utf-8") as handle:
        cases = json.load(handle)["cases"]
    pickers = {
        ("TelegramDesktop", "windows"): WindowsDevice.RandomDevice,
        ("TelegramDesktop", "linux"): LinuxDevice.RandomDevice,
        ("TelegramDesktop", "macos"): macOSDevice.RandomDevice,
        ("TelegramAndroid", None): AndroidDevice.RandomDevice,
        ("TelegramAndroidX", None): AndroidDevice.RandomDevice,
        ("TelegramIOS", None): IOSDevice.RandomDevice,
        ("TelegramMacOS", None): lambda seed: macOSDevice.RandomDevice(seed, variant="swift"),
    }
    checked = 0
    for case in cases:
        pick = pickers.get((case["entry_point"], case["system"]))
        if pick is None:
            continue
        device = pick(case["seed"])
        label = f"{case['entry_point']} {case['system']} {case['seed']!r}"
        assert device.model.encode() == case["device_model"].encode(), label
        assert device.version.encode() == case["system_version"].encode(), label
        checked += 1
    assert checked == 2450


def test_random_device_is_deterministic_and_takes_str_of_other_seeds() -> None:
    # 1.5.0 hashed str(unique_id) for any unique_id that is not a str.
    int_seed: Any = 1234
    float_seed: Any = 1.5
    for pick in (
        WindowsDevice.RandomDevice,
        LinuxDevice.RandomDevice,
        macOSDevice.RandomDevice,
        AndroidDevice.RandomDevice,
        IOSDevice.RandomDevice,
        WebBrowserDevice.RandomDevice,
    ):
        first, second = pick("determinism"), pick("determinism")
        assert (first.model, first.version) == (second.model, second.version)
        by_int, by_str = pick(int_seed), pick("1234")
        assert (by_int.model, by_int.version) == (by_str.model, by_str.version)
        by_float, by_text = pick(float_seed), pick("1.5")
        assert (by_float.model, by_float.version) == (by_text.model, by_text.version)
        assert isinstance(pick(None), DeviceInfo)


# ---------------------------------------------------------------- android


def test_android_models_are_build_manufacturer_and_model() -> None:
    found = sample(AndroidDevice.RandomDevice)
    prefixes = tuple(f"{name.lower()} " for name in EXPECTED_MANUFACTURERS)
    for device in found:
        assert device.model.startswith(tuple(EXPECTED_MANUFACTURERS)), device.model
        assert not device.model.lower().startswith(prefixes), device.model


def test_android_sdks_are_within_the_validation_range() -> None:
    versions = _native.platform_versions()
    assert versions["android_sdk_range"] == (29, 37)
    assert versions["android_latest_sdk"] == 37
    sdks = {sdk(device) for device in sample(AndroidDevice.RandomDevice)}
    assert {36, 37} <= sdks
    assert min(sdks) >= 29
    assert max(sdks) <= 37


@pytest.mark.parametrize("api", [API.TelegramAndroid, API.TelegramAndroidX])
def test_android_default_device(api: type[APIData]) -> None:
    assert api.device_model == "samsungSM-S938B"
    assert api.system_version == "SDK 36"


# ---------------------------------------------------------------- iOS


def test_ios_versions_are_released_and_supported() -> None:
    found = sample(IOSDevice.RandomDevice)
    assert len({(device.model, device.version) for device in found}) > 100
    majors = {major(device.version) for device in found}
    assert not majors & set(range(19, 26))
    assert min(majors) >= 18
    assert "Unknown iPhone" not in {device.model for device in found}
    for device in found:
        if device.model == "iPhone XS":
            assert major(device.version) == 18
        if device.version == "18.7.10":
            assert device.model in {"iPhone XS", "iPhone XS Max", "iPhone XR"}


def test_ios_default_device() -> None:
    assert API.TelegramIOS.device_model == "iPhone 17 Pro"
    assert API.TelegramIOS.system_version == _native.platform_versions()["ios_system_version"]


# ---------------------------------------------------------------- macOS


def test_mac_variants_draw_the_same_machine() -> None:
    for seed in SEEDS:
        tdesktop = macOSDevice.RandomDevice(seed)
        swift = macOSDevice.RandomDevice(seed, variant="swift")
        assert _MAC_MODEL.match(tdesktop.model), tdesktop.model
        assert _TDESKTOP_VERSION.match(tdesktop.version), tdesktop.version
        assert _SWIFT_VERSION.match(swift.version), swift.version
        assert swift.model == tdesktop.model
        assert tdesktop.version == f"macOS {swift.version}"
        assert major(swift.version) >= 15, swift.version
        assert not tdesktop.model.startswith(_UNVERIFIED_MAC_PREFIXES)


def test_macos_default_device() -> None:
    assert _native.platform_versions()["macos_system_version"] == "27.0.1"
    assert API.TelegramMacOS.device_model == "MacBook Air M4"
    assert API.TelegramMacOS.system_version == "27.0.1"


# ---------------------------------------------------------------- desktop


def _model_fits_device_model_pretty(model: str) -> bool:
    # DeviceModelPretty drops a model over 15 characters unless it is an HP one.
    return len(model) <= 15 or model.startswith("HP ")


def test_windows_devices_match_lib_base() -> None:
    found = sample(WindowsDevice.RandomDevice)
    versions = {device.version for device in found}
    assert versions
    assert versions <= _WINDOWS_VERSIONS, sorted(versions - _WINDOWS_VERSIONS)
    assert all(_model_fits_device_model_pretty(device.model) for device in found)


def test_linux_devices_match_lib_base() -> None:
    found = sample(LinuxDevice.RandomDevice)
    for device in found:
        assert _LINUX_VERSION.match(device.version), device.version
        assert not _KERNEL.search(_GLIBC_TAIL.sub("", device.version)), device.version
        assert not [name for name in _DISTRO_NAMES if name in device.version], device.version
        assert _model_fits_device_model_pretty(device.model), device.model


def test_default_desktop_system_version_is_windows_11_x64() -> None:
    assert API.TelegramDesktop.system_version == "Windows 11 x64"


# ---------------------------------------------------------------- web


def test_web_variants_share_the_user_agent() -> None:
    platforms = {"Windows": "Win32", "macOS": "MacIntel", "Linux": "Linux x86_64"}
    for seed in SEEDS:
        z = WebBrowserDevice.RandomDevice(seed)
        k = WebBrowserDevice.RandomDevice(seed, variant="k")
        assert z.model == k.model
        assert z.model.startswith("Mozilla/5.0 (")
        assert platforms[z.version] == k.version, z.model


def test_web_catalog_spans_several_browsers() -> None:
    agents = {device.model for device in sample(WebBrowserDevice.RandomDevice)}
    assert len(agents) > 1
    assert any("Firefox/" in agent for agent in agents)
    assert any("Edg/" in agent for agent in agents)
    assert any("Chrome/" in agent and "Edg/" not in agent for agent in agents)
    for agent in agents:
        if "Firefox/" in agent:
            rv = re.search(r"rv:(\d+)", agent)
            product = re.search(r"Firefox/(\d+)", agent)
            assert rv, agent
            assert product, agent
            assert rv.group(1) == product.group(1), agent


def _digest(lines: list[str]) -> str:
    return hashlib.sha256("".join(lines).encode()).hexdigest()[:16]


# 1.5.0 after cls.__gen__(): len and the digest above of deviceList (one
# "model\tversion\n" per entry), device_models ("\n"-joined) and
# system_versions ("\n"-joined).
CATALOG_ATTRIBUTES: list[tuple[type[SystemInfo], int, str, int, str, int, str]] = [
    (WindowsDevice, 3050, "91c2da4d084fa446", 116, "14a54035d03301e2", 2, "2ba2f90b5dd04ff1"),
    (LinuxDevice, 21045, "69af1ab21f27a801", 116, "14a54035d03301e2", 34, "7d7fe6c3a69aff93"),
    (macOSDevice, 19680, "aa968dc54ea0f982", 36, "6ca7a048d212ffd7", 42, "e3c26e2503f5f986"),
    (AndroidDevice, 31148, "4ac8cda518351b10", 0, "e3b0c44298fc1c14", 0, "e3b0c44298fc1c14"),
    (IOSDevice, 18115, "b0e515f3b0880335", 33, "cd8307af8a812531", 46, "6d91cbe1558dc05a"),
]


@pytest.mark.parametrize(
    (
        "cls",
        "devices_len",
        "devices_digest",
        "models_len",
        "models_digest",
        "versions_len",
        "versions_digest",
    ),
    CATALOG_ATTRIBUTES,
)
def test_catalog_class_attributes_match_1_5_0(
    cls: type[SystemInfo],
    devices_len: int,
    devices_digest: str,
    models_len: int,
    models_digest: str,
    versions_len: int,
    versions_digest: str,
) -> None:
    device_list = cls.deviceList
    assert all(isinstance(device, DeviceInfo) for device in device_list)
    assert len(device_list) == devices_len
    assert _digest([f"{d.model}\t{d.version}\n" for d in device_list]) == devices_digest
    assert len(cls.device_models) == models_len
    assert _digest(["\n".join(cls.device_models)]) == models_digest
    assert len(cls.system_versions) == versions_len
    assert _digest(["\n".join(cls.system_versions)]) == versions_digest


def test_catalog_class_attributes_are_read_only_copies() -> None:
    assert (SystemInfo.deviceList, SystemInfo.device_models, SystemInfo.system_versions) == (
        [],
        [],
        [],
    )
    # 1.5.0 src/devices.py WebBrowserDevice.BROWSER_WEIGHTS.
    assert WebBrowserDevice.BROWSER_WEIGHTS == {"chrome": 19, "edge": 2, "firefox": 1}
    assert WebBrowserDevice.deviceList, "the Web A browsers"
    picked = WindowsDevice.RandomDevice("seed").model
    edited = WindowsDevice.deviceList
    edited.clear()
    WindowsDevice.device_models.append("edited")
    WebBrowserDevice.BROWSER_WEIGHTS["chrome"] = 0
    assert len(WindowsDevice.deviceList) == 3050
    assert "edited" not in WindowsDevice.device_models
    assert WebBrowserDevice.BROWSER_WEIGHTS["chrome"] == 19
    assert WindowsDevice.RandomDevice("seed").model == picked
    with pytest.raises(AttributeError, match="read-only"):
        WindowsDevice().deviceList = []
