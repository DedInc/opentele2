from __future__ import annotations

import json
import pathlib
import re
from collections import Counter

import pytest

import src
from src.api import API
from src.devices import LinuxDevice, SystemInfo, WindowsDevice

# lib_base SystemVersionPretty on Windows: the product name plus " x64" on
# AMD64; never a feature update or a build number.
_WINDOWS_VERSIONS = {
    "Windows 11 x64",
    "Windows 11 arm64",
    "Windows 10 x64",
    "Windows 10",
}

# lib_base on Linux: "Linux", the XDG_CURRENT_DESKTOP items, the display
# server and gnu_get_libc_version().
_LINUX_VERSION = re.compile(r"^Linux( \S+)+ (Wayland|Xwayland|X11) glibc 2\.\d+$")
_GLIBC_TAIL = re.compile(r" glibc 2\.\d+$")
_KERNEL = re.compile(r"\d+\.\d+")
# Distribution names as /etc/os-release spells them. The lowercase "ubuntu",
# "pop" and "zorin" are XDG_CURRENT_DESKTOP items, which lib_base does send.
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

_UNIQUE_IDS = [f"desktop-{i}" for i in range(200)]


def _catalog() -> dict:
    path = pathlib.Path(src.__file__).parent / "devices" / "desktop.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _model_ok(model: str) -> bool:
    # DeviceModelPretty drops a model over 15 characters unless it is an HP one.
    return len(model) <= 15 or model.startswith("HP ")


def test_windows_versions_match_lib_base() -> None:
    WindowsDevice.__gen__()
    versions = {d.version for d in WindowsDevice.deviceList}

    assert versions
    assert versions <= _WINDOWS_VERSIONS, sorted(versions - _WINDOWS_VERSIONS)


def test_linux_versions_match_lib_base() -> None:
    LinuxDevice.__gen__()
    versions = {d.version for d in LinuxDevice.deviceList}

    assert versions
    for version in sorted(versions):
        assert _LINUX_VERSION.match(version), version
        head = _GLIBC_TAIL.sub("", version)
        assert not _KERNEL.search(head), version
        assert not [n for n in _DISTRO_NAMES if n in version], version


@pytest.mark.parametrize("device", [WindowsDevice, LinuxDevice])
def test_generated_models_fit_device_model_pretty(device: type[SystemInfo]) -> None:
    device.__gen__()
    models = {d.model for d in device.deviceList}

    assert models
    assert not [m for m in sorted(models) if not _model_ok(m)]


@pytest.mark.parametrize("system", ["windows", "linux"])
def test_generate_is_deterministic_per_unique_id(system: str) -> None:
    for unique_id in _UNIQUE_IDS:
        first = API.TelegramDesktop.Generate(system, unique_id)
        second = API.TelegramDesktop.Generate(system, unique_id)

        assert (first.device_model, first.system_version) == (
            second.device_model,
            second.system_version,
        )
        assert _model_ok(first.device_model), first.device_model


@pytest.mark.parametrize(
    ("device", "key"), [(WindowsDevice, "windows"), (LinuxDevice, "linux")]
)
def test_device_weight_is_model_weight_times_version_weight(
    device: type[SystemInfo], key: str
) -> None:
    catalog = _catalog()
    device.__gen__()
    counts = Counter((d.model, d.version) for d in device.deviceList)

    for model in catalog["models"]:
        for version in catalog[key]:
            pair = (model["model"], version["version"])
            assert counts[pair] == model["weight"] * version["weight"], pair


def test_default_desktop_system_version_is_windows_11_x64() -> None:
    assert API.TelegramDesktop.system_version == "Windows 11 x64"
