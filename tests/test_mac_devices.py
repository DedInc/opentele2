from __future__ import annotations

import json
import pathlib
import re

import pytest

import src
from src.api import API
from src.devices import macOSDevice
from src.fingerprint import PLATFORM_VERSIONS

_MODEL = re.compile(
    r"^(MacBook Pro|MacBook Air|MacBook Neo|Mac mini|iMac|Mac Studio|Mac Pro)"
    r" (M\d+( Pro| Max| Ultra)?|A\d+ Pro)$"
)
_TDESKTOP_VERSION = re.compile(r"^macOS \d+\.\d+(\.[1-9]\d*)?$")
_SWIFT_VERSION = re.compile(r"^\d+\.\d+(\.[1-9]\d*)?$")

_SEEDS = [f"mac-{i}" for i in range(300)]


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def _min_macos() -> dict[str, tuple[int, ...]]:
    catalog = json.loads(
        (pathlib.Path(src.__file__).parent / "devices" / "mac.json").read_text(
            encoding="utf-8"
        )
    )
    return {
        e["model"]: _version_tuple(e["min_macos"])
        for e in catalog["models"]
        if "min_macos" in e
    }


def test_device_list_uses_catalog_model_names() -> None:
    macOSDevice.__gen__()
    assert macOSDevice.deviceList
    bad = {d.model for d in macOSDevice.deviceList if not _MODEL.match(d.model)}
    assert not bad


def test_no_version_older_than_the_model_launch() -> None:
    minimum = _min_macos()
    macOSDevice.__gen__()
    for device in macOSDevice.deviceList:
        assert device.model in minimum, device.model
        assert _version_tuple(device.version) >= minimum[device.model], str(device)


def test_device_list_weights_are_model_times_version() -> None:
    catalog = json.loads(
        (pathlib.Path(src.__file__).parent / "devices" / "mac.json").read_text(
            encoding="utf-8"
        )
    )
    model = catalog["models"][0]
    version = catalog["versions"][0]
    macOSDevice.__gen__()
    count = sum(
        1
        for d in macOSDevice.deviceList
        if d.model == model["model"] and d.version == version["version"]
    )
    assert count == model["weight"] * version["weight"]


@pytest.mark.parametrize("seed", _SEEDS)
def test_tdesktop_generate(seed: str) -> None:
    api = API.TelegramDesktop.Generate("macos", seed)
    assert _MODEL.match(api.device_model), api.device_model
    assert api.system_version is not None
    assert _TDESKTOP_VERSION.match(api.system_version), api.system_version
    version = api.system_version.removeprefix("macOS ")
    assert _version_tuple(version) >= _min_macos()[api.device_model]


@pytest.mark.parametrize("seed", _SEEDS)
def test_telegram_macos_generate(seed: str) -> None:
    api = API.TelegramMacOS.Generate(seed)
    assert _MODEL.match(api.device_model), api.device_model
    assert api.system_version is not None
    assert _SWIFT_VERSION.match(api.system_version), api.system_version
    assert _version_tuple(api.system_version) >= _min_macos()[api.device_model]


def test_generate_is_deterministic() -> None:
    for seed in _SEEDS[:20]:
        a = API.TelegramDesktop.Generate("macos", seed)
        b = API.TelegramDesktop.Generate("macos", seed)
        assert (a.device_model, a.system_version) == (b.device_model, b.system_version)
        c = API.TelegramMacOS.Generate(seed)
        d = API.TelegramMacOS.Generate(seed)
        assert (c.device_model, c.system_version) == (d.device_model, d.system_version)
        # Both clients draw the same machine for a seed; only the format differs.
        assert c.device_model == a.device_model
        assert a.system_version == f"macOS {c.system_version}"


def test_telegram_macos_defaults() -> None:
    assert PLATFORM_VERSIONS.macos_system_version == "27.0.1"
    assert API.TelegramMacOS.device_model == "MacBook Air M4"
    assert API.TelegramMacOS.system_version == "27.0.1"
