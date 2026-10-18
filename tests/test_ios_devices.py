from __future__ import annotations

import json
import os

import pytest

from src.devices import DeviceInfo, IOSDevice

_CATALOG_PATH = os.path.join(
    os.path.dirname(__file__), os.pardir, "src", "devices", "ios.json"
)


@pytest.fixture(scope="module")
def catalog() -> dict:
    with open(_CATALOG_PATH, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def device_list() -> list[DeviceInfo]:
    IOSDevice.__gen__()
    return IOSDevice.deviceList


def _major(version: str) -> int:
    return int(version.split(".")[0])


def test_versions_come_from_catalog(catalog: dict, device_list: list) -> None:
    released = {e["version"] for e in catalog["versions"]}
    assert {d.version for d in device_list} <= released


def test_no_unreleased_majors(device_list: list) -> None:
    majors = {_major(d.version) for d in device_list}
    assert not majors & set(range(19, 26))


def test_iphone_xs_capped_at_18(device_list: list) -> None:
    xs_versions = {d.version for d in device_list if d.model == "iPhone XS"}
    assert xs_versions
    assert max(_major(v) for v in xs_versions) == 18


def test_18_7_10_only_on_a12_iphones(device_list: list) -> None:
    models = {d.model for d in device_list if d.version == "18.7.10"}
    assert models == {"iPhone XS", "iPhone XS Max", "iPhone XR"}


def test_models_are_catalog_names(catalog: dict, device_list: list) -> None:
    names = {e["model"] for e in catalog["models"]}
    assert {d.model for d in device_list} <= names


def test_random_device_deterministic() -> None:
    a = IOSDevice.RandomDevice("ios-seed")
    b = IOSDevice.RandomDevice("ios-seed")
    assert (a.model, a.version) == (b.model, b.version)


def test_device_list_size(device_list: list) -> None:
    assert len(device_list) > 100
