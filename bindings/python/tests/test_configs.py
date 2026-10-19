"""The 1.5.0 ``src/utils.py`` names ``opentele2.tl.configs`` re-exports
(APP_VERSION, APP_VERSION_STR, TDF_MAGIC, PrettyTable, format_app_version),
ported from 1.5.0 tests/test_desktop_version.py and the TestAppVersion class
of tests/test_version_layer.py. ``PrettyTable`` outputs are the strings 1.5.0
``src/utils.py`` rendered for the same inputs."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from opentele2 import _compat, _native, fingerprint
from opentele2.api import API
from opentele2.exception import OpenTeleException
from opentele2.td import TDesktop
from opentele2.tl import configs
from opentele2.tl.configs import (
    APP_VERSION,
    APP_VERSION_STR,
    TDF_MAGIC,
    PrettyTable,
    format_app_version,
)

ROOT = Path(__file__).resolve().parents[3]
VECTORS = ROOT / "crates" / "opentele2-core" / "tests" / "vectors"
VERSION_H = ROOT / "refs" / "tdesktop-dev" / "Telegram" / "SourceFiles" / "core" / "version.h"
UTILS_NAMES = [
    "APP_VERSION",
    "APP_VERSION_STR",
    "TDF_MAGIC",
    "BaseMetaClass",
    "BaseObject",
    "PrettyTable",
    "format_app_version",
    "sharemethod",
]


def test_configs_re_exports_the_1_5_0_utils_names() -> None:
    assert _compat.__all__ == UTILS_NAMES
    for name in UTILS_NAMES:
        assert name in configs.__all__, name
        assert getattr(configs, name) is getattr(_compat, name), name


@pytest.mark.parametrize(
    ("packed", "display"),
    [
        (7000009, "7.0.9"),
        (7003000, "7.3"),
        (7003001, "7.3.1"),
        (6008002, "6.8.2"),
        (10000000, "10.0"),
    ],
)
def test_format_app_version_matches_tdesktop_display(packed: int, display: str) -> None:
    assert format_app_version(packed) == display


def test_app_version_is_7_3_1_and_the_cores() -> None:
    assert APP_VERSION == 7003001
    assert APP_VERSION == _native.TData.new([]).app_version
    assert APP_VERSION_STR == "7.3.1"


def test_app_version_matches_tdesktop_header() -> None:
    if not VERSION_H.is_file():
        raise pytest.skip.Exception(f"missing tdesktop reference checkout: {VERSION_H}")
    source = VERSION_H.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"constexpr auto AppVersion = (\d+);", source)
    assert match is not None, "AppVersion not found in version.h"
    assert int(match.group(1)) == APP_VERSION


def test_advertised_desktop_version_is_derived_from_app_version() -> None:
    assert format_app_version(APP_VERSION) == APP_VERSION_STR
    assert fingerprint.PlatformVersions().desktop_app_version == APP_VERSION_STR
    assert fingerprint.PLATFORM_VERSIONS.desktop_app_version == APP_VERSION_STR
    assert API.TelegramDesktop.app_version.split(" ")[0] == APP_VERSION_STR


def test_written_tdf_headers_carry_the_magic_and_app_version(tmp_path: Path) -> None:
    accounts = _native.TData.load(VECTORS / "tdata_plain/performance_on").accounts
    _native.TData.new(accounts).save(tmp_path)
    written = sorted(path for path in tmp_path.rglob("*") if path.is_file())
    assert written
    for path in written:
        raw = path.read_bytes()
        assert raw[:4] == TDF_MAGIC, path.name
        assert int.from_bytes(raw[4:8], "little") == APP_VERSION, path.name
    assert TDesktop(str(tmp_path)).AppVersion == APP_VERSION


def test_a_corrupted_trailer_fails_the_checksum(tmp_path: Path) -> None:
    accounts = _native.TData.load(VECTORS / "tdata_plain/performance_on").accounts
    _native.TData.new(accounts).save(tmp_path)
    key_file = tmp_path / "key_datas"
    raw = bytearray(key_file.read_bytes())
    raw[-1] ^= 0xFF
    key_file.write_bytes(bytes(raw))
    with pytest.raises(OpenTeleException):
        TDesktop(str(tmp_path))


@pytest.mark.parametrize(
    ("table", "add_split", "rendered"),
    [
        (
            [{"Name": "a", "Count": 1}, {"Name": "longer name", "Count": 12345}],
            None,
            "|-------------+-------|\n|    Name     | Count |\n|-------------+-------|\n"
            "|      a      |   1   |\n| longer name | 12345 |\n|-------------+-------|",
        ),
        (
            [
                {" ": "Current", "Device": "PC 64bit", "API_ID": 2040},
                {" ": 1, "Device": "iPhone", "API_ID": 10840},
                {" ": 2, "Device": "x", "API_ID": 6},
            ],
            [1],
            "|---------+----------+--------|\n|         |  Device  | API_ID |\n"
            "|---------+----------+--------|\n| Current | PC 64bit |  2040  |\n"
            "|---------+----------+--------|\n|    1    |  iPhone  | 10840  |\n"
            "|    2    |    x     |   6    |\n|---------+----------+--------|",
        ),
        (
            [{"odd": "abc", "e": "xy"}, {"odd": "z", "e": ""}],
            [0, 1],
            "|-----+----|\n| odd | e  |\n|-----+----|\n|-----+----|\n| abc | xy |\n"
            "|-----+----|\n|  z  |    |\n|-----+----|",
        ),
    ],
)
def test_pretty_table_renders_as_1_5_0(
    table: list[dict[str, object]], add_split: list[int] | None, rendered: str
) -> None:
    assert PrettyTable(table, add_split) == rendered
    if add_split is None:
        assert PrettyTable(table) == rendered
