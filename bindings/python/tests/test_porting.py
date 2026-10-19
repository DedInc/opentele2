"""PORTING.md lists every 1.5.0 library test file once, and each row names
existing files of this directory or records why there is none."""

from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
TABLE = HERE / "PORTING.md"

# The 1.5.0 tests/*.py files, without the agent-kernel tests test_agentctl,
# test_audit_remediation, test_control_plane, test_guard_bypasses,
# test_install, test_market_routing and test_model_routing.
LEGACY_TEST_FILES = [
    "__init__.py",
    "tdata_test.py",
    "test_android_devices.py",
    "test_api_typing.py",
    "test_client_kwargs.py",
    "test_core_bridge.py",
    "test_desktop_devices.py",
    "test_desktop_version.py",
    "test_device_catalog_currency.py",
    "test_fingerprints.py",
    "test_full.py",
    "test_init_connection.py",
    "test_ios_devices.py",
    "test_mac_devices.py",
    "test_no_suppressions.py",
    "test_platform_versions.py",
    "test_session_io.py",
    "test_tdata_keydata.py",
    "test_tdata_localkey.py",
    "test_tdata_mapdata.py",
    "test_tdata_mtp.py",
    "test_tdata_readfile.py",
    "test_tdata_storage.py",
    "test_version_fetcher.py",
    "test_version_layer.py",
    "test_web_devices.py",
]

_CODE = re.compile(r"`([^`]+)`")


def _rows() -> list[tuple[str, str, str]]:
    rows = []
    for line in TABLE.read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[0].startswith("`"):
            legacy, ported, notes = cells
            rows.append((legacy.strip("`"), ported, notes))
    return rows


def test_the_table_lists_every_1_5_0_test_file_once() -> None:
    listed = [legacy for legacy, _, _ in _rows()]
    assert sorted(listed) == sorted(set(listed)), "a 1.5.0 file is listed twice"
    assert sorted(listed) == LEGACY_TEST_FILES


def test_every_row_names_existing_files_or_a_reason() -> None:
    for legacy, ported, notes in _rows():
        if ported == "none":
            assert notes, f"{legacy}: no ported file and no reason"
            continue
        named = _CODE.findall(ported)
        assert named, f"{legacy}: the second column names no file"
        missing = [name for name in named if not (HERE / name).is_file()]
        assert not missing, f"{legacy}: {missing} not in bindings/python/tests"


def test_the_parser_reads_the_table_rows() -> None:
    rows = dict((legacy, ported) for legacy, ported, _ in _rows())
    assert rows["__init__.py"] == "none"
    assert rows["test_no_suppressions.py"] == "`test_no_suppressions.py`"
