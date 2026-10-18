from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from src import fingerprint
from src.consistency import CheckResult, ConsistencyChecker
from src.exception import OpenTeleException
from src.qt_compat import QByteArray
from src.td import shared as td
from src.tl.telethon import TelegramClient
from src.utils import APP_VERSION, TDF_MAGIC

_VERSION_H = (
    Path(__file__).resolve().parents[1]
    / "refs"
    / "tdesktop-dev"
    / "Telegram"
    / "SourceFiles"
    / "core"
    / "version.h"
)

requires_tdesktop_ref = pytest.mark.skipif(
    not _VERSION_H.is_file(),
    reason=f"missing tdesktop reference checkout: {_VERSION_H}",
)


def _app_version_from_header() -> int:
    source = _VERSION_H.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"constexpr auto AppVersion = (\d+);", source)
    assert match is not None, "AppVersion not found in version.h"
    return int(match.group(1))


class TestAppVersion:
    @requires_tdesktop_ref
    def test_app_version_matches_tdesktop_header(self) -> None:
        assert APP_VERSION == _app_version_from_header()

    def test_app_version_is_7_3_1(self) -> None:
        assert APP_VERSION == 7003001

    def test_written_tdf_header_carries_app_version(self, tmp_path: Path) -> None:
        basePath = str(tmp_path)
        writer = td.Storage.FileWriteDescriptor("version_probe", basePath)
        writer.writeData(QByteArray(b"opentele-version-layer-probe"))
        writer.finish()

        raw = (tmp_path / "version_probes").read_bytes()
        assert raw[:4] == TDF_MAGIC
        assert int.from_bytes(raw[4:8], "little") == APP_VERSION

    def test_written_tdf_reads_back_with_valid_md5(self, tmp_path: Path) -> None:
        basePath = str(tmp_path)
        payload = QByteArray(b"round-trip-payload")
        writer = td.Storage.FileWriteDescriptor("roundtrip", basePath)
        writer.writeData(payload)
        writer.finish()

        descriptor = td.Storage.ReadFile("roundtrip", basePath)
        assert descriptor.version == APP_VERSION
        readBack = QByteArray()
        descriptor.stream >> readBack
        assert bytes(readBack.data()) == b"round-trip-payload"

    def test_corrupted_trailer_still_fails_checksum(self, tmp_path: Path) -> None:
        basePath = str(tmp_path)
        writer = td.Storage.FileWriteDescriptor("corrupt", basePath)
        writer.writeData(QByteArray(b"payload"))
        writer.finish()

        target = tmp_path / "corrupts"
        raw = bytearray(target.read_bytes())
        raw[-1] ^= 0xFF
        target.write_bytes(bytes(raw))

        with pytest.raises(OpenTeleException):
            td.Storage.ReadFile("corrupt", basePath)


_REFS = Path(__file__).resolve().parents[1] / "refs"
_SCHEMAS = {
    "tdesktop": _REFS / "tdesktop-dev/Telegram/SourceFiles/mtproto/scheme/api.tl",
    "telethon": _REFS / "telethon/telethon_generator/data/api.tl",
}


class TestAdvertisedLayer:
    @pytest.mark.parametrize("ref", sorted(_SCHEMAS))
    def test_advertised_layer_matches_reference_schema(self, ref: str) -> None:
        api_tl = _SCHEMAS[ref]
        if not api_tl.is_file():
            raise pytest.skip.Exception(f"missing {ref} reference checkout: {api_tl}")
        source = api_tl.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"^// LAYER (\d+)", source, re.MULTILINE)
        assert match is not None, "LAYER marker not found in api.tl"
        assert fingerprint.get_advertised_layer() == int(match.group(1))

    def test_installed_telethon_passes_the_layer_check(self) -> None:
        result = _run_layer_check()
        assert result.passed, result.detail


def _run_layer_check() -> CheckResult:
    # A real, never-connected client: construction is offline (MemorySession).
    checker = ConsistencyChecker(TelegramClient(), auto_warn=False)
    return asyncio.run(checker.check_layer_match())


class TestLayerCheck:
    def test_advertised_layer_is_a_standalone_constant(self) -> None:
        assert fingerprint.get_advertised_layer() == fingerprint.LAYER

    def test_layer_check_passes_when_layers_agree(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        advertised = fingerprint.get_advertised_layer()
        monkeypatch.setattr(fingerprint, "_detect_telethon_layer", lambda: advertised)

        result = _run_layer_check()
        assert result.passed
        assert "diff=0" in result.detail

    def test_layer_check_reports_mismatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        detected = fingerprint._detect_telethon_layer()
        monkeypatch.setattr(fingerprint, "get_advertised_layer", lambda: detected - 40)

        result = _run_layer_check()
        assert not result.passed
        assert "diff=40" in result.detail
        assert str(detected) in result.detail

    def test_layer_check_uses_detected_telethon_layer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        advertised = fingerprint.get_advertised_layer()
        monkeypatch.setattr(
            fingerprint, "_detect_telethon_layer", lambda: advertised + 100
        )

        result = _run_layer_check()
        assert not result.passed
        assert "diff=100" in result.detail
