from __future__ import annotations

import hashlib
import pathlib

import pytest

from src.exception import TDataInvalidCheckSum, TDataInvalidMagic, TFileNotFound
from src.qt_compat import QByteArray
from src.td import shared as td
from src.utils import TDF_MAGIC

_VERSION = 7000009


def _tdfBytes(payload: bytes, version: int = _VERSION) -> bytes:
    versionBytes = version.to_bytes(4, "little")
    digest = hashlib.md5(
        payload + len(payload).to_bytes(4, "little") + versionBytes + TDF_MAGIC
    ).digest()
    return TDF_MAGIC + versionBytes + payload + digest


def _corrupt(blob: bytes) -> bytes:
    return blob[:-1] + bytes([blob[-1] ^ 0xFF])


def test_a_valid_file_reads_back(tmp_path: pathlib.Path) -> None:
    (tmp_path / "probes").write_bytes(_tdfBytes(b"payload"))

    result = td.Storage.ReadFile("probe", str(tmp_path))

    assert result.version == _VERSION
    assert bytes(result.data) == b"payload"


def test_a_corrupted_checksum_is_reported_as_a_checksum_failure(
    tmp_path: pathlib.Path,
) -> None:
    (tmp_path / "probes").write_bytes(_corrupt(_tdfBytes(b"payload")))

    with pytest.raises(TDataInvalidCheckSum):
        td.Storage.ReadFile("probe", str(tmp_path))


def test_a_bad_magic_is_reported_as_a_magic_failure(tmp_path: pathlib.Path) -> None:
    (tmp_path / "probe0").write_bytes(b"XXXX" + _tdfBytes(b"payload")[4:])

    with pytest.raises(TDataInvalidMagic):
        td.Storage.ReadFile("probe", str(tmp_path))


def test_an_absent_file_still_raises_file_not_found(tmp_path: pathlib.Path) -> None:
    with pytest.raises(TFileNotFound):
        td.Storage.ReadFile("probe", str(tmp_path))


def test_a_valid_fallback_suffix_wins_over_a_corrupted_one(
    tmp_path: pathlib.Path,
) -> None:
    (tmp_path / "probes").write_bytes(_corrupt(_tdfBytes(b"broken")))
    (tmp_path / "probe1").write_bytes(_tdfBytes(b"fallback"))

    result = td.Storage.ReadFile("probe", str(tmp_path))

    assert bytes(result.data) == b"fallback"


def test_encrypted_padding_is_random_and_still_decrypts() -> None:
    key = td.AuthKey(bytes(range(256)))

    def encrypt() -> bytes:
        data = td.Storage.EncryptedDescriptor(5)
        data.stream.writeRawData(b"hello")
        return bytes(td.Storage.PrepareEncrypted(data, key))

    first, second = encrypt(), encrypt()

    assert first != second
    for blob in (first, second):
        decrypted = td.Storage.DecryptLocal(QByteArray(blob), key)
        assert decrypted.stream.readRawData(5) == b"hello"
