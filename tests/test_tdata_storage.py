from __future__ import annotations

from typing import Any

import pytest

from src.exception import AccountAuthKeyNotFound, TDataReadMapDataFailed
from src.qt_compat import QByteArray, QDataStream, QIODevice
from src.td import shared as td
from src.td.account import Account
from src.td.configs import DcId, FileKey, dbi
from src.td.map_data import MapData
from src.td.storage_account import StorageAccount, TDataAccountMapReadFailed
from src.td.tdesktop import TDesktop


def _writeStream(data: QByteArray) -> QDataStream:
    stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
    stream.setVersion(QDataStream.Version.Qt_5_1)
    return stream


def _readDescriptor(payload: QByteArray) -> td.Storage.FileReadDescriptor:
    descriptor = td.Storage.FileReadDescriptor()
    descriptor.version = 1000
    descriptor.data = payload
    descriptor.buffer.setBuffer(descriptor.data)
    descriptor.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
    descriptor.stream.setDevice(descriptor.buffer)
    descriptor.stream.setVersion(QDataStream.Version.Qt_5_1)
    return descriptor


class _RecordingAccount(Account):
    """A real Account that records what StorageAccount hands it instead of
    parsing it."""

    def __init__(self) -> None:
        super().__init__(TDesktop())
        self.serialized: QByteArray | None = None
        self.custom: tuple[int, int, list[td.AuthKey]] | None = None

    def _setMtpAuthorization(self, serialized: QByteArray) -> None:
        self.serialized = serialized

    def _setMtpAuthorizationCustom(
        self,
        dcId: DcId,
        userId: int,
        mtpKeys: list[td.AuthKey],
        mtpKeysToDestroy: list[td.AuthKey] | None = None,
    ) -> None:
        self.custom = (int(dcId), int(userId), list(mtpKeys))


def _storageAccount(
    monkeypatch: pytest.MonkeyPatch, payload: QByteArray | None
) -> tuple[StorageAccount, _RecordingAccount]:
    owner = _RecordingAccount()
    account = StorageAccount(owner, "in-memory-base", "data")
    account.localKey = td.AuthKey(bytes(range(256)))

    if payload is not None:

        def _fake(fileName: str, basePath: str, authKey: Any) -> Any:
            return _readDescriptor(payload)

        monkeypatch.setattr(td.Storage, "ReadEncryptedFile", staticmethod(_fake))

    return account, owner


def _modernPayload(serialized: QByteArray) -> QByteArray:
    payload = QByteArray()
    stream = _writeStream(payload)
    stream.writeUInt32(dbi.MtpAuthorization)
    stream << serialized
    return payload


def _legacyPayload(userId: int, dcId: int, keys: list[tuple[int, bytes]]) -> QByteArray:
    payload = QByteArray()
    stream = _writeStream(payload)
    stream.writeUInt32(dbi.User)
    stream.writeInt32(userId)
    stream.writeUInt32(dcId)
    for keyDcId, keyBytes in keys:
        stream.writeUInt32(dbi.Key)
        stream.writeInt32(keyDcId)
        stream.writeRawData(keyBytes)
    return payload


def test_legacy_multi_block_mtp_payload_is_read_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyOne = bytes(range(256))
    keyTwo = bytes(255 - i for i in range(256))
    payload = _legacyPayload(
        userId=424242,
        dcId=int(DcId._2),
        keys=[(int(DcId._2), keyOne), (int(DcId._4), keyTwo)],
    )
    account, owner = _storageAccount(monkeypatch, payload)

    account._readMtpData()

    assert owner.serialized is None
    assert owner.custom is not None
    dcId, userId, mtpKeys = owner.custom
    assert (dcId, userId) == (int(DcId._2), 424242)
    assert [int(key.dcId) for key in mtpKeys] == [int(DcId._2), int(DcId._4)]
    assert bytes(mtpKeys[0].key) == keyOne
    assert bytes(mtpKeys[1].key) == keyTwo


def test_modern_single_block_payload_yields_identical_authorization_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serialized = QByteArray(b"\x01\x02\x03\x04mtp-authorization-blob")
    payload = _modernPayload(serialized)
    account, owner = _storageAccount(monkeypatch, payload)

    account._readMtpData()

    assert owner.custom is None
    assert owner.serialized is not None
    assert bytes(owner.serialized) == bytes(serialized)
    assert int(dbi.MtpAuthorization) == 75


def test_trailing_legacy_blocks_after_authorization_do_not_break_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serialized = QByteArray(b"modern-blob")
    payload = QByteArray()
    stream = _writeStream(payload)
    stream.writeUInt32(dbi.MtpAuthorization)
    stream << serialized
    stream.writeUInt32(dbi.User)
    stream.writeInt32(7)
    stream.writeUInt32(int(DcId._1))

    account, owner = _storageAccount(monkeypatch, payload)
    account._readMtpData()

    assert owner.custom is None
    assert owner.serialized is not None
    assert bytes(owner.serialized) == bytes(serialized)


def test_reading_mtp_data_without_a_local_key_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    account, _owner = _storageAccount(monkeypatch, _modernPayload(QByteArray(b"x")))
    account.localKey = None

    with pytest.raises(AccountAuthKeyNotFound):
        account._readMtpData()


def test_failed_map_read_raises_instead_of_silently_skipping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    account, _owner = _storageAccount(monkeypatch, None)

    def _boom(localKey: Any, legacyPasscode: Any) -> None:
        raise TDataReadMapDataFailed("could not decrypt map data")

    monkeypatch.setattr(account.mapData, "read", _boom)

    def _neverCalled() -> None:
        raise AssertionError("_readMtpData must not run after a failed map read")

    monkeypatch.setattr(account, "_readMtpData", _neverCalled)

    with pytest.raises(TDataAccountMapReadFailed) as excinfo:
        # start() takes a real key; the patched map read fails regardless.
        account.start(td.AuthKey(bytes(range(256))))

    assert "data" in str(excinfo.value)


def _roundTrip(source: MapData) -> MapData:
    written = source.prepareToWrite()
    body = QByteArray(bytes(written.data)[4:])
    written.finish()

    assert body.size() == source._calculateMapSize()

    reader = td.Storage.EncryptedDescriptor()
    reader.data = body
    reader.buffer.setBuffer(reader.data)
    reader.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
    reader.stream.setDevice(reader.buffer)
    reader.stream.setVersion(QDataStream.Version.Qt_5_1)

    target = MapData("in-memory-base")
    target._parseMapStream(reader, None, 1000)
    return target


def test_map_round_trip_preserves_previously_dropped_entries() -> None:
    source = MapData("in-memory-base")
    source._legacyBackgroundKeyDay = FileKey(0x1122334455667788)
    source._legacyBackgroundKeyNight = FileKey(0x8877665544332211)
    source._selfSerialized = QByteArray(b"serialized-self-blob")
    source._locationsKey = FileKey(0xDEADBEEF)

    target = _roundTrip(source)

    assert int(target._legacyBackgroundKeyDay) == 0x1122334455667788
    assert int(target._legacyBackgroundKeyNight) == 0x8877665544332211
    assert bytes(target._selfSerialized) == b"serialized-self-blob"
    assert int(target._locationsKey) == 0xDEADBEEF


def test_map_round_trip_covers_the_lsk_key_set_the_reader_understands() -> None:
    source = MapData("in-memory-base")
    source._legacyBackgroundKeyDay = FileKey(11)
    source._selfSerialized = QByteArray(b"self")
    source._prefsKey = FileKey(21)
    source._installedStickersKey = FileKey(31)
    source._favedStickersKey = FileKey(41)

    target = _roundTrip(source)

    assert int(target._legacyBackgroundKeyDay) == 11
    assert int(target._legacyBackgroundKeyNight) == 0
    assert bytes(target._selfSerialized) == b"self"
    assert int(target._prefsKey) == 21
    assert int(target._installedStickersKey) == 31
    assert int(target._favedStickersKey) == 41
    assert int(target._settingsKey) == int(MapData._HARDCODED_SETTINGS_KEY)


def test_empty_map_round_trip_reports_a_consistent_size() -> None:
    source = MapData("in-memory-base")
    written = source.prepareToWrite()
    body = bytes(written.data)[4:]
    written.finish()

    assert len(body) == source._calculateMapSize()
