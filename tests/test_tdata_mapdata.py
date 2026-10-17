from __future__ import annotations

import pytest

from src.qt_compat import QByteArray, QDataStream, QIODevice
from src.td import shared as td
from src.td.configs import FileKey, lskType
from src.td.map_data import MapData


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


def test_webview_tokens_survive_a_map_round_trip() -> None:
    source = MapData("in-memory-base")
    source._webviewStorageTokenBots = QByteArray(b"bots")
    source._webviewStorageTokenOther = QByteArray(b"other-token")
    source._prefsKey = FileKey(7)

    target = _roundTrip(source)

    assert isinstance(target._webviewStorageTokenBots, QByteArray)
    assert isinstance(target._webviewStorageTokenOther, QByteArray)
    assert bytes(target._webviewStorageTokenBots) == b"bots"
    assert bytes(target._webviewStorageTokenOther) == b"other-token"
    assert int(target._prefsKey) == 7


@pytest.mark.parametrize(
    ("bots", "other"),
    [(b"only-bots", b""), (b"", b"only-other")],
)
def test_a_single_webview_token_round_trips(bots: bytes, other: bytes) -> None:
    source = MapData("in-memory-base")
    source._webviewStorageTokenBots = QByteArray(bots)
    source._webviewStorageTokenOther = QByteArray(other)

    target = _roundTrip(source)

    assert bytes(target._webviewStorageTokenBots) == bots
    assert bytes(target._webviewStorageTokenOther) == other


def test_absent_webview_tokens_stay_empty_byte_arrays() -> None:
    target = _roundTrip(MapData("in-memory-base"))

    assert isinstance(target._webviewStorageTokenBots, QByteArray)
    assert target._webviewStorageTokenBots.isEmpty()
    assert target._webviewStorageTokenOther.isEmpty()


def test_a_second_round_trip_is_byte_identical() -> None:
    source = MapData("in-memory-base")
    source._webviewStorageTokenBots = QByteArray(b"bots")
    source._webviewStorageTokenOther = QByteArray(b"other")

    first = _roundTrip(source)
    second = _roundTrip(first)

    assert bytes(second._webviewStorageTokenBots) == b"bots"
    assert bytes(second._webviewStorageTokenOther) == b"other"
    assert second._calculateMapSize() == source._calculateMapSize()


def _descriptorFrom(raw: bytes) -> td.Storage.EncryptedDescriptor:
    reader = td.Storage.EncryptedDescriptor()
    reader.data = QByteArray(raw)
    reader.buffer.setBuffer(reader.data)
    reader.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
    reader.stream.setDevice(reader.buffer)
    reader.stream.setVersion(QDataStream.Version.Qt_5_1)
    return reader


def _rawMap(*entries: tuple[int, bytes]) -> bytes:
    return b"".join(keyType.to_bytes(4, "big") + body for keyType, body in entries)


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _qstring(value: str) -> bytes:
    encoded = value.encode("utf-16-be")
    return len(encoded).to_bytes(4, "big") + encoded


def test_wallet_engine_storages_round_trip() -> None:
    source = MapData("in-memory-base")
    source._walletEngineStoragesMap = {
        "ton-main": FileKey(0x1111),
        "кошелёк": FileKey(0x2222),
    }
    source._prefsKey = FileKey(3)

    target = _roundTrip(source)

    assert target._walletEngineStoragesMap == {
        "ton-main": 0x1111,
        "кошелёк": 0x2222,
    }
    assert int(target._prefsKey) == 3


def test_keys_after_a_tdesktop_7_3_wallet_entry_are_still_read() -> None:
    raw = _rawMap(
        (lskType.lskWalletKey, _u64(0xAA)),
        (lskType.lskWalletEngineKey, _u64(0xBB)),
        (
            lskType.lskWalletEngineStorages,
            (1).to_bytes(4, "big") + _u64(0xCC) + _qstring("engine"),
        ),
        (lskType.lskPrefs, _u64(0xDD)),
    )
    target = MapData("in-memory-base")
    target._parseMapStream(_descriptorFrom(raw), None, 7003001)

    assert int(target._walletLegacyKey) == 0xAA
    assert int(target._walletEngineLegacyKey) == 0xBB
    assert target._walletEngineStoragesMap == {"engine": 0xCC}
    assert int(target._prefsKey) == 0xDD


def test_legacy_wallet_keys_are_not_written_back() -> None:
    source = MapData("in-memory-base")
    source._walletLegacyKey = FileKey(0xAA)
    source._walletEngineLegacyKey = FileKey(0xBB)

    target = _roundTrip(source)

    assert int(target._walletLegacyKey) == 0
    assert int(target._walletEngineLegacyKey) == 0


def test_an_unknown_key_stops_parsing_without_misreading() -> None:
    raw = _rawMap(
        (lskType.lskPrefs, _u64(0x10)),
        (0x7F, _u64(0xFFFFFFFFFFFFFFFF)),
        (lskType.lskLocations, _u64(0x20)),
    )
    target = MapData("in-memory-base")
    target._parseMapStream(_descriptorFrom(raw), None, 7003001)

    assert int(target._prefsKey) == 0x10
    assert int(target._locationsKey) == 0
