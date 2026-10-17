from __future__ import annotations

import pytest

from src.qt_compat import QByteArray, QDataStream, QIODevice
from src.td import shared as td
from src.td.configs import FileKey
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
