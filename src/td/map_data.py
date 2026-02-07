from __future__ import annotations

import logging
import typing
from ctypes import sizeof, c_uint32 as uint32, c_uint64 as uint64
from typing import Dict

from ..qt_compat import QByteArray

from ..exception import (
    Expects,
    ExpectStreamStatus,
    OpenTeleException,
    TDataReadMapDataFailed,
    TDataReadMapDataIncorrectPasscode,
)
from ..utils import BaseObject
from .configs import FileKey, PeerId, lskType
from . import shared as td


class MapData(BaseObject):  # nocov
    _HARDCODED_SETTINGS_KEY = FileKey(1851671142505648812)
    _LEGACY_SALT_SIZE = 32

    _KEY_TO_ATTR = {
        "locationsKey": "_locationsKey",
        "trustedBotsKey": "_trustedBotsKey",
        "recentStickersKeyOld": "_recentStickersKeyOld",
        "installedStickersKey": "_installedStickersKey",
        "featuredStickersKey": "_featuredStickersKey",
        "recentStickersKey": "_recentStickersKey",
        "favedStickersKey": "_favedStickersKey",
        "archivedStickersKey": "_archivedStickersKey",
        "savedGifsKey": "_savedGifsKey",
        "installedMasksKey": "_installedMasksKey",
        "recentMasksKey": "_recentMasksKey",
        "archivedMasksKey": "_archivedMasksKey",
        "installedCustomEmojiKey": "_installedCustomEmojiKey",
        "featuredCustomEmojiKey": "_featuredCustomEmojiKey",
        "archivedCustomEmojiKey": "_archivedCustomEmojiKey",
        "searchSuggestionsKey": "_searchSuggestionsKey",
        "webviewStorageTokenBots": "_webviewStorageTokenBots",
        "webviewStorageTokenOther": "_webviewStorageTokenOther",
        "legacyBackgroundKeyDay": "_legacyBackgroundKeyDay",
        "legacyBackgroundKeyNight": "_legacyBackgroundKeyNight",
        "userSettingsKey": "_settingsKey",
        "recentHashtagsAndBotsKey": "_recentHashtagsAndBotsKey",
        "exportSettingsKey": "_exportSettingsKey",
    }

    _LSK_KEY_MAP = {
        lskType.lskLocations: ("locationsKey",),
        lskType.lskTrustedBots: ("trustedBotsKey",),
        lskType.lskRecentStickersOld: ("recentStickersKeyOld",),
        lskType.lskBackgroundOldOld: ("legacyBackgroundKeyDay",),
        lskType.lskUserSettings: ("userSettingsKey",),
        lskType.lskRecentHashtagsAndBots: ("recentHashtagsAndBotsKey",),
        lskType.lskStickersOld: ("installedStickersKey",),
        lskType.lskFavedStickers: ("favedStickersKey",),
        lskType.lskSavedGifs: ("savedGifsKey",),
        lskType.lskExportSettings: ("exportSettingsKey",),
        lskType.lskSearchSuggestions: ("searchSuggestionsKey",),
        lskType.lskBackgroundOld: (
            "legacyBackgroundKeyDay",
            "legacyBackgroundKeyNight",
        ),
        lskType.lskStickersKeys: (
            "installedStickersKey",
            "featuredStickersKey",
            "recentStickersKey",
            "archivedStickersKey",
        ),
        lskType.lskMasksKeys: (
            "installedMasksKey",
            "recentMasksKey",
            "archivedMasksKey",
        ),
        lskType.lskCustomEmojiKeys: (
            "installedCustomEmojiKey",
            "featuredCustomEmojiKey",
            "archivedCustomEmojiKey",
        ),
    }

    _LSK_SKIP_TYPES = frozenset(
        {
            lskType.lskReportSpamStatusesOld,
            lskType.lskSavedGifsOld,
            lskType.lskSavedPeersOld,
        }
    )

    def __init__(self, basePath: str) -> None:
        self.basePath = basePath

        self._draftsMap: Dict[PeerId, FileKey] = {}
        self._draftCursorsMap: Dict[PeerId, FileKey] = {}
        self._draftsNotReadMap: Dict[PeerId, bool] = {}

        self._locationsKey = FileKey(0)
        self._trustedBotsKey = FileKey(0)
        self._installedStickersKey = FileKey(0)
        self._featuredStickersKey = FileKey(0)
        self._recentStickersKey = FileKey(0)
        self._favedStickersKey = FileKey(0)
        self._archivedStickersKey = FileKey(0)
        self._archivedMasksKey = FileKey(0)
        self._installedCustomEmojiKey = FileKey(0)
        self._featuredCustomEmojiKey = FileKey(0)
        self._archivedCustomEmojiKey = FileKey(0)
        self._searchSuggestionsKey = FileKey(0)
        self._webviewStorageTokenBots = FileKey(0)
        self._webviewStorageTokenOther = FileKey(0)
        self._savedGifsKey = FileKey(0)
        self._recentStickersKeyOld = FileKey(0)
        self._legacyBackgroundKeyDay = FileKey(0)
        self._legacyBackgroundKeyNight = FileKey(0)
        self._settingsKey = self._HARDCODED_SETTINGS_KEY
        self._recentHashtagsAndBotsKey = FileKey(0)
        self._exportSettingsKey = FileKey(0)
        self._installedMasksKey = FileKey(0)
        self._recentMasksKey = FileKey(0)

    def read(self, localKey: td.AuthKey, legacyPasscode: QByteArray) -> None:
        try:
            mapData = td.Storage.ReadFile("map", self.basePath)
        except OpenTeleException as e:
            raise TDataReadMapDataFailed(
                "Could not read map data, file not found or couldn't be opened"
            ) from e

        legacySalt, legacyKeyEncrypted, mapEncrypted = (
            QByteArray(),
            QByteArray(),
            QByteArray(),
        )

        mapData.stream >> legacySalt >> legacyKeyEncrypted >> mapEncrypted
        ExpectStreamStatus(mapData.stream, "Could not stream data from mapData")

        if not localKey:
            Expects(
                legacySalt.size() == self._LEGACY_SALT_SIZE,
                TDataReadMapDataFailed(
                    f"Bad salt in map file, size: {legacySalt.size()}"
                ),
            )

            legacyPasscodeKey = td.Storage.CreateLegacyLocalKey(
                legacySalt, legacyPasscode
            )

            try:
                keyData = td.Storage.DecryptLocal(legacyKeyEncrypted, legacyPasscodeKey)
            except OpenTeleException as e:
                raise TDataReadMapDataIncorrectPasscode(
                    "Could not decrypt pass-protected key from map file, maybe bad password..."
                ) from e

            localKey = td.AuthKey.FromStream(keyData.stream)

        try:
            map = td.Storage.DecryptLocal(mapEncrypted, localKey)
        except OpenTeleException as e:
            raise TDataReadMapDataFailed("Could not decrypt map data") from e

        self._parseMapStream(map, localKey, mapData.version)

    def _parseMapStream(self, map, localKey, mapVersion) -> None:
        draftsMap: typing.Dict[PeerId, FileKey] = {}
        draftCursorsMap: typing.Dict[PeerId, FileKey] = {}
        draftsNotReadMap: typing.Dict[PeerId, bool] = {}

        keys = {k: 0 for k in self._KEY_TO_ATTR}

        while not map.stream.atEnd():
            keyType = map.stream.readUInt32()

            if not self._readMapEntry(
                keyType, map, draftsMap, draftCursorsMap, draftsNotReadMap, keys
            ):
                break

            ExpectStreamStatus(map.stream, "Could not stream data from mapData")

        self._applyParsedKeys(
            localKey, mapVersion, draftsMap, draftCursorsMap, draftsNotReadMap, keys
        )

    def _readMapEntry(
        self, keyType, map, draftsMap, draftCursorsMap, draftsNotReadMap, keys
    ) -> bool:
        if keyType == lskType.lskDraft:
            count = map.stream.readUInt32()
            for i in range(count):
                key = FileKey(map.stream.readUInt64())
                peerIdSerialized = map.stream.readUInt64()
                peerId = PeerId.FromSerialized(peerIdSerialized)
                draftsMap[peerId] = key
                draftsNotReadMap[peerId] = True

        elif keyType == lskType.lskSelfSerialized:
            selfSerialized = QByteArray()
            map.stream >> selfSerialized

        elif keyType == lskType.lskDraftPosition:
            count = map.stream.readUInt32()
            for i in range(count):
                key = FileKey(map.stream.readUInt64())
                peerIdSerialized = map.stream.readUInt64()
                peerId = PeerId.FromSerialized(peerIdSerialized)
                draftCursorsMap[peerId] = key

        elif keyType in (
            lskType.lskLegacyImages,
            lskType.lskLegacyStickerImages,
            lskType.lskLegacyAudios,
        ):
            count = map.stream.readUInt32()
            for i in range(count):
                map.stream.readUInt64()
                map.stream.readUInt64()
                map.stream.readUInt64()
                map.stream.readInt32()

        elif keyType in self._LSK_KEY_MAP:
            for key_name in self._LSK_KEY_MAP[keyType]:
                keys[key_name] = map.stream.readUInt64()

        elif keyType in self._LSK_SKIP_TYPES:
            map.stream.readUInt64()

        elif keyType == lskType.lskWebviewTokens:
            return False

        else:
            logging.warning(f"Unknown key type in encrypted map: {keyType}")

        return True

    def _applyParsedKeys(
        self, localKey, mapVersion, draftsMap, draftCursorsMap, draftsNotReadMap, keys
    ) -> None:
        self.__localKey = localKey
        self._draftsMap = draftsMap
        self._draftCursorsMap = draftCursorsMap
        self._draftsNotReadMap = draftsNotReadMap
        for key_name, attr_name in self._KEY_TO_ATTR.items():
            setattr(self, attr_name, keys[key_name])
        self._oldMapVersion = mapVersion

    def prepareToWrite(self) -> td.Storage.EncryptedDescriptor:
        mapSize = self._calculateMapSize()
        mapData = td.Storage.EncryptedDescriptor(mapSize)
        self._writeMapEntries(mapData.stream)
        return mapData

    def _calculateMapSize(self) -> int:
        mapSize = 0

        if len(self._draftsMap) > 0:
            mapSize += sizeof(uint32) * 2 + len(self._draftsMap) * sizeof(uint64) * 2
        if len(self._draftCursorsMap) > 0:
            mapSize += (
                sizeof(uint32) * 2 + len(self._draftCursorsMap) * sizeof(uint64) * 2
            )

        single_key_fields = [
            self._locationsKey,
            self._trustedBotsKey,
            self._recentStickersKeyOld,
            self._favedStickersKey,
            self._savedGifsKey,
            self._settingsKey,
            self._recentHashtagsAndBotsKey,
            self._exportSettingsKey,
            self._searchSuggestionsKey,
        ]
        for key in single_key_fields:
            if key:
                mapSize += sizeof(uint32) + sizeof(uint64)

        mapSize += self._groupKeySize(
            4,
            self._installedStickersKey,
            self._featuredStickersKey,
            self._recentStickersKey,
            self._archivedStickersKey,
        )
        mapSize += self._groupKeySize(
            3, self._installedMasksKey, self._recentMasksKey, self._archivedMasksKey
        )
        mapSize += self._groupKeySize(
            3,
            self._installedCustomEmojiKey,
            self._featuredCustomEmojiKey,
            self._archivedCustomEmojiKey,
        )
        mapSize += self._groupKeySize(
            2, self._webviewStorageTokenBots, self._webviewStorageTokenOther
        )

        return mapSize

    def _writeMapEntries(self, stream) -> None:
        if len(self._draftsMap) > 0:
            stream.writeUInt32(lskType.lskDraft)
            stream.writeUInt32(len(self._draftsMap))
            for key, value in self._draftsMap.items():
                stream.writeUInt64(value)
                stream.writeUInt64(PeerId(key).Serialize())

        if len(self._draftCursorsMap) > 0:
            stream.writeUInt32(lskType.lskDraftPosition)
            stream.writeUInt32(len(self._draftCursorsMap))
            for key, value in self._draftCursorsMap.items():
                stream.writeUInt64(value)
                stream.writeUInt64(PeerId(key).Serialize())

        self._writeKeyIfSet(stream, lskType.lskLocations, self._locationsKey)
        self._writeKeyIfSet(stream, lskType.lskTrustedBots, self._trustedBotsKey)
        self._writeKeyIfSet(
            stream, lskType.lskRecentStickersOld, self._recentStickersKeyOld
        )

        self._writeKeyGroupIfAnySet(
            stream,
            lskType.lskStickersKeys,
            self._installedStickersKey,
            self._featuredStickersKey,
            self._recentStickersKey,
            self._archivedStickersKey,
        )

        self._writeKeyIfSet(stream, lskType.lskFavedStickers, self._favedStickersKey)
        self._writeKeyIfSet(stream, lskType.lskSavedGifs, self._savedGifsKey)
        self._writeKeyIfSet(stream, lskType.lskUserSettings, self._settingsKey)
        self._writeKeyIfSet(
            stream, lskType.lskRecentHashtagsAndBots, self._recentHashtagsAndBotsKey
        )
        self._writeKeyIfSet(stream, lskType.lskExportSettings, self._exportSettingsKey)

        self._writeKeyGroupIfAnySet(
            stream,
            lskType.lskMasksKeys,
            self._installedMasksKey,
            self._recentMasksKey,
            self._archivedMasksKey,
        )
        self._writeKeyGroupIfAnySet(
            stream,
            lskType.lskCustomEmojiKeys,
            self._installedCustomEmojiKey,
            self._featuredCustomEmojiKey,
            self._archivedCustomEmojiKey,
        )

        self._writeKeyIfSet(
            stream, lskType.lskSearchSuggestions, self._searchSuggestionsKey
        )

        self._writeKeyGroupIfAnySet(
            stream,
            lskType.lskWebviewTokens,
            self._webviewStorageTokenBots,
            self._webviewStorageTokenOther,
        )

    @staticmethod
    def _writeKeyIfSet(stream, keyType: int, keyValue) -> None:
        if keyValue:
            stream.writeUInt32(keyType)
            stream.writeUInt64(keyValue)

    @staticmethod
    def _writeKeyGroupIfAnySet(stream, keyType: int, *keys) -> None:
        if any(keys):
            stream.writeUInt32(keyType)
            for key in keys:
                stream.writeUInt64(key)

    @staticmethod
    def _groupKeySize(count: int, *keys) -> int:
        if any(keys):
            return sizeof(uint32) + count * sizeof(uint64)
        return 0
