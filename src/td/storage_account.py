from __future__ import annotations

from ctypes import sizeof, c_uint32 as uint32
from typing import Optional, TYPE_CHECKING

from ..qt_compat import QByteArray

from ..exception import (
    AccountAuthKeyNotFound,
    Expects,
    ExpectStreamStatus,
    OpenTeleException,
    TDataInvalidMagic,
)
from ..utils import BaseObject
from .configs import dbi
from . import shared as td
from .map_data import MapData

if TYPE_CHECKING:
    from .account import Account


class StorageAccount(BaseObject):  # nocov
    def __init__(self, owner: Account, basePath: str, keyFile: str) -> None:
        self.__owner = owner
        self.__keyFile = keyFile
        self.__dataNameKey = td.Storage.ComputeDataNameKey(self.__keyFile)
        self.__baseGlobalPath = td.Storage.GetAbsolutePath(basePath)
        self.__basePath = td.Storage.PathJoin(
            self.__baseGlobalPath, td.Storage.ToFilePart(self.__dataNameKey)
        )
        self.__localKey = None
        self.__mapData = MapData(self.basePath)
        self.__config = td.MTP.Config(td.MTP.Environment.Production)

    @property
    def owner(self) -> Account:
        return self.__owner

    @property
    def localKey(self) -> Optional[td.AuthKey]:
        return self.__localKey

    @localKey.setter
    def localKey(self, value):
        self.__localKey = value

    @property
    def keyFile(self) -> str:
        return self.__keyFile

    @keyFile.setter
    def keyFile(self, value):
        self.__keyFile = value
        self.__dataNameKey = td.Storage.ComputeDataNameKey(self.__keyFile)
        self.baseGlobalPath = self.baseGlobalPath

    @property
    def baseGlobalPath(self) -> str:
        return self.__baseGlobalPath

    @baseGlobalPath.setter
    def baseGlobalPath(self, basePath):
        self.__baseGlobalPath = td.Storage.GetAbsolutePath(basePath)
        self.__basePath = td.Storage.PathJoin(
            self.__baseGlobalPath, td.Storage.ToFilePart(self.__dataNameKey)
        )

    @property
    def basePath(self) -> str:
        return self.__basePath

    @property
    def config(self) -> td.MTP.Config:
        return self.__config

    @property
    def mapData(self) -> MapData:
        return self.__mapData

    def start(self, localKey: td.AuthKey) -> td.MTP.Config:
        self.__localKey = localKey
        self._readMapWith(localKey)
        return (
            self.__config
            if self.owner.owner.kPerformanceMode
            else self._readMtpConfig()
        )

    def _readMtpData(self):
        mtp = td.Storage.ReadEncryptedFile(
            td.Storage.ToFilePart(self.__dataNameKey),
            self.__baseGlobalPath,
            self.localKey,
        )  # type: ignore

        blockId = mtp.stream.readInt32()
        Expects(blockId == 75, TDataInvalidMagic("Not supported file version"))

        serialized = QByteArray()
        mtp.stream >> serialized
        self.owner._setMtpAuthorization(serialized)

    def _readMtpConfig(self) -> td.MTP.Config:
        Expects(
            self.localKey is not None,
            AccountAuthKeyNotFound("The localKey has not been initialized yet"),
        )

        try:
            file = td.Storage.ReadEncryptedFile("config", self.basePath, self.localKey)  # type: ignore
            serialized = QByteArray()
            file.stream >> serialized
            ExpectStreamStatus(file.stream, "Could not stream data from MtpConfig")
            self.__config = td.MTP.Config.FromSerialized(serialized)
            return self.__config
        except OpenTeleException:
            pass

        return td.MTP.Config(td.MTP.Environment.Production)

    def _readMapWith(
        self, localKey: td.AuthKey, legacyPasscode: QByteArray = QByteArray()
    ):
        try:
            self.__mapData.read(localKey, legacyPasscode)
        except OpenTeleException:
            return False

        self._readMtpData()

    def _writeMtpConfig(self, basePath: str) -> None:
        Expects(self.localKey is not None, "localKey not found")
        Expects(basePath is not None and basePath != "", "basePath can't be empty")

        serialized = self.owner.MtpConfig.Serialize()
        size = td.Serialize.bytearraySize(serialized)
        file = td.Storage.FileWriteDescriptor("config", basePath)
        data = td.Storage.EncryptedDescriptor(size)
        data.stream << serialized
        file.writeEncrypted(data, self.localKey)  # type: ignore
        file.finish()

    def _writeMap(self, basePath: str) -> None:
        Expects(self.localKey is not None, "localKey not found")
        Expects(basePath is not None and basePath != "", "basePath can't be empty")

        map = td.Storage.FileWriteDescriptor("map", basePath)
        map.writeData(QByteArray())
        map.writeData(QByteArray())

        mapDataEncrypted = self.mapData.prepareToWrite()
        map.writeEncrypted(mapDataEncrypted, self.localKey)  # type: ignore
        map.finish()

    def _writeMtpData(self, baseGlobalPath: str, dataNameKey: int) -> None:
        Expects(self.localKey is not None, "localKey not found")
        Expects(
            baseGlobalPath is not None and baseGlobalPath != "",
            "baseGlobalPath can't be empty",
        )

        serialized = self.owner.serializeMtpAuthorization()
        size = sizeof(uint32) + td.Serialize.bytearraySize(serialized)
        mtp = td.Storage.FileWriteDescriptor(
            td.Storage.ToFilePart(dataNameKey), baseGlobalPath
        )
        data = td.Storage.EncryptedDescriptor(size)
        data.stream.writeInt32(dbi.MtpAuthorization)
        data.stream << serialized
        mtp.writeEncrypted(data, self.localKey)  # type: ignore
        mtp.finish()

    def _writeData(self, baseGlobalPath: str, keyFile: str = None) -> None:
        Expects(
            baseGlobalPath is not None and baseGlobalPath != "",
            "baseGlobalPath can't be empty",
        )

        if keyFile is not None and self.keyFile != keyFile:
            self.__keyFile = keyFile
            dataNameKey = td.Storage.ComputeDataNameKey(self.__keyFile)
        else:
            dataNameKey = self.__dataNameKey

        basePath = td.Storage.PathJoin(
            baseGlobalPath, td.Storage.ToFilePart(dataNameKey)
        )
        self._writeMap(basePath)

        if not self.owner.owner.kPerformanceMode:
            self._writeMtpConfig(basePath)

        self._writeMtpData(baseGlobalPath, dataNameKey)
