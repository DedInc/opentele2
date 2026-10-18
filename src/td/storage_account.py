from __future__ import annotations

from ctypes import c_uint32 as uint32
from ctypes import sizeof
from typing import TYPE_CHECKING

from ..exception import (
    AccountAuthKeyNotFound,
    Expects,
    ExpectStreamStatus,
    OpenTeleException,
    TDataInvalidMagic,
)
from ..qt_compat import QByteArray
from ..utils import BaseObject
from . import shared as td
from .configs import DcId, dbi
from .map_data import MapData

if TYPE_CHECKING:
    from .account import Account


class TDataAccountMapReadFailed(OpenTeleException):
    """The map file of a single account could not be read."""


class StorageAccount(BaseObject):
    def __init__(self, owner: Account, basePath: str, keyFile: str) -> None:
        self.__owner = owner
        self.__keyFile = keyFile
        self.__dataNameKey = td.Storage.ComputeDataNameKey(self.__keyFile)
        self.__baseGlobalPath = td.Storage.GetAbsolutePath(basePath)
        self.__basePath = td.Storage.PathJoin(
            self.__baseGlobalPath, td.Storage.ToFilePart(self.__dataNameKey)
        )
        self.__localKey: td.AuthKey | None = None
        self.__mapData = MapData(self.basePath)
        self.__config = td.MTP.Config(td.MTP.Environment.Production)

    @property
    def owner(self) -> Account:
        return self.__owner

    @property
    def localKey(self) -> td.AuthKey | None:
        return self.__localKey

    @localKey.setter
    def localKey(self, value: td.AuthKey | None) -> None:
        self.__localKey = value

    def _requireLocalKey(self) -> td.AuthKey:
        localKey = self.__localKey
        if localKey is None:
            raise AccountAuthKeyNotFound(
                f"The localKey of account {self.__keyFile!r} "
                "has not been initialized yet"
            )
        return localKey

    @property
    def keyFile(self) -> str:
        return self.__keyFile

    @keyFile.setter
    def keyFile(self, value: str) -> None:
        self.__keyFile = value
        self.__dataNameKey = td.Storage.ComputeDataNameKey(self.__keyFile)
        self.baseGlobalPath = self.baseGlobalPath

    @property
    def baseGlobalPath(self) -> str:
        return self.__baseGlobalPath

    @baseGlobalPath.setter
    def baseGlobalPath(self, basePath: str) -> None:
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
        if self._readMapWith(localKey) is False:
            raise TDataAccountMapReadFailed(
                "Could not read the map of account "
                f"{self.__keyFile!r} at {self.basePath!r}"
            )
        return (
            self.__config
            if self.owner.owner.kPerformanceMode
            else self._readMtpConfig()
        )

    def _readMtpData(self) -> None:
        mtp = td.Storage.ReadEncryptedFile(
            td.Storage.ToFilePart(self.__dataNameKey),
            self.__baseGlobalPath,
            self._requireLocalKey(),
        )

        context = td.Storage.ReadSettingsContext()

        while not mtp.stream.atEnd():
            blockId = mtp.stream.readUInt32()
            ExpectStreamStatus(mtp.stream, "Could not read a block id from MtpData")
            Expects(
                td.Storage.ReadSetting(blockId, mtp.stream, mtp.version, context),
                TDataInvalidMagic(f"Unsupported block id in MtpData: {blockId}"),
            )

        ExpectStreamStatus(mtp.stream, "Could not stream data from MtpData")
        self._applyReadContext(context)

    def _applyReadContext(self, context: td.Storage.ReadSettingsContext) -> None:
        if not context.mtpAuthorization.isEmpty():
            self.owner._setMtpAuthorization(context.mtpAuthorization)
        elif context.mtpLegacyKeys or context.mtpLegacyMainDcId:
            self.owner._setMtpAuthorizationCustom(
                DcId(context.mtpLegacyMainDcId),
                context.mtpLegacyUserId,
                list(context.mtpLegacyKeys),
            )

    def _readMtpConfig(self) -> td.MTP.Config:
        localKey = self._requireLocalKey()

        try:
            file = td.Storage.ReadEncryptedFile("config", self.basePath, localKey)
            serialized = QByteArray()
            file.stream >> serialized
            ExpectStreamStatus(file.stream, "Could not stream data from MtpConfig")
            self.__config = td.MTP.Config.FromSerialized(serialized)
            return self.__config
        except OpenTeleException:
            pass

        return td.MTP.Config(td.MTP.Environment.Production)

    def _readMapWith(
        self, localKey: td.AuthKey, legacyPasscode: QByteArray | None = None
    ) -> bool | None:
        try:
            self.__mapData.read(
                localKey,
                legacyPasscode if legacyPasscode is not None else QByteArray(),
            )
        except OpenTeleException:
            return False

        self._readMtpData()

    def _writeMtpConfig(self, basePath: str) -> None:
        localKey = self._requireLocalKey()
        Expects(basePath is not None and basePath != "", "basePath can't be empty")

        serialized = self.owner.MtpConfig.Serialize()
        size = td.Serialize.bytearraySize(serialized)
        file = td.Storage.FileWriteDescriptor("config", basePath)
        data = td.Storage.EncryptedDescriptor(size)
        data.stream << serialized
        file.writeEncrypted(data, localKey)
        file.finish()

    def _writeMap(self, basePath: str) -> None:
        localKey = self._requireLocalKey()
        Expects(basePath is not None and basePath != "", "basePath can't be empty")

        map = td.Storage.FileWriteDescriptor("map", basePath)
        map.writeData(QByteArray())
        map.writeData(QByteArray())

        mapDataEncrypted = self.mapData.prepareToWrite()
        map.writeEncrypted(mapDataEncrypted, localKey)
        map.finish()

    def _writeMtpData(self, baseGlobalPath: str, dataNameKey: int) -> None:
        localKey = self._requireLocalKey()
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
        mtp.writeEncrypted(data, localKey)
        mtp.finish()

    def _writeData(self, baseGlobalPath: str, keyFile: str | None = None) -> None:
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
