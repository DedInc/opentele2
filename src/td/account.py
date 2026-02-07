from __future__ import annotations

from ..utils import BaseObject
from ..exception import (
    Expects,
    LoginFlagInvalid,
    MaxAccountLimit,
    QDataStreamFailed,
    TDAccountNotLoaded,
    TDataAuthKeyNotFound,
    TelethonUnauthorized,
)
from ..api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from .configs import DcId
from . import shared as td
from .. import tl
from .map_data import MapData
from .storage_account import StorageAccount
from typing import List, Optional, Type, Union
from ..qt_compat import QByteArray, QDataStream, QIODevice
import asyncio
import typing

from telethon.network.connection.connection import Connection
from telethon.network.connection.tcpfull import ConnectionTcpFull
from telethon.sessions.abstract import Session

import logging


class Account(BaseObject):
    """Telegram Desktop account."""

    kWideIdsTag: int = int(~0)

    def __init__(
        self,
        owner: td.TDesktop,
        basePath: str = None,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        keyFile: str = None,
        index: int = 0,
    ) -> None:
        self.__owner = owner
        self.__localKey = None
        self.__authKey = None
        self.__isLoaded = False
        self.__isAuthorized = False
        self.__UserId = 0
        self.__MainDcId = DcId(0)

        self.__basePath = td.Storage.GetAbsolutePath(basePath)
        self.__keyFile = (
            keyFile if (keyFile is not None) else td.TDesktop.kDefaultKeyFile
        )

        self.__mtpKeys: typing.List[td.AuthKey] = []
        self.__mtpKeysToDestroy: typing.List[td.AuthKey] = []
        self.api = api

        self._local = StorageAccount(
            self, self.basePath, td.Storage.ComposeDataString(self.__keyFile, index)
        )
        self.index = index

    @property
    def api(self) -> APIData:
        return self.__api

    @api.setter
    def api(self, value) -> None:
        self.__api = value
        if self.owner.api != self.api:
            self.owner.api = self.api

    @property
    def owner(self) -> td.TDesktop:
        return self.__owner

    @property
    def basePath(self) -> str:
        return self.__basePath

    @property
    def keyFile(self) -> str:
        return self.__keyFile

    @keyFile.setter
    def keyFile(self, value):
        self.__keyFile = value
        self._local.keyFile = td.Storage.ComposeDataString(value, self.index)

    @property
    def localKey(self) -> Optional[td.AuthKey]:
        return self.__localKey

    @localKey.setter
    def localKey(self, value):
        self.__localKey = value
        self._local.localKey = value

    @property
    def authKey(self) -> Optional[td.AuthKey]:
        return self.__authKey

    @property
    def UserId(self) -> int:
        return self.__UserId

    @property
    def MainDcId(self) -> DcId:
        return self.__MainDcId

    @property
    def MtpConfig(self) -> td.MTP.Config:
        return self._local.config

    @property
    def MapData(self) -> MapData:
        return self._local.mapData

    def isAuthorized(self) -> bool:
        return self.__isAuthorized

    def isLoaded(self) -> bool:
        return self.__isLoaded

    def prepareToStart(self, localKey: td.AuthKey) -> td.MTP.Config:
        self.__localKey = localKey
        return self._local.start(localKey)

    def _findMainAuthKey(self):
        for key in self.__mtpKeys:
            if key.dcId == self.MainDcId:
                self.__authKey = key
                return
        raise TDataAuthKeyNotFound("Could not find the main authKey")

    def _setMtpAuthorizationCustom(
        self,
        dcId: DcId,
        userId: int,
        mtpKeys: List[td.AuthKey],
        mtpKeysToDestroy: List[td.AuthKey] = None,
    ):
        if mtpKeysToDestroy is None:
            mtpKeysToDestroy = []
        self.__MainDcId = dcId
        self.__UserId = userId
        self.__mtpKeys = mtpKeys
        self._findMainAuthKey()
        self.__isLoaded = True

    def _setMtpAuthorization(self, serialized: QByteArray):
        stream = QDataStream(serialized)
        stream.setVersion(QDataStream.Version.Qt_5_1)

        self.__UserId = stream.readInt32()
        self.__MainDcId = DcId(stream.readInt32())

        if ((self.__UserId << 32) | self.__MainDcId) == Account.kWideIdsTag:
            self.__UserId = stream.readUInt64()
            self.__MainDcId = DcId(stream.readInt32())

        Expects(
            stream.status() == QDataStream.Status.Ok,
            QDataStreamFailed("Could not read main fields from mtp authorization."),
        )

        def readKeys(keys: typing.List[td.AuthKey]):
            key_count = stream.readInt32()
            Expects(
                stream.status() == QDataStream.Status.Ok,
                QDataStreamFailed("Could not read keys count from mtp authorization."),
            )
            for i in range(key_count):
                dcId = DcId(stream.readInt32())
                keys.append(
                    td.AuthKey.FromStream(stream, td.AuthKeyType.ReadFromFile, dcId)
                )

        self.__mtpKeys.clear()
        self.__mtpKeysToDestroy.clear()

        readKeys(self.__mtpKeys)
        readKeys(self.__mtpKeysToDestroy)

        self._findMainAuthKey()
        self.__isLoaded = True

    def serializeMtpAuthorization(self) -> QByteArray:
        Expects(self.isLoaded(), "Account data not loaded yet")

        def writeKeys(stream: QDataStream, keys: typing.List[td.AuthKey]):
            stream.writeInt32(len(keys))
            for key in keys:
                stream.writeInt32(key.dcId)
                stream.writeRawData(key.key)

        result = QByteArray()
        stream = QDataStream(result, QIODevice.OpenModeFlag.WriteOnly)
        stream.setVersion(QDataStream.Version.Qt_5_1)

        stream.writeInt64(Account.kWideIdsTag)
        stream.writeInt64(self.UserId)
        stream.writeInt32(self.MainDcId)

        writeKeys(stream, self.__mtpKeys)
        writeKeys(stream, self.__mtpKeysToDestroy)
        return result

    def _writeData(self, baseGlobalPath: str, keyFile: str = None) -> None:
        self._local._writeData(baseGlobalPath, keyFile)

    def SaveTData(
        self, basePath: str = None, passcode: str = None, keyFile: str = None
    ) -> None:
        """Save this account to a tdata folder."""
        if basePath is None:
            basePath = self.basePath

        basePath = td.Storage.GetAbsolutePath(basePath)

        if self.basePath is None:
            self.__basePath = basePath

        self.owner.SaveTData(basePath, passcode, keyFile)

    @typing.overload
    async def ToTelethon(
        self,
        session: Union[str, Session] = None,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
        *,
        connection: typing.Type[Connection] = ConnectionTcpFull,
        use_ipv6: bool = False,
        proxy: Union[tuple, dict] = None,
        local_addr: Union[str, tuple] = None,
        timeout: int = 10,
        request_retries: int = 5,
        connection_retries: int = 5,
        retry_delay: int = 1,
        auto_reconnect: bool = True,
        sequential_updates: bool = False,
        flood_sleep_threshold: int = 60,
        raise_last_call_error: bool = False,
        loop: asyncio.AbstractEventLoop = None,
        base_logger: Union[str, logging.Logger] = None,
        receive_updates: bool = True,
    ) -> tl.TelegramClient:
        pass

    async def ToTelethon(  # noqa: F811
        self,
        session: Union[str, Session] = None,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
        **kwargs,
    ) -> tl.TelegramClient:
        Expects(
            self.isLoaded(),
            TDAccountNotLoaded("Account not loaded yet"),
        )

        return await tl.TelegramClient.FromTDesktop(
            self, session=session, flag=flag, api=api, password=password, **kwargs
        )

    @staticmethod
    async def FromTelethon(
        telethonClient: tl.TelegramClient,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
        owner: td.TDesktop = None,
    ):
        Expects(
            (flag == CreateNewSession) or (flag == UseCurrentSession),
            LoginFlagInvalid("LoginFlag invalid"),
        )

        if flag == CreateNewSession:
            if not telethonClient.is_connected():
                try:
                    await telethonClient.connect()
                except OSError as e:
                    raise TelethonUnauthorized(
                        "Could not connect telethon client to the server"
                    ) from e

                Expects(
                    await telethonClient.is_user_authorized(),
                    exception=TelethonUnauthorized("Telethon client is unauthorized"),
                )

            copy = await telethonClient.QRLoginToNewClient(api=api, password=password)
            await copy.get_me()
        else:
            copy = telethonClient

        ss = copy.session
        authKey = ss.auth_key.key
        dcId = DcId(ss.dc_id)
        userId = copy.UserId
        authKey = td.AuthKey(authKey, td.AuthKeyType.ReadFromFile, dcId)

        if userId is None:
            await copy.connect()
            await copy.get_me()
            userId = copy.UserId

        if owner is not None:
            Expects(
                owner.accountsCount < td.TDesktop.kMaxAccounts,
                exception=MaxAccountLimit(
                    "You can't have more than 3 accounts in one TDesktop client"
                ),
            )

            index = owner.accountsCount
            newAccount = Account(
                owner=owner,
                basePath=owner.basePath,
                api=api,
                keyFile=owner.keyFile,
                index=index,
            )
            newAccount._setMtpAuthorizationCustom(dcId, userId, [authKey])  # type: ignore
            owner._addSingleAccount(newAccount)
        else:
            index = 0
            newOwner = td.TDesktop()
            newAccount = Account(owner=newOwner, api=api, index=index)
            newAccount._setMtpAuthorizationCustom(dcId, userId, [authKey])  # type: ignore
            newOwner._addSingleAccount(newAccount)

        return newAccount
