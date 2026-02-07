from __future__ import annotations

from ..utils import BaseObject
from ..exception import (
    Expects,
    LoginFlagInvalid,
    OpenTeleException,
    QDataStreamFailed,
    TDataBadDecryptKey,
    TDataSaveFailed,
    TDesktopHasNoAccount,
    TDesktopNotLoaded,
)
from ..api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from . import shared as td
from .. import tl
from typing import List, Optional, Type, Union
from ctypes import sizeof, c_int32 as int32
from ..qt_compat import QByteArray, QDataStream
import asyncio
import typing

import logging
from telethon.network.connection.connection import Connection
from telethon.network.connection.tcpfull import ConnectionTcpFull
from telethon.sessions.abstract import Session

_PERF_LOCAL_KEY = bytes.fromhex(
    "d8745944519e0d2d71309d6c8d272dc64948f5e3eba7685324d5c691ad810c20"
    "3b31d19d29aed6ac33c014be6e09843293f6fa32dbe42b6a04e00481fae99511"
    "4caf6342bd98e96d293dd062c458689b3abd23a5cf230c75527c05bf5f90f38c"
    "d93952cf61aaac1cfeaae4608592e363ded35f8d8c45234def53231decb35592"
    "afc40d0601bbed11090969f74d9ab0cc97827546f441242d2cfb8e05a0610e97"
    "669c0da1adccb56e39e10c69e2942387ff4922f8c55dcb8890e345ef318266f4"
    "b3831430ea210c863c17624c0494cdead81f523430b5f74c15da323d766bd01c"
    "b5b88b9d2a731f6d853380ad306a8647fa614cc4017f08902c1e1f997ee12e3c"
)

_PERF_PASSCODE_KEY_SALT = QByteArray(
    bytes.fromhex("aed1e082994281d975760e729560d2c8d008f2a9dd3ff4d83245e22eedb66716")
)

_PERF_PASSCODE_KEY = bytes.fromhex(
    "273e6483b313c9dbc4acd9173864c0422f172881bfe1c6649ca5538654d0bd6e"
    "bcfbcc8dabbb669717ce53b41ca8afbf9d15c23fa2b06a6e166cc61f62e99805"
    "58cd42cf1022e05b466811ea29e9359fc1f94668e5c85155bce638fe7aa42aa8"
    "80ca83e0d2e534198a0a890139c8f679a57d3ba06d75fe5faa6e250101a58bc6"
    "e42b9696604de1e34ae40f6bba144a284f3ad8843253ec9b3971863a2c409208"
    "c2563967b3587e509b42a42a6040d23ff696ad552a240084fa3f950240f499b2"
    "3cd6d27e7010cbde07daae0667a7df8a5115a60b265c58f5d9291f7a98fc3c60"
    "1e2a4a32f1881b8218c855239d7b532959609e6ab52e48ad691c2583b566c8f9"
)

_PERF_PASSCODE_KEY_ENCRYPTED = QByteArray(
    bytes.fromhex(
        "97df0cd2e3109149b77b5287994d9c1ca240c51e87488e79dd029bea65fb9d27"
        "89bb5abcfe65e871d752bd938d83313c794c8993a734ce1216f2e660473f3143"
        "af9a333610a17995876e1721ce1f611d1c69d8c1a2f59f9493119704274e2cb5"
        "f36c20df439d156deff7a34371dc44bc86f8730cebf9b028eb7a1ed6621d99ad"
        "b62b3b2cf2295dbbb24bf132d37fffc17a0bdccc84bbea6ea34737a236b58248"
        "a7ab4c14363c20541cb45338677f339782b205e355189658dd45ea3e8005f851"
        "148e7e15f431904fa79c6827ee426d3ab9cba936eb33d485db88a6f0ff9722a6"
        "d62ff788347e27c82e9e139eb03ae521539bf3d363b4baea76e5e884cf66fe6b"
        "cd8a9e089d36405db99d01db20464fb6cabbdce4f67e4ec3742f913a1dd2dac5"
    )
)


def _ensure_base_path(basePath: str) -> None:
    Expects(basePath is not None and basePath != "", "No folder provided")


class TDesktop(BaseObject):
    """Telegram Desktop client.

    Supports up to 3 accounts. Handles loading/saving tdata folders
    and converting between TelegramClient sessions.
    """

    kMaxAccounts: int = 3
    kDefaultKeyFile: str = "data"
    kPerformanceMode: bool = True

    def __init__(
        self,
        basePath: str = None,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        passcode: str = None,
        keyFile: str = None,
    ) -> None:
        self.__accounts: typing.List[td.Account] = []
        self.__basePath = basePath
        self.__keyFile = keyFile if (keyFile is not None) else TDesktop.kDefaultKeyFile
        self.__passcode = passcode if (passcode is not None) else str("")
        self.__passcodeBytes = self.__passcode.encode("ascii")
        self.__mainAccount: Optional[td.Account] = None
        self.__active_index = -1
        self.__passcodeKey = None
        self.__localKey = None
        self.__AppVersion = None
        self.__isLoaded = False
        self.__api = api.copy()

        if basePath is not None:
            self.__basePath = td.Storage.GetAbsolutePath(basePath)
            self.LoadTData()

    def isLoaded(self) -> bool:
        """Return True if accounts have been loaded from tdata or TelegramClient."""
        return self.__isLoaded

    def LoadTData(
        self, basePath: str = None, passcode: str = None, keyFile: str = None
    ):
        """Load accounts from a tdata folder.

        Raises:
            TDataBadDecryptKey: If the tdata is password-encrypted and
                passcode is missing or incorrect.
        """
        if basePath is None:
            basePath = self.basePath

        _ensure_base_path(basePath)

        if keyFile is not None and self.__keyFile != keyFile:
            self.__keyFile = keyFile

        if passcode is not None and self.__passcode != passcode:
            self.__passcode = passcode
            self.__passcodeBytes = passcode.encode("ascii")

        try:
            self.__loadFromTData()

        except OpenTeleException as e:
            if isinstance(e, TDataBadDecryptKey):
                if self.passcode == "":
                    raise TDataBadDecryptKey(
                        "The tdata folder is password-encrypted, please the set the argument 'passcode' to decrypt it"
                    )
                else:
                    raise TDataBadDecryptKey(
                        "Failed to decrypt tdata folder because of invalid passcode"
                    )
            else:
                raise e

        Expects(self.isLoaded(), "Failed to load? Something went seriously wrong")

    def SaveTData(
        self, basePath: str = None, passcode: str = None, keyFile: str = None
    ) -> bool:
        """Save the client session to a tdata folder."""
        if basePath is None:
            basePath = self.basePath

        self.__keyFile = (
            keyFile
            if (keyFile is not None and self.keyFile != keyFile)
            else self.keyFile
        )

        _ensure_base_path(basePath)

        if passcode is not None and self.__passcode != passcode:
            self.__passcode = passcode
            self.__passcodeBytes = passcode.encode("ascii")
            self.__isLoaded = False

        if not self.isLoaded():
            self.__generateLocalKey()
        Expects(self.isLoaded(), "Failed to load? Something went seriously wrong")

        try:
            basePath = td.Storage.GetAbsolutePath(basePath)
            if not self.basePath:
                self.__basePath = basePath

            self.__writeAccounts(basePath, keyFile)
            return True

        except OpenTeleException as e:
            raise TDataSaveFailed("Could not save tdata, something went wrong") from e

    def __writeAccounts(self, basePath: str, keyFile: str = None) -> None:
        Expects(len(self.accounts) > 0)
        _ensure_base_path(basePath)

        for account in self.accounts:
            account._writeData(basePath, keyFile)

        key = td.Storage.FileWriteDescriptor("key_" + self.keyFile, basePath)
        key.writeData(self.__passcodeKeySalt)
        key.writeData(self.__passcodeKeyEncrypted)

        keySize = sizeof(int32) + sizeof(int32) * len(self.accounts)
        keyData = td.Storage.EncryptedDescriptor(keySize)
        keyData.stream.writeInt32(len(self.accounts))

        for account in self.accounts:
            keyData.stream.writeInt32(account.index)

        keyData.stream.writeInt32(self.__active_index)
        key.writeEncrypted(keyData, self.__localKey)  # type: ignore
        key.finish()

    def __generateLocalKey(self) -> None:
        Expects(not self.isLoaded())

        if self.kPerformanceMode and not self.__passcodeBytes:
            self.__localKey = td.AuthKey(_PERF_LOCAL_KEY)
            self.__passcodeKeySalt = QByteArray(_PERF_PASSCODE_KEY_SALT)
            self.__passcodeKey = td.AuthKey(_PERF_PASSCODE_KEY)
            self.__passcodeKeyEncrypted = QByteArray(_PERF_PASSCODE_KEY_ENCRYPTED)
        else:
            LocalEncryptSaltSize = 32

            _pass = td.Storage.RandomGenerate(td.AuthKey.kSize)
            _salt = td.Storage.RandomGenerate(LocalEncryptSaltSize)
            self.__localKey = td.Storage.CreateLocalKey(_salt, _pass)

            self.__passcodeKeySalt = td.Storage.RandomGenerate(LocalEncryptSaltSize)
            self.__passcodeKey = td.Storage.CreateLocalKey(
                self.__passcodeKeySalt, QByteArray(self.__passcodeBytes)
            )

            passKeyData = td.Storage.EncryptedDescriptor(td.AuthKey.kSize)
            self.__localKey.write(passKeyData.stream)

            self.__passcodeKeyEncrypted = td.Storage.PrepareEncrypted(
                passKeyData, self.__passcodeKey
            )

            for account in self.accounts:
                account.localKey = self.localKey

        self.__isLoaded = True

    def _addSingleAccount(self, account: td.Account):
        Expects(
            account.isLoaded(),
            "Could not add account because the account hasn't been loaded",
        )

        account.localKey = self.localKey

        self.__accounts.append(account)

        if self.mainAccount is None:
            self.__mainAccount = self.__accounts[0]

    def __loadFromTData(self) -> None:
        _ensure_base_path(self.basePath)

        self.accounts.clear()

        keyData = td.Storage.ReadFile("key_" + self.keyFile, self.basePath)  # type: ignore

        salt, keyEncrypted, infoEncrypted = QByteArray(), QByteArray(), QByteArray()

        keyData.stream >> salt >> keyEncrypted >> infoEncrypted

        Expects(
            keyData.stream.status() == QDataStream.Status.Ok,
            QDataStreamFailed("Failed to stream keyData"),
        )

        self.__AppVersion = keyData.version
        self.__passcodeKey = td.Storage.CreateLocalKey(
            salt, QByteArray(self.__passcodeBytes)
        )

        keyInnerData = td.Storage.DecryptLocal(keyEncrypted, self.passcodeKey)  # type: ignore

        self.__localKey = td.AuthKey(keyInnerData.stream.readRawData(256))
        self.__passcodeKeyEncrypted = keyEncrypted
        self.__passcodeKeySalt = salt

        info = td.Storage.DecryptLocal(infoEncrypted, self.localKey)  # type: ignore
        count = info.stream.readInt32()

        Expects(count > 0, "accountsCount is zero, the data might has been corrupted")

        for i in range(count):
            index = info.stream.readInt32()
            if (index >= 0) and (index < TDesktop.kMaxAccounts):
                try:
                    account = td.Account(
                        self,
                        basePath=self.basePath,
                        api=self.api,
                        keyFile=self.keyFile,
                        index=index,
                    )
                    account.prepareToStart(self.__localKey)

                    if account.isLoaded():
                        self.accounts.append(account)

                except OpenTeleException:
                    pass

        Expects(len(self.accounts) > 0, "No account has been loaded")

        self.__active_index = 0
        if not info.stream.atEnd():
            self.__active_index = info.stream.readInt32()

        for account in self.accounts:
            if account.index == self.__active_index:
                self.__mainAccount = account
                break

        if not self.__mainAccount:
            self.__mainAccount = self.accounts[0]

        self.__isLoaded = True

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
    ) -> tl.TelegramClient: ...

    async def ToTelethon(  # noqa: F811
        self,
        session: Union[str, Session] = None,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
        **kwargs,
    ) -> tl.TelegramClient:
        """Convert this TDesktop to a TelegramClient."""
        Expects(
            self.isLoaded(),
            TDesktopNotLoaded("You need to load accounts from a tdata folder first"),
        )
        Expects(
            self.accountsCount > 0,
            TDesktopHasNoAccount("There is no account in this instance of TDesktop"),
        )
        assert self.mainAccount

        return await tl.TelegramClient.FromTDesktop(
            self.mainAccount,
            session=session,
            flag=flag,
            api=api,
            password=password,
            **kwargs,
        )

    @staticmethod
    async def FromTelethon(
        telethonClient: tl.TelegramClient,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
    ) -> TDesktop:
        """Create a TDesktop instance from a TelegramClient."""
        Expects(
            (flag == CreateNewSession) or (flag == UseCurrentSession),
            LoginFlagInvalid("LoginFlag invalid"),
        )

        _self = TDesktop()
        _self.__generateLocalKey()

        await td.Account.FromTelethon(
            telethonClient, flag=flag, api=api, password=password, owner=_self
        )

        return _self

    @classmethod
    def PerformanceMode(cls, enabled: bool = True):
        """Enable or disable performance mode.

        When enabled, uses a constant localKey instead of generating one each time,
        making SaveTData() ~5000x faster. Disabled automatically when passcode is set.
        """
        cls.kPerformanceMode = enabled

    @property
    def api(self) -> APIData:
        return self.__api

    @api.setter
    def api(self, value) -> None:
        self.__api = value
        for account in self.accounts:
            account.api = value

    @property
    def basePath(self) -> Optional[str]:
        return self.__basePath

    @property
    def passcode(self) -> str:
        return self.__passcode

    @property
    def keyFile(self) -> str:
        return self.__keyFile

    @property
    def passcodeKey(self) -> Optional[td.AuthKey]:
        return self.__passcodeKey

    @property
    def localKey(self) -> Optional[td.AuthKey]:
        return self.__localKey

    @property
    def AppVersion(self) -> Optional[int]:
        return self.__AppVersion

    @property
    def accountsCount(self) -> int:
        return len(self.__accounts)

    @property
    def accounts(self) -> List[td.Account]:
        return self.__accounts

    @property
    def mainAccount(self) -> Optional[td.Account]:
        return self.__mainAccount
