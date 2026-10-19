"""1.5.0 ``src/td/account.py``: one account of a Telegram Desktop folder,
read and written by :mod:`opentele2._native` through its
:class:`~opentele2.td.TDesktop`."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from .. import _native, tl
from .._compat import BaseObject
from ..api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from ..exception import (
    Expects,
    LoginFlagInvalid,
    TDAccountNotLoaded,
    TelethonUnauthorized,
)
from .auth import AuthKey, AuthKeyType

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Literal

    from telethon.sessions.abstract import Session
    from typing_extensions import Unpack

    from .._native import Endpoint, Endpoints, MtpConfigFields, RsaPublicKey
    from ..tl.client_kwargs import TelethonClientKwargs
    from .tdesktop import TDesktop

__all__ = ["Account"]

# TDesktop.kDefaultKeyFile, which this module cannot import at load time.
_DEFAULT_KEY_FILE = "data"


def _absolute_path(path: str | None) -> str:
    """1.5.0 ``Storage.GetAbsolutePath``: no path is the working directory."""
    if path is None or path == "":
        path = os.getcwd()
    return os.path.abspath(path)


class MtpConfigView(BaseObject):
    """1.5.0 ``Account.MtpConfig``, read only: the MTP config of one loaded
    account as ``_native.account_mtp_config`` parses it, or the production
    default for no account. Every read returns a new copy, so editing a
    result changes nothing that is saved."""

    def __init__(self, account: _native.Account | None) -> None:
        self.__account = account

    @property
    def environment(self) -> Literal["production", "test"]:
        return _native.account_mtp_config(self.__account)["environment"]

    def isTestMode(self) -> bool:
        return self.environment != "production"

    @property
    def dcOptions(self) -> dict[int, list[Endpoint]]:
        """The endpoints of every DC, by DC id, in the stored order."""
        dcs = _native.account_mtp_config(self.__account)["dcs"]
        return {dc["dc_id"]: dc["endpoints"] for dc in dcs}

    @property
    def cdnPublicKeys(self) -> list[RsaPublicKey]:
        return _native.account_mtp_config(self.__account)["cdn_public_keys"]

    @property
    def fields(self) -> MtpConfigFields:
        return _native.account_mtp_config(self.__account)["fields"]

    def endpoints(self, dcId: int | None = None) -> Endpoints | None:
        """The endpoints of ``dcId`` (the account's main DC by default) by
        address family and protocol, as 1.5.0 ``MTP.Config.endpoints``
        sorted them; None when the config lists no such DC."""
        return _native.account_endpoints(self.__account, dcId)


class Account(BaseObject):
    kWideIdsTag: int = ~0

    def __init__(
        self,
        owner: TDesktop,
        basePath: str | None = None,
        api: type[APIData] | APIData = API.TelegramDesktop,
        keyFile: str | None = None,
        index: int = 0,
    ) -> None:
        self.__owner = owner
        self.__localKey: AuthKey | None = None
        self.__authKey: AuthKey | None = None
        self.__core: _native.Account | None = None
        self.__isLoaded = False
        self.__isAuthorized = False
        self.__UserId = 0
        self.__MainDcId = 0

        self.__basePath = _absolute_path(basePath)
        self.__keyFile = keyFile if (keyFile is not None) else _DEFAULT_KEY_FILE
        self.api = api
        self.index = index

    def _load(self, account: _native.Account) -> None:
        """Takes the user, main DC and main auth key of a loaded account."""
        self.__core = account
        self.__UserId = account.user_id
        self.__MainDcId = account.main_dc
        self.__authKey = AuthKey(account.auth_key, AuthKeyType.ReadFromFile, account.main_dc)
        self.__isLoaded = True

    @property
    def _core(self) -> _native.Account | None:
        """The core account this one was loaded from, None until loaded."""
        return self.__core

    @property
    def api(self) -> type[APIData] | APIData:
        return self.__api

    @api.setter
    def api(self, value: type[APIData] | APIData) -> None:
        self.__api = value
        if self.owner.api != self.api:
            self.owner.api = self.api

    @property
    def owner(self) -> TDesktop:
        return self.__owner

    @property
    def basePath(self) -> str:
        return self.__basePath

    @property
    def keyFile(self) -> str:
        return self.__keyFile

    @keyFile.setter
    def keyFile(self, value: str) -> None:
        self.__keyFile = value

    @property
    def localKey(self) -> AuthKey | None:
        return self.__localKey

    @localKey.setter
    def localKey(self, value: AuthKey | None) -> None:
        self.__localKey = value

    @property
    def authKey(self) -> AuthKey | None:
        return self.__authKey

    @property
    def UserId(self) -> int:
        return self.__UserId

    @property
    def MainDcId(self) -> int:
        return self.__MainDcId

    @property
    def MtpConfig(self) -> MtpConfigView:
        """The account's MTP config, as 1.5.0 read it from the folder: the
        production default when the folder stores none or it does not parse.
        An account that was never loaded has the production default, as
        1.5.0 starts every account with it."""
        return MtpConfigView(self.__core)

    def isAuthorized(self) -> bool:
        return self.__isAuthorized

    def isLoaded(self) -> bool:
        return self.__isLoaded

    def SaveTData(
        self,
        basePath: str | None = None,
        passcode: str | None = None,
        keyFile: str | None = None,
        *,
        draws: Iterable[bytes] | None = None,
    ) -> None:
        """Saves the owner's folder; see :meth:`TDesktop.SaveTData`."""
        if basePath is None:
            basePath = self.basePath
        self.owner.SaveTData(_absolute_path(basePath), passcode, keyFile, draws=draws)

    async def ToTelethon(
        self,
        session: str | Session | None = None,
        flag: type[LoginFlag] = CreateNewSession,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
        **kwargs: Unpack[TelethonClientKwargs],
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
        flag: type[LoginFlag] = CreateNewSession,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
        owner: TDesktop | None = None,
    ) -> Account:
        Expects(
            (flag == CreateNewSession) or (flag == UseCurrentSession),
            LoginFlagInvalid("LoginFlag invalid"),
        )

        copy: tl.TelegramClient | None = None
        should_disconnect_copy = flag == CreateNewSession

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

        try:
            ss = copy.session
            sessionKey = ss.auth_key
            if sessionKey is None:
                raise TelethonUnauthorized("Telethon client is unauthorized")
            dcId = ss.dc_id
            userId = copy.UserId
            authKey = AuthKey(sessionKey.key, AuthKeyType.ReadFromFile, dcId)

            if userId is None:
                await copy.connect()
                await copy.get_me()
                userId = copy.UserId
            if userId is None:
                raise TelethonUnauthorized("Could not resolve the account's user id")

            if owner is None:
                # The tdesktop module imports this one, so it is only
                # importable once both have loaded.
                from .tdesktop import TDesktop

                owner = TDesktop()
            return owner._addAccount(userId, authKey, api)
        finally:
            if should_disconnect_copy and copy is not None:
                await tl.TelegramClient._disconnect_client(copy, close_session=True)
