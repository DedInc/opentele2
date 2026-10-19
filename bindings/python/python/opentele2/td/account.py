"""1.5.0 ``src/td/account.py``: one account of a Telegram Desktop folder,
read and written by :mod:`opentele2._native` through its
:class:`~opentele2.td.TDesktop`."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from .._compat import BaseObject
from ..api import API, APIData
from .auth import AuthKey, AuthKeyType

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .. import _native
    from .tdesktop import TDesktop

__all__ = ["Account"]

# TDesktop.kDefaultKeyFile, which this module cannot import at load time.
_DEFAULT_KEY_FILE = "data"


def _absolute_path(path: str | None) -> str:
    """1.5.0 ``Storage.GetAbsolutePath``: no path is the working directory."""
    if path is None or path == "":
        path = os.getcwd()
    return os.path.abspath(path)


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
        self.__UserId = account.user_id
        self.__MainDcId = account.main_dc
        self.__authKey = AuthKey(account.auth_key, AuthKeyType.ReadFromFile, account.main_dc)
        self.__isLoaded = True

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
