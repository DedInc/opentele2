"""1.5.0 ``src/td/tdesktop.py``: a Telegram Desktop ``tdata`` folder, loaded
and saved by :mod:`opentele2._native`.

Saving replays nothing by default; the ``draws`` hook of ``SaveTData``
replaces the OS random source with recorded draws, the ``os.urandom`` calls
1.5.0 made for the same save, so that a save can be compared byte for byte
with a folder 1.5.0 wrote.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .._compat import BaseObject
from .._native import CoreError, TData
from ..api import API, APIData
from ..exception import (
    Expects,
    OpenTeleException,
    TDataBadDecryptKey,
    TDataSaveFailed,
    TFileNotFound,
    raise_core_error,
)
from .account import _DEFAULT_KEY_FILE, Account, _absolute_path
from .auth import AuthKey

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["TDesktop"]

logger = logging.getLogger(__name__)

# 1.5.0's active index of a folder it created, written until one is loaded.
_NEW_FOLDER_ACTIVE_INDEX = -1


def _ensure_base_path(basePath: str | None) -> str:
    if basePath is None or basePath == "":
        raise OpenTeleException("No folder provided")
    return basePath


def _wrap_draws(passcode: str) -> int:
    """The draws of a 7.3 key wrap in 1.5.0: the open salt, a passcode wrap
    salt when there is a passcode, and the wrap padding."""
    return 3 if passcode else 2


def _key_draws(passcode: str, performance_mode: bool) -> int:
    """The draws of a new local key in 1.5.0: its pass and salt, then its
    wrap; none for the fixed performance-mode keys."""
    if performance_mode and not passcode:
        return 0
    return 2 + _wrap_draws(passcode)


def _split(draws: list[bytes] | None, count: int) -> tuple[list[bytes] | None, list[bytes] | None]:
    """The first ``count`` draws and the rest; no replay stays no replay."""
    if draws is None:
        return None, None
    return draws[:count], draws[count:]


class TDesktop(BaseObject):
    """Telegram Desktop client.

    Supports up to 6 accounts. Handles loading/saving tdata folders.
    """

    kMaxAccounts: int = 6
    kDefaultKeyFile: str = _DEFAULT_KEY_FILE
    kPerformanceMode: bool = True

    def __init__(
        self,
        basePath: str | None = None,
        api: type[APIData] | APIData = API.TelegramDesktop,
        passcode: str | None = None,
        keyFile: str | None = None,
    ) -> None:
        self.__accounts: list[Account] = []
        self.__basePath = basePath
        self.__keyFile = keyFile if (keyFile is not None) else TDesktop.kDefaultKeyFile
        self.__passcode = passcode if (passcode is not None) else ""
        self.__mainAccount: Account | None = None
        self.__folder: TData | None = None
        self.__passcodeKey: AuthKey | None = None
        self.__localKey: AuthKey | None = None
        self.__AppVersion: int | None = None
        self.__isLoaded = False
        self.__api = api.copy()

        if basePath is not None:
            self.__basePath = _absolute_path(basePath)
            self.LoadTData()

    def isLoaded(self) -> bool:
        """Return True if accounts have been loaded from tdata."""
        return self.__isLoaded

    def LoadTData(
        self,
        basePath: str | None = None,
        passcode: str | None = None,
        keyFile: str | None = None,
    ) -> None:
        """Load accounts from the tdata folder at :attr:`basePath`.

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

        # 1.5.0 checks the argument but reads the folder at basePath.
        folderPath = _ensure_base_path(self.basePath)
        self.__accounts.clear()
        try:
            folder = TData.load(folderPath, self.__passcode, self.__keyFile)
        except CoreError as error:
            # The core skips accounts whose files fail to read, so only the
            # key file is ever missing, and no account loading is the one
            # reason it reports a missing auth key.
            if error.code == "TDATA_BAD_DECRYPT_KEY":
                if self.passcode == "":
                    raise TDataBadDecryptKey(
                        "The tdata folder is password-encrypted, please "
                        "the set the argument 'passcode' to decrypt it"
                    ) from error
                raise TDataBadDecryptKey(
                    "Failed to decrypt tdata folder because of invalid passcode"
                ) from error
            if error.code == "TFILE_NOT_FOUND":
                raise TFileNotFound(f"Could not open key_{self.__keyFile}") from error
            if error.code == "TDATA_AUTH_KEY_NOT_FOUND":
                raise OpenTeleException("No account has been loaded") from error
            raise_core_error(error)

        if len(folder.accounts) > TDesktop.kMaxAccounts:
            # tdesktop 7.3.1 caps this at 6, but a later build may raise the
            # cap without changing the format, so read what is there.
            logger.warning(
                f"tdata lists {len(folder.accounts)} accounts, above the "
                f"{TDesktop.kMaxAccounts} known to Telegram Desktop 7.3.1; loading them anyway"
            )

        self.__useFolder(folder)
        self.__AppVersion = folder.app_version
        for loaded in folder.accounts:
            account = Account(
                self,
                basePath=folderPath,
                api=self.api,
                keyFile=self.keyFile,
                index=loaded.index,
            )
            account._load(loaded)
            account.localKey = self.localKey
            self.__accounts.append(account)

        main = folder.main_account
        self.__mainAccount = None
        for account in self.__accounts:
            if main is not None and account.index == main.index:
                self.__mainAccount = account
                break

        Expects(self.isLoaded(), "Failed to load? Something went seriously wrong")

    def SaveTData(
        self,
        basePath: str | None = None,
        passcode: str | None = None,
        keyFile: str | None = None,
        *,
        draws: Iterable[bytes] | None = None,
    ) -> bool:
        """Save the accounts to a tdata folder.

        A new passcode, or a folder never loaded, gets a new local key; a
        loaded pre-7.3 key file is migrated to 7.3 once, keeping its local
        key. :attr:`kPerformanceMode` picks the fixed keys for a new local
        key without a passcode, and leaves the ``configs`` files out.

        ``draws``, a testing hook, replays exactly the ``os.urandom`` draws
        1.5.0 made for this save, in order, instead of the OS random source.
        """
        # An OpenTeleException lists the arguments of the frame raising it,
        # so the replayed draws (key material) leave the argument list.
        replay = None if draws is None else [bytes(draw) for draw in draws]
        draws = None

        if basePath is None:
            basePath = self.basePath

        self.__keyFile = (
            keyFile if (keyFile is not None and self.keyFile != keyFile) else self.keyFile
        )

        basePath = _ensure_base_path(basePath)

        if passcode is not None and self.__passcode != passcode:
            self.__passcode = passcode
            self.__isLoaded = False

        folder = self.__folder
        if folder is None or not self.isLoaded():
            keyDraws, replay = _split(replay, _key_draws(self.passcode, self.kPerformanceMode))
            try:
                folder = TData.new(
                    [] if folder is None else folder.accounts,
                    self.passcode,
                    self.kPerformanceMode,
                    _NEW_FOLDER_ACTIVE_INDEX if folder is None else folder.active_index,
                    draws=keyDraws,
                )
            except CoreError as error:
                raise_core_error(error)
            self.__useFolder(folder)
        elif folder.legacy_key_file:
            # tdesktop 7.3 migrates a pre-7.3 key file on start; write the
            # migrated shape directly, keeping the local key the accounts use.
            wrapDraws, replay = _split(replay, _wrap_draws(self.passcode))
            try:
                folder.migrate(draws=wrapDraws)
            except CoreError as error:
                raise_core_error(error)
            self.__passcodeKey = AuthKey(folder.passcode_key)
        Expects(self.isLoaded(), "Failed to load? Something went seriously wrong")

        try:
            basePath = _absolute_path(basePath)
            if not self.basePath:
                self.__basePath = basePath

            Expects(len(self.accounts) > 0)
            if folder.key_file != self.keyFile:
                raise NotImplementedError(
                    f"opentele2._native writes the key file {folder.key_file!r} of this "
                    f"folder and cannot write it as {self.keyFile!r}"
                )
            try:
                folder.save(basePath, self.kPerformanceMode, draws=replay)
            except CoreError as error:
                raise_core_error(error)
            return True

        except OpenTeleException as e:
            raise TDataSaveFailed("Could not save tdata, something went wrong") from e

    def __useFolder(self, folder: TData) -> None:
        """Holds ``folder`` and hands its local key to every account."""
        self.__folder = folder
        self.__localKey = AuthKey(folder.local_key)
        self.__passcodeKey = AuthKey(folder.passcode_key)
        for account in self.__accounts:
            account.localKey = self.__localKey
        self.__isLoaded = True

    @classmethod
    def PerformanceMode(cls, enabled: bool = True) -> None:
        """Enable or disable performance mode.

        When enabled, uses a constant localKey instead of generating one each time,
        making SaveTData() ~5000x faster. Disabled automatically when passcode is set.
        """
        cls.kPerformanceMode = enabled

    @property
    def api(self) -> type[APIData] | APIData:
        return self.__api

    @api.setter
    def api(self, value: type[APIData] | APIData) -> None:
        self.__api = value
        for account in self.accounts:
            account.api = value

    @property
    def basePath(self) -> str | None:
        return self.__basePath

    @property
    def passcode(self) -> str:
        return self.__passcode

    @property
    def keyFile(self) -> str:
        return self.__keyFile

    @property
    def passcodeKey(self) -> AuthKey | None:
        return self.__passcodeKey

    @property
    def localKey(self) -> AuthKey | None:
        return self.__localKey

    @property
    def AppVersion(self) -> int | None:
        return self.__AppVersion

    @property
    def accountsCount(self) -> int:
        return len(self.__accounts)

    @property
    def accounts(self) -> list[Account]:
        return self.__accounts

    @property
    def mainAccount(self) -> Account | None:
        return self.__mainAccount
