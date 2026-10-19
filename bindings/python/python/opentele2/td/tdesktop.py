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

from .. import _native, tl
from .._compat import BaseObject
from .._native import CoreError, TData
from ..api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from ..exception import (
    Expects,
    LoginFlagInvalid,
    MaxAccountLimit,
    OpenTeleException,
    TDataBadDecryptKey,
    TDataSaveFailed,
    TDesktopHasNoAccount,
    TDesktopNotLoaded,
    TFileNotFound,
    raise_core_error,
)
from .account import _DEFAULT_KEY_FILE, Account, _absolute_path
from .auth import AuthKey

if TYPE_CHECKING:
    from collections.abc import Iterable

    from telethon.sessions.abstract import Session
    from typing_extensions import Unpack

    from ..tl.client_kwargs import TelethonClientKwargs

__all__ = ["TDesktop"]

logger = logging.getLogger(__name__)

# 1.5.0's active index of a folder it created, written until one is loaded.
_NEW_FOLDER_ACTIVE_INDEX = -1


def _ensure_base_path(basePath: str | None) -> str:
    if basePath is None or basePath == "":
        raise OpenTeleException("No folder provided")
    return basePath


def _split(draws: list[bytes] | None, count: int) -> tuple[list[bytes] | None, list[bytes] | None]:
    """The first ``count`` draws and the rest; no replay stays no replay."""
    if draws is None:
        return None, None
    return draws[:count], draws[count:]


def _account_state(
    account: _native.Account,
) -> tuple[int, int, int, list[tuple[int, bytes]], bytes | None]:
    """Everything a save writes for ``account``, to compare two of them."""
    return (account.index, account.user_id, account.main_dc, account.keys, account.config)


def _same_accounts(held: list[_native.Account], wanted: list[_native.Account]) -> bool:
    """Whether a folder holding ``held`` already writes exactly ``wanted``."""
    return [_account_state(account) for account in held] == [
        _account_state(account) for account in wanted
    ]


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

        # 1.5.0 writes the accounts listed in self.accounts, so removing one
        # from the list or appending one is saved.
        accounts = [account._core for account in self.accounts]
        written = [core for core in accounts if core is not None]
        if len(written) != len(accounts):
            raise TDataSaveFailed("Could not save tdata, something went wrong")

        folder = self.__folder
        if folder is None or not self.isLoaded() or not _same_accounts(folder.accounts, written):
            # The core keeps a local key only with the accounts it holds, so
            # another account list is written under a new local key.
            plan = _native.draw_plan(
                "new",
                {"has_passcode": self.passcode != "", "performance_mode": self.kPerformanceMode},
            )
            keyDraws, replay = _split(replay, len(plan))
            try:
                folder = TData.new(
                    written,
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
            wrapDraws, replay = _split(replay, len(_native.draw_plan("migrate", folder)))
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
            try:
                if folder.key_file != self.keyFile:
                    # 1.5.0 names the key file and the account files after
                    # keyFile on every save.
                    folder.key_file = self.keyFile
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

    def __newFolder(self) -> TData:
        """A folder holding this instance's accounts under a new local key."""
        folder = self.__folder
        try:
            return TData.new(
                [] if folder is None else folder.accounts,
                self.passcode,
                self.kPerformanceMode,
                _NEW_FOLDER_ACTIVE_INDEX if folder is None else folder.active_index,
            )
        except CoreError as error:
            raise_core_error(error)

    def __generateLocalKey(self) -> None:
        """1.5.0 ``__generateLocalKey``: a new local key for an instance that
        was never loaded."""
        Expects(not self.isLoaded())
        self.__useFolder(self.__newFolder())

    def _addAccount(
        self, userId: int, authKey: AuthKey, api: type[APIData] | APIData = API.TelegramDesktop
    ) -> Account:
        """1.5.0 ``Account.FromTelethon`` on this owner: an account of ``userId``
        holding ``authKey`` as the key of its main DC, at the next index."""
        Expects(
            self.accountsCount < TDesktop.kMaxAccounts,
            exception=MaxAccountLimit("You can't have more than 6 accounts in one TDesktop client"),
        )
        folder = self.__folder
        if folder is None:
            # 1.5.0 holds the accounts of an instance that was never loaded
            # without a local key until it is saved, which generates one; the
            # core holds them in a folder, which a save then replaces.
            folder = self.__newFolder()
            self.__folder = folder
        try:
            index = folder.add_account(userId, authKey.dcId, authKey.key)
        except CoreError as error:
            if error.code == "MAX_ACCOUNT_LIMIT":
                raise MaxAccountLimit(
                    "You can't have more than 6 accounts in one TDesktop client"
                ) from error
            raise_core_error(error)

        account = Account(
            owner=self,
            basePath=self.basePath,
            api=api,
            keyFile=self.keyFile,
            index=index,
        )
        for loaded in folder.accounts:
            if loaded.index == index:
                account._load(loaded)
        self._addSingleAccount(account)
        return account

    def _addSingleAccount(self, account: Account) -> None:
        Expects(
            account.isLoaded(),
            "Could not add account because the account hasn't been loaded",
        )

        account.localKey = self.localKey

        self.__accounts.append(account)

        if self.mainAccount is None:
            self.__mainAccount = self.__accounts[0]

    async def ToTelethon(
        self,
        session: str | Session | None = None,
        flag: type[LoginFlag] = CreateNewSession,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
        **kwargs: Unpack[TelethonClientKwargs],
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
        mainAccount = self.mainAccount
        if mainAccount is None:
            raise TDesktopHasNoAccount("There is no main account in this instance of TDesktop")

        return await tl.TelegramClient.FromTDesktop(
            mainAccount,
            session=session,
            flag=flag,
            api=api,
            password=password,
            **kwargs,
        )

    @staticmethod
    async def FromTelethon(
        telethonClient: tl.TelegramClient,
        flag: type[LoginFlag] = CreateNewSession,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
    ) -> TDesktop:
        """Create a TDesktop instance from a TelegramClient."""
        Expects(
            (flag == CreateNewSession) or (flag == UseCurrentSession),
            LoginFlagInvalid("LoginFlag invalid"),
        )

        _self = TDesktop()
        _self.__generateLocalKey()

        await Account.FromTelethon(
            telethonClient, flag=flag, api=api, password=password, owner=_self
        )

        return _self

    @staticmethod
    async def FromSessionJson(
        session_path: str,
        json_path: str | None = None,
        flag: type[LoginFlag] = UseCurrentSession,
        api: type[APIData] | APIData | None = None,
        password: str | None = None,
    ) -> TDesktop:
        """Create a TDesktop instance from .session + .json files.

        Args:
            session_path: Path to the .session file.
            json_path: Path to the .json metadata file. If None, derived
                       from session_path.
            flag: UseCurrentSession or CreateNewSession.
            api: API to use for the TDesktop. If None, uses the API
                 from the JSON file.
            password: 2FA password for CreateNewSession.

        Returns:
            A loaded TDesktop instance.
        """
        client = await tl.TelegramClient.FromSessionJson(
            session_path,
            json_path,
            flag=UseCurrentSession,
            password=password,
        )
        use_api = api if api is not None else (client._api_data or API.TelegramDesktop)
        try:
            return await TDesktop.FromTelethon(client, flag=flag, api=use_api, password=password)
        finally:
            await tl.TelegramClient._disconnect_client(client, close_session=True)

    async def SaveSessionJson(
        self,
        session_path: str,
        api: type[APIData] | APIData | None = None,
        fetch_user_info: bool = False,
    ) -> tuple[str, str]:
        """Save this TDesktop's session to .session + .json files.

        Args:
            session_path: Output path for the .session file.
            api: APIData for the JSON metadata. Defaults to self.api.
            fetch_user_info: If True and connected, fetch user info.

        Returns:
            Tuple of (session_file_path, json_file_path).
        """
        Expects(
            self.isLoaded(),
            TDesktopNotLoaded("You need to load accounts from a tdata folder first"),
        )
        Expects(
            self.accountsCount > 0,
            TDesktopHasNoAccount("There is no account in this instance of TDesktop"),
        )

        use_api = api if api is not None else self.api
        client = await self.ToTelethon(flag=UseCurrentSession, api=use_api)
        return await client.SaveSessionJson(
            session_path, api=use_api, fetch_user_info=fetch_user_info
        )

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
