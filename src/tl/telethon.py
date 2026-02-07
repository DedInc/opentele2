from __future__ import annotations

from ..utils import (
    BaseObject,
    extend_class,
    extend_override_class,
    override,
    PrettyTable,
)
from ..exception import (
    Expects,
    LoginFlagInvalid,
    NoPasswordProvided,
    PasswordIncorrect,
    TDesktopHasNoAccount,
    TDesktopNotLoaded,
    TDesktopUnauthorized,
)
from ..api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from .. import td

import telethon
from telethon.crypto import AuthKey
from telethon import functions, types, password as pwd_mod
from telethon.network.connection.connection import Connection
from telethon.network.connection.tcpfull import ConnectionTcpFull
from telethon.sessions.abstract import Session
from telethon.sessions.sqlite import SQLiteSession
from telethon.sessions.memory import MemorySession
from typing import Optional, Type, Union
import asyncio
import typing

from telethon.errors.rpcerrorlist import (
    PasswordHashInvalidError,
    AuthTokenAlreadyAcceptedError,
    AuthTokenExpiredError,
    AuthTokenInvalidError,
    FreshResetAuthorisationForbiddenError,
    HashInvalidError,
)
from telethon.tl.types import TypeInputClientProxy, TypeJSONValue
import warnings
import datetime
from typing import Awaitable, TYPE_CHECKING

if TYPE_CHECKING:
    import logging

_DEFAULT_REQUEST_RETRIES = 5
_QR_EXPIRE_SAFETY_SECONDS = 5

_API_FIELDS = [
    "api_id",
    "device_model",
    "system_version",
    "app_version",
    "system_lang_code",
    "lang_pack",
    "lang_code",
]


@extend_override_class
class CustomInitConnectionRequest(functions.InitConnectionRequest):
    def __init__(
        self,
        api_id: int,
        device_model: str,
        system_version: str,
        app_version: str,
        system_lang_code: str,
        lang_pack: str,
        lang_code: str,
        query,
        proxy: TypeInputClientProxy = None,
        params: TypeJSONValue = None,
    ):
        data = APIData.findData(device_model)  # type: ignore
        if data is not None:
            local_vals = locals()
            for field in _API_FIELDS:
                data_val = getattr(data, field)
                setattr(self, field, data_val if data_val else local_vals.get(field))
            data.destroy()
        else:
            self.api_id = api_id
            self.device_model = device_model
            self.system_version = system_version
            self.app_version = app_version
            self.system_lang_code = system_lang_code
            self.lang_pack = lang_pack
            self.lang_code = lang_code

        self.query = query
        self.proxy = proxy
        self.params = params


@extend_class
class TelegramClient(telethon.TelegramClient, BaseObject):
    """Extended TelegramClient with TDesktop conversion and session management."""

    @typing.overload
    def __init__(
        self: TelegramClient,
        session: Union[str, Session] = None,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
    ): ...

    @typing.overload
    def __init__(  # noqa: F811
        self,
        session: Union[str, Session] = None,
        api: Union[Type[APIData], APIData] = None,
        api_id: int = 0,
        api_hash: str = None,
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
        device_model: str = None,
        system_version: str = None,
        app_version: str = None,
        lang_code: str = "en",
        system_lang_code: str = "en",
        loop: asyncio.AbstractEventLoop = None,
        base_logger: Union[str, logging.Logger] = None,
        receive_updates: bool = True,
    ): ...

    @override
    def __init__(  # noqa: F811
        self,
        session: Union[str, Session] = None,
        api: Union[Type[APIData], APIData] = None,
        api_id: int = 0,
        api_hash: str = None,
        **kwargs,
    ):
        if api is not None:
            if isinstance(api, APIData) or (
                isinstance(api, type)
                and APIData.__subclasscheck__(api)
                and api != APIData
            ):
                api_id = api.api_id
                api_hash = api.api_hash
                kwargs["device_model"] = api.pid  # type: ignore
            else:
                if (
                    (isinstance(api, int) or isinstance(api, str))
                    and api_id
                    and isinstance(api_id, str)
                ):
                    api_id = api
                    api_hash = api_id
                api = None

        elif api_id == 0 and api_hash is None:
            api = API.TelegramDesktop
            api_id = api.api_id
            api_hash = api.api_hash
            kwargs["device_model"] = api.pid  # type: ignore

        self._user_id = None
        self.__TelegramClient____init__(session, api_id, api_hash, **kwargs)

    @property
    def UserId(self):
        return self._self_id if self._self_id else self._user_id

    @UserId.setter
    def UserId(self, id):
        self._user_id = id

    async def GetSessions(self) -> Optional[types.account.Authorizations]:
        """Get all logged-in sessions."""
        return await self(functions.account.GetAuthorizationsRequest())  # type: ignore

    async def GetCurrentSession(self) -> Optional[types.Authorization]:
        """Get current logged-in session."""
        results = await self.GetSessions()
        if results is None:
            return None
        return next((auth for auth in results.authorizations if auth.current), None)

    async def TerminateSession(self, hash: int):
        """Terminate a specific session by hash."""
        try:
            await self(functions.account.ResetAuthorizationRequest(hash))
        except FreshResetAuthorisationForbiddenError:
            raise FreshResetAuthorisationForbiddenError(
                "You can't logout other sessions if less than 24 hours have passed since you logged on the current session."
            )
        except HashInvalidError:
            raise HashInvalidError("The provided hash is invalid.")

    async def TerminateAllSessions(self) -> bool:
        """Terminate all other sessions."""
        sessions = await self.GetSessions()
        if sessions is None:
            return False

        for ss in sessions.authorizations:
            if not ss.current:
                await self.TerminateSession(ss.hash)

        return True

    async def PrintSessions(self, sessions: types.account.Authorizations = None):
        """Pretty-print all logged-in sessions."""
        if sessions is None or not isinstance(sessions, types.account.Authorizations):
            sessions = await self.GetSessions()

        assert sessions

        table = []
        for index, session in enumerate(sessions.authorizations):
            table.append(
                {
                    " ": "Current" if session.current else index,
                    "Device": session.device_model,
                    "Platform": session.platform,
                    "System": session.system_version,
                    "API_ID": session.api_id,
                    "App name": "{} {}".format(session.app_name, session.app_version),
                    "Official App": "✔" if session.official_app else "✖",
                }
            )

        print(PrettyTable(table, [1]))

    async def is_official_app(self) -> bool:
        """Return True if logged-in using an official app API."""
        auth = await self.GetCurrentSession()
        return False if auth is None else bool(auth.official_app)

    @typing.overload
    async def QRLoginToNewClient(
        self,
        session: Union[str, Session] = None,
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
    ) -> TelegramClient: ...

    async def QRLoginToNewClient(  # noqa: F811
        self,
        session: Union[str, Session] = None,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
        **kwargs,
    ) -> TelegramClient:
        """Create a new authorized client via QR code login."""
        newClient = TelegramClient(session, api=api, **kwargs)

        try:
            await newClient.connect()
            if newClient.session.dc_id != self.session.dc_id:
                await newClient._switch_dc(self.session.dc_id)
        except OSError:
            raise BaseException("Cannot connect")

        if await newClient.is_user_authorized():  # nocov
            return await self._handleExistingSession(
                newClient, session, api, password, **kwargs
            )

        if not self._self_id:
            await self.get_me()

        return await self._performQRLogin(newClient, session, api, password, **kwargs)

    @staticmethod
    async def _cleanup_client(client) -> None:
        """Disconnect and delete a client's session."""
        disconnect = client.disconnect()
        if disconnect:
            await disconnect
            await client.disconnected
        client.session.close()
        client.session.delete()

    async def _handleExistingSession(
        self, newClient, session, api, password, **kwargs
    ) -> TelegramClient:  # nocov
        """Handle case where session file already exists and is authorized."""
        currentAuth = await newClient.GetCurrentSession()
        if currentAuth is None:
            return newClient

        if currentAuth.api_id == api.api_id:
            warnings.warn(
                "\nCreateNewSession - a session file with the same name "
                "is already existed, returning the old session"
            )
        else:
            warnings.warn(
                "\nCreateNewSession - a session file with the same name "
                "is already existed, but its api_id is different from "
                "the current one, it will be overwritten"
            )

            await self._cleanup_client(newClient)

            newClient = await self.QRLoginToNewClient(
                session=session, api=api, password=password, **kwargs
            )

        return newClient

    async def _performQRLogin(
        self, newClient, session, api, password, **kwargs
    ) -> TelegramClient:
        """Execute the QR login flow with retry logic."""
        timeout_err = None
        request_retries = kwargs.get("request_retries", _DEFAULT_REQUEST_RETRIES)

        for attempt in range(request_retries):  # nocov
            try:
                if attempt > 0 and await newClient.is_user_authorized():
                    break

                qr_login = await newClient.qr_login()

                if isinstance(qr_login._resp, types.auth.LoginTokenMigrateTo):
                    await newClient._switch_dc(qr_login._resp.dc_id)
                    qr_login._resp = await newClient(
                        functions.auth.ImportLoginTokenRequest(qr_login._resp.token)
                    )

                if isinstance(qr_login._resp, types.auth.LoginTokenSuccess):
                    coro = newClient._on_login(qr_login._resp.authorization.user)
                    if isinstance(coro, Awaitable):
                        await coro
                    break

                time_now = datetime.datetime.now(datetime.timezone.utc)
                time_out = (
                    qr_login.expires - time_now
                ).seconds + _QR_EXPIRE_SAFETY_SECONDS

                await self(functions.auth.AcceptLoginTokenRequest(qr_login.token))

                await qr_login.wait(time_out)
                break

            except (
                AuthTokenAlreadyAcceptedError,
                AuthTokenExpiredError,
                AuthTokenInvalidError,
            ):
                raise

            except (TimeoutError, asyncio.TimeoutError) as e:
                warnings.warn(
                    "\nQRLoginToNewClient attempt {} failed because {}".format(
                        attempt + 1, type(e)
                    )
                )
                timeout_err = TimeoutError(
                    "Something went wrong, i couldn't perform the QR login process"
                )

            except telethon.errors.SessionPasswordNeededError:
                return await self._handle2FA(newClient, password)

            warnings.warn(
                "\nQRLoginToNewClient attempt {} failed. Retrying..".format(attempt + 1)
            )

        if timeout_err:
            raise timeout_err

        return newClient

    async def _handle2FA(self, newClient, password) -> TelegramClient:
        """Handle two-factor authentication during QR login."""
        Expects(
            password is not None,
            NoPasswordProvided(
                "Two-step verification is enabled for this account.\n"
                "You need to provide the `password` to argument"
            ),
        )

        try:
            pwd: types.account.Password = await newClient(
                functions.account.GetPasswordRequest()
            )  # type: ignore
            result = await newClient(
                functions.auth.CheckPasswordRequest(
                    pwd_mod.compute_check(pwd, password)  # type: ignore
                )
            )

            coro = newClient._on_login(result.user)  # type: ignore
            if isinstance(coro, Awaitable):
                await coro
            return newClient

        except PasswordHashInvalidError as e:
            raise PasswordIncorrect(e.__str__()) from e

    async def ToTDesktop(
        self,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
    ) -> td.TDesktop:
        """Convert this TelegramClient instance to TDesktop."""
        return await td.TDesktop.FromTelethon(
            self, flag=flag, api=api, password=password
        )

    @typing.overload
    @staticmethod
    async def FromTDesktop(
        account: Union[td.TDesktop, td.Account],
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
    ) -> TelegramClient: ...

    @staticmethod
    async def FromTDesktop(  # noqa: F811
        account: Union[td.TDesktop, td.Account],
        session: Union[str, Session] = None,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
        **kwargs,
    ) -> TelegramClient:
        """Create a TelegramClient from a TDesktop account."""
        Expects(
            (flag == CreateNewSession) or (flag == UseCurrentSession),
            LoginFlagInvalid("LoginFlag invalid"),
        )

        account = TelegramClient._resolveTDesktopAccount(account)

        if (flag == UseCurrentSession) and not (
            isinstance(api, APIData) or APIData.__subclasscheck__(api)
        ):  # nocov
            warnings.warn(  # type: ignore
                "\nIf you use an existing Telegram Desktop session "
                "with unofficial API_ID and API_HASH, "
                "Telegram might ban your account because of suspicious activities.\n"
                "Please use the default APIs to get rid of this."
            )

        auth_session = TelegramClient._createAuthSession(account, session, flag)

        endpoints = account._local.config.endpoints(account.MainDcId)
        address = td.MTP.DcOptions.Address.IPv4
        protocol = td.MTP.DcOptions.Protocol.Tcp

        Expects(
            len(endpoints[address][protocol]) > 0,
            "Couldn't find endpoint for this account, something went wrong?",
        )  # type: ignore

        endpoint = endpoints[address][protocol][0]  # type: ignore

        auth_session.set_dc(endpoint.id, endpoint.ip, endpoint.port)  # type: ignore
        auth_session.auth_key = AuthKey(account.authKey.key)  # type: ignore

        client = TelegramClient(auth_session, api=account.api, **kwargs)

        if flag == UseCurrentSession:
            client.UserId = account.UserId
            return client

        await client.connect()
        Expects(
            await client.is_user_authorized(),
            TDesktopUnauthorized("TDesktop client is unauthorized"),
        )

        return await client.QRLoginToNewClient(
            session=session, api=api, password=password, **kwargs
        )

    @staticmethod
    def _resolveTDesktopAccount(account: Union[td.TDesktop, td.Account]) -> td.Account:
        """Resolve a TDesktop or Account to an Account instance."""
        if isinstance(account, td.TDesktop):
            Expects(
                account.isLoaded(),
                TDesktopNotLoaded(
                    "You need to load accounts from a tdata folder first"
                ),
            )
            Expects(
                account.accountsCount > 0,
                TDesktopHasNoAccount(
                    "There is no account in this instance of TDesktop"
                ),
            )
            assert account.mainAccount
            return account.mainAccount
        return account

    @staticmethod
    def _createAuthSession(account: td.Account, session, flag):
        """Create the appropriate session object for authentication."""
        if flag == CreateNewSession:
            return MemorySession()

        if isinstance(session, str) or session is None:
            try:
                return SQLiteSession(session)
            except ImportError:
                warnings.warn(
                    "The sqlite3 module is not available under this "
                    "Python installation and no custom session "
                    "instance was given; using MemorySession.\n"
                    "You will need to re-login every time unless "
                    "you use another session storage"
                )
                return MemorySession()

        if not isinstance(session, Session):
            raise TypeError("The given session must be a str or a Session instance.")

        return session
