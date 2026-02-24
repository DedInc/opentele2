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
from .session_io import (
    write_session_file,
    from_session_json,
    save_session_json,
)
from ..fingerprint import (
    DEFAULT_CONFIG,
    FingerprintConfig,
    TransportRecommendation,
)
from .. import td

import telethon
from telethon.crypto import AuthKey
from telethon import functions, types, password as pwd_mod
from telethon.network.connection.connection import Connection
from telethon.network.connection.tcpobfuscated import ConnectionTcpObfuscated
from telethon.sessions.abstract import Session
from telethon.sessions.sqlite import SQLiteSession
from telethon.sessions.memory import MemorySession
from typing import Optional, Type, Union
import asyncio
import random
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

_POST_LOGIN_STEPS = [
    (None, lambda lp: functions.help.GetConfigRequest(), None),
    ((100, 300), lambda lp: functions.help.GetNearestDcRequest(), None),
    ((200, 400), lambda lp: functions.account.UpdateStatusRequest(offline=False), None),
    (
        (100, 200),
        lambda lp: functions.langpack.GetLanguagesRequest(lang_pack=lp),
        lambda lp: bool(lp),
    ),
    ((300, 500), lambda lp: functions.help.GetAppUpdateRequest(source=""), None),
    ((100, 300), lambda lp: functions.help.GetTermsOfServiceUpdateRequest(), None),
    (
        (50, 150),
        lambda lp: functions.help.GetCountriesListRequest(lang_code="en", hash=0),
        None,
    ),
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
        data = APIData.findData(device_model)
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

        try:
            DEFAULT_CONFIG.validate_params(
                api_id=self.api_id,
                device_model=self.device_model,
                system_version=self.system_version,
                app_version=self.app_version,
                system_lang_code=self.system_lang_code,
                lang_pack=self.lang_pack,
                lang_code=self.lang_code,
            )
        except Exception:
            pass


@extend_class
class TelegramClient(telethon.TelegramClient, BaseObject):
    @typing.overload
    def __init__(
        self: TelegramClient,
        session: Union[str, Session] = None,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
    ): ...

    @typing.overload
    def __init__(
        self,
        session: Union[str, Session] = None,
        api: Optional[Union[Type[APIData], APIData]] = None,
        api_id: int = 0,
        api_hash: Optional[str] = None,
        *,
        connection: typing.Type[Connection] = ConnectionTcpObfuscated,
        use_ipv6: bool = False,
        proxy: Optional[Union[tuple, dict]] = None,
        local_addr: Optional[Union[str, tuple]] = None,
        timeout: int = 10,
        request_retries: int = 5,
        connection_retries: int = 5,
        retry_delay: int = 1,
        auto_reconnect: bool = True,
        sequential_updates: bool = False,
        flood_sleep_threshold: int = 60,
        raise_last_call_error: bool = False,
        device_model: Optional[str] = None,
        system_version: Optional[str] = None,
        app_version: Optional[str] = None,
        lang_code: str = "en",
        system_lang_code: str = "en",
        loop: Optional[asyncio.AbstractEventLoop] = None,
        base_logger: Optional[Union[str, logging.Logger]] = None,
        receive_updates: bool = True,
        fingerprint_config: Optional[FingerprintConfig] = None,
        auto_post_login: bool = True,
    ): ...

    @override
    def __init__(
        self,
        session: Union[str, Session] = None,
        api: Optional[Union[Type[APIData], APIData]] = None,
        api_id: int = 0,
        api_hash: Optional[str] = None,
        **kwargs,
    ):
        self._fingerprint_config: FingerprintConfig = (
            kwargs.pop("fingerprint_config", None) or DEFAULT_CONFIG
        )

        self._auto_post_login: bool = kwargs.pop("auto_post_login", True)
        self._post_login_done: bool = False

        if "connection" not in kwargs:
            kwargs["connection"] = TransportRecommendation.get_connection_class()

        if api is not None:
            if isinstance(api, APIData) or (
                isinstance(api, type)
                and APIData.__subclasscheck__(api)
                and api != APIData
            ):
                api_id = api.api_id
                api_hash = api.api_hash
                kwargs["device_model"] = api.pid
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
            kwargs["device_model"] = api.pid

        if api is not None and (
            isinstance(api, APIData)
            or (isinstance(api, type) and APIData.__subclasscheck__(api))
        ):
            self._api_data = api.copy()
        else:
            self._api_data = None

        self._user_id = None
        self.__TelegramClient____init__(session, api_id, api_hash, **kwargs)

    @property
    def UserId(self):
        return self._self_id if self._self_id else self._user_id

    @UserId.setter
    def UserId(self, id):
        self._user_id = id

    @override
    async def connect(self):
        result = await getattr(self, "__TelegramClient__connect")()

        if self._auto_post_login and not self._post_login_done:
            try:
                if await self.is_user_authorized():
                    await self._run_post_login_requests()
            except Exception:
                pass

        return result

    def _get_lang_pack(self) -> str:
        init_req = getattr(self, "_init_request", None)
        if init_req is not None:
            lp = getattr(init_req, "lang_pack", "")
            if lp:
                return lp
        sender = getattr(self, "_sender", None)
        if sender is not None:
            init_req = getattr(sender, "_init_request", None)
            if init_req is not None:
                return getattr(init_req, "lang_pack", "")
        return ""

    async def _run_post_login_requests(self):
        if self._post_login_done:
            return
        self._post_login_done = True

        lang_pack = self._get_lang_pack()

        for delay_range, request_factory, condition in _POST_LOGIN_STEPS:
            if condition is not None and not condition(lang_pack):
                continue
            if delay_range is not None:
                await asyncio.sleep(random.randint(*delay_range) / 1000.0)
            try:
                await self(request_factory(lang_pack))
            except Exception:
                pass

    async def GetSessions(self) -> Optional[types.account.Authorizations]:
        return await self(functions.account.GetAuthorizationsRequest())

    async def GetCurrentSession(self) -> Optional[types.Authorization]:
        results = await self.GetSessions()
        if results is None:
            return None
        return next((auth for auth in results.authorizations if auth.current), None)

    async def TerminateSession(self, hash: int):
        try:
            await self(functions.account.ResetAuthorizationRequest(hash))
        except FreshResetAuthorisationForbiddenError:
            raise FreshResetAuthorisationForbiddenError(
                "You can't logout other sessions if less than 24 hours have passed since you logged on the current session."
            )
        except HashInvalidError:
            raise HashInvalidError("The provided hash is invalid.")

    async def TerminateAllSessions(self) -> bool:
        sessions = await self.GetSessions()
        if sessions is None:
            return False

        for ss in sessions.authorizations:
            if not ss.current:
                await self.TerminateSession(ss.hash)

        return True

    async def PrintSessions(self, sessions: types.account.Authorizations = None):
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
        auth = await self.GetCurrentSession()
        return False if auth is None else bool(auth.official_app)

    async def RunConsistencyChecks(self, *, auto_warn: bool = True):
        from ..consistency import ConsistencyChecker

        checker = ConsistencyChecker(self, auto_warn=auto_warn)
        return await checker.run_all()

    @typing.overload
    async def QRLoginToNewClient(
        self,
        session: Union[str, Session] = None,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: Optional[str] = None,
        *,
        connection: typing.Type[Connection] = ConnectionTcpObfuscated,
        use_ipv6: bool = False,
        proxy: Optional[Union[tuple, dict]] = None,
        local_addr: Optional[Union[str, tuple]] = None,
        timeout: int = 10,
        request_retries: int = 5,
        connection_retries: int = 5,
        retry_delay: int = 1,
        auto_reconnect: bool = True,
        sequential_updates: bool = False,
        flood_sleep_threshold: int = 60,
        raise_last_call_error: bool = False,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        base_logger: Optional[Union[str, logging.Logger]] = None,
        receive_updates: bool = True,
    ) -> TelegramClient: ...

    async def QRLoginToNewClient(
        self,
        session: Union[str, Session] = None,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: Optional[str] = None,
        **kwargs,
    ) -> TelegramClient:
        newClient = TelegramClient(session, api=api, **kwargs)

        try:
            await newClient.connect()
            if newClient.session.dc_id != self.session.dc_id:
                await newClient._switch_dc(self.session.dc_id)
        except OSError:
            raise OSError("Cannot connect")

        if await newClient.is_user_authorized():
            return await self._handleExistingSession(
                newClient, session, api, password, **kwargs
            )

        if not self._self_id:
            await self.get_me()

        newClient = await self._performQRLogin(
            newClient, session, api, password, **kwargs
        )

        if newClient._auto_post_login and not newClient._post_login_done:
            try:
                await newClient._run_post_login_requests()
            except Exception:
                pass

        return newClient

    @staticmethod
    async def _cleanup_client(client) -> None:
        disconnect = client.disconnect()
        if disconnect:
            await disconnect
            await client.disconnected
        client.session.close()
        client.session.delete()

    async def _handleExistingSession(
        self, newClient, session, api, password, **kwargs
    ) -> TelegramClient:
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
        timeout_err = None
        request_retries = kwargs.get("request_retries", _DEFAULT_REQUEST_RETRIES)

        for attempt in range(request_retries):
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
            )
            result = await newClient(
                functions.auth.CheckPasswordRequest(
                    pwd_mod.compute_check(pwd, password)
                )
            )

            coro = newClient._on_login(result.user)
            if isinstance(coro, Awaitable):
                await coro
            return newClient

        except PasswordHashInvalidError as e:
            raise PasswordIncorrect(e.__str__()) from e

    async def ToTDesktop(
        self,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: Optional[str] = None,
    ) -> td.TDesktop:
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
        password: Optional[str] = None,
        *,
        connection: typing.Type[Connection] = ConnectionTcpObfuscated,
        use_ipv6: bool = False,
        proxy: Optional[Union[tuple, dict]] = None,
        local_addr: Optional[Union[str, tuple]] = None,
        timeout: int = 10,
        request_retries: int = 5,
        connection_retries: int = 5,
        retry_delay: int = 1,
        auto_reconnect: bool = True,
        sequential_updates: bool = False,
        flood_sleep_threshold: int = 60,
        raise_last_call_error: bool = False,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        base_logger: Optional[Union[str, logging.Logger]] = None,
        receive_updates: bool = True,
    ) -> TelegramClient: ...

    @staticmethod
    async def FromTDesktop(
        account: Union[td.TDesktop, td.Account],
        session: Union[str, Session] = None,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: Optional[str] = None,
        **kwargs,
    ) -> TelegramClient:
        Expects(
            (flag == CreateNewSession) or (flag == UseCurrentSession),
            LoginFlagInvalid("LoginFlag invalid"),
        )

        account = TelegramClient._resolveTDesktopAccount(account)

        if (flag == UseCurrentSession) and not (
            isinstance(api, APIData) or APIData.__subclasscheck__(api)
        ):
            warnings.warn(
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
        )

        endpoint = endpoints[address][protocol][0]

        auth_session.set_dc(endpoint.id, endpoint.ip, endpoint.port)
        auth_session.auth_key = AuthKey(account.authKey.key)

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

    @staticmethod
    def _write_session_file(
        path: str,
        dc_id: int,
        server_address: str,
        port: int,
        auth_key_bytes: bytes,
    ) -> str:
        return write_session_file(path, dc_id, server_address, port, auth_key_bytes)

    @staticmethod
    async def FromSessionJson(
        session_path: str,
        json_path: Optional[str] = None,
        flag: Type[LoginFlag] = UseCurrentSession,
        password: Optional[str] = None,
        **kwargs,
    ) -> TelegramClient:
        return await from_session_json(
            session_path, json_path, flag, password, **kwargs
        )

    async def SaveSessionJson(
        self,
        session_path: str,
        api: Optional[Union[Type[APIData], APIData]] = None,
        fetch_user_info: bool = False,
    ) -> typing.Tuple[str, str]:
        return await save_session_json(self, session_path, api, fetch_user_info)
