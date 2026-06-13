from __future__ import annotations

import asyncio
import datetime
import random
import typing
import warnings
from collections.abc import Awaitable
from typing import TYPE_CHECKING

import telethon
from telethon import functions, types
from telethon import password as pwd_mod
from telethon.crypto import AuthKey
from telethon.errors.rpcerrorlist import (
    AuthTokenAlreadyAcceptedError,
    AuthTokenExpiredError,
    AuthTokenInvalidError,
    FreshResetAuthorisationForbiddenError,
    HashInvalidError,
    PasswordHashInvalidError,
)
from telethon.network.connection.connection import Connection
from telethon.network.connection.tcpobfuscated import ConnectionTcpObfuscated
from telethon.sessions.abstract import Session
from telethon.sessions.memory import MemorySession
from telethon.sessions.sqlite import SQLiteSession

from .. import td
from ..api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from ..exception import (
    Expects,
    LoginFlagInvalid,
    NoPasswordProvided,
    PasswordIncorrect,
    TDesktopHasNoAccount,
    TDesktopNotLoaded,
    TDesktopUnauthorized,
)
from ..fingerprint import (
    DEFAULT_CONFIG,
    FingerprintConfig,
    TransportRecommendation,
)
from ..utils import PrettyTable
from ..pg.pyrogram_io import from_pyrogram_session, save_pyrogram_session
from .session_io import (
    from_session_json,
    save_session_json,
    write_session_file,
)

if TYPE_CHECKING:
    import logging

    from ..consistency import ConsistencyReport

_DEFAULT_REQUEST_RETRIES = 5
_QR_EXPIRE_SAFETY_SECONDS = 5

_POST_LOGIN_STEPS = [
    (None, lambda _lang_pack: functions.help.GetConfigRequest(), None),
    ((100, 300), lambda _lang_pack: functions.help.GetNearestDcRequest(), None),
    (
        (200, 400),
        lambda _lang_pack: functions.account.UpdateStatusRequest(offline=False),
        None,
    ),
    (
        (100, 200),
        lambda lang_pack: functions.langpack.GetLanguagesRequest(lang_pack=lang_pack),
        lambda lang_pack: bool(lang_pack),
    ),
    (
        (300, 500),
        lambda _lang_pack: functions.help.GetAppUpdateRequest(source=""),
        None,
    ),
    (
        (100, 300),
        lambda _lang_pack: functions.help.GetTermsOfServiceUpdateRequest(),
        None,
    ),
    (
        (50, 150),
        lambda _lang_pack: functions.help.GetCountriesListRequest(
            lang_code="en", hash=0
        ),
        None,
    ),
]


def _resolve_api(
    api: type[APIData] | APIData | None,
) -> APIData | None:
    """Normalize an api argument into an APIData instance (or None)."""
    if api is None:
        return None
    if isinstance(api, APIData):
        return api
    if isinstance(api, type) and issubclass(api, APIData) and api is not APIData:
        return api()
    return None


class TelegramClient(telethon.TelegramClient):
    """Subclass of ``telethon.TelegramClient`` with opentele2 extensions.

    Accepts an ``api`` parameter (:class:`APIData` or subclass) that sets
    device fingerprint fields (device_model, system_version, app_version,
    lang_code, system_lang_code, lang_pack) to mimic official clients.
    """

    @typing.overload
    def __init__(
        self: TelegramClient,
        session: str | Session = None,
        api: type[APIData] | APIData = API.TelegramDesktop,
    ) -> None: ...

    @typing.overload
    def __init__(
        self,
        session: str | Session = None,
        api: type[APIData] | APIData | None = None,
        api_id: int = 0,
        api_hash: str | None = None,
        *,
        connection: type[Connection] = ConnectionTcpObfuscated,
        use_ipv6: bool = False,
        proxy: tuple | dict | None = None,
        local_addr: str | tuple | None = None,
        timeout: int = 10,
        request_retries: int = 5,
        connection_retries: int = 5,
        retry_delay: int = 1,
        auto_reconnect: bool = True,
        sequential_updates: bool = False,
        flood_sleep_threshold: int = 60,
        raise_last_call_error: bool = False,
        device_model: str | None = None,
        system_version: str | None = None,
        app_version: str | None = None,
        lang_code: str = "en",
        system_lang_code: str = "en",
        loop: asyncio.AbstractEventLoop | None = None,
        base_logger: str | logging.Logger | None = None,
        receive_updates: bool = True,
        fingerprint_config: FingerprintConfig | None = None,
        auto_post_login: bool = True,
    ) -> None: ...

    def __init__(
        self,
        session: str | Session = None,
        api: type[APIData] | APIData | None = None,
        api_id: int = 0,
        api_hash: str | None = None,
        **kwargs,
    ):
        self._fingerprint_config: FingerprintConfig = (
            kwargs.pop("fingerprint_config", None) or DEFAULT_CONFIG
        )
        self._auto_post_login: bool = kwargs.pop("auto_post_login", True)
        self._post_login_done: bool = False

        if "connection" not in kwargs:
            kwargs["connection"] = TransportRecommendation.get_connection_class()

        # Handle the legacy pattern: TelegramClient(session, api_id_int, api_hash_str)
        if api is not None and not isinstance(api, (APIData, type)):
            if isinstance(api, (int, str)) and api_id and isinstance(api_id, str):
                api_id = int(api)
                api_hash = str(api_id)
            api = None

        # Resolve APIData
        api_data = _resolve_api(api)
        if api_data is None and api_id == 0 and api_hash is None:
            api_data = _resolve_api(API.TelegramDesktop)

        if api_data is not None:
            api_id = api_data.api_id
            api_hash = api_data.api_hash
            kwargs.setdefault("device_model", api_data.device_model)
            kwargs.setdefault("system_version", api_data.system_version)
            kwargs.setdefault("app_version", api_data.app_version)
            kwargs.setdefault("lang_code", api_data.lang_code or "en")
            kwargs.setdefault("system_lang_code", api_data.system_lang_code or "en")

        self._api_data: APIData | None = api_data
        self._user_id = None

        super().__init__(session, api_id, api_hash, **kwargs)

        # Telethon hardcodes lang_pack to '' — override it for official client mimicry
        if api_data is not None and api_data.lang_pack:
            self._init_request.lang_pack = api_data.lang_pack

        # Validate fingerprint params
        try:
            self._fingerprint_config.validate_params(
                api_id=self._init_request.api_id,
                device_model=self._init_request.device_model,
                system_version=self._init_request.system_version,
                app_version=self._init_request.app_version,
                system_lang_code=self._init_request.system_lang_code,
                lang_pack=self._init_request.lang_pack,
                lang_code=self._init_request.lang_code,
            )
        except Exception:
            pass

    @property
    def UserId(self) -> int | None:
        return self._self_id if self._self_id else self._user_id

    @UserId.setter
    def UserId(self, id: int | None) -> None:
        self._user_id = id

    async def connect(self) -> None:
        await super().connect()

        if self._auto_post_login and not self._post_login_done:
            try:
                if await self.is_user_authorized():
                    await self._run_post_login_requests()
            except Exception:
                pass

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

    async def _run_post_login_requests(self) -> None:
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

    async def GetSessions(self) -> types.account.Authorizations | None:
        return await self(functions.account.GetAuthorizationsRequest())

    async def GetCurrentSession(self) -> types.Authorization | None:
        results = await self.GetSessions()
        if results is None:
            return None
        return next((auth for auth in results.authorizations if auth.current), None)

    async def TerminateSession(self, hash: int) -> None:
        try:
            await self(functions.account.ResetAuthorizationRequest(hash))
        except FreshResetAuthorisationForbiddenError:
            raise FreshResetAuthorisationForbiddenError(
                "You can't logout other sessions if less than 24 hours "
                "have passed since you logged on the current session."
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

    async def PrintSessions(
        self, sessions: types.account.Authorizations = None
    ) -> None:
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
                    "App name": f"{session.app_name} {session.app_version}",
                    "Official App": "✔" if session.official_app else "✖",
                }
            )

        print(PrettyTable(table, [1]))

    async def is_official_app(self) -> bool:
        auth = await self.GetCurrentSession()
        return False if auth is None else bool(auth.official_app)

    async def RunConsistencyChecks(
        self, *, auto_warn: bool = True
    ) -> ConsistencyReport:
        from ..consistency import ConsistencyChecker

        checker = ConsistencyChecker(self, auto_warn=auto_warn)
        return await checker.run_all()

    @typing.overload
    async def QRLoginToNewClient(
        self,
        session: str | Session = None,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
        *,
        connection: type[Connection] = ConnectionTcpObfuscated,
        use_ipv6: bool = False,
        proxy: tuple | dict | None = None,
        local_addr: str | tuple | None = None,
        timeout: int = 10,
        request_retries: int = 5,
        connection_retries: int = 5,
        retry_delay: int = 1,
        auto_reconnect: bool = True,
        sequential_updates: bool = False,
        flood_sleep_threshold: int = 60,
        raise_last_call_error: bool = False,
        loop: asyncio.AbstractEventLoop | None = None,
        base_logger: str | logging.Logger | None = None,
        receive_updates: bool = True,
    ) -> TelegramClient: ...

    async def QRLoginToNewClient(
        self,
        session: str | Session = None,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
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

        newClient = await self._performQRLogin(newClient, password, **kwargs)

        if newClient._auto_post_login and not newClient._post_login_done:
            try:
                await newClient._run_post_login_requests()
            except Exception:
                pass

        return newClient

    @staticmethod
    async def _cleanup_client(client: TelegramClient) -> None:
        await TelegramClient._disconnect_client(client)
        client.session.close()
        client.session.delete()

    @staticmethod
    async def _disconnect_client(
        client: TelegramClient, *, close_session: bool = False
    ) -> None:
        try:
            if client.is_connected():
                disconnect = client.disconnect()
                if disconnect:
                    await disconnect
                    await client.disconnected
        finally:
            if close_session:
                client.session.close()

    async def _handleExistingSession(
        self,
        newClient: TelegramClient,
        session: str | Session | None,
        api: type[APIData] | APIData,
        password: str | None,
        **kwargs: object,
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
        self,
        newClient: TelegramClient,
        password: str | None,
        **kwargs: object,
    ) -> TelegramClient:
        timeout_err = None
        request_retries = kwargs.get("request_retries", _DEFAULT_REQUEST_RETRIES)
        if not isinstance(request_retries, int):
            request_retries = _DEFAULT_REQUEST_RETRIES

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
                    "\nQRLoginToNewClient attempt "
                    f"{attempt + 1} failed because {type(e)}"
                )
                timeout_err = TimeoutError(
                    "Something went wrong, i couldn't perform the QR login"
                )

            except telethon.errors.SessionPasswordNeededError:
                return await self._handle2FA(newClient, password)

            warnings.warn(
                f"\nQRLoginToNewClient attempt {attempt + 1} failed. Retrying.."
            )

        if timeout_err:
            raise timeout_err

        return newClient

    async def _handle2FA(
        self, newClient: TelegramClient, password: str | None
    ) -> TelegramClient:
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
        flag: type[LoginFlag] = CreateNewSession,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
    ) -> td.TDesktop:
        return await td.TDesktop.FromTelethon(
            self, flag=flag, api=api, password=password
        )

    @typing.overload
    @staticmethod
    async def FromTDesktop(
        account: td.TDesktop | td.Account,
        session: str | Session = None,
        flag: type[LoginFlag] = CreateNewSession,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
        *,
        connection: type[Connection] = ConnectionTcpObfuscated,
        use_ipv6: bool = False,
        proxy: tuple | dict | None = None,
        local_addr: str | tuple | None = None,
        timeout: int = 10,
        request_retries: int = 5,
        connection_retries: int = 5,
        retry_delay: int = 1,
        auto_reconnect: bool = True,
        sequential_updates: bool = False,
        flood_sleep_threshold: int = 60,
        raise_last_call_error: bool = False,
        loop: asyncio.AbstractEventLoop | None = None,
        base_logger: str | logging.Logger | None = None,
        receive_updates: bool = True,
    ) -> TelegramClient: ...

    @staticmethod
    async def FromTDesktop(
        account: td.TDesktop | td.Account,
        session: str | Session = None,
        flag: type[LoginFlag] = CreateNewSession,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
        **kwargs,
    ) -> TelegramClient:
        Expects(
            (flag == CreateNewSession) or (flag == UseCurrentSession),
            LoginFlagInvalid("LoginFlag invalid"),
        )

        account = TelegramClient._resolveTDesktopAccount(account)

        if (flag == UseCurrentSession) and not (
            isinstance(api, APIData)
            or (isinstance(api, type) and issubclass(api, APIData))
        ):
            warnings.warn(
                "\nIf you use an existing Telegram Desktop session "
                "with unofficial API_ID and API_HASH, "
                "Telegram might ban your account because of "
                "suspicious activities.\n"
                "Please use the default APIs to get rid of this."
            )

        auth_session = TelegramClient._createAuthSession(session, flag)

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

        try:
            await client.connect()
            Expects(
                await client.is_user_authorized(),
                TDesktopUnauthorized("TDesktop client is unauthorized"),
            )

            return await client.QRLoginToNewClient(
                session=session, api=api, password=password, **kwargs
            )
        finally:
            await TelegramClient._disconnect_client(client, close_session=True)

    @staticmethod
    def _resolveTDesktopAccount(
        account: td.TDesktop | td.Account,
    ) -> td.Account:
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
    def _createAuthSession(
        session: str | Session | None,
        flag: type[LoginFlag],
    ) -> Session:
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
        json_path: str | None = None,
        flag: type[LoginFlag] = UseCurrentSession,
        password: str | None = None,
        **kwargs: object,
    ) -> TelegramClient:
        return await from_session_json(
            session_path, json_path, flag, password, **kwargs
        )

    async def SaveSessionJson(
        self,
        session_path: str,
        api: type[APIData] | APIData | None = None,
        fetch_user_info: bool = False,
    ) -> tuple[str, str]:
        return await save_session_json(self, session_path, api, fetch_user_info)
        
    async def ToPyrogram(
        self,
        session_path: str,
        api: type[APIData] | APIData | None = None,
        fetch_user_info: bool = False,
    ) -> str:
        """
        Export this Telethon session as a Pyrogram-compatible .session file.

        Parameters
        ----------
        session_path:
            Destination path (with or without the ``.session`` extension).
        api:
            API preset / instance whose ``api_id`` is stored in the Pyrogram
            session.  Defaults to the client's own API data.
        fetch_user_info:
            If *True* and the client is connected, call ``get_me()`` to
            populate ``user_id`` in the output file.

        Returns
        -------
        str
            Absolute path of the written ``.session`` file.
        """
        return await save_pyrogram_session(
            self, session_path, api=api, fetch_user_info=fetch_user_info
        )

    @staticmethod
    async def FromPyrogram(
        session_path: str,
        api: type[APIData] | APIData | None = None,
        output_session: str | None = None,
        **kwargs: object,
    ) -> TelegramClient:
        """
        Load a Pyrogram .session file and return an authenticated
        ``TelegramClient`` (Telethon).

        Parameters
        ----------
        session_path:
            Path to the Pyrogram .session file.
        api:
            API preset to use.  When *None*, the preset is inferred from
            the ``api_id`` stored in the Pyrogram session (works for
            official Telegram clients: Android, iOS, Desktop …).
            For custom ``api_id``/``api_hash`` you **must** pass an explicit
            ``APIData(api_id, api_hash)`` instance.
        output_session:
            Path for the resulting Telethon .session file.  When *None* an
            in-memory session is used (not persisted to disk).
        **kwargs:
            Forwarded to ``TelegramClient.__init__``.

        Returns
        -------
        TelegramClient
            Ready-to-use client.  Call ``await client.connect()`` and then
            ``await client.is_user_authorized()`` to verify.
        """
        return await from_pyrogram_session(
            session_path, api=api, output_session=output_session, **kwargs
        )
