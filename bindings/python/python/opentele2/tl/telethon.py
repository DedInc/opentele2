"""1.5.0 ``src/tl/telethon.py``: ``telethon.TelegramClient`` with official
client fingerprints and the tdata conversions. The endpoint and key of a
tdata account, the sessions table, the 2FA check, the post-login sequence
with its delays, the QR login rules and the fixed messages come from
:mod:`opentele2._native`."""

from __future__ import annotations

import asyncio
import datetime
import logging
import warnings
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

import telethon
from telethon import functions, types
from telethon.crypto import AuthKey
from telethon.errors.rpcerrorlist import (
    AuthTokenAlreadyAcceptedError,
    AuthTokenExpiredError,
    AuthTokenInvalidError,
    FreshResetAuthorisationForbiddenError,
    HashInvalidError,
    PasswordHashInvalidError,
)
from telethon.sessions.abstract import Session
from telethon.sessions.memory import MemorySession
from telethon.sessions.sqlite import SQLiteSession

from .. import _native, td
from .._native import CoreError
from ..api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from ..exception import (
    Expects,
    LoginFlagInvalid,
    NoPasswordProvided,
    OpenTeleException,
    PasswordIncorrect,
    TDataAuthKeyNotFound,
    TDesktopHasNoAccount,
    TDesktopNotLoaded,
    TDesktopUnauthorized,
    raise_core_error,
)
from ..fingerprint import (
    DEFAULT_CONFIG,
    FingerprintConfig,
    TransportRecommendation,
    tdesktop_tz_offset,
)
from .session_io import (
    from_session_json,
    save_session_json,
    write_session_file,
)

if TYPE_CHECKING:
    from typing_extensions import Unpack

    from .._native import TelethonSessionRows
    from ..consistency import ConsistencyReport
    from .client_kwargs import TelethonClientKwargs

_DEFAULT_REQUEST_RETRIES = _native.QR_LOGIN_ATTEMPTS
_QR_EXPIRE_SAFETY_SECONDS = _native.QR_EXPIRE_SAFETY_SECONDS

logger = logging.getLogger(__name__)

# The Telethon request of each core post-login step, by its TL name; the
# core decides the order, the sleeps and which steps run.
_POST_LOGIN_REQUESTS: dict[str, Callable[[str], Any]] = {
    "help.getConfig": lambda _lang_pack: functions.help.GetConfigRequest(),
    "help.getNearestDc": lambda _lang_pack: functions.help.GetNearestDcRequest(),
    "account.updateStatus": lambda _lang_pack: functions.account.UpdateStatusRequest(offline=False),
    "langpack.getLanguages": lambda lang_pack: functions.langpack.GetLanguagesRequest(
        lang_pack=lang_pack
    ),
    "help.getAppUpdate": lambda _lang_pack: functions.help.GetAppUpdateRequest(
        source=_native.POST_LOGIN_APP_UPDATE_SOURCE
    ),
    "help.getTermsOfServiceUpdate": lambda _lang_pack: (
        functions.help.GetTermsOfServiceUpdateRequest()
    ),
    "help.getCountriesList": lambda _lang_pack: functions.help.GetCountriesListRequest(
        lang_code=_native.POST_LOGIN_COUNTRIES_LANG_CODE, hash=0
    ),
}

# Telethon's class of the only 2FA algorithm the core supports: its TL name
# with a capital first letter. The annotation only tells type checkers
# which class that is.
_SRP_ALGORITHM_CLASS: type[
    types.PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow
] = getattr(types, _native.SRP_ALGORITHM[:1].upper() + _native.SRP_ALGORITHM[1:])

_NO_ENDPOINT = "Couldn't find endpoint for this account, something went wrong?"
_NO_AUTH_KEY = "The account has no authKey loaded"


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


def _session_rows(account: td.Account, use_ipv6: bool) -> TelethonSessionRows:
    """The endpoint 1.5.0 ``FromTDesktop`` connects ``account`` to: the first
    TCP endpoint of its main DC in its stored config (else the built-in
    table), IPv6 when asked for and available, else IPv4."""
    loaded = account._core
    if loaded is None:
        raise TDataAuthKeyNotFound(_NO_AUTH_KEY)
    try:
        return _native.telethon_session_rows(loaded, use_ipv6)
    except CoreError as error:
        if error.code == "TDATA_BAD_CONFIG_DATA":
            raise OpenTeleException(_NO_ENDPOINT) from error
        if error.code == "TDATA_AUTH_KEY_NOT_FOUND":
            raise TDataAuthKeyNotFound(_NO_AUTH_KEY) from error
        raise_core_error(error)


def _compute_check(pwd: types.account.Password, password: str) -> types.InputCheckPasswordSRP:
    """Telethon ``password.compute_check``, computed by the core."""
    algo = pwd.current_algo
    if not isinstance(algo, _SRP_ALGORITHM_CLASS):
        raise ValueError(_native.unsupported_password_algorithm(algo.__class__.__name__))
    srp_id, srp_b = pwd.srp_id, pwd.srp_B
    if srp_id is None or srp_b is None:
        # Telethon cannot run the check without them either; the core
        # refuses the empty B as a bad one.
        srp_id, srp_b = 0, b""
    try:
        check = _native.srp_check(
            {
                "srp_id": srp_id,
                "g": algo.g,
                "p": algo.p,
                "salt1": algo.salt1,
                "salt2": algo.salt2,
                "srp_b": srp_b,
            },
            password,
        )
    except CoreError as error:
        raise_core_error(error)
    return types.InputCheckPasswordSRP(check["srp_id"], check["a"], check["m1"])


class TelegramClient(telethon.TelegramClient):
    """Subclass of ``telethon.TelegramClient`` with opentele2 extensions.

    Accepts an ``api`` parameter (:class:`APIData` or subclass) that sets
    device fingerprint fields (device_model, system_version, app_version,
    lang_code, system_lang_code, lang_pack) to mimic official clients.
    """

    # Telethon assigns this in __init__; it is never None afterwards.
    session: Session

    def __init__(
        self,
        session: str | Session | None = None,
        # int and str cover the legacy TelegramClient(session, api_id, api_hash).
        api: type[APIData] | APIData | int | str | None = None,
        api_id: int | str = 0,
        api_hash: str | None = None,
        *,
        fingerprint_config: FingerprintConfig | None = None,
        auto_post_login: bool = True,
        **kwargs: Unpack[TelethonClientKwargs],
    ) -> None:
        self._fingerprint_config: FingerprintConfig = fingerprint_config or DEFAULT_CONFIG
        self._auto_post_login: bool = auto_post_login
        self._post_login_done: bool = False

        if "connection" not in kwargs:
            kwargs["connection"] = TransportRecommendation.get_connection_class()

        # Handle the legacy pattern: TelegramClient(session, api_id_int, api_hash_str)
        if api is not None and not isinstance(api, (APIData, type)):
            if isinstance(api, (int, str)) and api_id and isinstance(api_id, str):
                # Both from the original arguments: api holds the id and
                # api_id the hash in this positional form.
                api_id, api_hash = int(api), api_id
            api = None

        # Resolve APIData
        api_data = _resolve_api(api)
        if api_data is None and api_id == 0 and api_hash is None:
            api_data = _resolve_api(API.TelegramDesktop)

        if api_data is not None:
            api_id = api_data.api_id
            api_hash = api_data.api_hash
            kwargs.setdefault("device_model", api_data.device_model)
            # Telethon defaults both to None, so a missing value is left out.
            if api_data.system_version is not None:
                kwargs.setdefault("system_version", api_data.system_version)
            if api_data.app_version is not None:
                kwargs.setdefault("app_version", api_data.app_version)
            kwargs.setdefault("lang_code", api_data.lang_code or "en")
            kwargs.setdefault("system_lang_code", api_data.system_lang_code or "en")

        self._api_data: APIData | None = api_data
        self._user_id: int | None = None

        # Telethon's own guard and int(), run here so api_id and api_hash
        # reach it as the int and str its signature declares.
        if not api_id or not api_hash:
            raise ValueError(
                "Your API ID or Hash cannot be empty or None. "
                "Refer to telethon.rtfd.io for more information."
            )
        # Telethon builds a MemorySession from None; do it here so the
        # argument matches its declared str | Path | Session.
        telethon_session = MemorySession() if session is None else session
        super().__init__(telethon_session, int(api_id), api_hash, **kwargs)

        # Telethon hardcodes lang_pack to '' — override it for official client mimicry
        if api_data is not None and api_data.lang_pack:
            self._init_request.lang_pack = api_data.lang_pack
        self._refresh_init_params()

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
            logger.debug("Fingerprint validation raised", exc_info=True)

    @property
    def UserId(self) -> int | None:
        return self._self_id if self._self_id else self._user_id

    @UserId.setter
    def UserId(self, id: int | None) -> None:
        self._user_id = id

    def _refresh_init_params(self) -> None:
        """Send ``params`` the way the impersonated client does.

        Telegram Desktop always sets ``params`` to ``{"tz_offset": <seconds>}``
        (mtproto/session_private.cpp prepareInitParams); Telethon sends none.
        """
        if self._init_request.lang_pack != "tdesktop":
            return
        self._init_request.params = types.JsonObject(
            [types.JsonObjectValue("tz_offset", types.JsonNumber(tdesktop_tz_offset()))]
        )

    async def connect(self) -> None:
        # The offset is computed per connection in tdesktop, so DST shifts
        # between connects are reflected too.
        self._refresh_init_params()
        await super().connect()

        if self._auto_post_login and not self._post_login_done:
            try:
                if await self.is_user_authorized():
                    await self._run_post_login_requests()
            except Exception:
                logger.debug("Post-login requests failed", exc_info=True)

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

        for step in _native.post_login_steps(lang_pack):
            delay_ms = step["delay_ms"]
            if delay_ms is not None:
                await asyncio.sleep(_native.random_delay_ms(*delay_ms) / 1000.0)
            try:
                await self(_POST_LOGIN_REQUESTS[step["request"]](lang_pack))
            except Exception:
                logger.debug("Post-login request failed", exc_info=True)

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
        except FreshResetAuthorisationForbiddenError as e:
            raise FreshResetAuthorisationForbiddenError(_native.FRESH_RESET_FORBIDDEN) from e
        except HashInvalidError as e:
            raise HashInvalidError(_native.HASH_INVALID) from e

    async def TerminateAllSessions(self) -> bool:
        sessions = await self.GetSessions()
        if sessions is None:
            return False

        for ss in sessions.authorizations:
            if not ss.current:
                await self.TerminateSession(ss.hash)

        return True

    async def PrintSessions(self, sessions: types.account.Authorizations | None = None) -> None:
        if sessions is None or not isinstance(sessions, types.account.Authorizations):
            sessions = await self.GetSessions()

        if sessions is None:
            raise OpenTeleException(_native.SESSIONS_UNAVAILABLE)

        print(
            _native.format_sessions([_native.session_row(auth) for auth in sessions.authorizations])
        )

    async def is_official_app(self) -> bool:
        auth = await self.GetCurrentSession()
        return False if auth is None else bool(auth.official_app)

    async def RunConsistencyChecks(self, *, auto_warn: bool = True) -> ConsistencyReport:
        from ..consistency import ConsistencyChecker

        checker = ConsistencyChecker(self, auto_warn=auto_warn)
        return await checker.run_all()

    async def QRLoginToNewClient(
        self,
        session: str | Session | None = None,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
        **kwargs: Unpack[TelethonClientKwargs],
    ) -> TelegramClient:
        newClient = TelegramClient(session, api=api, **kwargs)

        try:
            await newClient.connect()
            if newClient.session.dc_id != self.session.dc_id:
                await newClient._switch_dc(self.session.dc_id)
        except OSError as e:
            raise OSError("Cannot connect") from e

        if await newClient.is_user_authorized():
            return await self._handleExistingSession(newClient, session, api, password, **kwargs)

        if not self._self_id:
            await self.get_me()

        newClient = await self._performQRLogin(newClient, password, **kwargs)

        if newClient._auto_post_login and not newClient._post_login_done:
            try:
                await newClient._run_post_login_requests()
            except Exception:
                logger.debug("Post-login requests failed", exc_info=True)

        return newClient

    @staticmethod
    async def _cleanup_client(client: TelegramClient) -> None:
        await TelegramClient._disconnect_client(client)
        client.session.close()
        client.session.delete()

    @staticmethod
    async def _disconnect_client(client: TelegramClient, *, close_session: bool = False) -> None:
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
        **kwargs: Unpack[TelethonClientKwargs],
    ) -> TelegramClient:
        currentAuth = await newClient.GetCurrentSession()
        if currentAuth is None:
            return newClient

        if currentAuth.api_id == api.api_id:
            warnings.warn(_native.EXISTING_SESSION_KEPT, stacklevel=1)
        else:
            warnings.warn(_native.EXISTING_SESSION_REPLACED, stacklevel=1)

            await self._cleanup_client(newClient)

            newClient = await self.QRLoginToNewClient(
                session=session, api=api, password=password, **kwargs
            )

        return newClient

    async def _performQRLogin(
        self,
        newClient: TelegramClient,
        password: str | None,
        **kwargs: Unpack[TelethonClientKwargs],
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
                time_out = (qr_login.expires - time_now).seconds + _QR_EXPIRE_SAFETY_SECONDS

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
                    _native.qr_attempt_timeout_warning(attempt + 1, str(type(e))),
                    stacklevel=1,
                )
                timeout_err = TimeoutError(_native.QR_LOGIN_TIMEOUT)

            except telethon.errors.SessionPasswordNeededError:
                return await self._handle2FA(newClient, password)

            warnings.warn(_native.qr_attempt_retry_warning(attempt + 1), stacklevel=1)

        if timeout_err:
            raise timeout_err

        return newClient

    async def _handle2FA(self, newClient: TelegramClient, password: str | None) -> TelegramClient:
        if password is None:
            raise NoPasswordProvided(_native.NO_PASSWORD_PROVIDED)

        try:
            pwd: types.account.Password = await newClient(functions.account.GetPasswordRequest())
            result = await newClient(
                functions.auth.CheckPasswordRequest(_compute_check(pwd, password))
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
        return await td.TDesktop.FromTelethon(self, flag=flag, api=api, password=password)

    @staticmethod
    async def FromTDesktop(
        account: td.TDesktop | td.Account,
        session: str | Session | None = None,
        flag: type[LoginFlag] = CreateNewSession,
        api: type[APIData] | APIData = API.TelegramDesktop,
        password: str | None = None,
        **kwargs: Unpack[TelethonClientKwargs],
    ) -> TelegramClient:
        Expects(
            (flag == CreateNewSession) or (flag == UseCurrentSession),
            LoginFlagInvalid("LoginFlag invalid"),
        )

        account = TelegramClient._resolveTDesktopAccount(account)

        if (flag == UseCurrentSession) and not (
            isinstance(api, APIData) or (isinstance(api, type) and issubclass(api, APIData))
        ):
            warnings.warn(
                "\nIf you use an existing Telegram Desktop session "
                "with unofficial API_ID and API_HASH, "
                "Telegram might ban your account because of "
                "suspicious activities.\n"
                "Please use the default APIs to get rid of this.",
                stacklevel=1,
            )

        auth_session = TelegramClient._createAuthSession(session, flag)

        rows = _session_rows(account, bool(kwargs.get("use_ipv6", False)))
        auth_session.set_dc(rows["dc_id"], rows["server_address"], rows["port"])
        if account.authKey is None:
            raise TDataAuthKeyNotFound(_NO_AUTH_KEY)
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
                TDesktopNotLoaded("You need to load accounts from a tdata folder first"),
            )
            Expects(
                account.accountsCount > 0,
                TDesktopHasNoAccount("There is no account in this instance of TDesktop"),
            )
            mainAccount = account.mainAccount
            if mainAccount is None:
                raise TDesktopHasNoAccount("There is no main account in this instance of TDesktop")
            return mainAccount
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
                    "you use another session storage",
                    stacklevel=1,
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
        **kwargs: Unpack[TelethonClientKwargs],
    ) -> TelegramClient:
        return await from_session_json(session_path, json_path, flag, password, **kwargs)

    async def SaveSessionJson(
        self,
        session_path: str,
        api: type[APIData] | APIData | None = None,
        fetch_user_info: bool = False,
    ) -> tuple[str, str]:
        return await save_session_json(self, session_path, api, fetch_user_info)
