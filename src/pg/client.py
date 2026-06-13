from __future__ import annotations

from typing import TYPE_CHECKING

from ..api import API, APIData
from ..exception import Expects, SessionFileInvalid
from .configs import DC_ADDRESSES
from .pyrogram_io import read_pyrogram_session, write_pyrogram_session
from .session_string import decode_session_string, encode_session_string

if TYPE_CHECKING:
    from ..td.tdesktop import TDesktop
    from ..tl.telethon import TelegramClient

_PRESET_MAP: dict[int, type[APIData]] = {
    6: API.TelegramAndroid,
    21724: API.TelegramAndroidX,
    10840: API.TelegramIOS,
    2040: API.TelegramDesktop,
    2834: API.TelegramMacOS,
    2496: API.TelegramWeb_A,
}


def _resolve_api_from_id(
    pyro_api_id: int | None,
    api: type[APIData] | APIData | None,
) -> APIData:
    """Pick an APIData instance from an api_id or explicit ``api`` argument."""
    if api is not None:
        if isinstance(api, APIData):
            return api
        if isinstance(api, type) and issubclass(api, APIData):
            return api()

    if pyro_api_id and pyro_api_id in _PRESET_MAP:
        return _PRESET_MAP[pyro_api_id]()

    if pyro_api_id:
        raise SessionFileInvalid(
            f"Unknown api_id {pyro_api_id} in Pyrogram session.  "
            "Pass an explicit `api=APIData(api_id, api_hash)` argument."
        )

    return API.TelegramAndroid()


def _build_telethon_session(
    data: dict,
    api_data: APIData,
    output_session: str | None = None,
    **kwargs: object,
) -> TelegramClient:
    """Build a TelegramClient from raw session data dict."""
    from telethon.crypto import AuthKey
    from telethon.sessions.memory import MemorySession
    from telethon.sessions.sqlite import SQLiteSession

    from ..tl.telethon import TelegramClient

    dc_id: int = data["dc_id"]
    auth_key_bytes: bytes = data["auth_key"]
    user_id: int | None = data.get("user_id")

    if output_session is not None:
        base = output_session
        if base.endswith(".session"):
            base = base[: -len(".session")]
        tl_session = SQLiteSession(base)
    else:
        tl_session = MemorySession()

    server_address, port = DC_ADDRESSES.get(dc_id, ("149.154.167.51", 443))
    tl_session.set_dc(dc_id, server_address, port)
    tl_session.auth_key = AuthKey(auth_key_bytes)
    if hasattr(tl_session, "save"):
        tl_session.save()

    client = TelegramClient(tl_session, api=api_data, **kwargs)

    if user_id is not None:
        client.UserId = user_id

    return client

class PyrogramSession:
    """Represents a Pyrogram session with full conversion capabilities.

    Attributes
    ----------
    dc_id : int
        Data center ID (1–5).
    api_id : int
        Telegram API application ID.
    auth_key : bytes
        256-byte MTProto authorization key.
    user_id : int | None
        Telegram user ID (may be ``None`` if unknown).
    is_bot : bool
        Whether the session belongs to a bot account.
    test_mode : bool
        Whether this is a test-mode session.
    """

    def __init__(
        self,
        *,
        dc_id: int,
        api_id: int,
        auth_key: bytes,
        user_id: int | None = None,
        is_bot: bool = False,
        test_mode: bool = False,
    ) -> None:
        self.dc_id = dc_id
        self.api_id = api_id
        self.auth_key = bytes(auth_key) if auth_key else b""
        self.user_id = user_id
        self.is_bot = is_bot
        self.test_mode = test_mode

        Expects(
            isinstance(auth_key, (bytes, bytearray)) and len(auth_key) == 256,
            exception=SessionFileInvalid(
                f"auth_key must be exactly 256 bytes, "
                f"got {len(auth_key) if auth_key else 0}"
            ),
        )

    def __repr__(self) -> str:
        uid = self.user_id or "?"
        return (
            f"PyrogramSession(dc={self.dc_id}, api_id={self.api_id}, "
            f"user={uid}, bot={self.is_bot})"
        )

    @staticmethod
    def FromSessionFile(path: str) -> PyrogramSession:
        """Load from a Pyrogram ``.session`` SQLite file."""
        data = read_pyrogram_session(path)
        return PyrogramSession(**data)

    @staticmethod
    def FromSessionString(session_string: str) -> PyrogramSession:
        """Load from a Pyrogram session string (base64)."""
        data = decode_session_string(session_string)
        return PyrogramSession(**data)

    @staticmethod
    async def FromTelethon(
        client: TelegramClient,
        api: type[APIData] | APIData | None = None,
        fetch_user_info: bool = False,
    ) -> PyrogramSession:
        """Create from an authenticated Telethon client.

        Parameters
        ----------
        client:
            Connected ``TelegramClient``.
        api:
            API preset whose ``api_id`` is stored.
            Defaults to the client's own API data.
        fetch_user_info:
            If *True* and the client is connected, calls ``get_me()``
            to populate ``user_id``.
        """
        from ..tl.session_io import _resolve_api_data

        ss = client.session
        Expects(
            ss.auth_key is not None,
            exception=SessionFileInvalid("Telethon session has no auth_key"),
        )

        api_data = _resolve_api_data(api, client)

        user_id: int | None = None
        if fetch_user_info and client.is_connected():
            try:
                me = await client.get_me()
                if me:
                    user_id = me.id
            except Exception:
                pass

        if user_id is None and client.UserId:
            user_id = client.UserId

        return PyrogramSession(
            dc_id=ss.dc_id,
            api_id=api_data.api_id,
            auth_key=ss.auth_key.key,
            user_id=user_id,
        )

    @staticmethod
    async def FromTDesktop(
        tdesktop: TDesktop,
        api: type[APIData] | APIData | None = None,
    ) -> PyrogramSession:
        """Create from a loaded ``TDesktop`` instance.

        Internally converts via Telethon (UseCurrentSession).
        """
        from ..api import UseCurrentSession
        from ..tl.telethon import TelegramClient

        use_api = api if api is not None else tdesktop.api
        client = await tdesktop.ToTelethon(flag=UseCurrentSession, api=use_api)
        try:
            return await PyrogramSession.FromTelethon(client, api=use_api)
        finally:
            await TelegramClient._disconnect_client(client, close_session=True)

    def SaveSession(self, path: str) -> str:
        """Write this session as a Pyrogram ``.session`` SQLite file.

        Returns the full path of the written file.
        """
        return write_pyrogram_session(
            path,
            dc_id=self.dc_id,
            auth_key=self.auth_key,
            api_id=self.api_id,
            user_id=self.user_id,
            is_bot=self.is_bot,
            test_mode=self.test_mode,
        )

    def ToSessionString(self) -> str:
        """Export as a Pyrogram session string (base64).

        Returns
        -------
        str
            URL-safe base64 string (no ``=`` padding).
        """
        return encode_session_string(
            dc_id=self.dc_id,
            api_id=self.api_id,
            auth_key=self.auth_key,
            user_id=self.user_id or 0,
            is_bot=self.is_bot,
            test_mode=self.test_mode,
        )

    async def ToTelethon(
        self,
        session: str | None = None,
        api: type[APIData] | APIData | None = None,
        **kwargs: object,
    ) -> TelegramClient:
        """Convert to a ``TelegramClient`` (Telethon).

        Parameters
        ----------
        session:
            Output path for the Telethon ``.session`` file.
            ``None`` → in-memory session.
        api:
            API preset.  Defaults to the preset matching ``self.api_id``.
        **kwargs:
            Forwarded to ``TelegramClient.__init__``.
        """
        api_data = _resolve_api_from_id(self.api_id, api)
        data = {
            "dc_id": self.dc_id,
            "auth_key": self.auth_key,
            "user_id": self.user_id,
        }
        return _build_telethon_session(data, api_data, session, **kwargs)

    async def ToTDesktop(
        self,
        api: type[APIData] | APIData | None = None,
        password: str | None = None,
    ) -> TDesktop:
        """Convert to a ``TDesktop`` instance.

        Parameters
        ----------
        api:
            API preset for the TDesktop.
            Defaults to ``API.TelegramDesktop``.
        password:
            2FA password (only needed with ``CreateNewSession``).
        """
        from ..api import UseCurrentSession
        from ..td.tdesktop import TDesktop
        from ..tl.telethon import TelegramClient

        use_api = api or API.TelegramDesktop
        client = await self.ToTelethon(api=use_api)
        try:
            return await TDesktop.FromTelethon(
                client, flag=UseCurrentSession, api=use_api, password=password
            )
        finally:
            await TelegramClient._disconnect_client(client, close_session=True)

    def to_dict(self) -> dict:
        """Return session data as a plain dict."""
        return {
            "dc_id": self.dc_id,
            "api_id": self.api_id,
            "test_mode": self.test_mode,
            "auth_key": self.auth_key,
            "user_id": self.user_id,
            "is_bot": self.is_bot,
        }
