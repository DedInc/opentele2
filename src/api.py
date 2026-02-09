from __future__ import annotations

import os
import platform
from typing import Any, List, Dict, Tuple, Type, TypeVar, Union, Optional

from .devices import (
    AndroidDevice,
    IOSDevice,
    macOSDevice,
    SystemInfo,
    WindowsDevice,
    LinuxDevice,
    WebBrowserDevice,
)
from .exception import Expects, NoInstanceMatched
from .utils import BaseMetaClass, BaseObject, sharemethod

__all__ = [
    "APIData",
    "API",
    "LoginFlag",
    "UseCurrentSession",
    "CreateNewSession",
]

_T = TypeVar("_T")

_X64_ARCHES = ("x86_64", "AMD64")
_X86_ARCHES = ("i386", "i686", "x86")

_DEFAULT_EXTRA_FIELDS = {
    "twoFA": None,
    "role": "",
    "id": None,
    "phone": None,
    "username": None,
    "date_of_birth": None,
    "date_of_birth_integrity": None,
    "is_premium": False,
    "has_profile_pic": False,
    "spamblock": None,
    "register_time": None,
    "last_check_time": None,
    "avatar": None,
    "first_name": "",
    "last_name": "",
    "sex": None,
    "proxy": None,
    "ipv6": False,
    "session_file": "",
}


def _coalesce(val, default):
    return val if val is not None else default


class BaseAPIMetaClass(BaseMetaClass):
    def __new__(
        cls: Type[_T], clsName: str, bases: Tuple[type], attrs: Dict[str, Any]
    ) -> _T:
        result = super().__new__(cls, clsName, bases, attrs)
        result._clsMakePID()  # type: ignore
        result.__str__ = BaseAPIMetaClass.__str__  # type: ignore

        return result

    @sharemethod
    def __str__(glob) -> str:
        if isinstance(glob, type):
            cls = glob
            result = f"{cls.__name__} {{\n"
        else:
            cls = glob.__class__
            result = f"{cls.__name__}() = {{\n"

        for attr, val in glob.__dict__.items():
            if (
                attr.startswith(f"_{cls.__base__.__name__}__")
                or attr.startswith(f"_{cls.__name__}__")
                or (attr.startswith("__") and attr.endswith("__"))
                or type(val) is classmethod
                or callable(val)
            ):
                continue

            result += f"    {attr}: {val}\n"

        return result + "}"


class APIData(object, metaclass=BaseAPIMetaClass):
    """API configuration to connect to TelegramClient and TDesktop."""

    CustomInitConnectionList: List[Union[Type[APIData], APIData]] = []

    api_id: int = None  # type: ignore
    api_hash: str = None  # type: ignore
    device_model: str = None  # type: ignore
    system_version: str = None  # type: ignore
    app_version: str = None  # type: ignore
    lang_code: str = None  # type: ignore
    system_lang_code: str = None  # type: ignore
    lang_pack: str = None  # type: ignore

    def __init__(
        self,
        api_id: int = None,
        api_hash: str = None,
        device_model: str = None,
        system_version: str = None,
        app_version: str = None,
        lang_code: str = None,
        system_lang_code: str = None,
        lang_pack: str = None,
    ) -> None:
        Expects(
            (self.__class__ != APIData)
            or (api_id is not None and api_hash is not None),
            NoInstanceMatched("No instace of API matches the arguments"),
        )

        cls = self.get_cls()

        self.api_id = _coalesce(api_id, cls.api_id)
        self.api_hash = _coalesce(api_hash, cls.api_hash)
        self.device_model = _coalesce(device_model, cls.device_model)
        self.system_version = _coalesce(system_version, cls.system_version)
        self.app_version = _coalesce(app_version, cls.app_version)
        self.system_lang_code = _coalesce(system_lang_code, cls.system_lang_code)
        self.lang_pack = _coalesce(lang_pack, cls.lang_pack)
        self.lang_code = _coalesce(lang_code, cls.lang_code)

        if self.device_model is None:
            system = platform.uname()
            if system.machine in _X64_ARCHES:
                self.device_model = "PC 64bit"
            elif system.machine in _X86_ARCHES:
                self.device_model = "PC 32bit"
            else:
                self.device_model = system.machine

        self._makePID()

    @sharemethod
    def copy(glob: Union[Type[_T], _T] = _T) -> _T:  # type: ignore
        cls = glob if isinstance(glob, type) else glob.__class__

        return cls(
            glob.api_id,  # type: ignore
            glob.api_hash,  # type: ignore
            glob.device_model,  # type: ignore
            glob.system_version,  # type: ignore
            glob.app_version,  # type: ignore
            glob.lang_code,  # type: ignore
            glob.system_lang_code,  # type: ignore
            glob.lang_pack,  # type: ignore
        )  # type: ignore

    @sharemethod
    def get_cls(glob: Union[Type[_T], _T]) -> Type[_T]:  # type: ignore
        return glob if isinstance(glob, type) else glob.__class__

    @sharemethod
    def destroy(glob: Union[Type[_T], _T]):  # type: ignore
        if isinstance(glob, type):
            return

    @classmethod
    def _web_generate(cls: Type[_T], unique_id: str = None, variant: str = "z") -> _T:
        deviceInfo = WebBrowserDevice.RandomDevice(unique_id, variant=variant)
        return cls(device_model=deviceInfo.model, system_version=deviceInfo.version)

    @staticmethod
    def from_json(data: dict) -> APIData:
        """Create an APIData instance from a session JSON dictionary.

        Args:
            data: Dictionary loaded from a .json session metadata file.
                  Expected fields: app_id, app_hash, device, sdk, app_version,
                  lang_pack, lang_code, and either system_lang_pack or
                  system_lang_code.

        Returns:
            APIData instance with all fields populated.
        """
        api_id = data.get("app_id")
        api_hash = data.get("app_hash")
        system_lang_code = data.get("system_lang_code") or data.get(
            "system_lang_pack", "en"
        )

        return APIData(
            api_id=api_id,
            api_hash=api_hash,
            device_model=data.get("device"),
            system_version=data.get("sdk"),
            app_version=data.get("app_version"),
            lang_code=data.get("lang_code", "en"),
            system_lang_code=system_lang_code,
            lang_pack=data.get("lang_pack", ""),
        )

    def to_json(self, extra: dict = None) -> dict:
        """Serialize this APIData to a session JSON dictionary.

        Args:
            extra: Optional dictionary of extra fields to include
                   (twoFA, phone, username, etc.). If None, defaults
                   are used for all extra fields.

        Returns:
            Dictionary ready for json.dump().
        """
        result = {
            "app_id": self.api_id,
            "app_hash": self.api_hash,
            "device": self.device_model,
            "sdk": self.system_version,
            "app_version": self.app_version,
            "system_lang_pack": self.system_lang_code,
            "system_lang_code": self.system_lang_code,
            "lang_pack": self.lang_pack,
            "lang_code": self.lang_code,
        }
        defaults = dict(_DEFAULT_EXTRA_FIELDS)
        if extra:
            defaults.update(extra)
        result.update(defaults)
        return result

    def __eq__(self, __o: APIData) -> bool:
        if not isinstance(__o, APIData):
            return False
        return self.pid == __o.pid

    def __del__(self):
        self.destroy()

    @classmethod
    def _makePIDEnsure(cls) -> int:
        while True:
            pid = int.from_bytes(os.urandom(8), "little")
            if cls.findData(pid) is None:
                break
        return pid

    @classmethod
    def _clsMakePID(cls: Type[APIData]):
        cls.pid = cls._makePIDEnsure()
        cls.CustomInitConnectionList.append(cls)

    def _makePID(self):
        self.pid = self.get_cls()._makePIDEnsure()
        self.get_cls().CustomInitConnectionList.append(self)

    @classmethod
    def Generate(cls: Type[_T], unique_id: str = None) -> _T:
        """Generate random device model and system version.

        Args:
            unique_id: The unique ID to generate - ensures same data each time.
                       If not set, data is randomized on each run.

        Raises:
            NotImplementedError: Not supported for web browser APIs.
        """
        _GENERATE_MAP = {
            API.TelegramAndroid: (AndroidDevice, {}),
            API.TelegramAndroidX: (AndroidDevice, {}),
            API.TelegramIOS: (IOSDevice, {}),
            API.TelegramMacOS: (macOSDevice, {}),
            API.TelegramWeb_A: (WebBrowserDevice, {"variant": "z"}),
            API.TelegramWeb_K: (WebBrowserDevice, {"variant": "k"}),
            API.Webogram: (WebBrowserDevice, {"variant": "k"}),
        }

        if cls not in _GENERATE_MAP:
            raise NotImplementedError(
                f"{cls.__name__} device not supported for randomize yet"
            )

        device_cls, kwargs = _GENERATE_MAP[cls]
        deviceInfo = device_cls.RandomDevice(unique_id, **kwargs)
        return cls(device_model=deviceInfo.model, system_version=deviceInfo.version)

    @classmethod
    def findData(cls: Type[_T], pid: int) -> Optional[_T]:
        for x in cls.CustomInitConnectionList:  # type: ignore
            if x.pid == pid:
                return x
        return None


class API(BaseObject):
    """Built-in templates for official Telegram APIs.

    Uses official API credentials, making sessions indistinguishable from
    official apps. Supports the lang_pack parameter for official apps only.
    """

    class TelegramDesktop(APIData):
        """Official Telegram for Desktop (Windows, macOS, Linux)."""

        api_id = 2040
        api_hash = "b18441a1ff607e10a989891a5462e627"
        device_model = "Desktop"
        system_version = "Windows 11"
        app_version = "6.5 x64"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "tdesktop"

        @classmethod
        def Generate(cls: Type[_T], system: str = None, unique_id: str = None) -> _T:
            """Generate random TelegramDesktop device data.

            Args:
                system: Target OS - "windows", "macos", or "linux". Random if None.
                unique_id: Ensures deterministic generation per ID.
            """
            validList = ["windows", "macos", "linux"]
            if system is None or system not in validList:
                system = SystemInfo._hashtovalue(
                    SystemInfo._strtohashid(unique_id), validList
                )

            system = system.lower()

            if system == "windows":
                deviceInfo = WindowsDevice.RandomDevice(unique_id)
            elif system == "macos":
                deviceInfo = macOSDevice.RandomDevice(unique_id)
            else:
                deviceInfo = LinuxDevice.RandomDevice(unique_id)

            return cls(device_model=deviceInfo.model, system_version=deviceInfo.version)

    class TelegramAndroid(APIData):
        """Official Telegram for Android."""

        api_id = 6
        api_hash = "eb06d4abfb49dc3eeb1aeb98ae0f581e"
        device_model = "Samsung SM-S928B"
        system_version = "SDK 35"
        app_version = "12.4.1"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "android"

    class TelegramAndroidX(APIData):
        """Official TelegramX for Android."""

        api_id = 21724
        api_hash = "3e0cb5efcd52300aec5994fdfc5bdc16"
        device_model = "Samsung SM-S928B"
        system_version = "SDK 35"
        app_version = "12.4.1"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "android"

    class TelegramIOS(APIData):
        """Official Telegram for iOS."""

        api_id = 10840
        api_hash = "33c45224029d59cb3ad0c16134215aeb"
        device_model = "iPhone"
        system_version = "26.2"
        app_version = "12.3.1 (32078) "
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "ios"

    class TelegramMacOS(APIData):
        """Official Telegram-Swift for macOS."""

        api_id = 2834
        api_hash = "68875f756c9b437a8b916ca3de215815"
        device_model = "MacBook Pro"
        system_version = "macOS 26.2"
        app_version = "12.4.1 (277873) "
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "macos"

    class TelegramWeb_A(APIData):
        """Official Telegram Web A for Browsers."""

        api_id = 2496
        api_hash = "8da85b0d5bfe62527e5b244c209159c3"
        device_model = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
        system_version = "Windows"
        app_version = "5.0.0 A"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = ""

        @classmethod
        def Generate(cls: Type[_T], unique_id: str = None) -> _T:
            return cls._web_generate(unique_id, variant="z")

    # Web Z now redirects to Web A — they share the same codebase
    TelegramWeb_Z = TelegramWeb_A

    class TelegramWeb_K(APIData):
        """Official Telegram WebK (legacy) for Browsers."""

        api_id = 2496
        api_hash = "8da85b0d5bfe62527e5b244c209159c3"
        device_model = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
        system_version = "Win32"
        app_version = "1.4.2 K"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "macos"

        @classmethod
        def Generate(cls: Type[_T], unique_id: str = None) -> _T:
            return cls._web_generate(unique_id, variant="k")

    class Webogram(APIData):
        """Old Telegram for Browsers (legacy)."""

        api_id = 2496
        api_hash = "8da85b0d5bfe62527e5b244c209159c3"
        device_model = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
        system_version = "Win32"
        app_version = "0.7.0"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = ""

        @classmethod
        def Generate(cls: Type[_T], unique_id: str = None) -> _T:
            return cls._web_generate(unique_id, variant="k")


class LoginFlag(int):
    """Flag for converting sessions between TDesktop and TelegramClient."""


class UseCurrentSession(LoginFlag):
    """Use the current session - reads the 256-byte AuthKey and converts it directly.

    Warning: Only use the same consistent API throughout the session.
    """


class CreateNewSession(LoginFlag):
    """Create a new session via QR code login using the current session for authorization.

    Safe to use with any API, even different from the original session's API.
    """


def _sync_api_versions() -> None:
    """Patch API class-level ``app_version`` / ``system_version`` attributes
    to match the latest values stored in ``PLATFORM_VERSIONS``.

    Called once at module load time.  If the import or attribute access fails
    for any reason the hardcoded class defaults remain untouched.
    """
    try:
        from .fingerprint import PLATFORM_VERSIONS as pv

        # Desktop
        suffix = pv.desktop_app_version_suffix
        API.TelegramDesktop.app_version = (
            f"{pv.desktop_app_version} {suffix}" if suffix else pv.desktop_app_version
        )

        # Android
        API.TelegramAndroid.app_version = pv.android_app_version

        # TelegramX
        API.TelegramAndroidX.app_version = pv.android_x_app_version

        # iOS — format: "VERSION (BUILD) " (trailing space matches official client)
        API.TelegramIOS.app_version = f"{pv.ios_app_version} ({pv.ios_build_number}) "
        API.TelegramIOS.system_version = pv.ios_system_version

        # macOS — format: "VERSION (BUILD) " (trailing space matches official client)
        API.TelegramMacOS.app_version = (
            f"{pv.macos_app_version} ({pv.macos_build_number}) "
        )
        API.TelegramMacOS.system_version = pv.macos_system_version

        # Web clients
        API.TelegramWeb_A.app_version = pv.web_a_version
        API.TelegramWeb_K.app_version = pv.web_k_version
    except Exception:
        pass  # keep hardcoded defaults


_sync_api_versions()
