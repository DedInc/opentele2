from __future__ import annotations

import logging
import platform
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from typing_extensions import Self

from .devices import (
    AndroidDevice,
    IOSDevice,
    LinuxDevice,
    SystemInfo,
    WebBrowserDevice,
    WindowsDevice,
    macOSDevice,
)
from .exception import Expects, NoInstanceMatched
from .utils import BaseMetaClass, BaseObject, sharemethod

__all__ = [
    "API",
    "APIData",
    "CreateNewSession",
    "LoginFlag",
    "UseCurrentSession",
]

logger = logging.getLogger(__name__)

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

_DEFAULT_WEB_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.0.0 Safari/537.36"
)


def _coalesce(val: _T | None, default: _T) -> _T:
    return val if val is not None else default


class BaseAPIMetaClass(BaseMetaClass):
    def __new__(cls, clsName: str, bases: tuple[type], attrs: dict[str, Any]) -> Self:
        result = super().__new__(cls, clsName, bases, attrs)
        result.__str__ = BaseAPIMetaClass.__str__

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
                attr.startswith((f"_{cls.__base__.__name__}__", f"_{cls.__name__}__"))
                or (attr.startswith("__") and attr.endswith("__"))
                or type(val) is classmethod
                or callable(val)
            ):
                continue

            result += f"    {attr}: {val}\n"

        return result + "}"


class APIData(metaclass=BaseAPIMetaClass):
    api_id: int = None
    api_hash: str = None
    device_model: str = None
    system_version: str = None
    app_version: str = None
    lang_code: str = None
    system_lang_code: str = None
    lang_pack: str = None

    def __init__(
        self,
        api_id: int | None = None,
        api_hash: str | None = None,
        device_model: str | None = None,
        system_version: str | None = None,
        app_version: str | None = None,
        lang_code: str | None = None,
        system_lang_code: str | None = None,
        lang_pack: str | None = None,
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

    @sharemethod
    def copy(glob: type[_T] | _T = _T) -> _T:
        cls = glob if isinstance(glob, type) else glob.__class__

        return cls(
            glob.api_id,
            glob.api_hash,
            glob.device_model,
            glob.system_version,
            glob.app_version,
            glob.lang_code,
            glob.system_lang_code,
            glob.lang_pack,
        )

    @sharemethod
    def get_cls(glob: type[_T] | _T) -> type[_T]:
        return glob if isinstance(glob, type) else glob.__class__

    @sharemethod
    def destroy(glob: type[_T] | _T) -> None:
        if isinstance(glob, type):
            return

    @classmethod
    def _web_generate(cls, unique_id: str | None = None, variant: str = "z") -> Self:
        deviceInfo = WebBrowserDevice.RandomDevice(unique_id, variant=variant)
        return cls(device_model=deviceInfo.model, system_version=deviceInfo.version)

    @staticmethod
    def from_json(data: dict) -> APIData:
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

    def to_json(self, extra: dict | None = None) -> dict:
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

    def __eq__(self, other: object, /) -> bool:
        if not isinstance(other, APIData):
            return NotImplemented
        return (
            self.api_id == other.api_id
            and self.api_hash == other.api_hash
            and self.device_model == other.device_model
            and self.system_version == other.system_version
            and self.app_version == other.app_version
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.api_id,
                self.api_hash,
                self.device_model,
                self.system_version,
                self.app_version,
            )
        )

    def __del__(self) -> None:
        pass

    @classmethod
    def Generate(cls, unique_id: str | None = None) -> Self:
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


def _desktop_app_version(system: str) -> str:
    """The app version tdesktop's ``ComputeAppVersion`` sends for a platform.

    Only Windows x64 builds append " x64"; x86_64 builds elsewhere send the
    bare version and other CPUs append their architecture. Every model in
    devices/mac.json is Apple Silicon, so generated Macs report " arm64";
    generated Linux devices are x86_64.
    """
    from .fingerprint import PLATFORM_VERSIONS

    version = PLATFORM_VERSIONS.desktop_app_version
    if system == "windows":
        return f"{version} x64"
    if system == "macos":
        return f"{version} arm64"
    return version


class API(BaseObject):
    class TelegramDesktop(APIData):
        api_id = 2040
        api_hash = "b18441a1ff607e10a989891a5462e627"
        device_model = "Desktop"
        system_version = "Windows 11"
        app_version = "6.5 x64"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "tdesktop"

        @classmethod
        def Generate(
            cls, system: str | None = None, unique_id: str | None = None
        ) -> Self:
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

            return cls(
                device_model=deviceInfo.model,
                system_version=deviceInfo.version,
                app_version=_desktop_app_version(system),
            )

    class TelegramAndroid(APIData):
        api_id = 6
        api_hash = "eb06d4abfb49dc3eeb1aeb98ae0f581e"
        device_model = "Samsung SM-S928B"
        system_version = "SDK 35"
        app_version = "12.7.3"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "android"

    class TelegramAndroidX(APIData):
        api_id = 21724
        api_hash = "3e0cb5efcd52300aec5994fdfc5bdc16"
        device_model = "Samsung SM-S928B"
        system_version = "SDK 35"
        app_version = "0.28.3.1785"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "android"

    class TelegramIOS(APIData):
        api_id = 10840
        api_hash = "33c45224029d59cb3ad0c16134215aeb"
        device_model = "iPhone"
        system_version = "26.2"
        app_version = "12.7"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "ios"

    class TelegramMacOS(APIData):
        api_id = 2834
        api_hash = "68875f756c9b437a8b916ca3de215815"
        device_model = "MacBook Pro"
        system_version = "macOS 26.2"
        app_version = "12.7"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "macos"

    class TelegramWeb_A(APIData):
        api_id = 2496
        api_hash = "8da85b0d5bfe62527e5b244c209159c3"
        device_model = _DEFAULT_WEB_USER_AGENT
        system_version = "Windows"
        app_version = "12.0.28 A"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = ""

        @classmethod
        def Generate(cls, unique_id: str | None = None) -> Self:
            return cls._web_generate(unique_id, variant="z")

    TelegramWeb_Z = TelegramWeb_A

    class TelegramWeb_K(APIData):
        api_id = 2496
        api_hash = "8da85b0d5bfe62527e5b244c209159c3"
        device_model = _DEFAULT_WEB_USER_AGENT
        system_version = "Win32"
        app_version = "2.2 K"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "macos"

        @classmethod
        def Generate(cls, unique_id: str | None = None) -> Self:
            return cls._web_generate(unique_id, variant="k")

    class Webogram(APIData):
        api_id = 2496
        api_hash = "8da85b0d5bfe62527e5b244c209159c3"
        device_model = _DEFAULT_WEB_USER_AGENT
        system_version = "Win32"
        app_version = "0.7.0"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = ""

        @classmethod
        def Generate(cls, unique_id: str | None = None) -> Self:
            return cls._web_generate(unique_id, variant="k")


class LoginFlag(int):
    pass


class UseCurrentSession(LoginFlag):
    pass


class CreateNewSession(LoginFlag):
    pass


def _sync_api_versions() -> None:
    try:
        from .fingerprint import PLATFORM_VERSIONS as pv

        suffix = pv.desktop_app_version_suffix
        API.TelegramDesktop.app_version = (
            f"{pv.desktop_app_version} {suffix}" if suffix else pv.desktop_app_version
        )

        API.TelegramAndroid.app_version = (
            f"{pv.android_app_version} ({pv.android_app_version_code})"
        )

        API.TelegramAndroidX.app_version = pv.android_x_app_version

        API.TelegramIOS.app_version = f"{pv.ios_app_version} ({pv.ios_build_number}) "
        API.TelegramIOS.system_version = pv.ios_system_version

        API.TelegramMacOS.app_version = (
            f"{pv.macos_app_version} ({pv.macos_build_number}) "
        )
        API.TelegramMacOS.system_version = pv.macos_system_version

        API.TelegramWeb_A.app_version = pv.web_a_version
        API.TelegramWeb_K.app_version = pv.web_k_version
    except Exception:
        # Keep the class defaults if the platform versions are unusable.
        logger.debug("Could not sync API versions", exc_info=True)


_sync_api_versions()
