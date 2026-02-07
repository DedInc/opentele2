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
                or attr.startswith("__")
                and attr.endswith("__")
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
        if cls == API.TelegramAndroid or cls == API.TelegramAndroidX:
            deviceInfo = AndroidDevice.RandomDevice(unique_id)

        elif cls == API.TelegramIOS:
            deviceInfo = IOSDevice.RandomDevice(unique_id)

        elif cls == API.TelegramMacOS:
            deviceInfo = macOSDevice.RandomDevice(unique_id)

        else:
            raise NotImplementedError(
                f"{cls.__name__} device not supported for randomize yet"
            )

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
        system_version = "Windows 10"
        app_version = "3.4.3 x64"
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
        device_model = "Samsung Galaxy S24 Ultra"
        system_version = "SDK 35"
        app_version = "12.3.0"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "android"

    class TelegramAndroidX(APIData):
        """Official TelegramX for Android."""

        api_id = 21724
        api_hash = "3e0cb5efcd52300aec5994fdfc5bdc16"
        device_model = "Samsung Galaxy S24 Ultra"
        system_version = "SDK 35"
        app_version = "12.3.0"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "android"

    class TelegramIOS(APIData):
        """Official Telegram for iOS."""

        api_id = 10840
        api_hash = "33c45224029d59cb3ad0c16134215aeb"
        device_model = "iPhone 16 Pro Max"
        system_version = "26.2"
        app_version = "12.3"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "ios"

    class TelegramMacOS(APIData):
        """Official Telegram-Swift for macOS."""

        api_id = 2834
        api_hash = "68875f756c9b437a8b916ca3de215815"
        device_model = "MacBook Pro"
        system_version = "macOS 26.2"
        app_version = "12.3"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "macos"

    class TelegramWeb_Z(APIData):
        """Official Telegram WebZ for Browsers."""

        api_id = 2496
        api_hash = "8da85b0d5bfe62527e5b244c209159c3"
        device_model = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
        system_version = "Windows"
        app_version = "5.0.0 Z"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = ""

    class TelegramWeb_A(APIData):
        """Official Telegram WebA for Browsers."""

        api_id = 2496
        api_hash = "8da85b0d5bfe62527e5b244c209159c3"
        device_model = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
        system_version = "Windows"
        app_version = "5.0.0 A"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = ""

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
