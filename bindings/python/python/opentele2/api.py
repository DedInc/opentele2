"""The 1.5.0 API classes, with every value from :mod:`opentele2._native`.

Each client class holds the default profile ``_native.profile`` gives for
it, and ``Generate`` the device ``_native.generate`` picks for the seed.
"""

from __future__ import annotations

import logging
import platform
from typing import TYPE_CHECKING, overload

from . import _native
from ._compat import BaseMetaClass, BaseObject, sharemethod
from ._native import CoreError
from .devices import (
    AndroidDevice,
    DeviceInfo,
    IOSDevice,
    WebBrowserDevice,
    _seed,
    macOSDevice,
)
from .exception import Expects, NoInstanceMatched

if TYPE_CHECKING:
    from collections.abc import Callable

    from typing_extensions import Self

    from ._native import ApiProfile
    from .devices import _ClientName, _DesktopSystem

__all__ = [
    "API",
    "APIData",
    "CreateNewSession",
    "LoginFlag",
    "UseCurrentSession",
]

logger = logging.getLogger(__name__)

_X64_ARCHES = ("x86_64", "AMD64")
_X86_ARCHES = ("i386", "i686", "x86")

# Stands in for a field an instance leaves None while the core writes its
# session JSON, and is written back as the null 1.5.0 wrote for it.
_UNSET_FIELD = "\x00opentele2-unset-field\x00"


def _describe_api(glob: object) -> str:
    """``str()`` of an API class or instance: its plain data attributes."""
    if isinstance(glob, type):
        cls = glob
        result = f"{cls.__name__} {{\n"
    else:
        cls = glob.__class__
        result = f"{cls.__name__}() = {{\n"

    base = cls.__base__.__name__ if cls.__base__ is not None else ""
    for attr, val in glob.__dict__.items():
        if (
            attr.startswith((f"_{base}__", f"_{cls.__name__}__"))
            or (attr.startswith("__") and attr.endswith("__"))
            or type(val) is classmethod
            or callable(val)
        ):
            continue

        result += f"    {attr}: {val}\n"

    return result + "}"


class BaseAPIMetaClass(BaseMetaClass):
    # str(SomeAPI); APIData.__str__ below serves str(SomeAPI()).
    __str__ = sharemethod(_describe_api)


def _local_device_model() -> str:
    system = platform.uname()
    if system.machine in _X64_ARCHES:
        return "PC 64bit"
    if system.machine in _X86_ARCHES:
        return "PC 32bit"
    return system.machine


def _defaults(client: _ClientName) -> tuple[int, str, str, str, str, str, str, str]:
    """The class values of ``client``, in the order 1.5.0 declared them."""
    profile = _native.profile(client)
    return (
        profile["api_id"],
        profile["api_hash"],
        profile["device_model"],
        profile["system_version"],
        profile["app_version"],
        profile["lang_code"],
        profile["system_lang_code"],
        profile["lang_pack"],
    )


def _desktop_system(name: str | None) -> _DesktopSystem | None:
    # Matched case-sensitively, as 1.5.0 _DESKTOP_SYSTEMS was.
    if name == "windows":
        return "windows"
    if name == "macos":
        return "macos"
    if name == "linux":
        return "linux"
    return None


def _unset_marked(value: str | None) -> str:
    return _UNSET_FIELD if value is None else value


def _holds_null(data: dict, key: str) -> bool:
    return key in data and data[key] is None


class APIData(metaclass=BaseAPIMetaClass):
    # Declared, not bound: the base class has no credentials or device of its
    # own. Every concrete API binds them, and __init__ refuses to build an
    # instance without api_id/api_hash and falls back to the local machine
    # for device_model.
    api_id: int
    api_hash: str
    device_model: str
    # None is a real state here: APIData(api_id, api_hash) leaves whatever
    # was not supplied unset.
    system_version: str | None = None
    app_version: str | None = None
    lang_code: str | None = None
    system_lang_code: str | None = None
    lang_pack: str | None = None

    __str__ = sharemethod(_describe_api)

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
        cls = self.get_cls()

        # A class that binds no api_id/api_hash (APIData itself) needs both
        # passed explicitly.
        Expects(
            (api_id is not None or hasattr(cls, "api_id"))
            and (api_hash is not None or hasattr(cls, "api_hash")),
            NoInstanceMatched("No instace of API matches the arguments"),
        )

        self.api_id = cls.api_id if api_id is None else api_id
        self.api_hash = cls.api_hash if api_hash is None else api_hash
        if device_model is None:
            device_model = (
                cls.device_model if hasattr(cls, "device_model") else _local_device_model()
            )
        self.device_model = device_model
        self.system_version = cls.system_version if system_version is None else system_version
        self.app_version = cls.app_version if app_version is None else app_version
        self.system_lang_code = (
            cls.system_lang_code if system_lang_code is None else system_lang_code
        )
        self.lang_pack = cls.lang_pack if lang_pack is None else lang_pack
        self.lang_code = cls.lang_code if lang_code is None else lang_code

    @sharemethod
    def copy(glob: type[APIData] | APIData) -> APIData:
        if not isinstance(glob, APIData):
            # A class's own values are exactly what its constructor defaults to.
            return glob()

        return glob.__class__(
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
    def get_cls(glob: type[APIData] | APIData) -> type[APIData]:
        return type(glob) if isinstance(glob, APIData) else glob

    @sharemethod
    def destroy(glob: type[APIData] | APIData) -> None:
        if isinstance(glob, type):
            return

    @classmethod
    def _from_device(cls, device: DeviceInfo) -> Self:
        return cls(device_model=device.model, system_version=device.version)

    @classmethod
    def _web_generate(cls, unique_id: str | None = None, variant: str = "z") -> Self:
        return cls._from_device(WebBrowserDevice.RandomDevice(unique_id, variant=variant))

    @staticmethod
    def from_json(data: dict) -> APIData:
        """The API of session JSON as 1.5.0 read it: ``app_id`` and
        ``app_hash`` are required. A missing ``device`` is the local
        machine's model, and a missing ``sdk`` or ``app_version`` stays None.
        ``lang_code`` defaults to ``"en"``, ``lang_pack`` to ``""``, and
        ``system_lang_code`` falls back to ``system_lang_pack``, then
        ``"en"``; a language key holding null stays None."""
        completed = dict(data)
        # 1.5.0 read every key with dict.get, so null and absent are alike.
        if completed.get("device") is None:
            completed["device"] = _local_device_model()
        sdk_unset = completed.get("sdk") is None
        if sdk_unset:
            completed["sdk"] = ""
        app_version_unset = completed.get("app_version") is None
        if app_version_unset:
            completed["app_version"] = ""

        try:
            profile = _native.profile_from_session_json(completed)
        except CoreError as error:
            raise NoInstanceMatched(error.message) from error

        # The core reads a language key holding null as absent; 1.5.0's
        # dict.get defaults applied only to absent keys.
        system_lang_code: str | None = profile["system_lang_code"]
        if not data.get("system_lang_code") and _holds_null(data, "system_lang_pack"):
            system_lang_code = None

        return APIData(
            api_id=profile["api_id"],
            api_hash=profile["api_hash"],
            device_model=profile["device_model"],
            system_version=None if sdk_unset else profile["system_version"],
            app_version=None if app_version_unset else profile["app_version"],
            lang_code=None if _holds_null(data, "lang_code") else profile["lang_code"],
            system_lang_code=system_lang_code,
            lang_pack=None if _holds_null(data, "lang_pack") else profile["lang_pack"],
        )

    def to_json(self, extra: dict | None = None) -> dict:
        profile: ApiProfile = {
            "api_id": self.api_id,
            "api_hash": self.api_hash,
            "device_model": self.device_model,
            "system_version": _unset_marked(self.system_version),
            "app_version": _unset_marked(self.app_version),
            "lang_code": _unset_marked(self.lang_code),
            "system_lang_code": _unset_marked(self.system_lang_code),
            "lang_pack": _unset_marked(self.lang_pack),
        }
        written = _native.profile_to_session_json(profile, extra)
        return {key: None if value == _UNSET_FIELD else value for key, value in written.items()}

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
        random_device = _RANDOM_DEVICES.get(cls)
        if random_device is None:
            raise NotImplementedError(f"{cls.__name__} device not supported for randomize yet")

        return cls._from_device(random_device(unique_id))


class API(BaseObject):
    class TelegramDesktop(APIData):
        (
            api_id,
            api_hash,
            device_model,
            system_version,
            app_version,
            lang_code,
            system_lang_code,
            lang_pack,
        ) = _defaults("TelegramDesktop")

        @overload
        @classmethod
        def Generate(cls, unique_id: str | None = None) -> Self: ...

        @overload
        @classmethod
        def Generate(cls, system: str | None, unique_id: str | None) -> Self: ...

        @overload
        @classmethod
        def Generate(cls, *, system: str | None = None, unique_id: str | None = None) -> Self: ...

        @classmethod
        def Generate(cls, system: str | None = None, unique_id: str | None = None) -> Self:
            """A random desktop device, seeded by ``unique_id``.

            Public API since opentele puts the platform first:
            ``Generate("windows", "id")``. A single positional argument that
            is not a platform name is the ``unique_id`` of the base-class
            form ``Generate("id")``.
            """
            if unique_id is None and system is not None and _desktop_system(system) is None:
                system, unique_id = None, system

            # Without a platform, the core picks one from the unique_id hash.
            profile = _native.generate("TelegramDesktop", _seed(unique_id), _desktop_system(system))
            return cls(
                device_model=profile["device_model"],
                system_version=profile["system_version"],
                app_version=profile["app_version"],
            )

    class TelegramAndroid(APIData):
        (
            api_id,
            api_hash,
            device_model,
            system_version,
            app_version,
            lang_code,
            system_lang_code,
            lang_pack,
        ) = _defaults("TelegramAndroid")

    class TelegramAndroidX(APIData):
        (
            api_id,
            api_hash,
            device_model,
            system_version,
            app_version,
            lang_code,
            system_lang_code,
            lang_pack,
        ) = _defaults("TelegramAndroidX")

    class TelegramIOS(APIData):
        (
            api_id,
            api_hash,
            device_model,
            system_version,
            app_version,
            lang_code,
            system_lang_code,
            lang_pack,
        ) = _defaults("TelegramIOS")

    class TelegramMacOS(APIData):
        (
            api_id,
            api_hash,
            device_model,
            system_version,
            app_version,
            lang_code,
            system_lang_code,
            lang_pack,
        ) = _defaults("TelegramMacOS")

    class TelegramWeb_A(APIData):
        (
            api_id,
            api_hash,
            device_model,
            system_version,
            app_version,
            lang_code,
            system_lang_code,
            lang_pack,
        ) = _defaults("TelegramWeb_A")

        @classmethod
        def Generate(cls, unique_id: str | None = None) -> Self:
            return cls._web_generate(unique_id, variant="z")

    TelegramWeb_Z = TelegramWeb_A

    class TelegramWeb_K(APIData):
        (
            api_id,
            api_hash,
            device_model,
            system_version,
            app_version,
            lang_code,
            system_lang_code,
            lang_pack,
        ) = _defaults("TelegramWeb_K")

        @classmethod
        def Generate(cls, unique_id: str | None = None) -> Self:
            return cls._web_generate(unique_id, variant="k")

    class Webogram(APIData):
        (
            api_id,
            api_hash,
            device_model,
            system_version,
            app_version,
            lang_code,
            system_lang_code,
            lang_pack,
        ) = _defaults("Webogram")

        @classmethod
        def Generate(cls, unique_id: str | None = None) -> Self:
            return cls._web_generate(unique_id, variant="k")


def _swift_mac(unique_id: str | None) -> DeviceInfo:
    return macOSDevice.RandomDevice(unique_id, variant="swift")


# The device APIData.Generate gives each client that does not override it;
# 1.5.0 matched the exact class, so a subclass raises NotImplementedError.
_RANDOM_DEVICES: dict[type[APIData], Callable[[str | None], DeviceInfo]] = {
    API.TelegramAndroid: AndroidDevice.RandomDevice,
    API.TelegramAndroidX: AndroidDevice.RandomDevice,
    API.TelegramIOS: IOSDevice.RandomDevice,
    API.TelegramMacOS: _swift_mac,
}


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

        API.TelegramMacOS.app_version = f"{pv.macos_app_version} ({pv.macos_build_number}) "
        API.TelegramMacOS.system_version = pv.macos_system_version

        API.TelegramWeb_A.app_version = pv.web_a_version
        API.TelegramWeb_K.app_version = pv.web_k_version
    except Exception:
        # Keep the class defaults if the platform versions are unusable.
        logger.debug("Could not sync API versions", exc_info=True)


_sync_api_versions()
