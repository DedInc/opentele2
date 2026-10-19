"""The 1.5.0 device classes, picking every device with ``_native.generate``.

``RandomDevice(unique_id)`` returns the device 1.5.0 picked for
``unique_id``: a ``str`` as given, anything else as its ``str()``, and a
random device without one. The device catalogs live in the core.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Generic, TypeVar

from . import _native
from ._compat import BaseObject

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Literal

    from typing_extensions import TypeAlias

    from ._native import _Platform

    _ClientName: TypeAlias = Literal[
        "TelegramDesktop",
        "TelegramAndroid",
        "TelegramAndroidX",
        "TelegramIOS",
        "TelegramMacOS",
        "TelegramWeb_A",
        "TelegramWeb_K",
        "Webogram",
    ]
    _DesktopSystem: TypeAlias = Literal["windows", "macos", "linux"]

__all__ = [
    "AndroidDevice",
    "DeviceInfo",
    "IOSDevice",
    "LinuxDevice",
    "SystemInfo",
    "WebBrowserDevice",
    "WindowsDevice",
    "iOSDevice",
    "macOSDevice",
]


class DeviceInfo:
    def __init__(self, model: str, version: str) -> None:
        self.model = model
        self.version = version

    def __str__(self) -> str:
        return f"{self.model} {self.version}"


_T = TypeVar("_T")


class _CatalogList(Generic[_T]):
    """A read-only class attribute listing catalog data: built from the
    core's catalogs on first read, and a new list on every read, so editing
    one changes nothing ``RandomDevice`` picks."""

    def __init__(self, build: Callable[[], list[_T]]) -> None:
        self.__build = build
        self.__built: tuple[_T, ...] | None = None

    def __get__(self, instance: object, owner: type | None = None) -> list[_T]:
        if self.__built is None:
            self.__built = tuple(self.__build())
        return list(self.__built)

    def __set__(self, instance: object, value: object) -> None:
        raise AttributeError("catalog attributes are read-only")


class _BrowserWeights:
    """``WebBrowserDevice.BROWSER_WEIGHTS``: a new copy of the core's
    browser weights on every read."""

    def __get__(self, instance: object, owner: type | None = None) -> dict[str, int]:
        return dict(_native.WEB_BROWSER_WEIGHTS)

    def __set__(self, instance: object, value: object) -> None:
        raise AttributeError("catalog attributes are read-only")


def _weighted_devices(platform: _Platform) -> list[DeviceInfo]:
    """1.5.0 ``deviceList``: every catalog pair repeated by its weight, in
    catalog order."""
    devices: list[DeviceInfo] = []
    for entry in _native.catalog_entries(platform):
        device = DeviceInfo(entry["model"], entry["system_version"])
        devices.extend([device] * entry["weight"])
    return devices


def _no_devices() -> list[DeviceInfo]:
    return []


def _no_names() -> list[str]:
    return []


def _seed(unique_id: object) -> str | None:
    # 1.5.0 hashed str(unique_id) for anything that is not a str.
    if unique_id is None or isinstance(unique_id, str):
        return unique_id
    return str(unique_id)


def _generated_device(
    client: _ClientName, unique_id: object, system: _DesktopSystem | None = None
) -> DeviceInfo:
    profile = _native.generate(client, _seed(unique_id), system)
    return DeviceInfo(profile["device_model"], profile["system_version"])


class SystemInfo(BaseObject):
    # 1.5.0's catalog attributes; a class 1.5.0 filled none of leaves them
    # empty, as AndroidDevice does with device_models and system_versions.
    deviceList: _CatalogList[DeviceInfo] = _CatalogList(_no_devices)
    device_models: _CatalogList[str] = _CatalogList(_no_names)
    system_versions: _CatalogList[str] = _CatalogList(_no_names)

    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        raise NotImplementedError(f"{cls.__name__} device not supported for randomize yet")


class GeneralDesktopDevice(SystemInfo):
    pass


class WindowsDevice(GeneralDesktopDevice):
    deviceList = _CatalogList(lambda: _weighted_devices("windows"))
    device_models = _CatalogList(lambda: _native.device_models("windows"))
    system_versions = _CatalogList(lambda: _native.system_versions("windows"))

    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        # lib_base sends "Windows 11"/"Windows 10", plus " x64" on AMD64.
        return _generated_device("TelegramDesktop", unique_id, "windows")


class LinuxDevice(GeneralDesktopDevice):
    deviceList = _CatalogList(lambda: _weighted_devices("linux"))
    device_models = _CatalogList(lambda: _native.device_models("linux"))
    system_versions = _CatalogList(lambda: _native.system_versions("linux"))

    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        # lib_base sends "Linux", the XDG_CURRENT_DESKTOP items, the display
        # server and "glibc <version>"; no kernel and no distro name.
        return _generated_device("TelegramDesktop", unique_id, "linux")


class macOSDevice(GeneralDesktopDevice):
    # The bare versions; RandomDevice adds "macOS " for tdesktop, as 1.5.0 did.
    deviceList = _CatalogList(lambda: _weighted_devices("macos"))
    device_models = _CatalogList(lambda: _native.device_models("macos"))
    system_versions = _CatalogList(lambda: _native.system_versions("macos"))

    @classmethod
    def RandomDevice(cls, unique_id: str | None = None, variant: str = "tdesktop") -> DeviceInfo:
        """A catalog Mac for ``unique_id``.

        ``variant="tdesktop"`` formats the version as lib_base does
        ("macOS 26.7.1"); ``variant="swift"`` keeps TelegramSwift's bare
        "26.7.1". Both pick the same Mac for the same ``unique_id``.
        """
        if variant == "swift":
            return _generated_device("TelegramMacOS", unique_id)
        return _generated_device("TelegramDesktop", unique_id, "macos")


class AndroidDevice(SystemInfo):
    deviceList = _CatalogList(lambda: _weighted_devices("android"))

    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        # Telegram Android sends Build.MANUFACTURER + Build.MODEL verbatim.
        return _generated_device("TelegramAndroid", unique_id)


class IOSDevice(SystemInfo):
    deviceList = _CatalogList(lambda: _weighted_devices("ios"))
    device_models = _CatalogList(lambda: _native.device_models("ios"))
    system_versions = _CatalogList(lambda: _native.system_versions("ios"))

    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        # Telegram-iOS sends platformString(hw.machine), a marketing name such
        # as "iPhone 15 Pro", and UIDevice systemVersion ("17.4.1", "26.0").
        return _generated_device("TelegramIOS", unique_id)


iOSDevice = IOSDevice


class WebBrowserDevice(SystemInfo):
    BROWSER_WEIGHTS = _BrowserWeights()
    # The Web A browsers (user agent, OS name) that variant "z" picks from.
    deviceList = _CatalogList(lambda: _weighted_devices("web_a"))

    @classmethod
    def RandomDevice(cls, unique_id: str | None = None, variant: str = "z") -> DeviceInfo:
        """A browser for ``unique_id``: its user agent, and the OS name
        (``variant="z"``, Web A) or the ``navigator.platform`` string
        (``variant="k"``, Web K and Webogram) the client sends."""
        if variant == "k":
            return _generated_device("TelegramWeb_K", unique_id)
        return _generated_device("TelegramWeb_A", unique_id)
