"""The 1.5.0 device classes, picking every device with ``_native.generate``.

``RandomDevice(unique_id)`` returns the device 1.5.0 picked for
``unique_id``: a ``str`` as given, anything else as its ``str()``, and a
random device without one. The device catalogs live in the core.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import _native
from ._compat import BaseObject

if TYPE_CHECKING:
    from typing import Literal

    from typing_extensions import TypeAlias

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
    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        raise NotImplementedError(f"{cls.__name__} device not supported for randomize yet")


class GeneralDesktopDevice(SystemInfo):
    pass


class WindowsDevice(GeneralDesktopDevice):
    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        # lib_base sends "Windows 11"/"Windows 10", plus " x64" on AMD64.
        return _generated_device("TelegramDesktop", unique_id, "windows")


class LinuxDevice(GeneralDesktopDevice):
    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        # lib_base sends "Linux", the XDG_CURRENT_DESKTOP items, the display
        # server and "glibc <version>"; no kernel and no distro name.
        return _generated_device("TelegramDesktop", unique_id, "linux")


class macOSDevice(GeneralDesktopDevice):
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
    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        # Telegram Android sends Build.MANUFACTURER + Build.MODEL verbatim.
        return _generated_device("TelegramAndroid", unique_id)


class IOSDevice(SystemInfo):
    @classmethod
    def RandomDevice(cls, unique_id: str | None = None) -> DeviceInfo:
        # Telegram-iOS sends platformString(hw.machine), a marketing name such
        # as "iPhone 15 Pro", and UIDevice systemVersion ("17.4.1", "26.0").
        return _generated_device("TelegramIOS", unique_id)


iOSDevice = IOSDevice


class WebBrowserDevice(SystemInfo):
    @classmethod
    def RandomDevice(cls, unique_id: str | None = None, variant: str = "z") -> DeviceInfo:
        """A browser for ``unique_id``: its user agent, and the OS name
        (``variant="z"``, Web A) or the ``navigator.platform`` string
        (``variant="k"``, Web K and Webogram) the client sends."""
        if variant == "k":
            return _generated_device("TelegramWeb_K", unique_id)
        return _generated_device("TelegramWeb_A", unique_id)
