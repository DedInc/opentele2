from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import ItemsView
from typing import Any, ClassVar, NamedTuple, TypeVar

from .utils import BaseObject

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

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

_DEVICES_DIR = os.path.join(os.path.dirname(__file__), "devices")


def _load_device_data(filename: str) -> dict[str, Any]:
    filepath = os.path.join(_DEVICES_DIR, filename)
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


class _LazyData:
    """Lazy-loading wrapper: JSON is only read on first attribute access."""

    def __init__(self, filename: str) -> None:
        self._filename = filename
        self._data: dict[str, Any] | None = None

    @property
    def data(self) -> dict[str, Any]:
        if self._data is None:
            self._data = _load_device_data(self._filename)
        return self._data

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def items(self) -> ItemsView[str, Any]:
        return self.data.items()


_desktop_lazy = _LazyData("desktop.json")
_mac_lazy = _LazyData("mac.json")
_android_lazy = _LazyData("android.json")


def _mac_identifier_to_name(identifier: str) -> str:
    words = []
    word = ""
    for ch in identifier:
        if not ch.isalpha():
            continue
        if ch.isupper() and word:
            words.append(word)
            word = ""
        word += ch
    if word:
        words.append(word)

    result = ""
    for word in words:
        if result and word not in ("Mac", "Book"):
            result += " "
        result += word
    return result


class DeviceInfo:
    def __init__(self, model: str, version: str) -> None:
        self.model = model
        self.version = version

    def __str__(self) -> str:
        return f"{self.model} {self.version}"


class SystemInfo(BaseObject):
    deviceList: ClassVar[list[DeviceInfo]] = []
    device_models: ClassVar[Any] = []
    system_versions: ClassVar[Any] = []

    @classmethod
    def RandomDevice(cls: type[SystemInfo], unique_id: str | None = None) -> DeviceInfo:
        hash_id = cls._strtohashid(unique_id)
        return cls._RandomDevice(hash_id)

    @classmethod
    def _RandomDevice(cls: type[SystemInfo], hash_id: int) -> DeviceInfo:
        cls.__gen__()
        return cls._hashtovalue(hash_id, cls.deviceList)

    @classmethod
    def __gen__(cls: type[SystemInfo]) -> None:
        raise NotImplementedError(
            f"{cls.__name__} device not supported for randomize yet"
        )

    @classmethod
    def _strtohashid(cls: type[SystemInfo], unique_id: str | None = None) -> int:
        if unique_id is not None and not isinstance(unique_id, str):
            unique_id = str(unique_id)
        byteid = os.urandom(32) if unique_id is None else unique_id.encode("utf-8")
        return int(hashlib.sha1(byteid).hexdigest(), 16) % (10**12)

    @classmethod
    def _hashtorange(
        cls: type[SystemInfo], hash_id: int, max: int, min: int = 0
    ) -> int:
        return hash_id % (max - min) + min

    @classmethod
    def _hashtovalue(cls, hash_id: int, values: list[_T]) -> _T:
        return values[hash_id % len(values)]

    @classmethod
    def _CleanAndSimplify(cls, text: str) -> str:
        return " ".join(text.split())

    @classmethod
    def _build_device_list(
        cls, models: list[str], versions: list[str]
    ) -> list[DeviceInfo]:
        return [DeviceInfo(m, v) for m in models for v in versions]

    @classmethod
    def _build_weighted_device_list(
        cls,
        models: list[str],
        versions: list[str],
        weights: dict,
        version_weights: dict[str, int] | None = None,
    ) -> list[DeviceInfo]:
        # A pair is repeated model weight times version weight, so a uniform
        # hash pick lands on it with the product of both shares.
        result: list[DeviceInfo] = []
        for m in models:
            w = weights.get(m, 1)
            for v in versions:
                vw = 1 if version_weights is None else version_weights.get(v, 1)
                result.extend([DeviceInfo(m, v)] * (w * vw))
        return result

    @classmethod
    def _gen_cartesian(cls) -> None:
        if not cls.deviceList:
            cls.deviceList = cls._build_device_list(
                cls.device_models, cls.system_versions
            )


class GeneralDesktopDevice(SystemInfo):
    device_models: ClassVar[list[str]] = []
    _model_weights: ClassVar[dict[str, int]] = {}
    _data_loaded: bool = False

    @classmethod
    def _ensure_data(cls) -> None:
        if not cls._data_loaded:
            data = _desktop_lazy.data
            cls.device_models = [e["model"] for e in data["models"]]
            cls._model_weights = {
                e["model"]: e.get("weight", 1) for e in data["models"]
            }
            cls._data_loaded = True

    @classmethod
    def _gen_desktop(cls, versions_key: str) -> None:
        """Pair the cleaned catalog models with the weighted versions under
        ``versions_key`` ("windows" or "linux") of desktop.json."""
        if cls.deviceList:
            return
        cls._ensure_data()
        entries = _desktop_lazy[versions_key]
        cls.system_versions = [e["version"] for e in entries]
        version_weights = {e["version"]: e.get("weight", 1) for e in entries}
        cleaned_models = []
        cleaned_weights = {}
        for m in cls.device_models:
            c = cls._CleanAndSimplify(m.replace("_", ""))
            cleaned_models.append(c)
            cleaned_weights[c] = cls._model_weights.get(m, 1)
        cls.deviceList = cls._build_weighted_device_list(
            cleaned_models, cls.system_versions, cleaned_weights, version_weights
        )


class WindowsDevice(GeneralDesktopDevice):
    system_versions: ClassVar[list[str]] = []
    deviceList: ClassVar[list[DeviceInfo]] = []

    @classmethod
    def __gen__(cls: type[WindowsDevice]) -> None:
        # lib_base sends "Windows 11"/"Windows 10", plus " x64" on AMD64.
        cls._gen_desktop("windows")


class LinuxDevice(GeneralDesktopDevice):
    system_versions: ClassVar[list[str]] = []
    deviceList: ClassVar[list[DeviceInfo]] = []

    @classmethod
    def __gen__(cls: type[LinuxDevice]) -> None:
        # lib_base sends "Linux", the XDG_CURRENT_DESKTOP items, the display
        # server and "glibc <version>"; no kernel and no distro name.
        cls._gen_desktop("linux")


class macOSDevice(GeneralDesktopDevice):
    device_models: ClassVar[list[str]] = []
    _model_weights: ClassVar[dict[str, int]] = {}
    system_versions: ClassVar[list[str]] = []
    _version_weights: ClassVar[dict[str, int]] = {}
    deviceList: ClassVar[list[DeviceInfo]] = []
    _mac_data_loaded: bool = False

    @classmethod
    def _ensure_mac_data(cls) -> None:
        if not cls._mac_data_loaded:
            data = _mac_lazy.data
            cls.device_models = [e["model"] for e in data["models"]]
            cls._model_weights = {
                e["model"]: e.get("weight", 1) for e in data["models"]
            }
            cls.system_versions = [e["version"] for e in data["versions"]]
            cls._version_weights = {
                e["version"]: e.get("weight", 1) for e in data["versions"]
            }
            cls._mac_data_loaded = True

    @classmethod
    def __gen__(cls: type[macOSDevice]) -> None:
        if not cls.deviceList:
            cls._ensure_mac_data()
            seen = []
            seen_weights = {}
            for model in cls.device_models:
                name = cls._CleanAndSimplify(_mac_identifier_to_name(model))
                if name not in seen:
                    seen.append(name)
                    seen_weights[name] = cls._model_weights.get(model, 1)
                else:
                    existing_w = seen_weights.get(name, 1)
                    new_w = cls._model_weights.get(model, 1)
                    if new_w > existing_w:
                        seen_weights[name] = new_w

            weighted_versions = []
            for v in cls.system_versions:
                w = cls._version_weights.get(v, 1)
                for _ in range(w):
                    weighted_versions.append(v)

            cls.device_models = seen
            cls.deviceList = cls._build_weighted_device_list(
                cls.device_models, weighted_versions, seen_weights
            )


_SDK_TO_ANDROID = {
    29: "10",
    30: "11",
    31: "12",
    32: "12",
    33: "13",
    34: "14",
    35: "15",
    36: "16",
    37: "17",
}

# SDK 32 (12L) shipped only on a few large-screen and Pixel devices, so it is
# emitted only for catalog entries that actually reported it.
_SDK_12L = 32


class AndroidDevice(SystemInfo):
    _devices: ClassVar[list[dict[str, Any]] | None] = None
    deviceList: ClassVar[list[DeviceInfo]] = []

    @classmethod
    def _ensure_android_data(cls) -> None:
        if cls._devices is None:
            cls._devices = _android_lazy["devices"]

    @classmethod
    def __gen__(cls: type[AndroidDevice]) -> None:
        if cls.deviceList:
            return
        cls._ensure_android_data()
        result = []
        for entry in cls._devices or []:
            # Telegram Android sends Build.MANUFACTURER + Build.MODEL verbatim.
            model = entry["manufacturer"] + entry["model"]
            min_sdk = entry["min_sdk"]
            max_sdk = entry["max_sdk"]
            weight = entry.get("weight", 1)
            allow_12l = entry.get("sdk_32") is True or min_sdk == _SDK_12L
            for sdk in range(min_sdk, max_sdk + 1):
                if sdk == _SDK_12L and not allow_12l:
                    continue
                ver_str = _SDK_TO_ANDROID.get(sdk)
                if ver_str:
                    device = DeviceInfo(model, f"SDK {sdk}")
                    for _ in range(weight):
                        result.append(device)
        cls.deviceList = result


class IOSDevice(SystemInfo):
    device_models: ClassVar[dict[int, list[str]]] = {
        5: ["S"],
        6: [" Plus", "", "S", "S Plus"],
        7: ["", " Plus"],
        8: ["", " Plus"],
        10: ["", "S", "S Max", "R"],
        11: ["", " Pro", " Pro Max"],
        12: [" mini", "", " Pro", " Pro Max"],
        13: [" Pro", " Pro Max", " mini", ""],
        14: ["", " Plus", " Pro", " Pro Max"],
        15: ["", " Plus", " Pro", " Pro Max"],
        16: ["", " Plus", " Pro", " Pro Max"],
        17: ["", " Air", " Pro", " Pro Max"],
    }

    PATCH_PATTERNS: ClassVar[dict[str, list[int]]] = {
        "initial": [],
        "early": [1],
        "stable": [1, 2],
        "mature": [1, 2, 3],
        "final": [1, 2, 3, 4, 5],
    }

    system_versions: ClassVar[dict[int, dict[int, list[int]]]] = {
        12: {
            5: [5, 4, 3, 2, 1],
            4: [9, 8, 7, 6, 5, 4, 3, 2, 1],
            3: [2, 1],
            2: [],
            1: [4, 3, 2, 1],
            0: [1],
        },
        13: {
            7: [],
            6: [1],
            5: [1],
            4: [1],
            3: [1],
            2: [3, 2],
            1: [3, 2, 1],
            0: [],
        },
        14: {
            8: [1],
            7: [1],
            6: [],
            5: [1],
            4: [2, 1],
            3: [],
            2: [1],
            1: [],
            0: [1],
        },
        15: {
            8: [1],
            7: [8, 7, 6, 5, 4, 3, 2, 1],
            6: [1],
            5: [],
            4: [1],
            3: [1],
            2: [],
            1: [1],
            0: [2, 1],
        },
    }

    _IOS_VERSION_MAP: ClassVar[dict[int, list[int]]] = {
        5: [12],
        6: [12, 13, 14, 15, 16],
        7: [12, 13, 14, 15, 16, 17],
        8: [12, 13, 14, 15, 16, 17, 18],
        10: [12, 13, 14, 15, 16, 17, 18, 19, 20],
        11: [13, 14, 15, 16, 17, 18, 19, 20, 21],
        12: [14, 15, 16, 17, 18, 19, 20, 21, 22],
        13: [15, 16, 17, 18, 19, 20, 21, 22, 23],
        14: [16, 17, 18, 19, 20, 21, 22, 23, 24],
        15: [17, 18, 19, 20, 21, 22, 23, 24, 25],
        16: [18, 19, 20, 21, 22, 23, 24, 25, 26],
        17: [26],
    }

    _MAJOR_VERSION_WEIGHTS: ClassVar[dict[int, int]] = {
        26: 10,
        25: 1,
        24: 1,
        23: 1,
        22: 1,
        21: 1,
        20: 1,
        19: 1,
        18: 5,
        17: 2,
        16: 1,
        15: 1,
        14: 1,
        13: 1,
        12: 1,
    }

    deviceList: ClassVar[list[DeviceInfo]] = []

    @classmethod
    def _get_patch_pattern(cls, minor: int, max_minor: int) -> list[int]:
        if minor == 0:
            return cls.PATCH_PATTERNS["initial"]
        elif minor == 1:
            return cls.PATCH_PATTERNS["early"]
        elif minor <= 3:
            return cls.PATCH_PATTERNS["stable"]
        elif minor < max_minor:
            return cls.PATCH_PATTERNS["mature"]
        else:
            return cls.PATCH_PATTERNS["final"]

    @classmethod
    def _generate_version_structure(
        cls, _major: int, max_minor: int = 8
    ) -> dict[int, list[int]]:
        result = {}
        for minor in range(max_minor + 1):
            result[minor] = cls._get_patch_pattern(minor, max_minor)
        return result

    @classmethod
    def _expand_versions(cls, major: int, minor: int, patches: list[int]) -> list[str]:
        if not patches:
            return [f"{major}.{minor}"]
        return [f"{major}.{minor}.{patch}" for patch in patches]

    @classmethod
    def __gen__(cls: type[IOSDevice]) -> None:
        if cls.deviceList:
            return

        for major in range(16, 27):
            if major not in cls.system_versions:
                if major <= 18:
                    max_minor = 8
                elif major <= 22:
                    max_minor = 7
                else:
                    max_minor = 2

                cls.system_versions[major] = cls._generate_version_structure(
                    major, max_minor
                )

        results: list[DeviceInfo] = []
        seen_versions: set = set()

        for major in sorted(cls.system_versions.keys()):
            weight = cls._MAJOR_VERSION_WEIGHTS.get(major, 1)
            for minor, patches in cls.system_versions[major].items():
                for ver in cls._expand_versions(major, minor, patches):
                    if ver not in seen_versions:
                        seen_versions.add(ver)
                        device = DeviceInfo("iPhone", ver)
                        for _ in range(weight):
                            results.append(device)

        cls.deviceList = results


iOSDevice = IOSDevice


class _BrowserConfig(NamedTuple):
    name: str
    window: tuple[int, int]
    os: tuple[str, ...]
    count: int


def _get_firefox_latest_version() -> tuple[int | None, int | None]:
    import urllib.request

    url = "https://product-details.mozilla.org/1.0/firefox_versions.json"
    try:
        with urllib.request.urlopen(url, timeout=12) as response:
            if response.getcode() != 200:
                return None, None
            data = response.read()
            text = data.decode("utf-8")
            try:
                versions = json.loads(text)
            except json.JSONDecodeError:
                return None, None
            latest = versions.get("LATEST_FIREFOX_VERSION", "")
            if not latest:
                return None, None
            major = int(latest.split(".")[0])
            return major, major - 3
    except (OSError, ValueError, AttributeError):
        return None, None


def _get_chrome_last_good_versions() -> dict[str, Any] | None:
    import urllib.request

    url = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json"
    try:
        with urllib.request.urlopen(url, timeout=12) as response:
            if response.getcode() != 200:
                return None
            data = response.read()
            text = data.decode("utf-8")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return None
    except (OSError, ValueError, AttributeError):
        return None


def _parse_os_from_ua(user_agent: str) -> str:
    ua_lower = user_agent.lower()
    if "windows" in ua_lower:
        return "Windows"
    elif "macintosh" in ua_lower or "mac os" in ua_lower:
        return "macOS"
    elif "cros" in ua_lower:
        return "ChromeOS"
    elif "linux" in ua_lower:
        return "Linux"
    return "Windows"


def _parse_platform_from_ua(user_agent: str) -> str:
    ua_lower = user_agent.lower()
    if "win64" in ua_lower or "windows" in ua_lower:
        return "Win32"
    elif "macintosh" in ua_lower or "mac os" in ua_lower:
        return "MacIntel"
    elif "linux" in ua_lower:
        if "x86_64" in ua_lower or "x64" in ua_lower:
            return "Linux x86_64"
        elif "aarch64" in ua_lower or "arm" in ua_lower:
            return "Linux aarch64"
        return "Linux x86_64"
    return "Win32"


class WebBrowserDevice(SystemInfo):
    BROWSER_WEIGHTS: ClassVar[dict[str, int]] = {
        "chrome": 19,
        "edge": 2,
        "firefox": 1,
    }

    deviceList: ClassVar[list[DeviceInfo]] = []
    _k_deviceList: ClassVar[list[DeviceInfo]] = []
    _generated = False
    _max_chromium = 145
    _firefox_max = 147
    _firefox_min = 144
    # How many major versions the browserforge dataset may trail the live one.
    _max_dataset_lag = 24
    _UA_MAJOR_PATTERNS: ClassVar[dict[str, tuple[re.Pattern[str], ...]]] = {
        "chrome": (re.compile(r"(Chrome/)(\d+)"),),
        "edge": (re.compile(r"(Chrome/)(\d+)"), re.compile(r"(Edg/)(\d+)")),
        "firefox": (re.compile(r"(rv:)(\d+)"), re.compile(r"(Firefox/)(\d+)")),
    }

    @classmethod
    def _header_generator(
        cls, name: str, os_names: tuple[str, ...], min_v: int, max_v: int
    ) -> tuple[Any, int]:
        """A generator for the requested window, and the version offset applied.

        browserforge only produces versions present in its bundled dataset. When
        the live release is newer, the window slides down to the newest one the
        dataset covers and the caller shifts generated majors back up by the
        returned offset, so the spread is kept instead of collapsing to one UA.
        """
        from browserforge.headers import Browser, HeaderGenerator

        for offset in range(cls._max_dataset_lag + 1):
            gen = HeaderGenerator(
                browser=[
                    Browser(
                        name=name,
                        min_version=min_v - offset,
                        max_version=max_v - offset,
                    )
                ],
                os=os_names,
                device="desktop",
            )
            try:
                gen.generate()
            except ValueError:
                continue
            return gen, offset
        return None, 0

    @classmethod
    def _shift_ua_major(cls, name: str, ua: str, offset: int) -> str:
        if not offset:
            return ua
        for pattern in cls._UA_MAJOR_PATTERNS.get(name, ()):
            ua = pattern.sub(lambda m: f"{m.group(1)}{int(m.group(2)) + offset}", ua)
        return ua

    @classmethod
    def _fetch_max_chromium(cls) -> int:
        result = _get_chrome_last_good_versions()
        if result:
            try:
                return int(result["channels"]["Stable"]["version"].split(".")[0])
            except (KeyError, ValueError, IndexError):
                pass
        return 145

    @classmethod
    def __gen__(cls) -> None:
        if cls._generated:
            return

        try:
            import browserforge.headers  # noqa: F401
        except ImportError:
            raise ImportError(
                "browserforge is required for web browser fingerprint generation. "
                "Install it with: pip install browserforge"
            )

        import random as _rnd

        cls._max_chromium = cls._fetch_max_chromium()
        max_v = cls._max_chromium

        chrome_min = max_v - _rnd.randint(2, 4)

        ff_max, ff_min = _get_firefox_latest_version()
        if ff_max is not None and ff_min is not None:
            cls._firefox_max = ff_max
            cls._firefox_min = ff_min
        ff_max = cls._firefox_max
        ff_min = cls._firefox_min

        browser_configs = [
            _BrowserConfig(
                "chrome", (chrome_min, max_v), ("windows", "macos", "linux"), 60
            ),
            _BrowserConfig("edge", (chrome_min - 2, max_v), ("windows", "macos"), 30),
            _BrowserConfig(
                "firefox", (ff_min, ff_max), ("windows", "macos", "linux"), 20
            ),
        ]

        z_a_list: list[DeviceInfo] = []
        k_list: list[DeviceInfo] = []
        seen_uas: set[str] = set()

        for cfg in browser_configs:
            name = cfg.name
            weight = cls.BROWSER_WEIGHTS.get(name, 1)
            min_v, window_max = cfg.window
            try:
                gen, offset = cls._header_generator(name, cfg.os, min_v, window_max)
            except Exception:
                # browserforge raises assorted errors for unknown inputs; one
                # browser family missing must not break the others.
                logger.debug("No header generator for %s", name, exc_info=True)
                continue
            if gen is None:
                continue

            for _ in range(cfg.count):
                try:
                    headers = gen.generate()
                except ValueError:
                    logger.debug("browserforge could not generate %s", name)
                    continue
                ua = cls._shift_ua_major(name, headers.get("User-Agent", ""), offset)
                if not ua or ua in seen_uas:
                    continue
                seen_uas.add(ua)

                os_name = _parse_os_from_ua(ua)
                platform_name = _parse_platform_from_ua(ua)

                z_device = DeviceInfo(ua, os_name)
                k_device = DeviceInfo(ua, platform_name)

                for _ in range(weight):
                    z_a_list.append(z_device)
                    k_list.append(k_device)

        if not z_a_list:
            default_ua = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/{max_v}.0.0.0 Safari/537.36"
            )
            z_a_list.append(DeviceInfo(default_ua, "Windows"))
            k_list.append(DeviceInfo(default_ua, "Win32"))

        cls.deviceList = z_a_list
        cls._k_deviceList = k_list
        cls._generated = True

    @classmethod
    def RandomDevice(
        cls, unique_id: str | None = None, variant: str = "z"
    ) -> DeviceInfo:
        hash_id = cls._strtohashid(unique_id)
        cls.__gen__()
        if variant == "k":
            return cls._hashtovalue(hash_id, cls._k_deviceList)
        return cls._hashtovalue(hash_id, cls.deviceList)
