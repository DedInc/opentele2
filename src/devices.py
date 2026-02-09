from __future__ import annotations
from typing import Any, List, Dict, TypeVar, Type

try:
    from .utils import BaseObject
except ImportError:
    from utils import BaseObject
import hashlib
import os
import json

__all__ = [
    "DeviceInfo",
    "SystemInfo",
    "WindowsDevice",
    "LinuxDevice",
    "macOSDevice",
    "AndroidDevice",
    "IOSDevice",
    "iOSDevice",
    "WebBrowserDevice",
]

_T = TypeVar("_T")

_DEVICES_DIR = os.path.join(os.path.dirname(__file__), "devices")


def _load_device_data(filename: str) -> dict:
    filepath = os.path.join(_DEVICES_DIR, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


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


class DeviceInfo(object):
    def __init__(self, model, version) -> None:
        self.model = model
        self.version = version

    def __str__(self) -> str:
        return f"{self.model} {self.version}"


class SystemInfo(BaseObject):
    deviceList: List[DeviceInfo] = []
    device_models: Any = []
    system_versions: Any = []

    @classmethod
    def RandomDevice(cls: Type[SystemInfo], unique_id: str = None) -> DeviceInfo:
        hash_id = cls._strtohashid(unique_id)
        return cls._RandomDevice(hash_id)

    @classmethod
    def _RandomDevice(cls, hash_id: int):
        cls.__gen__()
        return cls._hashtovalue(hash_id, cls.deviceList)

    @classmethod
    def __gen__(cls):
        raise NotImplementedError(
            f"{cls.__name__} device not supported for randomize yet"
        )

    @classmethod
    def _strtohashid(cls, unique_id: str = None):
        if unique_id is not None and not isinstance(unique_id, str):
            unique_id = str(unique_id)
        byteid = os.urandom(32) if unique_id is None else unique_id.encode("utf-8")
        return int(hashlib.sha1(byteid).hexdigest(), 16) % (10**12)

    @classmethod
    def _hashtorange(cls, hash_id: int, max, min=0):
        return hash_id % (max - min) + min

    @classmethod
    def _hashtovalue(cls, hash_id: int, values: List[_T]) -> _T:
        return values[hash_id % len(values)]

    @classmethod
    def _CleanAndSimplify(cls, text: str) -> str:
        return " ".join(text.split())

    @classmethod
    def _build_device_list(
        cls, models: List[str], versions: List[str]
    ) -> List[DeviceInfo]:
        return [DeviceInfo(m, v) for m in models for v in versions]

    @classmethod
    def _build_weighted_device_list(
        cls, models: List[str], versions: List[str], weights: dict
    ) -> List[DeviceInfo]:
        result = []
        for m in models:
            w = weights.get(m, 1)
            for v in versions:
                device = DeviceInfo(m, v)
                for _ in range(w):
                    result.append(device)
        return result

    @classmethod
    def _gen_cartesian(cls):
        if not cls.deviceList:
            cls.deviceList = cls._build_device_list(
                cls.device_models, cls.system_versions
            )


_desktop_data = _load_device_data("desktop.json")


class GeneralDesktopDevice(SystemInfo):
    device_models = [e["model"] for e in _desktop_data["models"]]
    _model_weights = {e["model"]: e.get("weight", 1) for e in _desktop_data["models"]}


class WindowsDevice(GeneralDesktopDevice):
    system_versions = _desktop_data["versions"]
    deviceList: List[DeviceInfo] = []

    @classmethod
    def __gen__(cls: Type[WindowsDevice]) -> None:
        if not cls.deviceList:
            cleaned_models = []
            cleaned_weights = {}
            for m in cls.device_models:
                c = cls._CleanAndSimplify(m.replace("_", ""))
                cleaned_models.append(c)
                cleaned_weights[c] = cls._model_weights.get(m, 1)
            cls.deviceList = cls._build_weighted_device_list(
                cleaned_models, cls.system_versions, cleaned_weights
            )


class LinuxDevice(GeneralDesktopDevice):
    system_versions: List[str] = []
    deviceList: List[DeviceInfo] = []

    @classmethod
    def __gen__(cls: Type[LinuxDevice]) -> None:
        if cls.system_versions:
            return

        linux_distros = _desktop_data["linuxDistros"]
        enviroments = _desktop_data["environments"]
        wayland = _desktop_data["wayland"]

        versions = []
        for distro_name, distro_info in linux_distros.items():
            kernel = distro_info["kernel"]
            glibc = distro_info["glibc"]
            distro_weight = distro_info.get("weight", 1)

            for env in enviroments:
                for wl in wayland:
                    version = f"Linux {kernel} {distro_name} {env} {wl} glibc {glibc}"
                    cleaned = cls._CleanAndSimplify(version)
                    for _ in range(distro_weight):
                        versions.append(cleaned)

        cls.system_versions = versions

        cls.deviceList = cls._build_weighted_device_list(
            cls.device_models, cls.system_versions, cls._model_weights
        )


_mac_data = _load_device_data("mac.json")


class macOSDevice(GeneralDesktopDevice):
    device_models = [e["model"] for e in _mac_data["models"]]
    _model_weights = {e["model"]: e.get("weight", 1) for e in _mac_data["models"]}
    system_versions = [e["version"] for e in _mac_data["versions"]]
    _version_weights = {e["version"]: e.get("weight", 1) for e in _mac_data["versions"]}
    deviceList: List[DeviceInfo] = []

    @classmethod
    def __gen__(cls: Type[macOSDevice]) -> None:
        if not cls.deviceList:
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


_android_data = _load_device_data("android.json")

# SDK level to Android version string
_SDK_TO_ANDROID = {
    24: "7",
    25: "7.1",
    26: "8",
    27: "8.1",
    28: "9",
    29: "10",
    30: "11",
    31: "12",
    32: "12",
    33: "13",
    34: "14",
    35: "15",
}


class AndroidDevice(SystemInfo):
    _devices = _android_data["devices"]
    deviceList: List[DeviceInfo] = []

    @classmethod
    def __gen__(cls: Type[AndroidDevice]) -> None:
        if cls.deviceList:
            return
        result = []
        for entry in cls._devices:
            model = entry["model"]
            min_sdk = entry["min_sdk"]
            max_sdk = entry["max_sdk"]
            weight = entry.get("weight", 1)
            for sdk in range(min_sdk, max_sdk + 1):
                ver_str = _SDK_TO_ANDROID.get(sdk)
                if ver_str:
                    device = DeviceInfo(model, f"SDK {sdk}")
                    for _ in range(weight):
                        result.append(device)
        cls.deviceList = result


class IOSDevice(SystemInfo):
    device_models = {
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

    PATCH_PATTERNS = {
        "initial": [],
        "early": [1],
        "stable": [1, 2],
        "mature": [1, 2, 3],
        "final": [1, 2, 3, 4, 5],
    }

    system_versions: Dict[int, Dict[int, List[int]]] = {
        # iOS 12
        12: {
            5: [5, 4, 3, 2, 1],
            4: [9, 8, 7, 6, 5, 4, 3, 2, 1],
            3: [2, 1],
            2: [],
            1: [4, 3, 2, 1],
            0: [1],
        },
        # iOS 13
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
        # iOS 14
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
        # iOS 15
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

    _IOS_VERSION_MAP = {
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

    # Weight multipliers for iOS major versions based on market share (Jan 2026).
    # iOS 26.x ~67%, iOS 18.x ~28%, iOS 17.x ~3%, iOS 16.x ~2%, older <1%.
    _MAJOR_VERSION_WEIGHTS: Dict[int, int] = {
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

    deviceList: List[DeviceInfo] = []

    @classmethod
    def _get_patch_pattern(cls, minor: int, max_minor: int) -> List[int]:
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
        cls, major: int, max_minor: int = 8
    ) -> Dict[int, List[int]]:
        result = {}
        for minor in range(max_minor + 1):
            result[minor] = cls._get_patch_pattern(minor, max_minor)
        return result

    @classmethod
    def _expand_versions(cls, major: int, minor: int, patches: List[int]) -> List[str]:
        if not patches:
            return [f"{major}.{minor}"]
        return [f"{major}.{minor}.{patch}" for patch in patches]

    @classmethod
    def __gen__(cls: Type[IOSDevice]) -> None:
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

        results: List[DeviceInfo] = []
        seen_versions: set = set()

        # Real iOS client sends just "iPhone" as device_model
        # (UIDevice.current.localizedModel), so we only need unique iOS versions.
        # Weight each version by its major version's market share.
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


def _get_firefox_latest_version():
    """Fetch latest Firefox major version from Mozilla product-details.

    Returns (max_version, min_version) tuple where min = max - 3.
    Falls back to (None, None) on failure.
    """
    import urllib.request
    from urllib.error import HTTPError

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
    except (HTTPError, Exception):
        return None, None


def _get_chrome_last_good_versions():
    import urllib.request
    from urllib.error import HTTPError

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
    except (HTTPError, Exception):
        return None


def _parse_os_from_ua(user_agent: str) -> str:
    """Extract OS name from User-Agent for Web Z / Web A style system_version."""
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
    """Extract navigator.platform value from User-Agent for Web K style system_version."""
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
    """Generates realistic browser fingerprints using browserforge.

    Produces DeviceInfo where:
    - model = full User-Agent string
    - version = OS name (for Web Z/A) or navigator.platform (for Web K)

    Browser selection is weighted by global desktop market share
    (Statcounter, January 2026).
    """

    # Chrome ~76%, Edge ~9%, Firefox ~4%
    BROWSER_WEIGHTS: Dict[str, int] = {
        "chrome": 19,
        "edge": 2,
        "firefox": 1,
    }

    deviceList: List[DeviceInfo] = []
    _k_deviceList: List[DeviceInfo] = []
    _generated = False
    _max_chromium = 145
    _firefox_max = 147
    _firefox_min = 144

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
            from browserforge.headers import HeaderGenerator, Browser
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
        if ff_max is not None:
            cls._firefox_max = ff_max
            cls._firefox_min = ff_min
        ff_max = cls._firefox_max
        ff_min = cls._firefox_min

        # Per-browser generation configs.
        # Each browser gets its own HeaderGenerator so we control the
        # exact proportion of UAs via BROWSER_WEIGHTS.
        browser_configs = [
            {
                "name": "chrome",
                "browser": Browser(
                    name="chrome", min_version=chrome_min, max_version=max_v
                ),
                "os": ("windows", "macos", "linux"),
                "count": 60,
            },
            {
                "name": "edge",
                "browser": Browser(
                    name="edge", min_version=chrome_min - 2, max_version=max_v
                ),
                "os": ("windows", "macos"),
                "count": 30,
            },
            {
                "name": "firefox",
                "browser": Browser(
                    name="firefox", min_version=ff_min, max_version=ff_max
                ),
                "os": ("windows", "macos", "linux"),
                "count": 20,
            },
        ]

        z_a_list: List[DeviceInfo] = []
        k_list: List[DeviceInfo] = []
        seen_uas: set = set()

        for cfg in browser_configs:
            weight = cls.BROWSER_WEIGHTS.get(cfg["name"], 1)
            try:
                gen = HeaderGenerator(
                    browser=[cfg["browser"]],
                    os=cfg["os"],
                    device="desktop",
                )
            except Exception:
                continue

            for _ in range(cfg["count"]):
                try:
                    headers = gen.generate()
                except Exception:
                    continue
                ua = headers.get("User-Agent", "")
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
    def RandomDevice(cls, unique_id: str = None, variant: str = "z") -> DeviceInfo:
        """Generate a random web browser device fingerprint.

        Args:
            unique_id: Deterministic seed string. Random if None.
            variant: "z" or "a" for Web Z/A style, "k" for Web K style.
        """
        hash_id = cls._strtohashid(unique_id)
        cls.__gen__()
        if variant == "k":
            return cls._hashtovalue(hash_id, cls._k_deviceList)
        return cls._hashtovalue(hash_id, cls.deviceList)
