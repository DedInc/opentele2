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
    def _gen_cartesian(cls):
        if not cls.deviceList:
            cls.deviceList = cls._build_device_list(
                cls.device_models, cls.system_versions
            )


_desktop_data = _load_device_data("desktop.json")


class GeneralDesktopDevice(SystemInfo):
    device_models = _desktop_data["models"]


class WindowsDevice(GeneralDesktopDevice):
    system_versions = _desktop_data["versions"]
    deviceList: List[DeviceInfo] = []

    @classmethod
    def __gen__(cls: Type[WindowsDevice]) -> None:
        if not cls.deviceList:
            cleaned = [
                cls._CleanAndSimplify(m.replace("_", "")) for m in cls.device_models
            ]
            cls.deviceList = cls._build_device_list(cleaned, cls.system_versions)


class LinuxDevice(GeneralDesktopDevice):
    system_versions: List[str] = []
    deviceList: List[DeviceInfo] = []

    @classmethod
    def __gen__(cls: Type[LinuxDevice]) -> None:
        if cls.system_versions:
            return

        linux_distros = _desktop_data.get("linuxDistros")

        if linux_distros:
            enviroments = _desktop_data["environments"]
            wayland = _desktop_data["wayland"]

            versions = []
            for distro_name, distro_info in linux_distros.items():
                kernel = distro_info["kernel"]
                glibc = distro_info["glibc"]

                for env in enviroments:
                    for wl in wayland:
                        version = (
                            f"Linux {kernel} {distro_name} {env} {wl} glibc {glibc}"
                        )
                        versions.append(cls._CleanAndSimplify(version))

            cls.system_versions = versions
        else:
            enviroments = _desktop_data["environments"]
            wayland = _desktop_data["wayland"]
            libcNames = _desktop_data["libcNames"]
            libcVers = _desktop_data["libcVersions"]

            def cartesian_join(groups: List[List[str]], prefix: str = "") -> List[str]:
                prefix = "" if prefix == "" else prefix + " "
                if len(groups) == 1:
                    return [prefix + item for item in groups[0]]
                results = []
                for item in groups[0]:
                    results.extend(cartesian_join(groups[1:], prefix + item))
                return results

            libcFullNames = cartesian_join([libcNames, libcVers], "")
            cls.system_versions = cartesian_join(
                [enviroments, wayland, libcFullNames], "Linux"
            )

        cls.deviceList = cls._build_device_list(cls.device_models, cls.system_versions)


_mac_data = _load_device_data("mac.json")


class macOSDevice(GeneralDesktopDevice):
    device_models = _mac_data["models"]
    system_versions = _mac_data["versions"]
    deviceList: List[DeviceInfo] = []

    @classmethod
    def __gen__(cls: Type[macOSDevice]) -> None:
        if not cls.deviceList:
            seen = []
            for model in cls.device_models:
                name = cls._CleanAndSimplify(_mac_identifier_to_name(model))
                if name not in seen:
                    seen.append(name)
            cls.device_models = seen
            cls.deviceList = cls._build_device_list(
                cls.device_models, cls.system_versions
            )


_android_data = _load_device_data("android.json")


class AndroidDevice(SystemInfo):
    device_models = _android_data["models"]
    system_versions = _android_data["versions"]
    deviceList: List[DeviceInfo] = []

    @classmethod
    def __gen__(cls: Type[AndroidDevice]) -> None:
        cls._gen_cartesian()


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

        for id_model, model_suffixes in cls.device_models.items():
            available_versions = cls._IOS_VERSION_MAP.get(id_model, [12, 13, 14, 15])
            display_id = "X" if id_model == 10 else str(id_model)

            for suffix in model_suffixes:
                device_model = f"iPhone {display_id}{suffix}"

                for major in available_versions:
                    if major not in cls.system_versions:
                        continue

                    for minor, patches in cls.system_versions[major].items():
                        for ver in cls._expand_versions(major, minor, patches):
                            results.append(DeviceInfo(device_model, ver))

        cls.deviceList = results


iOSDevice = IOSDevice
