from __future__ import annotations

import random
import time
import warnings
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "LAYER",
    "PlatformVersions",
    "StrictMode",
    "FingerprintConfig",
    "TransportRecommendation",
    "validate_init_connection_params",
    "get_recommended_layer",
    "get_platform_versions",
]


LAYER: int = 216


_TELETHON_LAYER: Optional[int] = None


def _detect_telethon_layer() -> int:
    global _TELETHON_LAYER
    if _TELETHON_LAYER is None:
        try:
            from telethon.tl.alltlobjects import LAYER as _tl_layer

            _TELETHON_LAYER = _tl_layer
        except ImportError:
            _TELETHON_LAYER = LAYER
    return _TELETHON_LAYER


def get_recommended_layer() -> int:
    telethon_layer = _detect_telethon_layer()
    diff = abs(telethon_layer - LAYER)
    if diff > 15:
        warnings.warn(
            f"Telethon TL layer ({telethon_layer}) differs from the latest "
            f"official schema layer ({LAYER}) by {diff} layers. "
            f"This may cause initConnection fingerprint inconsistencies. "
            f"Consider updating Telethon or opentele2.",
            stacklevel=2,
        )
    return telethon_layer


@dataclass
class PlatformVersions:
    android_app_version: str = "12.4.1"
    android_app_version_code: int = 57428
    android_sdk_range: Tuple[int, int] = (24, 35)
    android_latest_sdk: int = 35

    ios_app_version: str = "12.3.1"
    ios_build_number: int = 32078
    ios_version_range: Tuple[str, str] = ("16.0", "26.2")

    ios_system_version: str = "26.2"
    macos_system_version: str = "macOS 26.2"

    desktop_app_version: str = "6.5"
    desktop_app_version_suffix: str = "x64"

    macos_app_version: str = "12.4.1"
    macos_build_number: int = 277873

    android_x_app_version: str = "12.4.1"

    web_a_version: str = "12.0.17 A"
    web_k_version: str = "1.4.2 K"

    chrome_version: str = "144.0.0.0"
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/144.0.0.0 Safari/537.36"
    )


PLATFORM_VERSIONS = PlatformVersions()


def _apply_fetched_versions() -> None:
    try:
        from .version_fetcher import fetch_all_versions

        fetched = fetch_all_versions()
        if not fetched:
            return

        pv = PLATFORM_VERSIONS
        for key, val in fetched.items():
            if hasattr(pv, key):
                setattr(pv, key, val)

        if "ios_system_version" in fetched:
            pv.ios_version_range = (
                pv.ios_version_range[0],
                str(fetched["ios_system_version"]),
            )
    except Exception:
        pass


_apply_fetched_versions()


def get_platform_versions() -> PlatformVersions:
    return PLATFORM_VERSIONS


_INIT_CONNECTION_FIELD_ORDER = [
    "api_id",
    "device_model",
    "system_version",
    "app_version",
    "system_lang_code",
    "lang_pack",
    "lang_code",
    "proxy",
    "params",
    "query",
]

_VALID_LANG_PACKS = frozenset(
    {
        "android",
        "ios",
        "tdesktop",
        "macos",
        "",
    }
)

_LANG_PACK_API_ID_MAP: Dict[str, int] = {
    "tdesktop": 2040,
    "android": 6,
    "ios": 10840,
    "macos": 2834,
}


def validate_init_connection_params(
    api_id: int,
    device_model: str,
    system_version: str,
    app_version: str,
    system_lang_code: str,
    lang_pack: str,
    lang_code: str,
    *,
    strict: bool = False,
) -> List[str]:
    issues: List[str] = []

    if lang_pack not in _VALID_LANG_PACKS:
        issues.append(
            f"lang_pack '{lang_pack}' is not a known official value. "
            f"Expected one of: {sorted(_VALID_LANG_PACKS)}"
        )

    if not lang_code or len(lang_code) < 2:
        issues.append(f"lang_code '{lang_code}' looks invalid (too short)")

    if lang_pack in ("android", "ios") and "-" not in system_lang_code:
        issues.append(
            f"system_lang_code '{system_lang_code}' should include a region "
            f"code (e.g. 'en-US') for {lang_pack} clients"
        )

    if not device_model:
        issues.append("device_model is empty")
    if not system_version:
        issues.append("system_version is empty")
    if not app_version:
        issues.append("app_version is empty")

    if strict and lang_pack in _LANG_PACK_API_ID_MAP:
        expected_api_id = _LANG_PACK_API_ID_MAP[lang_pack]
        if api_id != expected_api_id:
            issues.append(
                f"api_id {api_id} does not match lang_pack '{lang_pack}' "
                f"(expected {expected_api_id})"
            )

    if strict:
        _check_version_consistency(
            lang_pack, app_version, system_version, device_model, issues
        )

    return issues


def _check_version_consistency(
    lang_pack: str,
    app_version: str,
    system_version: str,
    device_model: str,
    issues: List[str],
) -> None:
    pv = PLATFORM_VERSIONS

    _PLATFORM_VERSION_MAP = {
        "android": ("android_app_version", "Android"),
        "ios": ("ios_app_version", "iOS"),
        "tdesktop": ("desktop_app_version", "Desktop"),
        "macos": ("macos_app_version", "macOS"),
    }

    if lang_pack in _PLATFORM_VERSION_MAP:
        attr, label = _PLATFORM_VERSION_MAP[lang_pack]
        known_version = getattr(pv, attr)
        if not app_version.startswith(known_version.split(".")[0]):
            issues.append(
                f"{label} app_version '{app_version}' major does not match "
                f"latest known '{known_version}'"
            )

    if lang_pack == "android":
        if "SDK" in system_version:
            try:
                sdk_num = int(system_version.replace("SDK ", ""))
                lo, hi = pv.android_sdk_range
                if not (lo <= sdk_num <= hi):
                    issues.append(
                        f"Android SDK {sdk_num} is outside the expected "
                        f"range [{lo}, {hi}]"
                    )
            except ValueError:
                pass
        else:
            import re

            m = re.match(r"^\d+(?:\.\d+)?\s*\((\d+)\)$", system_version)
            if m:
                try:
                    sdk_num = int(m.group(1))
                    lo, hi = pv.android_sdk_range
                    if not (lo <= sdk_num <= hi):
                        issues.append(
                            f"Android SDK {sdk_num} is outside the expected "
                            f"range [{lo}, {hi}]"
                        )
                except ValueError:
                    pass


class StrictMode(Enum):
    OFF = "off"
    """No extra checks — Telethon defaults."""

    WARN = "warn"
    """Emit warnings for inconsistencies but do not block."""

    STRICT = "strict"
    """Raise exceptions for any inconsistency that could be detected
    server-side."""


@dataclass
class FingerprintConfig:
    strict_mode: StrictMode = StrictMode.WARN
    """How to handle consistency issues."""

    auto_validate: bool = True
    """Automatically validate initConnection parameters on connect."""

    preferred_transport: str = "obfuscated"
    """Preferred transport type.  Official clients in 2025-2026 use
    ''obfuscated'' (intermediate padded with obfuscation) by default.
    Telethon supports ``ConnectionTcpObfuscated``.
    
    Valid values: 'full', 'intermediate', 'abridged', 'obfuscated'.
    """

    warn_on_layer_mismatch: bool = True
    """Warn when Telethon layer differs from official by >5 layers."""

    layer_override: Optional[int] = None
    """If set, override the layer used in ``invokeWithLayer``.
    Use with caution — mismatched layers cause deserialization errors."""

    randomize_msg_id_offset: bool = True
    """Add a small random offset to msg_id generation to avoid
    predictability.  Official clients do this."""

    _msg_id_offset: int = field(default_factory=lambda: random.randint(0, 0xFFFF))

    def get_effective_layer(self) -> int:
        if self.layer_override is not None:
            return self.layer_override
        return get_recommended_layer()

    def validate_params(self, **kwargs) -> None:
        if not self.auto_validate:
            return

        issues = validate_init_connection_params(
            strict=(self.strict_mode == StrictMode.STRICT),
            **kwargs,
        )

        if not issues:
            return

        msg = "initConnection fingerprint issues:\n" + "\n".join(
            f"  - {i}" for i in issues
        )

        if self.strict_mode == StrictMode.STRICT:
            raise ValueError(msg)
        elif self.strict_mode == StrictMode.WARN:
            warnings.warn(msg, stacklevel=3)


DEFAULT_CONFIG = FingerprintConfig()


class TransportRecommendation:
    @staticmethod
    def get_connection_class(lang_pack: str = "tdesktop"):
        try:
            from telethon.network.connection.tcpobfuscated import (
                ConnectionTcpObfuscated,
            )

            return ConnectionTcpObfuscated
        except ImportError:
            from telethon.network.connection.tcpfull import ConnectionTcpFull

            return ConnectionTcpFull

    @staticmethod
    def get_available_transports() -> Dict[str, Any]:
        _TRANSPORT_MODULES = {
            "full": "telethon.network.connection.tcpfull.ConnectionTcpFull",
            "abridged": "telethon.network.connection.tcpabridged.ConnectionTcpAbridged",
            "intermediate": "telethon.network.connection.tcpintermediate.ConnectionTcpIntermediate",
            "obfuscated": "telethon.network.connection.tcpobfuscated.ConnectionTcpObfuscated",
        }
        transports = {}
        for name, full_path in _TRANSPORT_MODULES.items():
            try:
                module_path, class_name = full_path.rsplit(".", 1)
                module = __import__(module_path, fromlist=[class_name])
                transports[name] = getattr(module, class_name)
            except ImportError:
                pass
        return transports


def generate_msg_id_offset() -> int:
    return random.randint(0, 0xFFFF)


def is_valid_msg_id(msg_id: int, *, from_client: bool = True) -> bool:
    if msg_id <= 0:
        return False
    parity_ok = (msg_id % 2 == 1) if from_client else (msg_id % 2 == 0)
    if not parity_ok:
        return False

    encoded_time = msg_id >> 32
    now = int(time.time())
    return abs(encoded_time - now) < 300
