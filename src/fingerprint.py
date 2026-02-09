"""Fingerprint configuration and consistency module for opentele2.

Centralizes TL layer tracking, per-platform app versioning, strict mode,
initConnection parameter validation, and transport recommendations.

The constants here should be updated whenever Telegram releases major
client updates (typically every 1-3 months).
"""

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


# Telethon may be slightly ahead or behind; we track both so the library
# can warn when they diverge significantly.
_TELETHON_LAYER: Optional[int] = None


def _detect_telethon_layer() -> int:
    """Detect the TL layer used by the installed Telethon version."""
    global _TELETHON_LAYER
    if _TELETHON_LAYER is None:
        try:
            from telethon.tl.alltlobjects import LAYER as _tl_layer

            _TELETHON_LAYER = _tl_layer
        except ImportError:
            _TELETHON_LAYER = LAYER
    return _TELETHON_LAYER


def get_recommended_layer() -> int:
    """Return the layer that should be used in ``invokeWithLayer``.

    Prefers the Telethon built-in layer (since it must match the generated
    TL objects) but warns if it is too far from the official schema.
    """
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
    """Tracks the latest known official client versions per platform.

    Default values serve as fallbacks when network fetching is unavailable.
    On first import the module attempts to fetch the latest versions from
    official sources (see :mod:`src.version_fetcher`) and patches this
    singleton in-place.
    """

    # Telegram for Android (Google Play / GitHub)
    android_app_version: str = "12.4.1"
    android_app_version_code: int = 57428  # build code sent in some requests
    android_sdk_range: Tuple[int, int] = (24, 35)  # API 24 (Android 7) – 35 (15)
    android_latest_sdk: int = 35

    # Telegram for iOS (App Store)
    ios_app_version: str = "12.3.1"
    ios_build_number: int = 32078
    ios_version_range: Tuple[str, str] = ("16.0", "26.2")

    # iOS / macOS system versions (used in API class system_version fields)
    ios_system_version: str = "26.2"
    macos_system_version: str = "macOS 26.2"

    # Telegram Desktop (GitHub releases)
    desktop_app_version: str = "6.5"
    desktop_app_version_suffix: str = "x64"  # or empty for 32-bit

    # Telegram macOS (Swift, App Store)
    macos_app_version: str = "12.4.1"
    macos_build_number: int = 277873

    # TelegramX for Android
    android_x_app_version: str = "12.4.1"

    # Web clients
    web_a_version: str = "12.0.17 A"
    web_k_version: str = "1.4.2 K"

    # Chrome user-agent for web clients (keep updated)
    chrome_version: str = "144.0.0.0"
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/144.0.0.0 Safari/537.36"
    )


PLATFORM_VERSIONS = PlatformVersions()


def _apply_fetched_versions() -> None:
    """Fetch latest versions and patch the singleton in-place."""
    try:
        from .version_fetcher import fetch_all_versions

        fetched = fetch_all_versions()
        if not fetched:
            return

        pv = PLATFORM_VERSIONS
        for key, val in fetched.items():
            if hasattr(pv, key):
                setattr(pv, key, val)

        # Keep ios_version_range upper bound in sync
        if "ios_system_version" in fetched:
            pv.ios_version_range = (
                pv.ios_version_range[0],
                str(fetched["ios_system_version"]),
            )
    except Exception:
        pass  # keep defaults on any failure


_apply_fetched_versions()


def get_platform_versions() -> PlatformVersions:
    """Return the current platform version constants."""
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

# Valid lang_pack values for official clients
_VALID_LANG_PACKS = frozenset(
    {
        "android",
        "ios",
        "tdesktop",
        "macos",
        "",  # Web clients use empty string
    }
)

# Map: lang_pack -> expected api_id
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
    """Validate initConnection parameters for consistency.

    Returns a list of warning strings. Empty list means all checks pass.
    If *strict* is True, checks are more aggressive (e.g. lang_pack must
    match api_id).
    """
    issues: List[str] = []

    # 1. lang_pack must be a known value
    if lang_pack not in _VALID_LANG_PACKS:
        issues.append(
            f"lang_pack '{lang_pack}' is not a known official value. "
            f"Expected one of: {sorted(_VALID_LANG_PACKS)}"
        )

    # 2. lang_code should be a valid IETF language tag (basic check)
    if not lang_code or len(lang_code) < 2:
        issues.append(f"lang_code '{lang_code}' looks invalid (too short)")

    # 3. system_lang_code should include region for mobile clients
    if lang_pack in ("android", "ios") and "-" not in system_lang_code:
        issues.append(
            f"system_lang_code '{system_lang_code}' should include a region "
            f"code (e.g. 'en-US') for {lang_pack} clients"
        )

    # 4. Empty strings are suspicious
    if not device_model:
        issues.append("device_model is empty")
    if not system_version:
        issues.append("system_version is empty")
    if not app_version:
        issues.append("app_version is empty")

    # 5. Strict: lang_pack <-> api_id consistency
    if strict and lang_pack in _LANG_PACK_API_ID_MAP:
        expected_api_id = _LANG_PACK_API_ID_MAP[lang_pack]
        if api_id != expected_api_id:
            issues.append(
                f"api_id {api_id} does not match lang_pack '{lang_pack}' "
                f"(expected {expected_api_id})"
            )

    # 6. Strict: app_version should match known current versions
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
    """Deep consistency check for strict mode."""
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
    """Controls how aggressively opentele2 enforces fingerprint consistency."""

    OFF = "off"
    """No extra checks — Telethon defaults."""

    WARN = "warn"
    """Emit warnings for inconsistencies but do not block."""

    STRICT = "strict"
    """Raise exceptions for any inconsistency that could be detected
    server-side."""


@dataclass
class FingerprintConfig:
    """Global fingerprint configuration for the opentele2 session.

    Instantiate once and pass it to ``TelegramClient`` or use the module-level
    default ``DEFAULT_CONFIG``.
    """

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
        """Return the layer to use, respecting overrides."""
        if self.layer_override is not None:
            return self.layer_override
        return get_recommended_layer()

    def validate_params(self, **kwargs) -> None:
        """Validate initConnection parameters based on strict_mode.

        Keyword args should match ``initConnection`` fields:
        api_id, device_model, system_version, app_version,
        system_lang_code, lang_pack, lang_code.
        """
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
    """Provides transport/connection type recommendations for 2025-2026.

    Official mobile clients (Android, iOS) use **obfuscated intermediate**
    transport.  Desktop uses **obfuscated abridged** or **obfuscated
    intermediate** depending on version.

    Using plain ``ConnectionTcpFull`` or ``ConnectionTcpAbridged`` without
    obfuscation is increasingly risky for mass operations.
    """

    @staticmethod
    def get_connection_class(lang_pack: str = "tdesktop"):
        """Return the recommended Telethon Connection class for a platform.

        Falls back to ``ConnectionTcpObfuscated`` for all platforms as it
        provides obfuscation which is what official clients use.
        """
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
        """List all available Telethon transport classes."""
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
    """Generate a random offset to add to msg_id base time.

    Official clients use ``time * 2^32`` plus a small counter.
    Adding a random offset within the valid range avoids trivially
    predictable msg_ids.
    """
    return random.randint(0, 0xFFFF)


def is_valid_msg_id(msg_id: int, *, from_client: bool = True) -> bool:
    """Check if a msg_id follows the official rules.

    Client msg_ids must be odd (``msg_id % 2 == 1``).
    Server msg_ids must be even (``msg_id % 2 == 0``).
    msg_id must be > 0 and roughly correspond to current unix time * 2^32.
    """
    if msg_id <= 0:
        return False
    parity_ok = (msg_id % 2 == 1) if from_client else (msg_id % 2 == 0)
    if not parity_ok:
        return False

    # Rough time check — msg_id encodes unix time in the upper 32 bits
    encoded_time = msg_id >> 32
    now = int(time.time())
    # Allow ±5 minutes drift
    return abs(encoded_time - now) < 300
