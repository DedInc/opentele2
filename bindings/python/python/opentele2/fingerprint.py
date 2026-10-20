"""The 1.5.0 initConnection fingerprint API, computing through
:mod:`opentele2._native`.

Importing this module fetches the current platform versions once, unless
``OPENTELE_NO_FETCH`` is set, and applies them to :data:`PLATFORM_VERSIONS`.
"""

from __future__ import annotations

import importlib
import logging
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

from . import _native
from ._version_fetcher import fetch_all_versions, versions_patch

if TYPE_CHECKING:
    from telethon.network.connection.connection import Connection

    from ._native import Issue
    from ._native import PlatformVersions as _NativeVersions

logger = logging.getLogger(__name__)

__all__ = [
    "LAYER",
    "FingerprintConfig",
    "PlatformVersions",
    "StrictMode",
    "TransportRecommendation",
    "get_advertised_layer",
    "get_platform_versions",
    "get_recommended_layer",
    "tdesktop_tz_offset",
    "validate_init_connection_params",
]


_BASE_LAYER: int = _native.LAYER
_TELETHON_LAYER: int | None = None


def _detect_telethon_layer() -> int:
    global _TELETHON_LAYER
    if _TELETHON_LAYER is None:
        try:
            from telethon.tl.alltlobjects import LAYER as _tl_layer

            _TELETHON_LAYER = _tl_layer
        except ImportError:
            _TELETHON_LAYER = _BASE_LAYER
    return _TELETHON_LAYER


_ADVERTISED_LAYER: int = _native.LAYER


def get_advertised_layer() -> int:
    """The TL schema layer opentele2 advertises to Telegram.

    This is a fixed property of the schema this library targets; it is
    deliberately independent of whatever layer the installed Telethon
    exposes, so the two can be compared and a real mismatch detected.
    """
    return _ADVERTISED_LAYER


LAYER: int = _ADVERTISED_LAYER


def get_recommended_layer() -> int:
    telethon_layer = _detect_telethon_layer()
    warning = _native.layer_mismatch_warning(telethon_layer)
    if warning is not None:
        warnings.warn(warning, stacklevel=2)
    return telethon_layer


# The bundled offline versions; the dataclass defaults below.
_OFFLINE = _native.platform_versions()


@dataclass
class PlatformVersions:
    android_app_version: str = _OFFLINE["android_app_version"]
    android_app_version_code: int = _OFFLINE["android_app_version_code"]
    android_sdk_range: tuple[int, int] = _OFFLINE["android_sdk_range"]
    android_latest_sdk: int = _OFFLINE["android_latest_sdk"]

    ios_app_version: str = _OFFLINE["ios_app_version"]
    ios_build_number: int = _OFFLINE["ios_build_number"]
    ios_version_range: tuple[str, str] = _OFFLINE["ios_version_range"]

    ios_system_version: str = _OFFLINE["ios_system_version"]
    macos_system_version: str = _OFFLINE["macos_system_version"]

    # Bound to the version stamped into written tdata; never fetched.
    desktop_app_version: str = _OFFLINE["desktop_app_version"]
    desktop_app_version_suffix: str = _OFFLINE["desktop_app_version_suffix"]

    macos_app_version: str = _OFFLINE["macos_app_version"]
    macos_build_number: int = _OFFLINE["macos_build_number"]

    android_x_app_version: str = _OFFLINE["android_x_app_version"]

    web_a_version: str = _OFFLINE["web_a_version"]
    web_k_version: str = _OFFLINE["web_k_version"]

    chrome_version: str = _OFFLINE["chrome_version"]
    user_agent: str = _OFFLINE["user_agent"]
    # A 2.0.0 addition: the Firefox major of the generated web user agents.
    firefox_version: str = _OFFLINE["firefox_version"]


PLATFORM_VERSIONS = PlatformVersions()


def _native_versions(pv: PlatformVersions) -> _NativeVersions:
    return {
        "android_app_version": pv.android_app_version,
        "android_app_version_code": pv.android_app_version_code,
        "android_sdk_range": pv.android_sdk_range,
        "android_latest_sdk": pv.android_latest_sdk,
        "ios_app_version": pv.ios_app_version,
        "ios_build_number": pv.ios_build_number,
        "ios_version_range": pv.ios_version_range,
        "ios_system_version": pv.ios_system_version,
        "macos_system_version": pv.macos_system_version,
        "desktop_app_version": pv.desktop_app_version,
        "desktop_app_version_suffix": pv.desktop_app_version_suffix,
        "macos_app_version": pv.macos_app_version,
        "macos_build_number": pv.macos_build_number,
        "android_x_app_version": pv.android_x_app_version,
        "web_a_version": pv.web_a_version,
        "web_k_version": pv.web_k_version,
        "chrome_version": pv.chrome_version,
        "user_agent": pv.user_agent,
        "firefox_version": pv.firefox_version,
    }


def _assign_versions(pv: PlatformVersions, values: _NativeVersions) -> None:
    pv.android_app_version = values["android_app_version"]
    pv.android_app_version_code = values["android_app_version_code"]
    pv.android_sdk_range = values["android_sdk_range"]
    pv.android_latest_sdk = values["android_latest_sdk"]
    pv.ios_app_version = values["ios_app_version"]
    pv.ios_build_number = values["ios_build_number"]
    pv.ios_version_range = values["ios_version_range"]
    pv.ios_system_version = values["ios_system_version"]
    pv.macos_system_version = values["macos_system_version"]
    pv.desktop_app_version = values["desktop_app_version"]
    pv.desktop_app_version_suffix = values["desktop_app_version_suffix"]
    pv.macos_app_version = values["macos_app_version"]
    pv.macos_build_number = values["macos_build_number"]
    pv.android_x_app_version = values["android_x_app_version"]
    pv.web_a_version = values["web_a_version"]
    pv.web_k_version = values["web_k_version"]
    pv.chrome_version = values["chrome_version"]
    pv.user_agent = values["user_agent"]
    pv.firefox_version = values["firefox_version"]


def _apply_fetched_versions() -> None:
    # The core leaves desktop_app_version alone: a fetched "latest release"
    # must not move it away from the version stamped into written tdata.
    try:
        fetched = fetch_all_versions()
        if not fetched:
            return

        pv = PLATFORM_VERSIONS
        applied = _native.apply_versions_patch(_native_versions(pv), versions_patch(fetched))
        _assign_versions(pv, applied)
    except Exception:
        # Fetching is best effort; the bundled defaults stay in place.
        logger.debug("Could not apply fetched platform versions", exc_info=True)


_apply_fetched_versions()


def get_platform_versions() -> PlatformVersions:
    return PLATFORM_VERSIONS


def tdesktop_tz_offset(now: datetime | None = None) -> float:
    """The ``tz_offset`` tdesktop puts into initConnection ``params``.

    Mirrors ``SessionPrivate::prepareInitParams``: the local UTC offset in
    seconds, wrapped into -12h..+14h and rounded to a multiple of 900.
    """
    if now is None:
        local = datetime.now(timezone.utc).astimezone()
    elif now.tzinfo is None:
        local = now.astimezone()
    else:
        local = now
    offset = local.utcoffset()
    return _native.tz_offset(int(offset.total_seconds()) if offset is not None else 0)


def _init_issues(
    api_id: int | None,
    device_model: str | None,
    system_version: str | None,
    app_version: str | None,
    system_lang_code: str | None,
    lang_pack: str | None,
    lang_code: str | None,
    *,
    strict: bool = False,
) -> list[Issue]:
    # The values go to the core as given, None and "2040" included; it
    # checks and words them as 1.5.0 did. Checked against PLATFORM_VERSIONS
    # as it is now, fetched or edited.
    params: dict[str, Any] = {
        "api_id": api_id,
        "device_model": device_model,
        "system_version": system_version,
        "app_version": app_version,
        "system_lang_code": system_lang_code,
        "lang_pack": lang_pack,
        "lang_code": lang_code,
    }
    return _native.validate_raw_init_params(
        params, _native_versions(PLATFORM_VERSIONS), "strict" if strict else "warn"
    )


def validate_init_connection_params(
    api_id: int | None,
    device_model: str | None,
    system_version: str | None,
    app_version: str | None,
    system_lang_code: str | None,
    lang_pack: str | None,
    lang_code: str | None,
    *,
    strict: bool = False,
) -> list[str]:
    issues = _init_issues(
        api_id,
        device_model,
        system_version,
        app_version,
        system_lang_code,
        lang_pack,
        lang_code,
        strict=strict,
    )
    return [issue["message"] for issue in issues]


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

    layer_override: int | None = None
    """If set, override the layer used in ``invokeWithLayer``.
    Use with caution — mismatched layers cause deserialization errors."""

    randomize_msg_id_offset: bool = True
    """Add a small random offset to msg_id generation to avoid
    predictability.  Official clients do this."""

    _msg_id_offset: int = field(default_factory=_native.msg_id_offset)

    def get_effective_layer(self) -> int:
        layer, warning = _native.effective_layer_for(_detect_telethon_layer(), self.layer_override)
        if warning is not None:
            # Where 1.5.0 get_recommended_layer warned from: this frame.
            warnings.warn(warning, stacklevel=1)
        return layer

    def validate_params(self, **kwargs: Any) -> None:
        if not self.auto_validate:
            # 1.5.0 returned before reading the arguments: wrong ones raise
            # nothing while validation is off.
            return

        issues = _native.validate_raw_fingerprint(
            self.strict_mode.value,
            self.auto_validate,
            kwargs,
            _native_versions(PLATFORM_VERSIONS),
        )

        if not issues:
            return

        msg = _native.issues_message(issues)

        if self.strict_mode == StrictMode.STRICT:
            raise ValueError(msg)
        elif self.strict_mode == StrictMode.WARN:
            warnings.warn(msg, stacklevel=3)


DEFAULT_CONFIG = FingerprintConfig()


class TransportRecommendation:
    @staticmethod
    def get_connection_class(lang_pack: str = "tdesktop") -> type[Connection]:
        # Every official client uses the obfuscated transport, whatever its
        # lang_pack; the parameter is kept for API compatibility.
        try:
            from telethon.network.connection.tcpobfuscated import (
                ConnectionTcpObfuscated,
            )
        except ImportError:
            from telethon.network.connection.tcpfull import ConnectionTcpFull

            return ConnectionTcpFull
        return ConnectionTcpObfuscated

    @staticmethod
    def get_available_transports() -> dict[str, type[object]]:
        _TRANSPORT_MODULES = {
            "full": "telethon.network.connection.tcpfull.ConnectionTcpFull",
            "abridged": "telethon.network.connection.tcpabridged.ConnectionTcpAbridged",
            "intermediate": (
                "telethon.network.connection.tcpintermediate.ConnectionTcpIntermediate"
            ),
            "obfuscated": "telethon.network.connection.tcpobfuscated.ConnectionTcpObfuscated",
        }
        transports = {}
        for name, full_path in _TRANSPORT_MODULES.items():
            try:
                module_path, class_name = full_path.rsplit(".", 1)
                module = importlib.import_module(module_path)
                transports[name] = getattr(module, class_name)
            except ImportError:
                pass
        return transports


def generate_msg_id_offset() -> int:
    # Drawn by the core from the OS random source. Unlike 1.5.0,
    # random.seed does not reproduce the offsets.
    return _native.msg_id_offset()


# msg_id is a signed 64-bit integer on the wire; anything wider encodes a
# time centuries away and was never valid.
_MSG_ID_LIMIT = 1 << 63


def is_valid_msg_id(msg_id: int, *, from_client: bool = True) -> bool:
    if msg_id <= 0 or msg_id >= _MSG_ID_LIMIT:
        return False
    return _native.is_valid_msg_id(msg_id, from_client, time.time())
