"""1.5.0 ``src/tl/shared.py``: the names ``opentele2.tl`` users import."""

from ..consistency import CheckResult, ConsistencyChecker, ConsistencyReport
from ..fingerprint import (
    DEFAULT_CONFIG,
    LAYER,
    PLATFORM_VERSIONS,
    FingerprintConfig,
    PlatformVersions,
    StrictMode,
    TransportRecommendation,
    validate_init_connection_params,
)
from .telethon import TelegramClient

__all__ = [
    "DEFAULT_CONFIG",
    "LAYER",
    "PLATFORM_VERSIONS",
    "CheckResult",
    "ConsistencyChecker",
    "ConsistencyReport",
    "FingerprintConfig",
    "PlatformVersions",
    "StrictMode",
    "TelegramClient",
    "TransportRecommendation",
    "validate_init_connection_params",
]
