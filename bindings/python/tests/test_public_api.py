"""Every public name imports from its dotted path in the package.

``PUBLIC_NAMES`` lists, as literals, the ``__all__`` of every public module,
with ``tl/configs.py``'s ``__all__ += _exception.__all__`` and
``__all__ += _utils.__all__`` expanded, and the names the ``opentele2``,
``opentele2.td`` and ``opentele2.tl`` package ``__init__`` modules import.

Not public, as ARCHITECTURE.md documents:
- the names ``td.MTP``, ``td.MapData``, ``td.Serialize``, ``td.Storage`` and
  ``td.StorageAccount`` and the modules ``qt_compat``, ``utils``, ``debug`` and
  ``version_fetcher``;
- the modules ``td.configs``, ``td.key_data`` and ``td.shared``: the tdata
  format lives in the core (``tdata``, ``kdf``, ``crypto``) and
  ``td/__init__.py`` re-exports the facades;
- ``annotations``: ``from __future__ import annotations`` is a compiler
  directive, not an export.
"""

from __future__ import annotations

import importlib

import pytest

# Each module's ``__all__``: the module lists every name, so
# ``from <module> import *`` brings them all.
ALL_NAMES: dict[str, list[str]] = {
    "opentele2.api": ["API", "APIData", "CreateNewSession", "LoginFlag", "UseCurrentSession"],
    "opentele2.consistency": ["CheckResult", "ConsistencyChecker", "ConsistencyReport"],
    "opentele2.devices": [
        "AndroidDevice",
        "DeviceInfo",
        "IOSDevice",
        "LinuxDevice",
        "SystemInfo",
        "WebBrowserDevice",
        "WindowsDevice",
        "iOSDevice",
        "macOSDevice",
    ],
    "opentele2.exception": [
        "AccountAuthKeyNotFound",
        "ExpectStreamStatus",
        "Expects",
        "LoginFlagInvalid",
        "MaxAccountLimit",
        "NoInstanceMatched",
        "NoPasswordProvided",
        "OpenTeleException",
        "PasswordIncorrect",
        "QDataStreamFailed",
        "SessionFileInvalid",
        "SessionFileNotFound",
        "TDAccountNotLoaded",
        "TDataAuthKeyNotFound",
        "TDataBadConfigData",
        "TDataBadDecryptKey",
        "TDataBadDecryptedDataSize",
        "TDataBadEncryptedDataSize",
        "TDataInvalidCheckSum",
        "TDataInvalidMagic",
        "TDataReadMapDataFailed",
        "TDataReadMapDataIncorrectPasscode",
        "TDataSaveFailed",
        "TDataWrongPasscode",
        "TDesktopHasNoAccount",
        "TDesktopNotLoaded",
        "TDesktopUnauthorized",
        "TFileNotFound",
        "TelethonUnauthorized",
    ],
    "opentele2.fingerprint": [
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
    ],
    "opentele2.tl.client_kwargs": ["ClientKwargs", "TelethonClientKwargs"],
    "opentele2.tl.configs": [
        "API",
        "TYPE_CHECKING",
        "APIData",
        "Any",
        "AuthKey",
        "Callable",
        "Connection",
        "ConnectionTcpFull",
        "CreateNewSession",
        "Dict",
        "List",
        "LoginFlag",
        "MemorySession",
        "SQLiteSession",
        "Session",
        "StringSession",
        "Type",
        "TypeVar",
        "Union",
        "UseCurrentSession",
        "asyncio",
        "functions",
        "sizeof",
        "td",
        "telethon",
        "tl",
        "types",
        "utils",
        # __all__ += _exception.__all__
        "AccountAuthKeyNotFound",
        "ExpectStreamStatus",
        "Expects",
        "LoginFlagInvalid",
        "MaxAccountLimit",
        "NoInstanceMatched",
        "NoPasswordProvided",
        "OpenTeleException",
        "PasswordIncorrect",
        "QDataStreamFailed",
        "SessionFileInvalid",
        "SessionFileNotFound",
        "TDAccountNotLoaded",
        "TDataAuthKeyNotFound",
        "TDataBadConfigData",
        "TDataBadDecryptKey",
        "TDataBadDecryptedDataSize",
        "TDataBadEncryptedDataSize",
        "TDataInvalidCheckSum",
        "TDataInvalidMagic",
        "TDataReadMapDataFailed",
        "TDataReadMapDataIncorrectPasscode",
        "TDataSaveFailed",
        "TDataWrongPasscode",
        "TDesktopHasNoAccount",
        "TDesktopNotLoaded",
        "TDesktopUnauthorized",
        "TFileNotFound",
        "TelethonUnauthorized",
        # __all__ += _utils.__all__
        "APP_VERSION",
        "APP_VERSION_STR",
        "TDF_MAGIC",
        "BaseMetaClass",
        "BaseObject",
        "PrettyTable",
        "format_app_version",
        "sharemethod",
    ],
    "opentele2.tl.shared": [
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
    ],
}

# The package ``__init__.py`` imports (checked by attribute, not __all__).
INIT_NAMES: dict[str, list[str]] = {
    "opentele2": ["consistency", "fingerprint", "td", "tl"],
    "opentele2.td": ["Account", "AuthKey", "AuthKeyType", "TDesktop"],
    "opentele2.tl": ["TelegramClient"],
}

INTERNAL_TD_NAMES = ["MTP", "MapData", "Serialize", "Storage", "StorageAccount"]

PUBLIC_NAMES = sorted(
    {
        (module, name)
        for table in (ALL_NAMES, INIT_NAMES)
        for module, names in table.items()
        for name in names
    }
)


@pytest.mark.parametrize(("module", "name"), PUBLIC_NAMES)
def test_every_public_name_imports_from_its_path(module: str, name: str) -> None:
    imported = importlib.import_module(module)
    assert hasattr(imported, name), f"{module}.{name}"


@pytest.mark.parametrize("module", sorted(ALL_NAMES))
def test_every_listed_name_is_in_the_module_all(module: str) -> None:
    exported = set(importlib.import_module(module).__all__)
    missing = [name for name in ALL_NAMES[module] if name not in exported]
    assert not missing, f"{module}.__all__ lacks {missing}"


def test_the_internal_td_names_are_not_public() -> None:
    td = importlib.import_module("opentele2.td")
    assert [name for name in INTERNAL_TD_NAMES if hasattr(td, name)] == []
