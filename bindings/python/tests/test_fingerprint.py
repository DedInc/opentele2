"""Tests of opentele2.fingerprint, ported from the 1.5.0 tests
test_fingerprints.py (TestFingerprintValidation, TestFingerprintConfig,
TestPlatformVersions) and test_init_connection.py (tz_offset), plus the
1.5.0 outputs of every public name the module keeps."""

from __future__ import annotations

import dataclasses
import time
import warnings
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from telethon.network.connection.tcpabridged import ConnectionTcpAbridged
from telethon.network.connection.tcpfull import ConnectionTcpFull
from telethon.network.connection.tcpintermediate import ConnectionTcpIntermediate
from telethon.network.connection.tcpobfuscated import ConnectionTcpObfuscated
from telethon.tl.alltlobjects import LAYER as TELETHON_LAYER

from opentele2 import _native, fingerprint
from opentele2.fingerprint import (
    DEFAULT_CONFIG,
    LAYER,
    PLATFORM_VERSIONS,
    FingerprintConfig,
    PlatformVersions,
    StrictMode,
    TransportRecommendation,
    generate_msg_id_offset,
    get_advertised_layer,
    get_platform_versions,
    get_recommended_layer,
    is_valid_msg_id,
    tdesktop_tz_offset,
    validate_init_connection_params,
)

ANDROID: dict[str, Any] = {
    "api_id": 6,
    "device_model": "Samsung SM-S928B",
    "system_version": "SDK 35",
    "app_version": "12.3.0",
    "system_lang_code": "en-US",
    "lang_pack": "android",
    "lang_code": "en",
}
ANDROID_MAJOR = "Android app_version '12.3.0' major does not match latest known '13.0.3'"


def android(**edits: Any) -> dict[str, Any]:
    """The Android base case of 1.5.0 test_fingerprints.py, with ``edits``."""
    return {**ANDROID, **edits}


def test_public_names_are_the_1_5_0_names() -> None:
    assert fingerprint.__all__ == [
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


# ---------------------------------------------------------------- layers


def test_layers() -> None:
    assert LAYER == get_advertised_layer() == _native.LAYER == 230
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert get_recommended_layer() == TELETHON_LAYER


def test_recommended_layer_warns_on_a_far_telethon_layer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fingerprint, "_TELETHON_LAYER", 200)
    with pytest.warns(UserWarning, match=r"Telethon TL layer \(200\) differs .* by 30 layers"):
        assert get_recommended_layer() == 200
    monkeypatch.setattr(fingerprint, "_TELETHON_LAYER", 215)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert get_recommended_layer() == 215


# ---------------------------------------------------------------- versions


def test_platform_versions_are_the_1_5_0_defaults() -> None:
    pv = get_platform_versions()
    assert pv is PLATFORM_VERSIONS
    assert dataclasses.asdict(PlatformVersions()) == {
        "android_app_version": "13.0.3",
        "android_app_version_code": 7183,
        "android_sdk_range": (29, 37),
        "android_latest_sdk": 37,
        "ios_app_version": "13.0",
        "ios_build_number": 35303,
        "ios_version_range": ("18.0", "27.0.1"),
        "ios_system_version": "27.0.1",
        "macos_system_version": "27.0.1",
        "desktop_app_version": "7.3.1",
        "desktop_app_version_suffix": "x64",
        "macos_app_version": "13.0",
        "macos_build_number": 283305,
        "android_x_app_version": "0.29.1.1817",
        "web_a_version": "12.0.47 A",
        "web_k_version": "2.2 K",
        "chrome_version": "155.0.0.0",
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
        ),
    }
    # OPENTELE_NO_FETCH is set for the tests: nothing was applied on import.
    assert pv == PlatformVersions()


def test_versions_not_empty() -> None:
    pv = get_platform_versions()
    assert pv.android_app_version
    assert pv.ios_app_version
    assert pv.desktop_app_version
    assert pv.macos_app_version
    assert pv.web_a_version
    assert pv.web_k_version
    assert pv.chrome_version


# ---------------------------------------------------------------- tz_offset


def _at(offset: timedelta) -> datetime:
    return datetime(2026, 10, 18, 12, 0, tzinfo=timezone(offset))


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (timedelta(hours=5), 18000.0),
        (timedelta(hours=5, minutes=30), 19800.0),
        (timedelta(hours=5, minutes=45), 20700.0),
        (timedelta(hours=-3, minutes=-30), -12600.0),
        (timedelta(hours=14), 50400.0),
        (timedelta(hours=-12), -43200.0),
        (timedelta(0), 0.0),
        # std::round sends halves away from zero.
        (timedelta(minutes=7, seconds=30), 900.0),
        (timedelta(minutes=-7, seconds=-30), -900.0),
        (timedelta(minutes=7), 0.0),
        # Wrapped into -12h..+14h.
        (timedelta(hours=14, minutes=1), -36000.0),
        (timedelta(hours=-12, minutes=-1), 43200.0),
    ],
)
def test_tz_offset_matches_prepare_init_params(offset: timedelta, expected: float) -> None:
    result = tdesktop_tz_offset(_at(offset))
    assert isinstance(result, float)
    assert result == expected


def test_tz_offset_defaults_to_the_local_zone() -> None:
    local = datetime.now(timezone.utc).astimezone().utcoffset()
    assert local is not None
    expected = _native.tz_offset(int(local.total_seconds()))
    assert tdesktop_tz_offset() == expected
    # A naive datetime is local time.
    naive = datetime(2026, 10, 18, 12, 0)
    naive_offset = naive.astimezone().utcoffset()
    assert naive_offset is not None
    assert tdesktop_tz_offset(naive) == _native.tz_offset(int(naive_offset.total_seconds()))


# ---------------------------------------------------------------- validation


def test_valid_android_params() -> None:
    assert validate_init_connection_params(**ANDROID) == []


def test_valid_desktop_params() -> None:
    issues = validate_init_connection_params(
        api_id=2040,
        device_model="Desktop",
        system_version="Windows 11",
        app_version="5.12.3 x64",
        system_lang_code="en-US",
        lang_pack="tdesktop",
        lang_code="en",
    )
    assert issues == []


def test_valid_web_params() -> None:
    issues = validate_init_connection_params(
        api_id=2496,
        device_model="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        system_version="Windows",
        app_version="5.0.0 Z",
        system_lang_code="en-US",
        lang_pack="",
        lang_code="en",
    )
    assert issues == []


def test_empty_device_model_flagged() -> None:
    assert validate_init_connection_params(**android(device_model="")) == ["device_model is empty"]


def test_invalid_lang_pack_flagged() -> None:
    assert validate_init_connection_params(**android(lang_pack="invalid_pack")) == [
        "lang_pack 'invalid_pack' is not a known official value. "
        "Expected one of: ['', 'android', 'ios', 'macos', 'tdesktop']"
    ]


def test_short_lang_code_flagged() -> None:
    assert validate_init_connection_params(**android(lang_code="x")) == [
        "lang_code 'x' looks invalid (too short)"
    ]


def test_strict_mode_api_id_mismatch() -> None:
    assert validate_init_connection_params(**android(api_id=99999), strict=True) == [
        "api_id 99999 does not match lang_pack 'android' (expected 6)",
        ANDROID_MAJOR,
    ]


def test_strict_mode_passes_for_correct_pair() -> None:
    issues = validate_init_connection_params(**ANDROID, strict=True)
    assert issues == [ANDROID_MAJOR]
    assert not any("api_id" in i for i in issues)


def test_android_missing_region_in_system_lang() -> None:
    assert validate_init_connection_params(**android(system_lang_code="en")) == [
        "system_lang_code 'en' should include a region code (e.g. 'en-US') for android clients"
    ]


def test_strict_checks_read_the_current_platform_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = android(app_version="13.0.3", system_version="SDK 37")
    assert validate_init_connection_params(**current, strict=True) == []
    monkeypatch.setattr(PLATFORM_VERSIONS, "android_app_version", "14.0")
    monkeypatch.setattr(PLATFORM_VERSIONS, "android_sdk_range", (29, 36))
    assert validate_init_connection_params(**current, strict=True) == [
        "Android app_version '13.0.3' major does not match latest known '14.0'",
        "Android SDK 37 is outside the expected range [29, 36]",
    ]
    # The module global is read at call time, as 1.5.0 read it.
    monkeypatch.setattr(fingerprint, "PLATFORM_VERSIONS", PlatformVersions())
    assert validate_init_connection_params(**current, strict=True) == []


# ---------------------------------------------------------------- config


def test_strict_mode_values() -> None:
    assert [mode.value for mode in StrictMode] == list(_native.STRICT_MODES)


def test_default_config() -> None:
    config = FingerprintConfig()
    assert config.strict_mode == StrictMode.WARN
    assert config.auto_validate is True
    assert config.preferred_transport == "obfuscated"
    assert config.warn_on_layer_mismatch is True
    assert config.layer_override is None
    assert config.randomize_msg_id_offset is True
    assert 0 <= config._msg_id_offset <= 0xFFFF
    assert DEFAULT_CONFIG.strict_mode == StrictMode.WARN


def test_strict_raises() -> None:
    config = FingerprintConfig(strict_mode=StrictMode.STRICT)
    with pytest.raises(ValueError, match="device_model is empty") as error:
        config.validate_params(**android(device_model=""))
    assert str(error.value) == (
        "initConnection fingerprint issues:\n  - device_model is empty\n  - " + ANDROID_MAJOR
    )


def test_warn_mode_warns() -> None:
    config = FingerprintConfig()
    with pytest.warns(UserWarning, match="initConnection fingerprint issues") as record:
        config.validate_params(**android(device_model=""))
    assert [str(w.message) for w in record] == [
        "initConnection fingerprint issues:\n  - device_model is empty"
    ]
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        config.validate_params(**ANDROID)


def test_off_mode_skips() -> None:
    invalid: dict[str, Any] = {
        "api_id": 6,
        "device_model": "",
        "system_version": "",
        "app_version": "",
        "system_lang_code": "",
        "lang_pack": "invalid",
        "lang_code": "",
    }
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        FingerprintConfig(strict_mode=StrictMode.OFF, auto_validate=False).validate_params(
            **invalid
        )
        FingerprintConfig(strict_mode=StrictMode.OFF).validate_params(**invalid)
        FingerprintConfig(strict_mode=StrictMode.STRICT, auto_validate=False).validate_params(
            **invalid
        )


def test_effective_layer() -> None:
    layer = FingerprintConfig().get_effective_layer()
    assert isinstance(layer, int)
    assert layer > 100
    assert layer == TELETHON_LAYER
    assert FingerprintConfig(layer_override=201).get_effective_layer() == 201


# ---------------------------------------------------------------- transport


def test_transport_recommendation() -> None:
    for lang_pack in ("tdesktop", "android", "ios", "macos", ""):
        assert TransportRecommendation.get_connection_class(lang_pack) is ConnectionTcpObfuscated
    assert TransportRecommendation.get_connection_class() is ConnectionTcpObfuscated
    assert TransportRecommendation.get_available_transports() == {
        "full": ConnectionTcpFull,
        "abridged": ConnectionTcpAbridged,
        "intermediate": ConnectionTcpIntermediate,
        "obfuscated": ConnectionTcpObfuscated,
    }


# ---------------------------------------------------------------- msg_id


def test_msg_id_offset_range() -> None:
    for _ in range(32):
        assert 0 <= generate_msg_id_offset() <= 0xFFFF


def test_is_valid_msg_id_matches_1_5_0() -> None:
    now = int(time.time())
    client = (now << 32) | 1
    server = now << 32
    assert is_valid_msg_id(client)
    assert is_valid_msg_id(client, from_client=True)
    assert not is_valid_msg_id(client, from_client=False)
    assert is_valid_msg_id(server, from_client=False)
    assert not is_valid_msg_id(server)
    # Clear of the 300 s edge, so a clock tick cannot flip the result.
    assert is_valid_msg_id(((now - 200) << 32) | 1)
    assert is_valid_msg_id(((now + 200) << 32) | 1)
    assert not is_valid_msg_id(((now + 400) << 32) | 1)
    assert not is_valid_msg_id(((now - 400) << 32) | 1)
    # 1.5.0 answered False, not an error, for ids outside the signed 64 bits.
    for msg_id in (0, -1, -2, 1, 2**63 - 1, 2**63, 2**63 + 1, 2**64 + 1, -(2**70)):
        assert not is_valid_msg_id(msg_id)
        assert not is_valid_msg_id(msg_id, from_client=False)


# validate_init_connection_params(**params, strict=strict) of 1.5.0 with one
# value None, on the API.TelegramDesktop values; 1.5.0 tested None as empty.
DESKTOP: dict[str, Any] = {
    "api_id": 2040,
    "device_model": "Desktop",
    "system_version": "Windows 11 x64",
    "app_version": "7.3.1 x64",
    "system_lang_code": "en-US",
    "lang_pack": "tdesktop",
    "lang_code": "en",
}
LANG_PACK_NONE = (
    "lang_pack 'None' is not a known official value. "
    "Expected one of: ['', 'android', 'ios', 'macos', 'tdesktop']"
)
NONE_REPORTS: list[tuple[str, bool, list[str]]] = [
    ("device_model", False, ["device_model is empty"]),
    ("device_model", True, ["device_model is empty"]),
    ("system_version", False, ["system_version is empty"]),
    ("system_version", True, ["system_version is empty"]),
    ("app_version", False, ["app_version is empty"]),
    ("system_lang_code", False, []),
    ("system_lang_code", True, []),
    ("lang_pack", False, [LANG_PACK_NONE]),
    ("lang_pack", True, [LANG_PACK_NONE]),
    ("api_id", False, []),
]


@pytest.mark.parametrize(("field", "strict", "expected"), NONE_REPORTS)
def test_none_values_are_reported_as_1_5_0(field: str, strict: bool, expected: list[str]) -> None:
    params = {**DESKTOP, field: None}
    assert validate_init_connection_params(**params, strict=strict) == expected


def test_validate_params_reports_a_none_value_as_1_5_0() -> None:
    config = FingerprintConfig(strict_mode=StrictMode.STRICT)
    with pytest.raises(ValueError, match="system_version is empty") as raised:
        config.validate_params(**{**DESKTOP, "system_version": None})
    assert str(raised.value) == "initConnection fingerprint issues:\n  - system_version is empty"
