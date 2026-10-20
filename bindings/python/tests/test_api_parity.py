"""Tests of the PlatformVersions, version patch, session JSON and fingerprint
exports of opentele2._native against the 1.5.0 values of
crates/opentele2-core/tests/{api,fingerprint}.rs and
crates/opentele2-versions/tests/{patch,live}.rs.

The network is only touched by the test marked ``live``.
"""

from __future__ import annotations

import json
import math
from typing import TYPE_CHECKING, Any

import pytest

from opentele2 import _native
from opentele2._native import CoreError

if TYPE_CHECKING:
    # TypedDicts of the stub only; they do not exist at runtime.
    from opentele2._native import ApiProfile, Issue, StrictMode, Versions

CLIENTS = (
    "TelegramDesktop",
    "TelegramAndroid",
    "TelegramAndroidX",
    "TelegramIOS",
    "TelegramMacOS",
    "TelegramWeb_A",
    "TelegramWeb_K",
    "Webogram",
)
WEB_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
)
OFFLINE = {
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
    "user_agent": WEB_USER_AGENT,
    # A 2.0.0 addition; 1.5.0 PlatformVersions had no Firefox version.
    "firefox_version": "150.0",
}
FULL_PATCH = {
    "desktop_app_version": "9.9.9",
    "android_app_version": "14.1.2",
    "android_app_version_code": 7300,
    "android_x_app_version": "0.30.0.1900",
    "ios_app_version": "14.1",
    "ios_build_number": 36000,
    "macos_app_version": "14.2",
    "macos_build_number": 290001,
    "web_k_version": "2.3 K",
    "web_a_version": "12.1.0 A",
}


# ---------------------------------------------------------------- versions


def test_platform_versions_and_layer() -> None:
    assert _native.platform_versions() == OFFLINE
    assert _native.LAYER == 230
    custom = _native.platform_versions(
        {
            "android_sdk_range": (21, 40),
            "ios_version_range": ("17.0", "28.0"),
            "android_latest_sdk": 40,
            "chrome_version": "160.0.0.0",
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/160.0.0.0",
        }
    )
    assert custom == {
        **OFFLINE,
        "android_sdk_range": (21, 40),
        "ios_version_range": ("17.0", "28.0"),
        "android_latest_sdk": 40,
        "chrome_version": "160.0.0.0",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/160.0.0.0",
    }
    # A full PlatformVersions is a valid override set, and lists are pairs too.
    assert _native.platform_versions(custom) == custom
    as_lists: Any = {"android_sdk_range": [21, 40], "ios_version_range": ["17.0", "28.0"]}
    assert _native.platform_versions(as_lists)["android_sdk_range"] == (21, 40)
    # The new fields reach the profiles: the web device is the user agent.
    assert _native.profile("TelegramWeb_A", custom)["device_model"] == custom["user_agent"]
    bad_range: Any = {"android_sdk_range": (1, 2, 3)}
    with pytest.raises(ValueError, match="exactly 2"):
        _native.platform_versions(bad_range)
    unknown: Any = {"bogus": 1}
    with pytest.raises(ValueError, match="unknown versions field"):
        _native.platform_versions(unknown)


def test_apply_versions_patch_skips_the_desktop_version() -> None:
    patch: Any = FULL_PATCH
    applied = _native.apply_versions_patch(None, patch)
    applicable = {k: v for k, v in FULL_PATCH.items() if k != "desktop_app_version"}
    assert applied == {**OFFLINE, **applicable}
    assert applied["desktop_app_version"] == "7.3.1"

    assert _native.apply_versions_patch(None, {}) == OFFLINE
    offline: Any = OFFLINE
    ios = _native.apply_versions_patch(offline, {"ios_app_version": "14.1"})
    assert ios == {**OFFLINE, "ios_app_version": "14.1"}
    # Overrides are applied before the patch, which wins; None is absent.
    both = _native.apply_versions_patch(
        {"ios_app_version": "12.0", "ios_build_number": 1},
        {"ios_app_version": "14.1", "ios_build_number": None},
    )
    assert both["ios_app_version"] == "14.1"
    assert both["ios_build_number"] == 1
    # chrome_version became a real patch field in 2.0.0.
    bad_patch: Any = {"bogus_version": "1"}
    with pytest.raises(ValueError, match="unknown versions patch field"):
        _native.apply_versions_patch(None, bad_patch)


def test_fetch_versions_rejects_a_bad_timeout() -> None:
    for timeout in (0.0, -1.0, math.inf, math.nan):
        with pytest.raises(ValueError, match="timeout"):
            _native.fetch_versions(timeout)


@pytest.mark.live
def test_fetch_versions_returns_current_versions() -> None:
    patch = _native.fetch_versions(10.0)
    assert patch, "no source answered"
    for value in patch.values():
        assert value != ""
    if "web_k_version" in patch:
        assert str(patch["web_k_version"]).endswith(" K")
    if "web_a_version" in patch:
        assert str(patch["web_a_version"]).endswith(" A")
    applied = _native.apply_versions_patch(None, patch)
    assert applied["desktop_app_version"] == OFFLINE["desktop_app_version"]


# ---------------------------------------------------------------- session JSON

ACCOUNT_KEYS = (
    '"twoFA":null,"role":"","id":null,"phone":null,"username":null,"date_of_birth":null,'
    '"date_of_birth_integrity":null,"is_premium":false,"has_profile_pic":false,'
    '"spamblock":null,"register_time":null,"last_check_time":null,"avatar":null,'
    '"first_name":"","last_name":"","sex":null,"proxy":null,"ipv6":false,"session_file":""'
)
# json.dumps(API.<X>().to_json(), separators=(",", ":")) of 1.5.0, in CLIENTS order.
SESSION_JSON_HEADS = (
    '{"app_id":2040,"app_hash":"b18441a1ff607e10a989891a5462e627","device":"Desktop",'
    '"sdk":"Windows 11 x64","app_version":"7.3.1 x64","system_lang_pack":"en-US",'
    '"system_lang_code":"en-US","lang_pack":"tdesktop","lang_code":"en",',
    '{"app_id":6,"app_hash":"eb06d4abfb49dc3eeb1aeb98ae0f581e","device":"samsungSM-S938B",'
    '"sdk":"SDK 36","app_version":"13.0.3 (7183)","system_lang_pack":"en-US",'
    '"system_lang_code":"en-US","lang_pack":"android","lang_code":"en",',
    '{"app_id":21724,"app_hash":"3e0cb5efcd52300aec5994fdfc5bdc16","device":"samsungSM-S938B",'
    '"sdk":"SDK 36","app_version":"0.29.1.1817","system_lang_pack":"en-US",'
    '"system_lang_code":"en-US","lang_pack":"android","lang_code":"en",',
    '{"app_id":10840,"app_hash":"33c45224029d59cb3ad0c16134215aeb","device":"iPhone 17 Pro",'
    '"sdk":"27.0.1","app_version":"13.0 (35303) ","system_lang_pack":"en-US",'
    '"system_lang_code":"en-US","lang_pack":"ios","lang_code":"en",',
    '{"app_id":2834,"app_hash":"68875f756c9b437a8b916ca3de215815","device":"MacBook Air M4",'
    '"sdk":"27.0.1","app_version":"13.0 (283305) ","system_lang_pack":"en-US",'
    '"system_lang_code":"en-US","lang_pack":"macos","lang_code":"en",',
    '{"app_id":2496,"app_hash":"8da85b0d5bfe62527e5b244c209159c3","device":"'
    + WEB_USER_AGENT
    + '",'
    '"sdk":"Windows","app_version":"12.0.47 A","system_lang_pack":"en-US",'
    '"system_lang_code":"en-US","lang_pack":"","lang_code":"en",',
    '{"app_id":2496,"app_hash":"8da85b0d5bfe62527e5b244c209159c3","device":"'
    + WEB_USER_AGENT
    + '",'
    '"sdk":"Win32","app_version":"2.2 K","system_lang_pack":"en-US",'
    '"system_lang_code":"en-US","lang_pack":"macos","lang_code":"en",',
    '{"app_id":2496,"app_hash":"8da85b0d5bfe62527e5b244c209159c3","device":"'
    + WEB_USER_AGENT
    + '",'
    '"sdk":"Win32","app_version":"0.7.0","system_lang_pack":"en-US",'
    '"system_lang_code":"en-US","lang_pack":"","lang_code":"en",',
)
SESSION_JSON_1_5_0 = tuple(head + ACCOUNT_KEYS + "}" for head in SESSION_JSON_HEADS)


def compact(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def test_profile_to_session_json_matches_1_5_0_and_reads_back() -> None:
    for client, want in zip(CLIENTS, SESSION_JSON_1_5_0):
        profile = _native.profile(client)
        written = _native.profile_to_session_json(profile)
        assert compact(written) == want, client
        assert compact(_native.profile_to_session_json(profile, {})) == want, client
        assert compact(_native.profile_to_session_json(profile, None)) == want, client
        assert _native.profile_from_session_json(written) == profile, client
        assert _native.profile_from_session_json(want) == profile, client


def test_session_json_extra_keys_override_in_place_and_append() -> None:
    want = (
        '{"app_id":7,"app_hash":"eb06d4abfb49dc3eeb1aeb98ae0f581e","device":"samsungSM-S938B",'
        '"sdk":"SDK 36","app_version":"13.0.3 (7183)","system_lang_pack":"en-US",'
        '"system_lang_code":"en-US","lang_pack":"android","lang_code":"en","twoFA":null,'
        '"role":"","id":null,"phone":"+100","username":null,"date_of_birth":null,'
        '"date_of_birth_integrity":null,"is_premium":false,"has_profile_pic":false,'
        '"spamblock":null,"register_time":null,"last_check_time":null,"avatar":null,'
        '"first_name":"","last_name":"","sex":null,"proxy":null,"ipv6":true,"session_file":"",'
        '"zeta":1,"alpha":null}'
    )
    extra = {"zeta": 1, "phone": "+100", "app_id": 7, "ipv6": True, "alpha": None}
    written = _native.profile_to_session_json(_native.profile("TelegramAndroid"), extra)
    assert compact(written) == want
    nested = _native.profile_to_session_json(
        _native.profile("TelegramAndroid"), {"proxy": {"port": 1080, "rdns": [True, 1.5]}}
    )
    assert nested["proxy"] == {"port": 1080, "rdns": [True, 1.5]}
    for bad in ({"x": object()}, {"x": math.nan}, {"x": 2**64}, {"x": {1: 2}}):
        with pytest.raises((TypeError, ValueError)):
            _native.profile_to_session_json(_native.profile("TelegramAndroid"), bad)


def test_profile_from_session_json_defaults_and_rejections() -> None:
    base = '"app_id":1,"app_hash":"h","device":"d","sdk":"s","app_version":"v"'
    cases = [
        ("{" + base + "}", ("en", "en", "")),
        ("{" + base + ',"system_lang_pack":"ru-RU"}', ("en", "ru-RU", "")),
        (
            "{" + base + ',"system_lang_code":"","system_lang_pack":"de-DE",'
            '"lang_code":"de","lang_pack":"tdesktop"}',
            ("de", "de-DE", "tdesktop"),
        ),
        (
            "{" + base + ',"system_lang_code":"fr-FR","system_lang_pack":"de-DE"}',
            ("en", "fr-FR", ""),
        ),
        (
            "{" + base + ',"system_lang_code":null,"lang_code":null,"lang_pack":null}',
            ("en", "en", ""),
        ),
    ]
    for text, (lang_code, system_lang_code, lang_pack) in cases:
        want = {
            "api_id": 1,
            "api_hash": "h",
            "device_model": "d",
            "system_version": "s",
            "app_version": "v",
            "lang_code": lang_code,
            "system_lang_code": system_lang_code,
            "lang_pack": lang_pack,
        }
        assert _native.profile_from_session_json(text) == want, text
        assert _native.profile_from_session_json(json.loads(text)) == want, text

    rest = '"app_hash":"h","device":"d","sdk":"s","app_version":"v"'
    rejected = [
        "[]",
        "{" + rest + "}",
        "{" + rest + ',"app_id":null}',
        "{" + rest + ',"app_id":"2040"}',
        "{" + rest + ',"app_id":4294967296}',
        "{" + rest + ',"app_id":1.5}',
        '{"app_id":1,"device":"d","sdk":"s","app_version":"v"}',
        '{"app_id":1,"app_hash":"h","sdk":"s","app_version":"v"}',
        '{"app_id":1,"app_hash":"h","device":"d","app_version":"v"}',
        '{"app_id":1,"app_hash":"h","device":"d","sdk":"s"}',
        "{" + rest + ',"app_id":1,"lang_code":5}',
        "{" + rest + ',"app_id":1,"system_lang_code":false}',
        "{not json",
    ]
    for text in rejected:
        with pytest.raises(CoreError) as error:
            _native.profile_from_session_json(text)
        assert error.value.code == "IO", text
    not_an_object: Any = []
    with pytest.raises(CoreError) as error:
        _native.profile_from_session_json(not_an_object)
    assert error.value.code == "IO"


def test_profiles_equal_ignores_the_language_fields() -> None:
    base = _native.profile("TelegramDesktop")
    relabelled: ApiProfile = {**base, "lang_code": "ru", "system_lang_code": "ru-RU"}
    relabelled["lang_pack"] = "x"
    assert _native.profiles_equal(base, relabelled)
    edits: list[tuple[str, object]] = [
        ("api_id", base["api_id"] + 1),
        ("api_hash", base["api_hash"] + "0"),
        ("device_model", base["device_model"] + "0"),
        ("system_version", base["system_version"] + "0"),
        ("app_version", base["app_version"] + "0"),
    ]
    for field, value in edits:
        changed: Any = {**base, field: value}
        assert not _native.profiles_equal(base, changed), field
    incomplete: Any = {"api_id": 1}
    with pytest.raises(TypeError, match="api_hash"):
        _native.profiles_equal(base, incomplete)


# ---------------------------------------------------------------- fingerprint

PACKS = "Expected one of: ['', 'android', 'ios', 'macos', 'tdesktop']"
ANDROID_MAJOR = "Android app_version '12.3.0' major does not match latest known '13.0.3'"


def profile_of(
    api_id: int,
    device_model: str,
    system_version: str,
    app_version: str,
    system_lang_code: str,
    lang_pack: str,
    lang_code: str,
) -> ApiProfile:
    return {
        "api_id": api_id,
        "api_hash": "",
        "device_model": device_model,
        "system_version": system_version,
        "app_version": app_version,
        "lang_code": lang_code,
        "system_lang_code": system_lang_code,
        "lang_pack": lang_pack,
    }


def android(**edits: Any) -> ApiProfile:
    """The Android base case of 1.5.0 tests/test_fingerprints.py."""
    profile: Any = {
        **profile_of(6, "Samsung SM-S928B", "SDK 35", "12.3.0", "en-US", "android", "en"),
        **edits,
    }
    return profile


def messages(issues: list[Issue]) -> list[str]:
    return [issue["message"] for issue in issues]


def check(label: str, profile: ApiProfile, loose: list[str], strict: list[str]) -> None:
    for mode, severity in (("off", "note"), ("warn", "warning")):
        issues = _native.validate_init_params(profile, None, mode)
        assert messages(issues) == loose, f"{label} {mode}"
        assert all(issue["severity"] == severity for issue in issues), label
    issues = _native.validate_init_params(profile, None, "strict")
    assert messages(issues) == strict, f"{label} strict"
    assert all(issue["severity"] == "error" for issue in issues), label


def test_tz_offset_matches_1_5_0() -> None:
    cases = [
        (18000, 18000),
        (19800, 19800),
        (20700, 20700),
        (-12600, -12600),
        (50400, 50400),
        (-43200, -43200),
        (0, 0),
        (450, 900),
        (-450, -900),
        (420, 0),
        (449, 0),
        (-449, 0),
        (451, 900),
        (1350, 1800),
        (-1350, -1800),
        (50401, -36000),
        (54000, -32400),
        (86399, 0),
        (-43201, 43200),
        (-86399, 0),
        (-50400, 36000),
        (45900, 45900),
        (-2670, -2700),
        (37800, 37800),
        (-34200, -34200),
    ]
    for offset, expected in cases:
        result = _native.tz_offset(offset)
        assert isinstance(result, float)
        assert result == expected, offset
    # 1.5.0: sum(int(tdesktop_tz_offset(at(s))) // 900 * (s + 86400)).
    total = sum(
        int(_native.tz_offset(offset)) // 900 * (offset + 86400) for offset in range(-86399, 86400)
    )
    assert total == 32358124800
    for offset in (-(2**31), 2**31 - 1, -1000000, 1000000):
        assert _native.tz_offset(offset) == _native.tz_offset(int(math.fmod(offset, 86400)))


def test_validate_init_params_matches_1_5_0() -> None:
    def unknown(pack: str) -> str:
        return f"lang_pack '{pack}' is not a known official value. {PACKS}"

    check("android_ok", android(), [], [ANDROID_MAJOR])
    check(
        "desktop_ok",
        profile_of(2040, "Desktop", "Windows 11", "5.12.3 x64", "en-US", "tdesktop", "en"),
        [],
        ["Desktop app_version '5.12.3 x64' major does not match latest known '7.3.1'"],
    )
    check(
        "web_ok",
        profile_of(
            2496,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Windows",
            "5.0.0 Z",
            "en-US",
            "",
            "en",
        ),
        [],
        [],
    )
    check(
        "empty_device",
        android(device_model=""),
        ["device_model is empty"],
        ["device_model is empty", ANDROID_MAJOR],
    )
    all_empty = [
        unknown("invalid"),
        "lang_code '' looks invalid (too short)",
        "device_model is empty",
        "system_version is empty",
        "app_version is empty",
    ]
    check("all_empty", profile_of(6, "", "", "", "", "invalid", ""), all_empty, all_empty)
    short = "lang_code 'x' looks invalid (too short)"
    check("short_lang", android(lang_code="x"), [short], [short, ANDROID_MAJOR])
    one_char = "lang_code 'é' looks invalid (too short)"
    check("one_char_lang", android(lang_code="é"), [one_char], [one_char, ANDROID_MAJOR])
    check("two_char_lang", android(lang_code="éé"), [], [ANDROID_MAJOR])
    check(
        "api_mismatch",
        android(api_id=99999),
        [],
        ["api_id 99999 does not match lang_pack 'android' (expected 6)", ANDROID_MAJOR],
    )
    region = "system_lang_code 'en' should include a region code (e.g. 'en-US') for android clients"
    check("no_region_android", android(system_lang_code="en"), [region], [region, ANDROID_MAJOR])
    check(
        "no_region_desktop",
        profile_of(2040, "Desktop", "Windows 11", "7.3.1 x64", "en", "tdesktop", "en"),
        [],
        [],
    )
    check(
        "ios_wrong_id",
        profile_of(6, "Samsung SM-S928B", "27.0.1", "13.0", "en-US", "ios", "en"),
        [],
        ["api_id 6 does not match lang_pack 'ios' (expected 10840)"],
    )
    check(
        "macos_old",
        profile_of(2834, "MacBook Air", "macOS 27.0.1", "12.9", "en-US", "macos", "en"),
        [],
        ["macOS app_version '12.9' major does not match latest known '13.0'"],
    )
    check("startswith_quirk", android(app_version="130.0"), [], [])
    check("android_current", android(app_version="13.0.3", system_version="SDK 37"), [], [])

    kinds = [
        issue["kind"]
        for issue in _native.validate_init_params(
            profile_of(1, "", "", "", "en", "ios", "x"), mode="strict"
        )
    ]
    assert kinds == [
        "ShortLangCode",
        "MissingRegion",
        "EmptyDeviceModel",
        "EmptySystemVersion",
        "EmptyAppVersion",
        "ApiIdMismatch",
        "AppVersionMajor",
    ]
    empty = android(device_model="")
    assert _native.validate_init_params(empty) == _native.validate_init_params(empty, None, "warn")
    assert _native.STRICT_MODES == ("off", "warn", "strict")
    loud: Any = "WARN"
    with pytest.raises(ValueError, match="unknown strict mode"):
        _native.validate_init_params(android(), None, loud)


def test_check_versions_reads_android_sdk_levels_as_1_5_0() -> None:
    def sdk(level: object, expected: str = "[29, 37]") -> str:
        return f"Android SDK {level} is outside the expected range {expected}"

    cases = [
        ("SDK 29", None),
        ("SDK 37", None),
        ("SDK 28", "28"),
        ("SDK 38", "38"),
        ("SDK35", None),
        ("SDK -5", "-5"),
        ("SDK 3_8", "38"),
        ("SDK 3__8", None),
        ("SDK ٣٨", "38"),
        ("SDK \u001c40", None),
        ("SDK -0", "0"),
        ("SDK " + "9" * 30, "9" * 30),
        ("SDK " + "9" * 4301, None),
        ("14 (40)", "40"),
        ("15.0(40)", "40"),
        ("15.0.1 (40)", None),
        ("14 (40)\n", "40"),
        ("14 (40)\n\n", None),
        ("14\u001c(40)", "40"),
        ("14 (" + chr(0xFF14) + chr(0xFF10) + ")", "40"),
        ("sdk 40", None),
    ]
    for system_version, level in cases:
        issues = _native.check_versions(
            android(app_version="13.0.3", system_version=system_version)
        )
        assert messages(issues) == ([] if level is None else [sdk(level)]), repr(system_version)
        assert all(i["kind"] == "AndroidSdkRange" and i["severity"] == "error" for i in issues)
    versions: Versions = {"android_app_version": "12.9", "android_sdk_range": (21, 40)}
    assert _native.check_versions(android(system_version="SDK 40"), versions) == []
    assert messages(_native.check_versions(android(system_version="SDK 41"), versions)) == [
        sdk(41, "[21, 40]")
    ]


def test_fingerprint_config_has_the_1_5_0_defaults_and_validates() -> None:
    config = _native.fingerprint_config(msg_id_offset=0x1234)
    assert config == {
        "strict_mode": "warn",
        "auto_validate": True,
        "preferred_transport": "obfuscated",
        "warn_on_layer_mismatch": True,
        "layer_override": None,
        "randomize_msg_id_offset": True,
        "msg_id_offset": 0x1234,
    }
    assert _native.effective_layer(config) == _native.LAYER
    assert _native.effective_layer({**config, "layer_override": 201}) == 201
    assert _native.fingerprint_config(layer_override=201)["layer_override"] == 201
    drawn = _native.fingerprint_config()["msg_id_offset"]
    assert 0 <= drawn <= 0xFFFF
    with pytest.raises(ValueError, match="msg_id_offset"):
        _native.fingerprint_config(msg_id_offset=0x10000)
    loud: Any = "loud"
    with pytest.raises(ValueError, match="unknown strict mode"):
        _native.fingerprint_config(strict_mode=loud)
    options: Any = {"bogus": 1}
    with pytest.raises(TypeError, match="bogus"):
        _native.fingerprint_config(**options)

    profile = android(api_id=1, device_model="")
    quiet_modes: list[tuple[StrictMode, bool]] = [
        ("off", True),
        ("off", False),
        ("warn", False),
        ("strict", False),
    ]
    for strict_mode, auto_validate in quiet_modes:
        quiet = _native.fingerprint_config(
            strict_mode=strict_mode, auto_validate=auto_validate, msg_id_offset=0
        )
        assert _native.validate_fingerprint(quiet, profile) == [], strict_mode
    warned = _native.validate_fingerprint(_native.fingerprint_config(msg_id_offset=0), profile)
    assert all(issue["severity"] == "warning" for issue in warned)
    assert (
        _native.issues_message(warned)
        == "initConnection fingerprint issues:\n  - device_model is empty"
    )
    raised = _native.validate_fingerprint(
        _native.fingerprint_config(strict_mode="strict", msg_id_offset=0), profile
    )
    assert all(issue["severity"] == "error" for issue in raised)
    assert _native.issues_message(raised) == (
        "initConnection fingerprint issues:\n  - device_model is empty\n"
        "  - api_id 1 does not match lang_pack 'android' (expected 6)\n"
        "  - Android app_version '12.3.0' major does not match latest known '13.0.3'"
    )
    assert _native.issues_message([]) == "initConnection fingerprint issues:"
    bogus: Any = [{"kind": "Nope", "severity": "note", "message": "x"}]
    with pytest.raises(ValueError, match="unknown issue kind"):
        _native.issues_message(bogus)


def test_msg_id_offset_and_is_valid_msg_id_match_1_5_0() -> None:
    for _ in range(32):
        assert 0 <= _native.msg_id_offset() <= 0xFFFF
    now = 1760000000
    cases = [
        (7559142440960000001, True, True),
        (7559142440960000001, False, False),
        (7559142440960000000, True, False),
        (7559142440960000000, False, True),
        (7559143725155221505, True, True),
        (7559143729450188801, True, False),
        (7559141156764778497, True, True),
        (7559141152469811201, True, False),
        (7559143729450188799, True, True),
        (7559141156764778495, True, False),
        (0, True, False),
        (0, False, False),
        (-1, True, False),
        (-2, False, False),
        (1, True, False),
        (2**63 - 1, True, False),
        (7559142440960000004, False, True),
    ]
    for msg_id, from_client, expected in cases:
        assert _native.is_valid_msg_id(msg_id, from_client, now) is expected, msg_id
        # time.time() == now + 0.9: the fraction is dropped.
        assert _native.is_valid_msg_id(msg_id, from_client, now + 0.9) is expected, msg_id
    with pytest.raises(OverflowError):
        _native.is_valid_msg_id(2**63, True, now)
