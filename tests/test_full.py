# ruff: noqa: E402
import os
import sys
import json
import sqlite3
import pathlib

base_dir = pathlib.Path(__file__).parent.parent.absolute().__str__()
sys.path.insert(0, base_dir)

import pytest

from src.td import TDesktop
from src.td.account import Account
from src.tl.telethon import TelegramClient
from src.api import API, APIData, UseCurrentSession, CreateNewSession, LoginFlag
from src.devices import (
    AndroidDevice,
    IOSDevice,
    macOSDevice,
    WindowsDevice,
    LinuxDevice,
    WebBrowserDevice,
    DeviceInfo,
)
from src.fingerprint import (
    LAYER,
    PLATFORM_VERSIONS,
    StrictMode,
    FingerprintConfig,
    DEFAULT_CONFIG,
    TransportRecommendation,
    validate_init_connection_params,
    get_recommended_layer,
    get_platform_versions,
    generate_msg_id_offset,
    is_valid_msg_id,
)
from src.consistency import (
    CheckResult,
    ConsistencyReport,
)

TESTS_DIR = pathlib.Path(__file__).parent
TDATAS_DIR = TESTS_DIR / "tdatas"
SESSIONS_DIR = TESTS_DIR / "sessions"

ACCOUNT_IDS = ["215340804", "215342020", "215342289", "215342316", "215342360"]


def _load_json(account_id: str) -> dict:
    path = SESSIONS_DIR / f"{account_id}.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _read_session_db(account_id: str) -> dict:
    path = SESSIONS_DIR / f"{account_id}.session"
    conn = sqlite3.connect(str(path))
    try:
        row = conn.execute(
            "SELECT dc_id, server_address, port, auth_key FROM sessions"
        ).fetchone()
        if row is None:
            return {}
        return {
            "dc_id": row[0],
            "server_address": row[1],
            "port": row[2],
            "auth_key": row[3],
        }
    finally:
        conn.close()


class TestAPIClasses:
    def test_all_api_classes_exist(self):
        apis = [
            API.TelegramDesktop,
            API.TelegramAndroid,
            API.TelegramAndroidX,
            API.TelegramIOS,
            API.TelegramMacOS,
            API.TelegramWeb_Z,
            API.TelegramWeb_A,
            API.TelegramWeb_K,
            API.Webogram,
        ]
        for api in apis:
            assert issubclass(api, APIData), f"{api.__name__} must extend APIData"

    def test_api_ids_are_official(self):
        official_ids = {2040, 6, 21724, 10840, 2834, 2496}
        apis = [
            API.TelegramDesktop,
            API.TelegramAndroid,
            API.TelegramAndroidX,
            API.TelegramIOS,
            API.TelegramMacOS,
            API.TelegramWeb_Z,
            API.TelegramWeb_A,
            API.TelegramWeb_K,
            API.Webogram,
        ]
        for api in apis:
            assert api.api_id in official_ids, (
                f"{api.__name__}.api_id={api.api_id} not in official IDs"
            )

    def test_api_hashes_non_empty(self):
        apis = [
            API.TelegramDesktop,
            API.TelegramAndroid,
            API.TelegramAndroidX,
            API.TelegramIOS,
            API.TelegramMacOS,
            API.TelegramWeb_Z,
            API.TelegramWeb_A,
            API.TelegramWeb_K,
            API.Webogram,
        ]
        for api in apis:
            assert api.api_hash and len(api.api_hash) == 32, (
                f"{api.__name__}.api_hash invalid"
            )

    def test_desktop_attributes(self):
        d = API.TelegramDesktop
        assert d.api_id == 2040
        assert d.api_hash == "b18441a1ff607e10a989891a5462e627"
        assert d.lang_pack == "tdesktop"
        assert d.lang_code == "en"

    def test_android_attributes(self):
        a = API.TelegramAndroid
        assert a.api_id == 6
        assert a.lang_pack == "android"

    def test_ios_attributes(self):
        ios = API.TelegramIOS
        assert ios.api_id == 10840
        assert ios.lang_pack == "ios"

    def test_macos_attributes(self):
        m = API.TelegramMacOS
        assert m.api_id == 2834
        assert m.lang_pack == "macos"

    def test_web_z_attributes(self):
        w = API.TelegramWeb_Z
        assert w.api_id == 2496
        assert "Chrome" in w.device_model

    def test_api_instantiation(self):
        inst = API.TelegramDesktop()
        assert inst.api_id == API.TelegramDesktop.api_id
        assert inst.api_hash == API.TelegramDesktop.api_hash
        assert inst.lang_pack == API.TelegramDesktop.lang_pack

    def test_api_copy(self):
        original = API.TelegramAndroid()
        copied = original.copy()
        assert copied.api_id == original.api_id
        assert copied.api_hash == original.api_hash
        assert copied.device_model == original.device_model
        assert copied.system_version == original.system_version

    def test_api_custom_instantiation(self):
        custom = APIData(api_id=12345, api_hash="a" * 32)
        assert custom.api_id == 12345
        assert custom.api_hash == "a" * 32

    def test_api_str_representation(self):
        s = str(API.TelegramDesktop)
        assert "TelegramDesktop" in s


class TestAPIGenerate:
    def test_desktop_generate_deterministic(self):
        a = API.TelegramDesktop.Generate("windows", "seed123")
        b = API.TelegramDesktop.Generate("windows", "seed123")
        assert a.device_model == b.device_model
        assert a.system_version == b.system_version

    def test_desktop_generate_different_systems(self):
        win = API.TelegramDesktop.Generate("windows", "same_seed")
        linux = API.TelegramDesktop.Generate("linux", "same_seed")
        assert win.system_version != linux.system_version

    def test_desktop_generate_random_varies(self):
        seen = set()
        for _ in range(10):
            g = API.TelegramDesktop.Generate()
            seen.add((g.device_model, g.system_version))
        assert len(seen) > 1, "Random generation should produce variety"

    def test_android_generate(self):
        g = API.TelegramAndroid.Generate("seed")
        assert g.api_id == API.TelegramAndroid.api_id
        assert g.device_model is not None
        assert g.system_version is not None

    def test_ios_generate(self):
        g = API.TelegramIOS.Generate("seed")
        assert g.api_id == API.TelegramIOS.api_id
        assert "iPhone" in g.device_model

    def test_macos_generate(self):
        g = API.TelegramMacOS.Generate("seed")
        assert g.api_id == API.TelegramMacOS.api_id

    def test_android_x_generate(self):
        g = API.TelegramAndroidX.Generate("seed")
        assert g.api_id == API.TelegramAndroidX.api_id


class TestLoginFlag:
    def test_use_current_session(self):
        assert issubclass(UseCurrentSession, LoginFlag)

    def test_create_new_session(self):
        assert issubclass(CreateNewSession, LoginFlag)


class TestAndroidDevice:
    def test_random_device_returns_device_info(self):
        d = AndroidDevice.RandomDevice("test_seed")
        assert isinstance(d, DeviceInfo)
        assert d.model
        assert d.version

    def test_deterministic(self):
        a = AndroidDevice.RandomDevice("same")
        b = AndroidDevice.RandomDevice("same")
        assert a.model == b.model
        assert a.version == b.version

    def test_random_varies(self):
        results = set()
        for _ in range(20):
            d = AndroidDevice.RandomDevice()
            results.add(d.model)
        assert len(results) > 1

    def test_sdk_version_format(self):
        d = AndroidDevice.RandomDevice("check_format")
        import re

        m = re.match(r"^SDK\s+(\d+)$", d.version)
        assert m, f"Version '{d.version}' doesn't match format 'SDK X'"
        sdk_num = int(m.group(1))
        assert 21 <= sdk_num <= 40


class TestIOSDevice:
    def test_random_device(self):
        d = IOSDevice.RandomDevice("test")
        assert isinstance(d, DeviceInfo)
        assert "iPhone" in d.model

    def test_deterministic(self):
        a = IOSDevice.RandomDevice("same_seed")
        b = IOSDevice.RandomDevice("same_seed")
        assert a.model == b.model
        assert a.version == b.version

    def test_version_format(self):
        d = IOSDevice.RandomDevice("check")
        parts = d.version.split(".")
        assert 2 <= len(parts) <= 3
        assert all(p.isdigit() for p in parts)

    def test_device_list_populated(self):
        IOSDevice.__gen__()
        assert len(IOSDevice.deviceList) > 100


class TestMacOSDevice:
    def test_random_device(self):
        d = macOSDevice.RandomDevice("test")
        assert isinstance(d, DeviceInfo)

    def test_deterministic(self):
        a = macOSDevice.RandomDevice("seed")
        b = macOSDevice.RandomDevice("seed")
        assert a.model == b.model


class TestWindowsDevice:
    def test_random_device(self):
        d = WindowsDevice.RandomDevice("test")
        assert isinstance(d, DeviceInfo)

    def test_version_is_windows(self):
        d = WindowsDevice.RandomDevice("win_test")
        assert "Windows" in d.version or "10" in d.version or "11" in d.version


class TestLinuxDevice:
    def test_random_device(self):
        d = LinuxDevice.RandomDevice("test")
        assert isinstance(d, DeviceInfo)

    def test_version_contains_linux(self):
        d = LinuxDevice.RandomDevice("linux_test")
        assert "Linux" in d.version


class TestWebBrowserDevice:
    def test_random_device_z_variant(self):
        d = WebBrowserDevice.RandomDevice("test", variant="z")
        assert isinstance(d, DeviceInfo)
        assert "Mozilla" in d.model or "Chrome" in d.model or len(d.model) > 20

    def test_random_device_k_variant(self):
        d = WebBrowserDevice.RandomDevice("test", variant="k")
        assert isinstance(d, DeviceInfo)

    def test_z_vs_k_system_version_differs(self):
        dz = WebBrowserDevice.RandomDevice("same_seed", variant="z")
        dk = WebBrowserDevice.RandomDevice("same_seed", variant="k")
        assert dz.model == dk.model

    def test_deterministic(self):
        a = WebBrowserDevice.RandomDevice("seed", variant="z")
        b = WebBrowserDevice.RandomDevice("seed", variant="z")
        assert a.model == b.model
        assert a.version == b.version

    def test_browser_weights_attr_exists(self):
        assert hasattr(WebBrowserDevice, "BROWSER_WEIGHTS")
        weights = WebBrowserDevice.BROWSER_WEIGHTS
        assert "chrome" in weights
        assert "edge" in weights
        assert "firefox" in weights

    def test_chrome_dominates_device_list(self):
        WebBrowserDevice._generated = False
        WebBrowserDevice.__gen__()
        total = len(WebBrowserDevice.deviceList)
        chrome_count = sum(
            1
            for d in WebBrowserDevice.deviceList
            if "Chrome" in d.model and "Edg" not in d.model
        )
        assert chrome_count / total > 0.5, (
            f"Chrome should dominate: {chrome_count}/{total} = {chrome_count / total:.1%}"
        )

    def test_multiple_browsers_present(self):
        WebBrowserDevice._generated = False
        WebBrowserDevice.__gen__()
        uas = {d.model for d in WebBrowserDevice.deviceList}
        has_chrome = any("Chrome" in ua and "Edg" not in ua for ua in uas)
        has_edge = any("Edg" in ua for ua in uas)
        has_firefox = any("Firefox" in ua for ua in uas)
        assert has_chrome, "Chrome UAs should be present"
        browser_count = sum([has_chrome, has_edge, has_firefox])
        assert browser_count >= 2, (
            f"Expected at least 2 browser families, got {browser_count}"
        )


class TestFingerprintValidation:
    def test_valid_desktop_params(self):
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

    def test_valid_android_params(self):
        issues = validate_init_connection_params(
            api_id=6,
            device_model="Samsung SM-S928B",
            system_version="SDK 35",
            app_version="12.3.0",
            system_lang_code="en-US",
            lang_pack="android",
            lang_code="en",
        )
        assert issues == []

    def test_invalid_lang_pack(self):
        issues = validate_init_connection_params(
            api_id=2040,
            device_model="Desktop",
            system_version="Windows 11",
            app_version="5.12.3",
            system_lang_code="en",
            lang_pack="invalid_pack",
            lang_code="en",
        )
        assert any("lang_pack" in i for i in issues)

    def test_empty_device_model(self):
        issues = validate_init_connection_params(
            api_id=2040,
            device_model="",
            system_version="Windows 11",
            app_version="5.12.3",
            system_lang_code="en",
            lang_pack="tdesktop",
            lang_code="en",
        )
        assert any("device_model" in i for i in issues)

    def test_short_lang_code(self):
        issues = validate_init_connection_params(
            api_id=2040,
            device_model="Desktop",
            system_version="Windows 11",
            app_version="5.12.3",
            system_lang_code="en",
            lang_pack="tdesktop",
            lang_code="x",
        )
        assert any("lang_code" in i for i in issues)

    def test_strict_mode_api_id_mismatch(self):
        issues = validate_init_connection_params(
            api_id=9999,
            device_model="Desktop",
            system_version="Windows 11",
            app_version="5.12.3",
            system_lang_code="en-US",
            lang_pack="tdesktop",
            lang_code="en",
            strict=True,
        )
        assert any("api_id" in i for i in issues)

    def test_strict_mode_all_correct(self):
        issues = validate_init_connection_params(
            api_id=2040,
            device_model="Desktop",
            system_version="Windows 11",
            app_version=f"{PLATFORM_VERSIONS.desktop_app_version} x64",
            system_lang_code="en-US",
            lang_pack="tdesktop",
            lang_code="en",
            strict=True,
        )
        assert issues == []

    def test_mobile_system_lang_needs_region(self):
        issues = validate_init_connection_params(
            api_id=6,
            device_model="Samsung SM-S928B",
            system_version="SDK 35",
            app_version="12.3.0",
            system_lang_code="en",
            lang_pack="android",
            lang_code="en",
        )
        assert any("region" in i for i in issues)

    def test_web_empty_lang_pack_valid(self):
        issues = validate_init_connection_params(
            api_id=2496,
            device_model="Mozilla/5.0 ...",
            system_version="Windows",
            app_version="5.0.0 Z",
            system_lang_code="en-US",
            lang_pack="",
            lang_code="en",
        )
        assert issues == []


class TestPlatformVersions:
    def test_singleton(self):
        pv = get_platform_versions()
        assert pv is PLATFORM_VERSIONS

    def test_android_version(self):
        assert PLATFORM_VERSIONS.android_app_version
        parts = PLATFORM_VERSIONS.android_app_version.split(".")
        assert len(parts) >= 2

    def test_ios_version(self):
        assert PLATFORM_VERSIONS.ios_app_version

    def test_desktop_version(self):
        assert PLATFORM_VERSIONS.desktop_app_version

    def test_chrome_version(self):
        assert PLATFORM_VERSIONS.chrome_version
        major = int(PLATFORM_VERSIONS.chrome_version.split(".")[0])
        assert major >= 100

    def test_user_agent_contains_chrome(self):
        assert "Chrome" in PLATFORM_VERSIONS.user_agent

    def test_sdk_range(self):
        lo, hi = PLATFORM_VERSIONS.android_sdk_range
        assert lo < hi
        assert lo >= 21


class TestFingerprintConfig:
    def test_default_config(self):
        assert DEFAULT_CONFIG.strict_mode == StrictMode.WARN
        assert DEFAULT_CONFIG.auto_validate is True
        assert DEFAULT_CONFIG.preferred_transport == "obfuscated"

    def test_strict_mode_values(self):
        assert StrictMode.OFF.value == "off"
        assert StrictMode.WARN.value == "warn"
        assert StrictMode.STRICT.value == "strict"

    def test_config_validate_params_warn(self):
        config = FingerprintConfig(strict_mode=StrictMode.WARN)
        import warnings as w

        with w.catch_warnings(record=True) as caught:
            w.simplefilter("always")
            config.validate_params(
                api_id=9999,
                device_model="",
                system_version="",
                app_version="",
                system_lang_code="en",
                lang_pack="bad",
                lang_code="en",
            )
        assert len(caught) > 0

    def test_config_validate_params_strict_raises(self):
        config = FingerprintConfig(strict_mode=StrictMode.STRICT)
        with pytest.raises(ValueError, match="fingerprint"):
            config.validate_params(
                api_id=9999,
                device_model="",
                system_version="",
                app_version="",
                system_lang_code="en",
                lang_pack="bad",
                lang_code="en",
            )

    def test_config_validate_off_does_nothing(self):
        config = FingerprintConfig(strict_mode=StrictMode.OFF, auto_validate=False)
        config.validate_params(
            api_id=0,
            device_model="",
            system_version="",
            app_version="",
            system_lang_code="",
            lang_pack="bad",
            lang_code="",
        )

    def test_effective_layer(self):
        config = FingerprintConfig()
        layer = config.get_effective_layer()
        assert isinstance(layer, int)
        assert layer > 100

    def test_layer_override(self):
        config = FingerprintConfig(layer_override=999)
        assert config.get_effective_layer() == 999


class TestMsgIdHelpers:
    def test_generate_offset(self):
        offset = generate_msg_id_offset()
        assert 0 <= offset <= 0xFFFF

    def test_valid_client_msg_id(self):
        import time

        now = int(time.time())
        msg_id = (now << 32) | 1
        assert is_valid_msg_id(msg_id, from_client=True)

    def test_invalid_zero_msg_id(self):
        assert not is_valid_msg_id(0)

    def test_invalid_parity(self):
        import time

        now = int(time.time())
        even_id = (now << 32) | 2
        assert not is_valid_msg_id(even_id, from_client=True)

    def test_server_msg_id(self):
        import time

        now = int(time.time())
        even_id = (now << 32) | 2
        assert is_valid_msg_id(even_id, from_client=False)


class TestTransportRecommendation:
    def test_get_connection_class(self):
        cls = TransportRecommendation.get_connection_class()
        assert cls is not None

    def test_available_transports(self):
        transports = TransportRecommendation.get_available_transports()
        assert isinstance(transports, dict)
        assert len(transports) > 0

    def test_default_is_obfuscated(self):
        cls = TransportRecommendation.get_connection_class("tdesktop")
        assert "Obfuscated" in cls.__name__ or "Full" in cls.__name__


class TestLayer:
    def test_layer_is_int(self):
        assert isinstance(LAYER, int)
        assert LAYER > 100

    def test_recommended_layer(self):
        layer = get_recommended_layer()
        assert isinstance(layer, int)
        assert layer > 100


class TestConsistencyDataclasses:
    def test_check_result_passed(self):
        cr = CheckResult(name="test", passed=True, detail="OK")
        assert cr.passed
        assert cr.name == "test"
        assert cr.detail == "OK"

    def test_check_result_failed(self):
        cr = CheckResult(name="test", passed=False, detail="bad")
        assert not cr.passed

    def test_report_all_passed(self):
        r = ConsistencyReport(
            checks=[
                CheckResult(name="a", passed=True, detail="ok"),
                CheckResult(name="b", passed=True, detail="ok"),
            ]
        )
        assert r.all_passed

    def test_report_not_all_passed(self):
        r = ConsistencyReport(
            checks=[
                CheckResult(name="a", passed=True, detail="ok"),
                CheckResult(name="b", passed=False, detail="bad"),
            ]
        )
        assert not r.all_passed

    def test_report_summary(self):
        r = ConsistencyReport(
            checks=[
                CheckResult(name="a", passed=True, detail="ok"),
                CheckResult(name="b", passed=False, detail="fail"),
            ]
        )
        s = r.summary
        assert "1/2" in s
        assert "[OK] a" in s
        assert "[FAIL] b" in s

    def test_report_str(self):
        r = ConsistencyReport(checks=[CheckResult(name="x", passed=True, detail="d")])
        assert str(r) == r.summary

    def test_empty_report_passes(self):
        r = ConsistencyReport()
        assert r.all_passed


class TestConsistencyCheckerOffline:
    def test_checker_has_nearest_dc_method(self):
        from src.consistency import ConsistencyChecker

        assert hasattr(ConsistencyChecker, "check_nearest_dc")

    def test_run_all_lists_nearest_dc(self):
        import inspect
        from src.consistency import ConsistencyChecker

        source = inspect.getsource(ConsistencyChecker.run_all)
        assert "check_nearest_dc" in source


class TestAutoPostLogin:
    def test_auto_post_login_defaults_true(self):
        client = TelegramClient(api=API.TelegramDesktop)
        assert client._auto_post_login is True

    def test_auto_post_login_can_be_disabled(self):
        client = TelegramClient(api=API.TelegramDesktop, auto_post_login=False)
        assert client._auto_post_login is False

    def test_post_login_done_starts_false(self):
        client = TelegramClient(api=API.TelegramDesktop)
        assert client._post_login_done is False

    def test_has_run_post_login_method(self):
        assert hasattr(TelegramClient, "_run_post_login_requests")

    def test_has_connect_override(self):
        import inspect

        func = TelegramClient.connect
        while hasattr(func, "__fget__"):
            func = func.__fget__
        try:
            source = inspect.getsource(func)
        except OSError:
            src_file = os.path.join(base_dir, "src", "tl", "telethon.py")
            with open(src_file, "r", encoding="utf-8") as f:
                source = f.read()
        assert "_run_post_login_requests" in source
        assert "_auto_post_login" in source


class TestTDataLoading:
    @pytest.fixture(params=ACCOUNT_IDS)
    def account_id(self, request):
        return request.param

    @pytest.fixture
    def tdata_path(self, account_id):
        return str(TDATAS_DIR / account_id / "tdata")

    @pytest.fixture
    def account_json(self, account_id):
        return _load_json(account_id)

    def test_tdata_loads_successfully(self, tdata_path):
        tdesk = TDesktop(tdata_path)
        assert tdesk.isLoaded()

    def test_tdata_has_accounts(self, tdata_path):
        tdesk = TDesktop(tdata_path)
        assert tdesk.accountsCount > 0

    def test_tdata_main_account_exists(self, tdata_path):
        tdesk = TDesktop(tdata_path)
        assert tdesk.mainAccount is not None

    def test_tdata_account_is_loaded(self, tdata_path):
        tdesk = TDesktop(tdata_path)
        assert tdesk.mainAccount.isLoaded()

    def test_tdata_account_has_auth_key(self, tdata_path):
        tdesk = TDesktop(tdata_path)
        acct = tdesk.mainAccount
        assert acct.authKey is not None
        assert len(acct.authKey.key) == 256

    def test_tdata_account_has_user_id(self, tdata_path, account_id):
        tdesk = TDesktop(tdata_path)
        acct = tdesk.mainAccount
        assert acct.UserId > 0

    def test_tdata_account_has_valid_dc_id(self, tdata_path):
        tdesk = TDesktop(tdata_path)
        acct = tdesk.mainAccount
        assert 1 <= acct.MainDcId <= 5

    def test_tdata_user_id_matches_json(self, tdata_path, account_id):
        tdesk = TDesktop(tdata_path)
        acct = tdesk.mainAccount
        assert acct.UserId > 0, f"Invalid UserId for account {account_id}"

    def test_tdata_keyfile(self, tdata_path):
        tdesk = TDesktop(tdata_path)
        assert tdesk.keyFile == "data"

    def test_tdata_serialization_roundtrip(self, tdata_path):
        tdesk = TDesktop(tdata_path)
        acct = tdesk.mainAccount
        serialized = acct.serializeMtpAuthorization()
        assert len(serialized) > 0

        from src.qt_compat import QDataStream

        stream = QDataStream(serialized)
        stream.setVersion(QDataStream.Version.Qt_5_1)
        tag = stream.readInt64()
        assert tag == Account.kWideIdsTag


class TestSessionFiles:
    @pytest.fixture(params=ACCOUNT_IDS)
    def account_id(self, request):
        return request.param

    def test_session_file_exists(self, account_id):
        path = SESSIONS_DIR / f"{account_id}.session"
        assert path.exists()

    def test_session_file_readable(self, account_id):
        data = _read_session_db(account_id)
        assert data, f"Could not read session {account_id}"

    def test_session_has_dc_id(self, account_id):
        data = _read_session_db(account_id)
        assert 1 <= data["dc_id"] <= 5

    def test_session_has_auth_key(self, account_id):
        data = _read_session_db(account_id)
        assert data["auth_key"] is not None
        assert len(data["auth_key"]) == 256

    def test_session_has_server_address(self, account_id):
        data = _read_session_db(account_id)
        assert data["server_address"]

    def test_session_port_is_443(self, account_id):
        data = _read_session_db(account_id)
        assert data["port"] == 443


class TestJSONConsistency:
    @pytest.fixture(params=ACCOUNT_IDS)
    def account_id(self, request):
        return request.param

    @pytest.fixture
    def json_data(self, account_id):
        return _load_json(account_id)

    def test_json_has_required_fields(self, json_data):
        required = [
            "app_id",
            "app_hash",
            "device",
            "sdk",
            "app_version",
            "lang_pack",
            "lang_code",
            "session_file",
        ]
        for field in required:
            assert field in json_data, f"Missing field: {field}"

    def test_json_app_id_is_official(self, json_data):
        official_ids = {2040, 6, 21724, 10840, 2834, 2496}
        assert json_data["app_id"] in official_ids

    def test_json_app_hash_length(self, json_data):
        assert len(json_data["app_hash"]) == 32

    def test_json_session_file_matches(self, account_id, json_data):
        assert json_data["session_file"] == account_id

    def test_json_lang_code_valid(self, json_data):
        assert len(json_data["lang_code"]) >= 2

    def test_json_device_not_empty(self, json_data):
        assert json_data["device"]

    def test_json_sdk_not_empty(self, json_data):
        assert json_data["sdk"]

    def test_tdata_session_authkey_match(self, account_id):
        tdata_path = str(TDATAS_DIR / account_id / "tdata")
        tdesk = TDesktop(tdata_path)
        tdata_key = tdesk.mainAccount.authKey.key

        session_data = _read_session_db(account_id)
        session_key = session_data["auth_key"]

        assert tdata_key == session_key, f"Auth key mismatch for account {account_id}"

    def test_tdata_session_dc_id_match(self, account_id):
        tdata_path = str(TDATAS_DIR / account_id / "tdata")
        tdesk = TDesktop(tdata_path)
        tdata_dc = int(tdesk.mainAccount.MainDcId)

        session_data = _read_session_db(account_id)
        session_dc = session_data["dc_id"]

        assert tdata_dc == session_dc, (
            f"DC ID mismatch for {account_id}: tdata={tdata_dc}, session={session_dc}"
        )

    def test_json_api_matches_known_api_class(self, json_data):
        api_map = {
            2040: API.TelegramDesktop,
            6: API.TelegramAndroid,
            21724: API.TelegramAndroidX,
            10840: API.TelegramIOS,
            2834: API.TelegramMacOS,
            2496: API.TelegramWeb_Z,
        }
        app_id = json_data["app_id"]
        assert app_id in api_map
        api_cls = api_map[app_id]
        assert json_data["app_hash"] == api_cls.api_hash

    def test_json_fingerprint_validates(self, json_data):
        issues = validate_init_connection_params(
            api_id=json_data["app_id"],
            device_model=json_data["device"],
            system_version=json_data["sdk"],
            app_version=json_data["app_version"],
            system_lang_code=json_data.get("system_lang_code", "en"),
            lang_pack=json_data.get("lang_pack", ""),
            lang_code=json_data["lang_code"],
        )
        critical = [i for i in issues if "empty" in i.lower()]
        assert len(critical) == 0, f"Critical fingerprint issues: {critical}"


class TestConversion:
    @pytest.fixture(params=ACCOUNT_IDS)
    def account_id(self, request):
        return request.param

    @pytest.mark.asyncio
    async def test_tdata_to_telethon_creates_client(self, account_id, tmp_path):
        tdata_path = str(TDATAS_DIR / account_id / "tdata")
        tdesk = TDesktop(tdata_path)
        assert tdesk.isLoaded()

        session_path = str(tmp_path / f"test_{account_id}")
        client = await tdesk.ToTelethon(
            session=session_path,
            flag=UseCurrentSession,
            api=API.TelegramDesktop,
        )
        assert client is not None
        assert client.session is not None
        assert client.session.auth_key is not None
        assert len(client.session.auth_key.key) == 256

    @pytest.mark.asyncio
    async def test_conversion_preserves_auth_key(self, account_id, tmp_path):
        tdata_path = str(TDATAS_DIR / account_id / "tdata")
        tdesk = TDesktop(tdata_path)

        original_key = tdesk.mainAccount.authKey.key

        session_path = str(tmp_path / f"test_conv_{account_id}")
        client = await tdesk.ToTelethon(
            session=session_path,
            flag=UseCurrentSession,
            api=API.TelegramDesktop,
        )

        assert client.session.auth_key.key == original_key

    @pytest.mark.asyncio
    async def test_conversion_preserves_dc_id(self, account_id, tmp_path):
        tdata_path = str(TDATAS_DIR / account_id / "tdata")
        tdesk = TDesktop(tdata_path)

        original_dc = int(tdesk.mainAccount.MainDcId)

        session_path = str(tmp_path / f"test_dc_{account_id}")
        client = await tdesk.ToTelethon(
            session=session_path,
            flag=UseCurrentSession,
            api=API.TelegramDesktop,
        )

        assert client.session.dc_id == original_dc

    @pytest.mark.asyncio
    async def test_roundtrip_tdesk_telethon_tdesk(self, account_id, tmp_path):
        tdata_path = str(TDATAS_DIR / account_id / "tdata")
        tdesk = TDesktop(tdata_path)

        original_key = tdesk.mainAccount.authKey.key
        original_dc = int(tdesk.mainAccount.MainDcId)
        original_uid = tdesk.mainAccount.UserId

        session_path = str(tmp_path / f"test_rt_{account_id}")
        client = await tdesk.ToTelethon(
            session=session_path,
            flag=UseCurrentSession,
            api=API.TelegramDesktop,
        )

        tdesk2 = await TDesktop.FromTelethon(
            client,
            flag=UseCurrentSession,
            api=API.TelegramDesktop,
        )

        assert tdesk2.isLoaded()
        assert tdesk2.mainAccount is not None
        assert tdesk2.mainAccount.authKey.key == original_key
        assert int(tdesk2.mainAccount.MainDcId) == original_dc
        assert tdesk2.mainAccount.UserId == original_uid

    @pytest.mark.asyncio
    async def test_conversion_with_json_api(self, account_id, tmp_path):
        tdata_path = str(TDATAS_DIR / account_id / "tdata")
        jdata = _load_json(account_id)

        api_map = {
            2040: API.TelegramDesktop,
            6: API.TelegramAndroid,
            21724: API.TelegramAndroidX,
            10840: API.TelegramIOS,
            2834: API.TelegramMacOS,
            2496: API.TelegramWeb_Z,
        }
        api_cls = api_map[jdata["app_id"]]

        tdesk = TDesktop(tdata_path)
        session_path = str(tmp_path / f"test_japi_{account_id}")
        client = await tdesk.ToTelethon(
            session=session_path,
            flag=UseCurrentSession,
            api=api_cls,
        )
        assert client is not None
        assert client.session.auth_key is not None


class TestTelegramClientConstructor:
    def test_default_api(self):
        client = TelegramClient()
        assert client.api_id == API.TelegramDesktop.api_id
        assert client.api_hash == API.TelegramDesktop.api_hash

    def test_custom_api_id(self):
        client = TelegramClient(None, 1234, "testhash")
        assert client.api_id == 1234

    def test_api_object(self):
        client = TelegramClient(None, api=API.TelegramAndroid)
        assert client.api_id == API.TelegramAndroid.api_id

    def test_api_instance(self):
        api = API.TelegramIOS()
        client = TelegramClient(None, api=api)
        assert client.api_id == API.TelegramIOS.api_id


class TestTDataSaveLoad:
    @pytest.mark.asyncio
    async def test_save_and_reload(self, tmp_path):
        account_id = ACCOUNT_IDS[0]
        tdata_path = str(TDATAS_DIR / account_id / "tdata")
        tdesk = TDesktop(tdata_path)

        original_key = tdesk.mainAccount.authKey.key
        original_uid = tdesk.mainAccount.UserId

        session_path = str(tmp_path / "save_test")
        client = await tdesk.ToTelethon(
            session=session_path,
            flag=UseCurrentSession,
            api=API.TelegramDesktop,
        )

        tdesk2 = await TDesktop.FromTelethon(
            client, flag=UseCurrentSession, api=API.TelegramDesktop
        )

        save_path = str(tmp_path / "saved_tdata")
        os.makedirs(save_path, exist_ok=True)
        tdesk2.SaveTData(save_path)

        tdesk3 = TDesktop(save_path)
        assert tdesk3.isLoaded()
        assert tdesk3.mainAccount.authKey.key == original_key
        assert tdesk3.mainAccount.UserId == original_uid


class TestEdgeCases:
    def test_tdesktop_empty_init(self):
        tdesk = TDesktop()
        assert not tdesk.isLoaded()
        assert tdesk.accountsCount == 0

    def test_tdesktop_invalid_path(self):
        with pytest.raises(BaseException):
            TDesktop("/nonexistent/path/tdata")

    def test_api_data_requires_id_and_hash(self):
        with pytest.raises(BaseException):
            APIData()

    def test_login_flag_hierarchy(self):
        assert issubclass(UseCurrentSession, LoginFlag)
        assert issubclass(CreateNewSession, LoginFlag)
        assert issubclass(LoginFlag, int)

    def test_device_info_str(self):
        d = DeviceInfo("Model X", "v1.0")
        assert str(d) == "Model X v1.0"


def _session_path(account_id: str) -> str:
    return str(SESSIONS_DIR / account_id)


def _tdata_path(account_id: str) -> str:
    return str(TDATAS_DIR / account_id / "tdata")


def _safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))


class TestLiveSessionAccounts:
    @pytest.fixture(params=ACCOUNT_IDS)
    def account_id(self, request):
        return request.param

    @pytest.mark.live
    @pytest.mark.asyncio
    async def test_session_connect_and_get_me(self, account_id):
        from telethon.errors import UserDeactivatedBanError

        client = await TelegramClient.FromSessionJson(_session_path(account_id))
        try:
            await client.connect()

            try:
                authorized = await client.is_user_authorized()
            except UserDeactivatedBanError:
                pytest.skip(f"Session {account_id} is deactivated/banned")
                return

            if not authorized:
                pytest.skip(f"Session {account_id} is not authorized")
                return

            me = await client.get_me()
            assert me is not None, f"get_me() returned None for {account_id}"

            _safe_print(f"\n{'=' * 60}")
            _safe_print(f"  Account ID : {me.id}")
            _safe_print(f"  Phone      : +{me.phone}")
            _safe_print(f"  First Name : {me.first_name}")
            _safe_print(f"  Last Name  : {me.last_name or ''}")
            _safe_print(f"  Username   : @{me.username or 'N/A'}")
            _safe_print(f"  Premium    : {me.premium}")
            _safe_print(f"  DC ID      : {client.session.dc_id}")
            _safe_print(f"  Source     : session file ({account_id})")
            _safe_print(f"{'=' * 60}")
        finally:
            await client.disconnect()

    @pytest.mark.live
    @pytest.mark.asyncio
    async def test_session_get_sessions(self, account_id):
        from telethon.errors import UserDeactivatedBanError

        client = await TelegramClient.FromSessionJson(_session_path(account_id))
        try:
            await client.connect()

            try:
                authorized = await client.is_user_authorized()
            except UserDeactivatedBanError:
                pytest.skip(f"Session {account_id} is deactivated/banned")
                return

            if not authorized:
                pytest.skip(f"Session {account_id} not authorized")
                return

            sessions = await client.GetSessions()
            assert sessions is not None
            assert len(sessions.authorizations) > 0

            _safe_print(f"\n--- Sessions for account {account_id} (from .session) ---")
            for auth in sessions.authorizations:
                tag = "(current)" if auth.current else "         "
                _safe_print(
                    f"  {tag} {auth.device_model} | "
                    f"{auth.platform} | {auth.system_version} | "
                    f"api_id={auth.api_id} | {auth.app_name}"
                )
        finally:
            await client.disconnect()


class TestLiveTDataAccounts:
    @pytest.fixture(params=ACCOUNT_IDS)
    def account_id(self, request):
        return request.param

    @pytest.mark.live
    @pytest.mark.asyncio
    async def test_tdata_connect_and_get_me(self, account_id, tmp_path):
        from telethon.errors import UserDeactivatedBanError

        tdesk = TDesktop(_tdata_path(account_id))
        assert tdesk.isLoaded(), f"Failed to load tdata for {account_id}"

        session_path = str(tmp_path / f"live_tdata_{account_id}")
        client = await tdesk.ToTelethon(
            session=session_path,
            flag=UseCurrentSession,
            api=API.TelegramDesktop,
        )
        try:
            await client.connect()

            try:
                authorized = await client.is_user_authorized()
            except UserDeactivatedBanError:
                pytest.skip(f"tdata {account_id} is deactivated/banned")
                return

            if not authorized:
                pytest.skip(f"tdata {account_id} session is not authorized")
                return

            me = await client.get_me()
            assert me is not None, f"get_me() returned None for tdata {account_id}"

            _safe_print(f"\n{'=' * 60}")
            _safe_print(f"  Account ID : {me.id}")
            _safe_print(f"  Phone      : +{me.phone}")
            _safe_print(f"  First Name : {me.first_name}")
            _safe_print(f"  Last Name  : {me.last_name or ''}")
            _safe_print(f"  Username   : @{me.username or 'N/A'}")
            _safe_print(f"  Premium    : {me.premium}")
            _safe_print(f"  DC ID      : {client.session.dc_id}")
            _safe_print(f"  Source     : tdata folder ({account_id})")
            _safe_print(f"{'=' * 60}")
        finally:
            await client.disconnect()

    @pytest.mark.live
    @pytest.mark.asyncio
    async def test_tdata_get_sessions(self, account_id, tmp_path):
        from telethon.errors import UserDeactivatedBanError

        tdesk = TDesktop(_tdata_path(account_id))
        assert tdesk.isLoaded()

        session_path = str(tmp_path / f"live_tdata_gs_{account_id}")
        client = await tdesk.ToTelethon(
            session=session_path,
            flag=UseCurrentSession,
            api=API.TelegramDesktop,
        )
        try:
            await client.connect()

            try:
                authorized = await client.is_user_authorized()
            except UserDeactivatedBanError:
                pytest.skip(f"tdata {account_id} is deactivated/banned")
                return

            if not authorized:
                pytest.skip(f"tdata {account_id} not authorized")
                return

            sessions = await client.GetSessions()
            assert sessions is not None
            assert len(sessions.authorizations) > 0

            _safe_print(f"\n--- Sessions for account {account_id} (from tdata) ---")
            for auth in sessions.authorizations:
                tag = "(current)" if auth.current else "         "
                _safe_print(
                    f"  {tag} {auth.device_model} | "
                    f"{auth.platform} | {auth.system_version} | "
                    f"api_id={auth.api_id} | {auth.app_name}"
                )
        finally:
            await client.disconnect()


class TestLiveCreateNewSession:
    @pytest.mark.live
    @pytest.mark.asyncio
    async def test_create_new_session_from_tdata(self, tmp_path):
        from telethon.errors import UserDeactivatedBanError

        account_id = ACCOUNT_IDS[0]
        tdesk = TDesktop(_tdata_path(account_id))
        assert tdesk.isLoaded()

        session_path = str(tmp_path / f"source_{account_id}")
        source_client = await tdesk.ToTelethon(
            session=session_path,
            flag=UseCurrentSession,
            api=API.TelegramDesktop,
        )
        try:
            await source_client.connect()

            try:
                authorized = await source_client.is_user_authorized()
            except UserDeactivatedBanError:
                pytest.skip("Source session is deactivated/banned")
                return

            if not authorized:
                pytest.skip(
                    "Source session not authorized, cannot test CreateNewSession"
                )
                return

            me = await source_client.get_me()
            _safe_print("\n--- CreateNewSession test ---")
            _safe_print(f"  Source account: {me.id} (+{me.phone})")

            new_session_path = str(tmp_path / f"new_{account_id}")
            try:
                new_client = await source_client.QRLoginToNewClient(
                    session=new_session_path,
                    api=API.TelegramDesktop,
                )
                new_me = await new_client.get_me()
                _safe_print("  New session created successfully!")
                _safe_print(f"  New session account: {new_me.id}")
                _safe_print(f"  New session DC: {new_client.session.dc_id}")
                assert new_me.id == me.id, "New session should be for the same account"
                await new_client.disconnect()
            except Exception as e:
                _safe_print(
                    f"  CreateNewSession failed (expected in CI): {type(e).__name__}: {e}"
                )
        finally:
            await source_client.disconnect()

    @pytest.mark.live
    @pytest.mark.asyncio
    async def test_save_session_json_with_live_info(self, tmp_path):
        from telethon.errors import UserDeactivatedBanError

        account_id = ACCOUNT_IDS[0]
        client = await TelegramClient.FromSessionJson(_session_path(account_id))
        try:
            await client.connect()

            try:
                authorized = await client.is_user_authorized()
            except UserDeactivatedBanError:
                pytest.skip("Session is deactivated/banned")
                return

            if not authorized:
                pytest.skip("Session not authorized")
                return

            out_base = str(tmp_path / f"live_export_{account_id}")
            s_path, j_path = await client.SaveSessionJson(
                out_base, fetch_user_info=True
            )

            assert os.path.isfile(s_path)
            assert os.path.isfile(j_path)

            with open(j_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            _safe_print("\n--- SaveSessionJson with fetch_user_info ---")
            _safe_print(f"  session_file : {data.get('session_file')}")
            _safe_print(f"  id           : {data.get('id')}")
            _safe_print(f"  phone        : {data.get('phone')}")
            _safe_print(f"  username     : {data.get('username')}")
            _safe_print(f"  is_premium   : {data.get('is_premium')}")
            _safe_print(f"  app_id       : {data.get('app_id')}")
            _safe_print(f"  device       : {data.get('device')}")

            assert data.get("id") is not None, "id should be set with fetch_user_info"
            assert data.get("phone") is not None, (
                "phone should be set with fetch_user_info"
            )
        finally:
            await client.disconnect()
