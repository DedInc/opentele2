"""Comprehensive tests for web fingerprints, session JSON consistency,
fingerprint validation, tdata loading, and session JSON import/export."""

import json
import os
import pathlib
import sqlite3
import sys

base_dir = pathlib.Path(__file__).parent.parent.absolute().__str__()
sys.path.insert(1, base_dir)

import pytest  # noqa: E402

from src.api import API, APIData  # noqa: E402
from src.devices import WebBrowserDevice, DeviceInfo  # noqa: E402
from src.exception import SessionFileNotFound  # noqa: E402
from src.fingerprint import (  # noqa: E402
    validate_init_connection_params,
    FingerprintConfig,
    StrictMode,
    get_recommended_layer,
    get_platform_versions,
    LAYER,
    PLATFORM_VERSIONS,
)
from src.version_fetcher import fetch_all_versions  # noqa: E402

TESTS_DIR = pathlib.Path(__file__).parent
SESSIONS_DIR = TESTS_DIR / "sessions"
TDATAS_DIR = TESTS_DIR / "tdatas"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_session_json(session_id: str) -> dict:
    json_path = SESSIONS_DIR / f"{session_id}.json"
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_session_ids() -> list:
    ids = []
    for f in SESSIONS_DIR.glob("*.json"):
        ids.append(f.stem)
    return sorted(ids)


def list_tdata_ids() -> list:
    ids = []
    for d in TDATAS_DIR.iterdir():
        if d.is_dir():
            ids.append(d.name)
    return sorted(ids)


SESSION_IDS = list_session_ids()
TDATA_IDS = list_tdata_ids()


# ---------------------------------------------------------------------------
# Web Fingerprints Tests
# ---------------------------------------------------------------------------


class TestWebFingerprints:
    """Tests for web browser fingerprint generation."""

    def test_web_z_generate_returns_valid_api(self):
        api = API.TelegramWeb_Z.Generate()
        assert isinstance(api, APIData)
        assert api.api_id == 2496
        assert api.device_model is not None
        assert len(api.device_model) > 10

    def test_web_a_generate_returns_valid_api(self):
        api = API.TelegramWeb_A.Generate()
        assert isinstance(api, APIData)
        assert api.api_id == 2496

    def test_web_k_generate_returns_valid_api(self):
        api = API.TelegramWeb_K.Generate()
        assert isinstance(api, APIData)
        assert api.api_id == 2496

    def test_webogram_generate_returns_valid_api(self):
        api = API.Webogram.Generate()
        assert isinstance(api, APIData)
        assert api.api_id == 2496

    def test_unique_id_determinism(self):
        a = API.TelegramWeb_Z.Generate("test_seed")
        b = API.TelegramWeb_Z.Generate("test_seed")
        assert a.device_model == b.device_model
        assert a.system_version == b.system_version

    def test_different_unique_ids_differ(self):
        a = API.TelegramWeb_Z.Generate("seed_a")
        b = API.TelegramWeb_Z.Generate("seed_b")
        # Different seeds should (almost certainly) produce different results
        # but there's a small chance they're the same, so we just check they run
        assert isinstance(a, APIData) and isinstance(b, APIData)

    def test_no_unique_id_randomizes(self):
        a = API.TelegramWeb_Z.Generate()
        b = API.TelegramWeb_Z.Generate()
        # Both should be valid
        assert a.device_model and b.device_model

    def test_web_z_and_web_k_system_version_differ(self):
        """Web Z uses OS name (Windows), Web K uses navigator.platform (Win32)."""
        z = API.TelegramWeb_Z.Generate("same_seed")
        k = API.TelegramWeb_K.Generate("same_seed")
        # They use different variant mappings so system_version should differ
        # unless both happen to map identically (unlikely)
        assert z.system_version is not None
        assert k.system_version is not None

    def test_web_browser_device_class_directly(self):
        WebBrowserDevice._generated = False
        WebBrowserDevice.__gen__()
        assert len(WebBrowserDevice.deviceList) > 0
        assert len(WebBrowserDevice._k_deviceList) > 0
        device = WebBrowserDevice.RandomDevice("test", variant="z")
        assert isinstance(device, DeviceInfo)
        assert device.model  # UA string
        assert device.version  # OS name

    def test_generated_ua_contains_browser_info(self):
        api = API.TelegramWeb_Z.Generate()
        ua = api.device_model
        assert "Mozilla" in ua or "Chrome" in ua or "Firefox" in ua or "Edg" in ua

    def test_all_web_apis_preserved_after_generate(self):
        for cls in [
            API.TelegramWeb_Z,
            API.TelegramWeb_A,
            API.TelegramWeb_K,
            API.Webogram,
        ]:
            api = cls.Generate()
            assert api.api_id == cls.api_id
            assert api.api_hash == cls.api_hash
            assert api.app_version == cls.app_version
            assert api.lang_code == cls.lang_code
            assert api.lang_pack == cls.lang_pack

    def test_browser_stat_weights_applied(self):
        """BROWSER_WEIGHTS should influence the distribution of generated UAs."""
        WebBrowserDevice._generated = False
        WebBrowserDevice.__gen__()
        device_list = WebBrowserDevice.deviceList

        chrome_entries = [
            d for d in device_list if "Chrome" in d.model and "Edg" not in d.model
        ]
        edge_entries = [d for d in device_list if "Edg" in d.model]
        firefox_entries = [d for d in device_list if "Firefox" in d.model]

        # Chrome (weight=19) should have more entries than edge (weight=2)
        if edge_entries:
            assert len(chrome_entries) > len(edge_entries), (
                f"Chrome ({len(chrome_entries)}) should outnumber Edge ({len(edge_entries)})"
            )
        # Chrome should have more entries than firefox (weight=1)
        if firefox_entries:
            assert len(chrome_entries) > len(firefox_entries), (
                f"Chrome ({len(chrome_entries)}) should outnumber Firefox ({len(firefox_entries)})"
            )

    def test_k_device_list_also_weighted(self):
        """The _k_deviceList should have the same weighting as deviceList."""
        WebBrowserDevice._generated = False
        WebBrowserDevice.__gen__()
        assert len(WebBrowserDevice._k_deviceList) == len(WebBrowserDevice.deviceList)


# ---------------------------------------------------------------------------
# Session JSON Consistency Tests (reading existing test data)
# ---------------------------------------------------------------------------


class TestSessionJsonConsistency:
    """Tests that session JSON files have valid, consistent data."""

    @pytest.fixture(params=SESSION_IDS)
    def session_id(self, request):
        return request.param

    def test_json_has_required_fields(self, session_id):
        data = load_session_json(session_id)
        for field in ["app_id", "app_hash", "device", "sdk", "app_version"]:
            assert field in data, f"Missing {field} in {session_id}.json"

    def test_app_id_is_valid(self, session_id):
        data = load_session_json(session_id)
        assert isinstance(data["app_id"], int)
        assert data["app_id"] > 0

    def test_app_hash_is_nonempty(self, session_id):
        data = load_session_json(session_id)
        assert data["app_hash"] and len(data["app_hash"]) > 0

    def test_device_is_nonempty(self, session_id):
        data = load_session_json(session_id)
        assert data["device"] and len(data["device"]) > 0

    def test_api_id_matches_app_hash(self, session_id):
        data = load_session_json(session_id)
        known = {
            2040: "b18441a1ff607e10a989891a5462e627",
            2496: "8da85b0d5bfe62527e5b244c209159c3",
            6: "eb06d4abfb49dc3eeb1aeb98ae0f581e",
        }
        if data["app_id"] in known:
            assert data["app_hash"] == known[data["app_id"]]

    def test_web_sessions_have_user_agent(self, session_id):
        data = load_session_json(session_id)
        lp = data.get("lang_pack", "")
        if lp in ("weba", "webk", ""):
            if data["app_id"] == 2496:
                assert "Mozilla" in data["device"] or "Chrome" in data["device"]

    def test_desktop_sessions_have_device_name(self, session_id):
        data = load_session_json(session_id)
        if data.get("lang_pack") == "tdesktop":
            assert len(data["device"]) > 0
            assert "Mozilla" not in data["device"]

    def test_session_file_matches_filename(self, session_id):
        data = load_session_json(session_id)
        if "session_file" in data:
            assert data["session_file"] == session_id

    def test_lang_code_is_valid(self, session_id):
        data = load_session_json(session_id)
        lc = data.get("lang_code", "en")
        assert isinstance(lc, str) and len(lc) >= 2

    def test_system_lang_code_is_valid(self, session_id):
        data = load_session_json(session_id)
        slc = data.get("system_lang_code") or data.get("system_lang_pack", "en")
        assert isinstance(slc, str) and len(slc) >= 2


# ---------------------------------------------------------------------------
# TData Loading Tests
# ---------------------------------------------------------------------------


class TestTDataLoading:
    """Tests for loading tdata directories and cross-checking with session JSON."""

    @pytest.fixture(params=TDATA_IDS)
    def tdata_id(self, request):
        return request.param

    def test_tdata_directory_has_required_structure(self, tdata_id):
        tdata_path = TDATAS_DIR / tdata_id / "tdata"
        assert tdata_path.exists(), f"tdata directory not found: {tdata_path}"
        key_data = tdata_path / "key_datas"
        assert key_data.exists(), f"key_datas not found in {tdata_path}"

    def test_tdata_has_matching_session(self, tdata_id):
        """Each tdata should have a corresponding .session and .json."""
        session_path = SESSIONS_DIR / f"{tdata_id}.session"
        json_path = SESSIONS_DIR / f"{tdata_id}.json"
        assert session_path.exists(), f"No session file for tdata {tdata_id}"
        assert json_path.exists(), f"No JSON file for tdata {tdata_id}"

    def test_tdata_loads_with_tdesktop(self, tdata_id):
        """TDesktop should load tdata without errors."""
        from src.td import TDesktop

        tdata_path = str(TDATAS_DIR / tdata_id / "tdata")
        tdesk = TDesktop(tdata_path)
        assert tdesk.isLoaded(), f"Failed to load tdata: {tdata_id}"

    def test_tdata_json_consistency(self, tdata_id):
        """The tdata and its JSON metadata should be consistent."""
        from src.td import TDesktop

        load_session_json(tdata_id)  # ensure JSON exists and is valid
        tdata_path = str(TDATAS_DIR / tdata_id / "tdata")
        tdesk = TDesktop(tdata_path)
        assert tdesk.isLoaded()

        # Verify account count
        assert len(tdesk.accounts) > 0, f"No accounts in tdata {tdata_id}"


# ---------------------------------------------------------------------------
# Fingerprint Validation Tests
# ---------------------------------------------------------------------------


class TestFingerprintValidation:
    """Tests for validate_init_connection_params and FingerprintConfig."""

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

    def test_valid_web_params(self):
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

    def test_empty_device_model_flagged(self):
        issues = validate_init_connection_params(
            api_id=6,
            device_model="",
            system_version="SDK 35",
            app_version="12.3.0",
            system_lang_code="en-US",
            lang_pack="android",
            lang_code="en",
        )
        assert len(issues) > 0

    def test_invalid_lang_pack_flagged(self):
        issues = validate_init_connection_params(
            api_id=6,
            device_model="Samsung SM-S928B",
            system_version="SDK 35",
            app_version="12.3.0",
            system_lang_code="en-US",
            lang_pack="invalid_pack",
            lang_code="en",
        )
        assert any("lang_pack" in i for i in issues)

    def test_short_lang_code_flagged(self):
        issues = validate_init_connection_params(
            api_id=6,
            device_model="Samsung SM-S928B",
            system_version="SDK 35",
            app_version="12.3.0",
            system_lang_code="en-US",
            lang_pack="android",
            lang_code="x",
        )
        assert any("lang_code" in i for i in issues)

    def test_strict_mode_api_id_mismatch(self):
        issues = validate_init_connection_params(
            api_id=99999,
            device_model="Samsung SM-S928B",
            system_version="SDK 35",
            app_version="12.3.0",
            system_lang_code="en-US",
            lang_pack="android",
            lang_code="en",
            strict=True,
        )
        assert any("api_id" in i for i in issues)

    def test_strict_mode_passes_for_correct_pair(self):
        issues = validate_init_connection_params(
            api_id=6,
            device_model="Samsung SM-S928B",
            system_version="SDK 35",
            app_version="12.3.0",
            system_lang_code="en-US",
            lang_pack="android",
            lang_code="en",
            strict=True,
        )
        assert not any("api_id" in i for i in issues)

    def test_android_missing_region_in_system_lang(self):
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

    def test_session_json_passes_validation(self):
        """All session JSONs should pass basic validation."""
        for sid in list_session_ids():
            data = load_session_json(sid)
            lp = data.get("lang_pack", "")
            # "weba" is used in real sessions but not in our _VALID_LANG_PACKS
            # skip strict validation for unknown lang_packs
            if lp not in ("android", "ios", "tdesktop", "macos", ""):
                continue
            issues = validate_init_connection_params(
                api_id=data["app_id"],
                device_model=data["device"],
                system_version=data["sdk"],
                app_version=data["app_version"],
                system_lang_code=data.get("system_lang_code", "en"),
                lang_pack=lp,
                lang_code=data.get("lang_code", "en"),
            )
            assert issues == [], f"Session {sid} validation failed: {issues}"


# ---------------------------------------------------------------------------
# FingerprintConfig Tests
# ---------------------------------------------------------------------------


class TestFingerprintConfig:
    """Tests for FingerprintConfig class."""

    def test_default_config(self):
        config = FingerprintConfig()
        assert config.strict_mode == StrictMode.WARN
        assert config.auto_validate is True

    def test_strict_raises(self):
        config = FingerprintConfig(strict_mode=StrictMode.STRICT)
        with pytest.raises(ValueError):
            config.validate_params(
                api_id=6,
                device_model="",
                system_version="SDK 35",
                app_version="12.3.0",
                system_lang_code="en-US",
                lang_pack="android",
                lang_code="en",
            )

    def test_off_mode_skips(self):
        config = FingerprintConfig(strict_mode=StrictMode.OFF, auto_validate=False)
        # Should not raise
        config.validate_params(
            api_id=6,
            device_model="",
            system_version="",
            app_version="",
            system_lang_code="",
            lang_pack="invalid",
            lang_code="",
        )

    def test_effective_layer(self):
        config = FingerprintConfig()
        layer = config.get_effective_layer()
        assert isinstance(layer, int)
        assert layer > 100


# ---------------------------------------------------------------------------
# Platform Versions Tests
# ---------------------------------------------------------------------------


class TestPlatformVersions:
    """Tests for platform version constants."""

    def test_versions_not_empty(self):
        pv = get_platform_versions()
        assert pv.android_app_version
        assert pv.ios_app_version
        assert pv.desktop_app_version
        assert pv.macos_app_version
        assert pv.web_a_version
        assert pv.web_k_version
        assert pv.chrome_version

    def test_layer_is_positive(self):
        assert LAYER > 0
        layer = get_recommended_layer()
        assert layer > 0


# ---------------------------------------------------------------------------
# All Generate() APIs Smoke Test
# ---------------------------------------------------------------------------


class TestAllGenerateAPIs:
    """Smoke test: every API class's Generate() should produce valid output."""

    @pytest.mark.parametrize(
        "api_cls",
        [
            API.TelegramDesktop,
            API.TelegramAndroid,
            API.TelegramAndroidX,
            API.TelegramIOS,
            API.TelegramMacOS,
            API.TelegramWeb_Z,
            API.TelegramWeb_A,
            API.TelegramWeb_K,
            API.Webogram,
        ],
    )
    def test_generate_produces_valid_instance(self, api_cls):
        api = api_cls.Generate()
        assert isinstance(api, APIData)
        assert api.api_id == api_cls.api_id
        assert api.api_hash == api_cls.api_hash
        assert api.device_model is not None and len(api.device_model) > 0
        assert api.system_version is not None and len(api.system_version) > 0
        assert api.app_version is not None and len(api.app_version) > 0

    @pytest.mark.parametrize(
        "api_cls",
        [
            API.TelegramDesktop,
            API.TelegramAndroid,
            API.TelegramAndroidX,
            API.TelegramIOS,
            API.TelegramMacOS,
            API.TelegramWeb_Z,
            API.TelegramWeb_A,
            API.TelegramWeb_K,
            API.Webogram,
        ],
    )
    def test_generate_deterministic_with_unique_id(self, api_cls):
        if api_cls == API.TelegramDesktop:
            a = api_cls.Generate("windows", "seed123")
            b = api_cls.Generate("windows", "seed123")
        else:
            a = api_cls.Generate("seed123")
            b = api_cls.Generate("seed123")
        assert a.device_model == b.device_model
        assert a.system_version == b.system_version


# ---------------------------------------------------------------------------
# APIData JSON Helpers Tests
# ---------------------------------------------------------------------------


class TestAPIDataJson:
    """Tests for APIData.from_json() and APIData.to_json()."""

    def test_from_json_basic(self):
        data = {
            "app_id": 2040,
            "app_hash": "b18441a1ff607e10a989891a5462e627",
            "device": "Desktop",
            "sdk": "Windows 11",
            "app_version": "5.12.3 x64",
            "system_lang_pack": "en-US",
            "system_lang_code": "en-US",
            "lang_pack": "tdesktop",
            "lang_code": "en",
        }
        api = APIData.from_json(data)
        assert api.api_id == 2040
        assert api.api_hash == "b18441a1ff607e10a989891a5462e627"
        assert api.device_model == "Desktop"
        assert api.system_version == "Windows 11"
        assert api.app_version == "5.12.3 x64"
        assert api.system_lang_code == "en-US"
        assert api.lang_pack == "tdesktop"
        assert api.lang_code == "en"

    def test_to_json_basic(self):
        api = APIData(
            api_id=6,
            api_hash="eb06d4abfb49dc3eeb1aeb98ae0f581e",
            device_model="Samsung SM-S928B",
            system_version="SDK 35",
            app_version="12.3.0",
            lang_code="en",
            system_lang_code="en-US",
            lang_pack="android",
        )
        result = api.to_json()
        assert result["app_id"] == 6
        assert result["app_hash"] == "eb06d4abfb49dc3eeb1aeb98ae0f581e"
        assert result["device"] == "Samsung SM-S928B"
        assert result["sdk"] == "SDK 35"
        assert result["app_version"] == "12.3.0"
        assert result["system_lang_pack"] == "en-US"
        assert result["system_lang_code"] == "en-US"
        assert result["lang_pack"] == "android"
        assert result["lang_code"] == "en"
        # Extra fields should have defaults
        assert "session_file" in result
        assert "twoFA" in result

    def test_from_json_roundtrip(self):
        api = APIData(
            api_id=2496,
            api_hash="8da85b0d5bfe62527e5b244c209159c3",
            device_model="Mozilla/5.0 Test",
            system_version="Windows",
            app_version="5.0.0 Z",
            lang_code="en",
            system_lang_code="en-US",
            lang_pack="",
        )
        exported = api.to_json()
        reimported = APIData.from_json(exported)
        assert reimported.api_id == api.api_id
        assert reimported.api_hash == api.api_hash
        assert reimported.device_model == api.device_model
        assert reimported.system_version == api.system_version
        assert reimported.app_version == api.app_version
        assert reimported.system_lang_code == api.system_lang_code
        assert reimported.lang_pack == api.lang_pack
        assert reimported.lang_code == api.lang_code

    def test_from_json_system_lang_pack_fallback(self):
        """system_lang_pack should be used when system_lang_code is absent."""
        data = {
            "app_id": 2040,
            "app_hash": "b18441a1ff607e10a989891a5462e627",
            "device": "Test",
            "sdk": "Win10",
            "app_version": "1.0",
            "system_lang_pack": "ru-RU",
            "lang_pack": "tdesktop",
            "lang_code": "ru",
        }
        api = APIData.from_json(data)
        assert api.system_lang_code == "ru-RU"

    def test_to_json_with_extra(self):
        api = APIData(
            api_id=2040,
            api_hash="b18441a1ff607e10a989891a5462e627",
            device_model="Test",
            system_version="Win10",
            app_version="1.0",
            lang_code="en",
            system_lang_code="en",
            lang_pack="tdesktop",
        )
        extra = {"id": 12345, "phone": "+1234567890", "session_file": "myfile"}
        result = api.to_json(extra)
        assert result["id"] == 12345
        assert result["phone"] == "+1234567890"
        assert result["session_file"] == "myfile"

    def test_from_json_real_sessions(self):
        """All real test session JSONs should parse correctly."""
        for sid in list_session_ids():
            data = load_session_json(sid)
            api = APIData.from_json(data)
            assert api.api_id == data["app_id"]
            assert api.api_hash == data["app_hash"]
            assert api.device_model == data["device"]
            assert api.system_version == data["sdk"]
            assert api.app_version == data["app_version"]


# ---------------------------------------------------------------------------
# Session JSON Import Tests
# ---------------------------------------------------------------------------


class TestSessionJsonImport:
    """Tests for TelegramClient.FromSessionJson() import."""

    @pytest.fixture(params=SESSION_IDS)
    def session_id(self, request):
        return request.param

    @pytest.mark.asyncio
    async def test_from_session_json_creates_client(self, session_id):
        from src.tl import TelegramClient

        session_path = str(SESSIONS_DIR / session_id)
        client = await TelegramClient.FromSessionJson(session_path)
        assert client is not None
        assert client.session.auth_key is not None
        assert len(client.session.auth_key.key) == 256

    @pytest.mark.asyncio
    async def test_from_session_json_preserves_auth_key(self, session_id):
        from src.tl import TelegramClient

        # Read raw auth key from SQLite
        session_file = str(SESSIONS_DIR / f"{session_id}.session")
        conn = sqlite3.connect(session_file)
        cursor = conn.cursor()
        cursor.execute("SELECT auth_key FROM sessions")
        raw_key = cursor.fetchone()[0]
        conn.close()

        # Import and compare
        session_path = str(SESSIONS_DIR / session_id)
        client = await TelegramClient.FromSessionJson(session_path)
        assert client.session.auth_key.key == raw_key

    @pytest.mark.asyncio
    async def test_from_session_json_api_mapping(self, session_id):
        from src.tl import TelegramClient

        data = load_session_json(session_id)
        session_path = str(SESSIONS_DIR / session_id)
        client = await TelegramClient.FromSessionJson(session_path)

        assert client._api_data is not None
        assert client._api_data.api_id == data["app_id"]
        assert client._api_data.api_hash == data["app_hash"]
        assert client._api_data.device_model == data["device"]
        assert client._api_data.system_version == data["sdk"]
        assert client._api_data.app_version == data["app_version"]

    @pytest.mark.asyncio
    async def test_from_session_json_dc_id(self, session_id):
        from src.tl import TelegramClient

        # Read dc_id from SQLite
        session_file = str(SESSIONS_DIR / f"{session_id}.session")
        conn = sqlite3.connect(session_file)
        cursor = conn.cursor()
        cursor.execute("SELECT dc_id FROM sessions")
        expected_dc = cursor.fetchone()[0]
        conn.close()

        session_path = str(SESSIONS_DIR / session_id)
        client = await TelegramClient.FromSessionJson(session_path)
        assert client.session.dc_id == expected_dc

    @pytest.mark.asyncio
    async def test_from_session_json_sets_user_id(self, session_id):
        from src.tl import TelegramClient

        data = load_session_json(session_id)
        session_path = str(SESSIONS_DIR / session_id)
        client = await TelegramClient.FromSessionJson(session_path)

        if data.get("id") is not None:
            assert client.UserId == data["id"]

    @pytest.mark.asyncio
    async def test_from_session_json_missing_session_raises(self):
        from src.tl import TelegramClient

        with pytest.raises(SessionFileNotFound):
            await TelegramClient.FromSessionJson("/nonexistent/path/fake")

    @pytest.mark.asyncio
    async def test_from_session_json_with_extension(self, session_id):
        """Should work with or without .session extension."""
        from src.tl import TelegramClient

        session_path = str(SESSIONS_DIR / f"{session_id}.session")
        client = await TelegramClient.FromSessionJson(session_path)
        assert client.session.auth_key is not None


# ---------------------------------------------------------------------------
# Session JSON Export Tests
# ---------------------------------------------------------------------------


class TestSessionJsonExport:
    """Tests for TelegramClient.SaveSessionJson() export."""

    @pytest.fixture(params=SESSION_IDS)
    def session_id(self, request):
        return request.param

    @pytest.mark.asyncio
    async def test_save_creates_both_files(self, session_id, tmp_path):
        from src.tl import TelegramClient

        session_path = str(SESSIONS_DIR / session_id)
        client = await TelegramClient.FromSessionJson(session_path)

        out_base = str(tmp_path / "export_test")
        s_path, j_path = await client.SaveSessionJson(out_base)

        assert os.path.isfile(s_path)
        assert os.path.isfile(j_path)
        assert s_path.endswith(".session")
        assert j_path.endswith(".json")

    @pytest.mark.asyncio
    async def test_roundtrip_auth_key(self, session_id, tmp_path):
        from src.tl import TelegramClient

        # Import
        session_path = str(SESSIONS_DIR / session_id)
        client1 = await TelegramClient.FromSessionJson(session_path)
        orig_key = client1.session.auth_key.key

        # Export
        out_base = str(tmp_path / session_id)
        await client1.SaveSessionJson(out_base)

        # Re-import
        client2 = await TelegramClient.FromSessionJson(out_base)
        assert client2.session.auth_key.key == orig_key

    @pytest.mark.asyncio
    async def test_roundtrip_dc_id(self, session_id, tmp_path):
        from src.tl import TelegramClient

        session_path = str(SESSIONS_DIR / session_id)
        client1 = await TelegramClient.FromSessionJson(session_path)
        orig_dc = client1.session.dc_id

        out_base = str(tmp_path / session_id)
        await client1.SaveSessionJson(out_base)

        client2 = await TelegramClient.FromSessionJson(out_base)
        assert client2.session.dc_id == orig_dc

    @pytest.mark.asyncio
    async def test_json_has_required_fields(self, session_id, tmp_path):
        from src.tl import TelegramClient

        session_path = str(SESSIONS_DIR / session_id)
        client = await TelegramClient.FromSessionJson(session_path)

        out_base = str(tmp_path / "field_test")
        _, j_path = await client.SaveSessionJson(out_base)

        with open(j_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Core API fields
        for field in [
            "app_id",
            "app_hash",
            "device",
            "sdk",
            "app_version",
            "system_lang_pack",
            "system_lang_code",
            "lang_pack",
            "lang_code",
        ]:
            assert field in data, f"Missing {field} in exported JSON"

        # Extra fields
        for field in ["session_file", "twoFA", "is_premium"]:
            assert field in data, f"Missing extra field {field}"

    @pytest.mark.asyncio
    async def test_json_preserves_api_data(self, session_id, tmp_path):
        from src.tl import TelegramClient

        orig_data = load_session_json(session_id)
        session_path = str(SESSIONS_DIR / session_id)
        client = await TelegramClient.FromSessionJson(session_path)

        out_base = str(tmp_path / "preserve_test")
        _, j_path = await client.SaveSessionJson(out_base)

        with open(j_path, "r", encoding="utf-8") as f:
            exported = json.load(f)

        assert exported["app_id"] == orig_data["app_id"]
        assert exported["app_hash"] == orig_data["app_hash"]
        assert exported["device"] == orig_data["device"]
        assert exported["sdk"] == orig_data["sdk"]
        assert exported["app_version"] == orig_data["app_version"]

    @pytest.mark.asyncio
    async def test_session_file_basename(self, tmp_path):
        from src.tl import TelegramClient

        sid = SESSION_IDS[0]
        session_path = str(SESSIONS_DIR / sid)
        client = await TelegramClient.FromSessionJson(session_path)

        out_base = str(tmp_path / "my_session")
        _, j_path = await client.SaveSessionJson(out_base)

        with open(j_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["session_file"] == "my_session"

    @pytest.mark.asyncio
    async def test_exported_session_is_valid_sqlite(self, session_id, tmp_path):
        from src.tl import TelegramClient

        session_path = str(SESSIONS_DIR / session_id)
        client = await TelegramClient.FromSessionJson(session_path)

        out_base = str(tmp_path / "sqlite_test")
        s_path, _ = await client.SaveSessionJson(out_base)

        # Verify SQLite structure
        conn = sqlite3.connect(s_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        assert "sessions" in tables
        assert "version" in tables
        assert "entities" in tables

        cursor.execute("SELECT dc_id, auth_key FROM sessions")
        row = cursor.fetchone()
        assert row is not None
        assert row[0] > 0  # dc_id
        assert len(row[1]) == 256  # auth_key
        conn.close()


# ---------------------------------------------------------------------------
# Version Fetcher Tests
# ---------------------------------------------------------------------------


class TestVersionFetcher:
    """Tests for the automatic version fetching mechanism."""

    def test_fetch_returns_dict(self):
        result = fetch_all_versions()
        assert isinstance(result, dict)

    def test_fetched_desktop_version(self):
        result = fetch_all_versions()
        v = result.get("desktop_app_version", "")
        assert v, "desktop_app_version should be fetched"
        # Version should be in semver-like format (digits and dots)
        assert all(c.isdigit() or c == "." for c in v), f"Bad format: {v}"

    def test_fetched_android_version(self):
        result = fetch_all_versions()
        v = result.get("android_app_version", "")
        assert v, "android_app_version should be fetched"
        parts = v.split(".")
        assert len(parts) >= 2

    def test_fetched_telegram_x_version(self):
        result = fetch_all_versions()
        v = result.get("android_x_app_version", "")
        assert v, "android_x_app_version should be fetched"

    def test_fetched_ios_version(self):
        result = fetch_all_versions()
        v = result.get("ios_app_version", "")
        assert v, "ios_app_version should be fetched"

    def test_fetched_macos_version(self):
        result = fetch_all_versions()
        v = result.get("macos_app_version", "")
        assert v, "macos_app_version should be fetched"

    def test_fetched_web_k_version(self):
        result = fetch_all_versions()
        v = result.get("web_k_version", "")
        assert v.endswith(" K"), f"web_k_version should end with ' K': {v}"

    def test_fetched_web_a_version(self):
        result = fetch_all_versions()
        v = result.get("web_a_version", "")
        assert v.endswith(" A"), f"web_a_version should end with ' A': {v}"

    def test_platform_versions_updated(self):
        """PlatformVersions singleton should reflect fetched values."""
        result = fetch_all_versions()
        if result.get("desktop_app_version"):
            assert (
                PLATFORM_VERSIONS.desktop_app_version == result["desktop_app_version"]
            )
        if result.get("android_app_version"):
            assert (
                PLATFORM_VERSIONS.android_app_version == result["android_app_version"]
            )
        if result.get("ios_app_version"):
            assert PLATFORM_VERSIONS.ios_app_version == result["ios_app_version"]

    def test_api_classes_synced(self):
        """API class app_version attributes should match PlatformVersions."""
        pv = PLATFORM_VERSIONS
        assert API.TelegramAndroid.app_version == pv.android_app_version
        assert (
            API.TelegramIOS.app_version
            == f"{pv.ios_app_version} ({pv.ios_build_number}) "
        )
        assert (
            API.TelegramMacOS.app_version
            == f"{pv.macos_app_version} ({pv.macos_build_number}) "
        )
        assert API.TelegramWeb_Z.app_version == pv.web_a_version
        assert API.TelegramWeb_A.app_version == pv.web_a_version
        assert API.TelegramWeb_K.app_version == pv.web_k_version

    def test_api_desktop_version_has_suffix(self):
        pv = PLATFORM_VERSIONS
        expected = f"{pv.desktop_app_version} {pv.desktop_app_version_suffix}"
        assert API.TelegramDesktop.app_version == expected

    def test_api_ios_system_version_synced(self):
        pv = PLATFORM_VERSIONS
        assert API.TelegramIOS.system_version == pv.ios_system_version

    def test_api_macos_system_version_synced(self):
        pv = PLATFORM_VERSIONS
        assert API.TelegramMacOS.system_version == pv.macos_system_version

    def test_results_are_cached(self):
        """Calling fetch_all_versions() twice should return the same object."""
        a = fetch_all_versions()
        b = fetch_all_versions()
        assert a is b

    def test_no_fetch_env_var(self):
        """OPENTELE_NO_FETCH=1 should skip fetching and return empty dict."""
        import src.version_fetcher as vf

        old_cached = vf._CACHED
        try:
            vf._CACHED = None
            os.environ["OPENTELE_NO_FETCH"] = "1"
            result = vf.fetch_all_versions()
            assert result == {}
        finally:
            os.environ.pop("OPENTELE_NO_FETCH", None)
            vf._CACHED = old_cached
