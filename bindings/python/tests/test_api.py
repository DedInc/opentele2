"""Tests of opentele2.api, ported from the 1.5.0 tests test_api_typing.py,
test_desktop_version.py and the API parts of test_fingerprints.py, plus
every case of crates/opentele2-core/tests/vectors/devices.json through
``API.<client>.Generate``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from opentele2 import _native, api
from opentele2.api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from opentele2.exception import NoInstanceMatched

if TYPE_CHECKING:
    # Builtin generics are 3.9+ at runtime; annotations are deferred, so
    # these aliases are only ever evaluated by the type checker.
    ApiClass = type[APIData]
    Fields = tuple[object, ...]

VECTORS = Path(__file__).resolve().parents[3] / "crates" / "opentele2-core" / "tests" / "vectors"
Desktop = API.TelegramDesktop
IDS = [f"typing-id-{n}" for n in range(25)] + ["opentele", "seed123", ""]
ALL_APIS = [
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
WEB_APIS = [API.TelegramWeb_Z, API.TelegramWeb_A, API.TelegramWeb_K, API.Webogram]
WEB_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
)
# The class values of 1.5.0 src/api.py after _sync_api_versions applied the
# offline PlatformVersions: api_id, api_hash, device_model, system_version,
# app_version, lang_code, system_lang_code, lang_pack.
CLASS_VALUES_1_5_0: dict[ApiClass, tuple[int, str, str, str, str, str]] = {
    API.TelegramDesktop: (
        2040,
        "b18441a1ff607e10a989891a5462e627",
        "Desktop",
        "Windows 11 x64",
        "7.3.1 x64",
        "tdesktop",
    ),
    API.TelegramAndroid: (
        6,
        "eb06d4abfb49dc3eeb1aeb98ae0f581e",
        "samsungSM-S938B",
        "SDK 36",
        "13.0.3 (7183)",
        "android",
    ),
    API.TelegramAndroidX: (
        21724,
        "3e0cb5efcd52300aec5994fdfc5bdc16",
        "samsungSM-S938B",
        "SDK 36",
        "0.29.1.1817",
        "android",
    ),
    API.TelegramIOS: (
        10840,
        "33c45224029d59cb3ad0c16134215aeb",
        "iPhone 17 Pro",
        "27.0.1",
        "13.0 (35303) ",
        "ios",
    ),
    API.TelegramMacOS: (
        2834,
        "68875f756c9b437a8b916ca3de215815",
        "MacBook Air M4",
        "27.0.1",
        "13.0 (283305) ",
        "macos",
    ),
    API.TelegramWeb_A: (
        2496,
        "8da85b0d5bfe62527e5b244c209159c3",
        WEB_USER_AGENT,
        "Windows",
        "12.0.47 A",
        "",
    ),
    API.TelegramWeb_K: (
        2496,
        "8da85b0d5bfe62527e5b244c209159c3",
        WEB_USER_AGENT,
        "Win32",
        "2.2 K",
        "macos",
    ),
    API.Webogram: (
        2496,
        "8da85b0d5bfe62527e5b244c209159c3",
        WEB_USER_AGENT,
        "Win32",
        "0.7.0",
        "",
    ),
}


def _fields(value: APIData) -> Fields:
    return (
        value.api_id,
        value.api_hash,
        value.device_model,
        value.system_version,
        value.app_version,
        value.lang_code,
        value.system_lang_code,
        value.lang_pack,
    )


def compact(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def test_public_names_match_1_5_0() -> None:
    assert api.__all__ == ["API", "APIData", "CreateNewSession", "LoginFlag", "UseCurrentSession"]
    assert API.TelegramWeb_Z is API.TelegramWeb_A
    assert issubclass(LoginFlag, int)
    assert UseCurrentSession.__bases__ == (LoginFlag,)
    assert CreateNewSession.__bases__ == (LoginFlag,)
    for cls in ALL_APIS:
        assert cls.__bases__ == (APIData,)


@pytest.mark.parametrize("cls", list(CLASS_VALUES_1_5_0))
def test_class_values_match_1_5_0(cls: ApiClass) -> None:
    api_id, api_hash, device_model, system_version, app_version, lang_pack = CLASS_VALUES_1_5_0[cls]
    expected = (api_id, api_hash, device_model, system_version, app_version, "en", "en-US")
    assert _fields(cls()) == (*expected, lang_pack)
    assert (
        cls.api_id,
        cls.api_hash,
        cls.device_model,
        cls.system_version,
        cls.app_version,
        cls.lang_code,
        cls.system_lang_code,
        cls.lang_pack,
    ) == (*expected, lang_pack)


def test_api_classes_follow_the_platform_versions() -> None:
    pv = _native.platform_versions()
    assert (
        API.TelegramAndroid.app_version
        == f"{pv['android_app_version']} ({pv['android_app_version_code']})"
    )
    assert API.TelegramIOS.app_version == f"{pv['ios_app_version']} ({pv['ios_build_number']}) "
    assert (
        API.TelegramMacOS.app_version == f"{pv['macos_app_version']} ({pv['macos_build_number']}) "
    )
    assert API.TelegramWeb_Z.app_version == pv["web_a_version"]
    assert API.TelegramWeb_K.app_version == pv["web_k_version"]
    suffix = pv["desktop_app_version_suffix"]
    assert API.TelegramDesktop.app_version == f"{pv['desktop_app_version']} {suffix}"
    assert API.TelegramDesktop.app_version.split(" ")[0] == "7.3.1"
    assert API.TelegramIOS.system_version == pv["ios_system_version"]
    assert API.TelegramMacOS.system_version == pv["macos_system_version"]


# ---------------------------------------------------------------- Generate


def test_vector_profiles_are_byte_identical() -> None:
    with (VECTORS / "devices.json").open(encoding="utf-8") as handle:
        cases = json.load(handle)["cases"]
    assert len(cases) == 2800
    fields = ("device_model", "system_version", "app_version", "system_lang_code", "lang_pack")
    for case in cases:
        cls: ApiClass = getattr(API, case["entry_point"])
        if case["system"] is None:
            generated = cls.Generate(unique_id=case["seed"])
        else:
            generated = Desktop.Generate(system=case["system"], unique_id=case["seed"])
        assert type(generated) is cls
        label = f"{case['entry_point']} {case['system']} {case['seed']!r}"
        assert (generated.api_id, generated.api_hash) == (cls.api_id, cls.api_hash), label
        for field in fields:
            value = getattr(generated, field)
            assert value.encode() == case[field].encode(), f"{label} {field}"


@pytest.mark.parametrize("unique_id", IDS)
@pytest.mark.parametrize("system", ["windows", "macos", "linux"])
def test_generate_platform_forms_agree(system: str, unique_id: str) -> None:
    positional = Desktop.Generate(system, unique_id)
    keyword = Desktop.Generate(system=system, unique_id=unique_id)
    assert _fields(positional) == _fields(keyword)
    assert _fields(positional) == _fields(Desktop.Generate(system, unique_id))


@pytest.mark.parametrize("unique_id", IDS)
def test_generate_unique_id_only_forms_agree(unique_id: str) -> None:
    expected = _fields(Desktop.Generate(unique_id=unique_id))
    assert _fields(Desktop.Generate(None, unique_id)) == expected
    assert _fields(Desktop.Generate(unique_id=unique_id)) == expected
    # Unknown platforms fall back to the platform hashed from unique_id.
    assert _fields(Desktop.Generate("bogus", unique_id)) == expected


@pytest.mark.parametrize("unique_id", [i for i in IDS if i])
def test_generate_base_style_positional_id_is_the_unique_id(unique_id: str) -> None:
    # APIData.Generate(unique_id): the base-class form must seed the device.
    expected = _fields(Desktop.Generate(unique_id=unique_id))
    assert _fields(Desktop.Generate(unique_id)) == expected


@pytest.mark.parametrize(
    ("system", "prefix"),
    [("windows", "Windows"), ("macos", "macOS"), ("linux", "Linux")],
)
def test_generate_platform_without_id_keeps_the_platform(system: str, prefix: str) -> None:
    for _ in range(10):
        generated = Desktop.Generate(system)
        assert isinstance(generated, Desktop)
        assert generated.system_version is not None
        assert generated.system_version.startswith(prefix)


def test_generate_without_arguments_returns_a_desktop() -> None:
    generated = Desktop.Generate()
    assert isinstance(generated, Desktop)
    assert generated.system_version is not None
    assert generated.system_version.split()[0] in {"Windows", "macOS", "Linux"}


@pytest.mark.parametrize("api_cls", ALL_APIS)
def test_generate_produces_valid_instance(api_cls: ApiClass) -> None:
    generated = api_cls.Generate()
    assert isinstance(generated, api_cls)
    assert generated.api_id == api_cls.api_id
    assert generated.api_hash == api_cls.api_hash
    assert generated.device_model
    assert generated.system_version
    assert generated.app_version


@pytest.mark.parametrize("api_cls", ALL_APIS)
def test_generate_deterministic_with_unique_id(api_cls: ApiClass) -> None:
    if api_cls is API.TelegramDesktop:
        a = API.TelegramDesktop.Generate("windows", "seed123")
        b = API.TelegramDesktop.Generate("windows", "seed123")
    else:
        a = api_cls.Generate("seed123")
        b = api_cls.Generate("seed123")
    assert a.device_model == b.device_model
    assert a.system_version == b.system_version


def test_generate_keeps_the_class_values_it_does_not_pick() -> None:
    for cls in [*WEB_APIS, API.TelegramAndroid, API.TelegramIOS, API.TelegramMacOS]:
        generated = cls.Generate("kept")
        assert generated.app_version == cls.app_version
        assert generated.lang_code == cls.lang_code
        assert generated.system_lang_code == cls.system_lang_code
        assert generated.lang_pack == cls.lang_pack


def test_web_generate_is_a_browser_and_deterministic() -> None:
    z = API.TelegramWeb_Z.Generate("same_seed")
    k = API.TelegramWeb_K.Generate("same_seed")
    assert z.api_id == 2496
    assert z.device_model == k.device_model
    assert "Mozilla" in z.device_model
    assert z.system_version in {"Windows", "macOS", "Linux"}
    assert k.system_version in {"Win32", "MacIntel", "Linux x86_64"}
    assert API.Webogram.Generate("same_seed").system_version == k.system_version
    assert _fields(API.TelegramWeb_A.Generate("same_seed")) == _fields(z)


def test_generate_matches_the_exact_class_as_1_5_0() -> None:
    with pytest.raises(NotImplementedError, match="APIData device not supported"):
        APIData.Generate("seed")

    class CustomAndroid(API.TelegramAndroid):
        pass

    with pytest.raises(NotImplementedError, match="CustomAndroid device not supported"):
        CustomAndroid.Generate("seed")

    class CustomDesktop(API.TelegramDesktop):
        app_version = "1.0 custom"

    generated = CustomDesktop.Generate("windows", "seed")
    assert type(generated) is CustomDesktop
    assert generated.device_model == Desktop.Generate("windows", "seed").device_model


# ---------------------------------------------------------------- str, copy


def test_str_of_class_and_instance() -> None:
    cls_text = str(Desktop)
    assert cls_text.startswith(
        "TelegramDesktop {\n    api_id: 2040\n    api_hash: b18441a1ff607e10a989891a5462e627\n"
        "    device_model: Desktop\n    system_version: Windows 11 x64\n"
        "    app_version: 7.3.1 x64\n    lang_code: en\n    system_lang_code: en-US\n"
        "    lang_pack: tdesktop\n"
    )
    assert cls_text.endswith("}")

    assert str(API.TelegramIOS()) == (
        "TelegramIOS() = {\n    api_id: 10840\n    api_hash: 33c45224029d59cb3ad0c16134215aeb\n"
        "    device_model: iPhone 17 Pro\n    system_version: 27.0.1\n"
        "    app_version: 13.0 (35303) \n    system_lang_code: en-US\n    lang_pack: ios\n"
        "    lang_code: en\n}"
    )
    assert str(APIData(1, "h")).startswith("APIData() = {\n    api_id: 1\n    api_hash: h\n")


def test_str_is_not_assigned_onto_each_class() -> None:
    for cls in (Desktop, API.TelegramAndroid, API.TelegramWeb_K):
        assert "__str__" not in vars(cls)
    assert "__str__" in vars(APIData)


def test_copy_from_class_and_instance() -> None:
    from_cls = Desktop.copy()
    assert type(from_cls) is Desktop
    assert _fields(from_cls) == _fields(Desktop())

    original = Desktop.Generate("windows", "copy-id")
    copied = original.copy()
    assert copied is not original
    assert _fields(copied) == _fields(original)


def test_copy_of_base_class_still_refuses() -> None:
    with pytest.raises(NoInstanceMatched):
        APIData.copy()


def test_get_cls() -> None:
    assert Desktop.get_cls() is Desktop
    assert Desktop().get_cls() is Desktop
    assert APIData(1, "h").get_cls() is APIData
    assert APIData.get_cls() is APIData
    assert Desktop.destroy() is None
    assert Desktop().destroy() is None


def test_constructed_instance_never_lacks_credentials() -> None:
    with pytest.raises(NoInstanceMatched):
        APIData()
    with pytest.raises(NoInstanceMatched):
        APIData(api_id=1)

    class NoCredentials(APIData):
        pass

    with pytest.raises(NoInstanceMatched):
        NoCredentials()

    built = NoCredentials(7, "hash")
    assert (built.api_id, built.api_hash) == (7, "hash")
    assert isinstance(built.device_model, str)
    assert (built.system_version, built.app_version, built.lang_code) == (None, None, None)


def test_sharemethod_keeps_the_wrapped_metadata() -> None:
    descriptor = vars(APIData)["copy"]
    assert descriptor.__name__ == "copy"
    assert descriptor.__qualname__ == "APIData.copy"
    assert descriptor.__wrapped__.__name__ == "copy"
    assert "return" in descriptor.__annotations__


def test_eq_and_hash_skip_the_language_fields() -> None:
    base = API.TelegramAndroid()
    relabelled = API.TelegramAndroid(lang_code="ru", system_lang_code="ru-RU", lang_pack="x")
    assert base == relabelled
    assert hash(base) == hash(relabelled)
    assert base != API.TelegramAndroid(app_version="1.0")
    assert base != "not an api"
    assert base == APIData(
        base.api_id, base.api_hash, base.device_model, base.system_version, base.app_version
    )


# ---------------------------------------------------------------- session JSON


def test_from_json_basic() -> None:
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
    loaded = APIData.from_json(data)
    assert type(loaded) is APIData
    assert _fields(loaded) == (
        2040,
        "b18441a1ff607e10a989891a5462e627",
        "Desktop",
        "Windows 11",
        "5.12.3 x64",
        "en",
        "en-US",
        "tdesktop",
    )


def test_from_json_defaults_and_system_lang_pack_fallback() -> None:
    data: dict[str, Any] = {
        "app_id": 2040,
        "app_hash": "b18441a1ff607e10a989891a5462e627",
        "device": "Test",
        "sdk": "Win10",
        "app_version": "1.0",
        "system_lang_pack": "ru-RU",
        "lang_pack": "tdesktop",
        "lang_code": "ru",
    }
    assert APIData.from_json(data).system_lang_code == "ru-RU"
    for key in ("system_lang_pack", "lang_pack", "lang_code"):
        del data[key]
    loaded = APIData.from_json(data)
    assert (loaded.lang_code, loaded.system_lang_code, loaded.lang_pack) == ("en", "en", "")


def test_from_json_without_credentials_raises_no_instance_matched() -> None:
    with pytest.raises(NoInstanceMatched, match="session JSON"):
        APIData.from_json({"app_hash": "h", "device": "d", "sdk": "s", "app_version": "v"})


def test_to_json_basic_and_roundtrip() -> None:
    written = APIData(
        api_id=6,
        api_hash="eb06d4abfb49dc3eeb1aeb98ae0f581e",
        device_model="Samsung SM-S928B",
        system_version="SDK 35",
        app_version="12.3.0",
        lang_code="en",
        system_lang_code="en-US",
        lang_pack="android",
    ).to_json()
    assert written["app_id"] == 6
    assert written["device"] == "Samsung SM-S928B"
    assert written["sdk"] == "SDK 35"
    assert written["system_lang_pack"] == written["system_lang_code"] == "en-US"
    assert "session_file" in written
    assert "twoFA" in written

    web = APIData(
        api_id=2496,
        api_hash="8da85b0d5bfe62527e5b244c209159c3",
        device_model="Mozilla/5.0 Test",
        system_version="Windows",
        app_version="5.0.0 Z",
        lang_code="en",
        system_lang_code="en-US",
        lang_pack="",
    )
    assert _fields(APIData.from_json(web.to_json())) == _fields(web)


def test_to_json_matches_1_5_0_bytes() -> None:
    # json.dumps(..., separators=(",", ":")) of 1.5.0 for the same calls.
    account = (
        '"twoFA":null,"role":"","id":12345,"phone":"+1234567890","username":null,'
        '"date_of_birth":null,"date_of_birth_integrity":null,"is_premium":false,'
        '"has_profile_pic":false,"spamblock":null,"register_time":null,'
        '"last_check_time":null,"avatar":null,"first_name":"","last_name":"","sex":null,'
        '"proxy":null,"ipv6":false,"session_file":"myfile"'
    )
    extra = {"id": 12345, "phone": "+1234567890", "session_file": "myfile"}
    assert compact(API.TelegramAndroid().to_json(extra)) == (
        '{"app_id":6,"app_hash":"eb06d4abfb49dc3eeb1aeb98ae0f581e","device":"samsungSM-S938B",'
        '"sdk":"SDK 36","app_version":"13.0.3 (7183)","system_lang_pack":"en-US",'
        '"system_lang_code":"en-US","lang_pack":"android","lang_code":"en",' + account + "}"
    )
    # Fields an instance leaves None are written as null, extra overriding in place.
    partial = APIData(1, "h", "PC 64bit").to_json({"sdk": "s", "x": 1})
    assert compact(partial) == (
        '{"app_id":1,"app_hash":"h","device":"PC 64bit","sdk":"s","app_version":null,'
        '"system_lang_pack":null,"system_lang_code":null,"lang_pack":null,"lang_code":null,'
        '"twoFA":null,"role":"","id":null,"phone":null,"username":null,"date_of_birth":null,'
        '"date_of_birth_integrity":null,"is_premium":false,"has_profile_pic":false,'
        '"spamblock":null,"register_time":null,"last_check_time":null,"avatar":null,'
        '"first_name":"","last_name":"","sex":null,"proxy":null,"ipv6":false,'
        '"session_file":"","x":1}'
    )
