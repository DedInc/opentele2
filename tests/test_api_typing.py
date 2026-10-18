from __future__ import annotations

import pytest

from src.api import API, APIData
from src.exception import NoInstanceMatched

Desktop = API.TelegramDesktop

IDS = [f"typing-id-{n}" for n in range(25)] + ["opentele", "seed123", ""]


def _fields(api: APIData) -> tuple[object, ...]:
    return (
        api.api_id,
        api.api_hash,
        api.device_model,
        api.system_version,
        api.app_version,
        api.lang_code,
        api.system_lang_code,
        api.lang_pack,
    )


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
def test_generate_platform_without_id_keeps_the_platform(
    system: str, prefix: str
) -> None:
    for _ in range(10):
        api = Desktop.Generate(system)
        assert isinstance(api, Desktop)
        assert api.system_version is not None
        assert api.system_version.startswith(prefix)


def test_generate_without_arguments_returns_a_desktop() -> None:
    api = Desktop.Generate()
    assert isinstance(api, Desktop)
    assert api.system_version is not None
    assert api.system_version.split()[0] in {"Windows", "macOS", "Linux"}


def test_str_of_class_and_instance() -> None:
    cls_text = str(Desktop)
    assert cls_text.startswith("TelegramDesktop {\n    api_id: 2040\n")
    assert "    lang_pack: tdesktop\n" in cls_text
    assert cls_text.endswith("}")

    inst_text = str(Desktop())
    assert inst_text.startswith("TelegramDesktop() = {\n    api_id: 2040\n")
    assert "    device_model: Desktop\n" in inst_text
    assert inst_text.endswith("\n}")

    assert str(APIData(1, "h")).startswith("APIData() = {\n    api_id: 1\n")


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


def test_constructed_instance_never_lacks_credentials() -> None:
    with pytest.raises(NoInstanceMatched):
        APIData()
    with pytest.raises(NoInstanceMatched):
        APIData(api_id=1)

    class NoCredentials(APIData):
        pass

    with pytest.raises(NoInstanceMatched):
        NoCredentials()

    api = NoCredentials(7, "hash")
    assert (api.api_id, api.api_hash) == (7, "hash")
    assert isinstance(api.device_model, str)


def test_sharemethod_keeps_the_wrapped_metadata() -> None:
    descriptor = vars(APIData)["copy"]
    assert descriptor.__name__ == "copy"
    assert descriptor.__qualname__ == "APIData.copy"
    assert descriptor.__wrapped__.__name__ == "copy"
    assert "return" in descriptor.__annotations__
