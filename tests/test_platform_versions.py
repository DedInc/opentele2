from __future__ import annotations

import ast
import re
from pathlib import Path
from types import ModuleType

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
_CHROME_FILES = ("api.py", "fingerprint.py", "version_fetcher.py")
_CHROME_UA = re.compile(r"Chrome/(\d+\.\d+\.\d+\.\d+)")
_CHROME_FIELD = re.compile(r'chrome_version: str = "(\d+\.\d+\.\d+\.\d+)"')


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, ModuleType]:
    """The bundled fallbacks, synced into API, with fetching disabled.

    The environment variable is set before ``src`` is imported, so importing
    it here never reaches the network either.
    """
    monkeypatch.setenv("OPENTELE_NO_FETCH", "1")
    from src import api, fingerprint, version_fetcher

    monkeypatch.setattr(version_fetcher, "_CACHED", None)
    monkeypatch.setattr(
        fingerprint, "PLATFORM_VERSIONS", fingerprint.PlatformVersions()
    )
    for cls in (
        api.API.TelegramDesktop,
        api.API.TelegramAndroid,
        api.API.TelegramAndroidX,
        api.API.TelegramIOS,
        api.API.TelegramMacOS,
        api.API.TelegramWeb_A,
        api.API.TelegramWeb_K,
    ):
        monkeypatch.setattr(cls, "app_version", cls.app_version)
        monkeypatch.setattr(cls, "system_version", cls.system_version)

    fingerprint._apply_fetched_versions()
    assert version_fetcher._CACHED == {}
    api._sync_api_versions()
    return api, fingerprint


def test_fallbacks_are_the_current_releases(
    offline: tuple[ModuleType, ModuleType],
) -> None:
    _, fingerprint = offline
    pv = fingerprint.PLATFORM_VERSIONS

    assert (pv.android_app_version, pv.android_app_version_code) == ("13.0.3", 7183)
    assert (pv.ios_app_version, pv.ios_build_number) == ("13.0", 35303)
    assert (pv.macos_app_version, pv.macos_build_number) == ("13.0", 283305)
    assert pv.android_x_app_version == "0.29.1.1817"
    assert pv.web_a_version == "12.0.47 A"
    assert pv.web_k_version == "2.2 K"
    assert pv.chrome_version == "155.0.0.0"
    assert f"Chrome/{pv.chrome_version} " in pv.user_agent
    assert pv.ios_version_range == ("18.0", "27.0.1")


def test_synced_api_versions_use_the_fallbacks(
    offline: tuple[ModuleType, ModuleType],
) -> None:
    api, fingerprint = offline
    from src.utils import APP_VERSION_STR

    API = api.API
    assert fingerprint.PLATFORM_VERSIONS.desktop_app_version == APP_VERSION_STR
    assert API.TelegramDesktop.app_version == f"{APP_VERSION_STR} x64"
    assert API.TelegramAndroid.app_version == "13.0.3 (7183)"
    assert API.TelegramAndroidX.app_version == "0.29.1.1817"
    assert API.TelegramIOS.app_version == "13.0 (35303) "
    assert API.TelegramMacOS.app_version == "13.0 (283305) "
    assert API.TelegramWeb_A.app_version == "12.0.47 A"
    assert API.TelegramWeb_K.app_version == "2.2 K"


def _api_class_defaults() -> dict[str, str]:
    tree = ast.parse((_SRC / "api.py").read_text(encoding="utf-8"))
    api_cls = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "API"
    )
    defaults: dict[str, str] = {}
    for cls in api_cls.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        for stmt in cls.body:
            if (
                isinstance(stmt, ast.Assign)
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == "app_version"
                and isinstance(stmt.value, ast.Constant)
            ):
                defaults[cls.name] = str(stmt.value.value)
    return defaults


def test_api_class_defaults_match_the_synced_versions(
    offline: tuple[ModuleType, ModuleType],
) -> None:
    api, _ = offline
    defaults = _api_class_defaults()

    # The class defaults are what callers see if syncing fails; the build
    # number suffix is only added by the sync.
    for name in (
        "TelegramDesktop",
        "TelegramAndroid",
        "TelegramAndroidX",
        "TelegramIOS",
        "TelegramMacOS",
        "TelegramWeb_A",
        "TelegramWeb_K",
    ):
        synced = getattr(api.API, name).app_version
        assert synced.split(" (")[0].strip() == defaults[name], name


def test_every_chrome_version_agrees(offline: tuple[ModuleType, ModuleType]) -> None:
    api, fingerprint = offline
    found: dict[str, set[str]] = {}
    for name in _CHROME_FILES:
        text = (_SRC / name).read_text(encoding="utf-8")
        found[name] = set(_CHROME_UA.findall(text)) | set(_CHROME_FIELD.findall(text))

    assert all(found.values()), found
    assert set().union(*found.values()) == {
        fingerprint.PLATFORM_VERSIONS.chrome_version
    }
    assert f"Chrome/{fingerprint.PLATFORM_VERSIONS.chrome_version} " in (
        api._DEFAULT_WEB_USER_AGENT
    )
