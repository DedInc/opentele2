"""Tests of the import-time platform-versions fetch, its cache and
OPENTELE_NO_FETCH, the version fetcher and the API class sync.
``_native.fetch_versions`` is mocked; only the ``live`` tests reach the
network."""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from typing import Any

import pytest

from opentele2 import _native, _version_fetcher, api, fingerprint
from opentele2.api import API

SYNCED = (
    API.TelegramDesktop,
    API.TelegramAndroid,
    API.TelegramAndroidX,
    API.TelegramIOS,
    API.TelegramMacOS,
    API.TelegramWeb_A,
    API.TelegramWeb_K,
)
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
BROWSER_PATCH = {"chrome_version": "160.0.0.0", "firefox_version": "155.0"}


class FakeFetch:
    """Stands in for ``_native.fetch_versions``, recording each timeout."""

    def __init__(self, patch: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self.patch = patch or {}
        self.error = error
        self.timeouts: list[float] = []

    def __call__(self, timeout: float = 10.0) -> dict[str, Any]:
        self.timeouts.append(timeout)
        if self.error is not None:
            raise self.error
        return dict(self.patch)


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bundled fallbacks, synced into API, with an empty cache.

    Everything the tests change (the cache, PLATFORM_VERSIONS, the synced
    class attributes, the native fetch) is restored afterwards.
    """
    monkeypatch.setenv("OPENTELE_NO_FETCH", "1")
    monkeypatch.setattr(_version_fetcher, "_CACHED", None)
    monkeypatch.setattr(fingerprint, "PLATFORM_VERSIONS", fingerprint.PlatformVersions())
    monkeypatch.setattr(_native, "fetch_versions", FakeFetch(error=AssertionError("fetched")))
    for cls in SYNCED:
        monkeypatch.setattr(cls, "app_version", cls.app_version)
        monkeypatch.setattr(cls, "system_version", cls.system_version)

    fingerprint._apply_fetched_versions()
    assert _version_fetcher._CACHED == {}
    api._sync_api_versions()


def _app_versions() -> dict[str, str | None]:
    return {cls.__name__: cls.app_version for cls in (*SYNCED, API.Webogram)}


# ---------------------------------------------------------------- fallbacks


@pytest.mark.usefixtures("offline")
def test_fallbacks_are_the_current_releases() -> None:
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


@pytest.mark.usefixtures("offline")
def test_synced_api_versions_use_the_fallbacks() -> None:
    assert fingerprint.PLATFORM_VERSIONS.desktop_app_version == "7.3.1"
    assert _app_versions() == {
        "TelegramDesktop": "7.3.1 x64",
        "TelegramAndroid": "13.0.3 (7183)",
        "TelegramAndroidX": "0.29.1.1817",
        "TelegramIOS": "13.0 (35303) ",
        "TelegramMacOS": "13.0 (283305) ",
        "TelegramWeb_A": "12.0.47 A",
        "TelegramWeb_K": "2.2 K",
        "Webogram": "0.7.0",
    }
    assert API.TelegramIOS.system_version == "27.0.1"
    assert API.TelegramMacOS.system_version == "27.0.1"


@pytest.mark.usefixtures("offline")
def test_api_class_defaults_match_the_synced_versions() -> None:
    # The core's profiles are what callers see if syncing fails.
    profiles = {
        API.TelegramDesktop: _native.profile("TelegramDesktop"),
        API.TelegramAndroid: _native.profile("TelegramAndroid"),
        API.TelegramAndroidX: _native.profile("TelegramAndroidX"),
        API.TelegramIOS: _native.profile("TelegramIOS"),
        API.TelegramMacOS: _native.profile("TelegramMacOS"),
        API.TelegramWeb_A: _native.profile("TelegramWeb_A"),
        API.TelegramWeb_K: _native.profile("TelegramWeb_K"),
    }
    assert set(profiles) == set(SYNCED)
    for cls, profile in profiles.items():
        assert cls.app_version == profile["app_version"], cls.__name__
        assert cls.system_version == profile["system_version"], cls.__name__


@pytest.mark.usefixtures("offline")
def test_every_chrome_version_agrees() -> None:
    pv = fingerprint.PLATFORM_VERSIONS
    assert f"Chrome/{pv.chrome_version} " in pv.user_agent
    for cls in (API.TelegramWeb_A, API.TelegramWeb_K, API.Webogram):
        assert cls.device_model == pv.user_agent


# ---------------------------------------------------------------- fetch and cache


@pytest.mark.usefixtures("offline")
def test_results_are_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTELE_NO_FETCH")
    monkeypatch.setattr(_version_fetcher, "_CACHED", None)
    fake = FakeFetch({"web_k_version": "2.3 K"})
    monkeypatch.setattr(_native, "fetch_versions", fake)

    a = _version_fetcher.fetch_all_versions()
    b = _version_fetcher.fetch_all_versions(3)
    assert a is b
    assert a == {"web_k_version": "2.3 K"}
    assert fake.timeouts == [10]


@pytest.mark.usefixtures("offline")
def test_the_native_patch_is_taken_as_is(monkeypatch: pytest.MonkeyPatch) -> None:
    # The core already leaves out every field no source answered with a
    # non-empty value; the fetcher keeps every field it returns.
    monkeypatch.delenv("OPENTELE_NO_FETCH")
    monkeypatch.setattr(_version_fetcher, "_CACHED", None)
    fake = FakeFetch({**FULL_PATCH, **BROWSER_PATCH})
    monkeypatch.setattr(_native, "fetch_versions", fake)

    assert _version_fetcher.fetch_all_versions(4.5) == {**FULL_PATCH, **BROWSER_PATCH}
    assert fake.timeouts == [4.5]


def test_the_default_timeout_is_the_core_one() -> None:
    assert _native.DEFAULT_TIMEOUT == 10.0
    assert _version_fetcher._TIMEOUT == _native.DEFAULT_TIMEOUT


@pytest.mark.usefixtures("offline")
def test_no_fetch_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_version_fetcher, "_CACHED", None)
    fake = FakeFetch(FULL_PATCH)
    monkeypatch.setattr(_native, "fetch_versions", fake)

    assert _version_fetcher.fetch_all_versions() == {}
    assert fake.timeouts == []


@pytest.mark.usefixtures("offline")
def test_a_failed_fetch_is_an_empty_cached_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTELE_NO_FETCH")
    monkeypatch.setattr(_version_fetcher, "_CACHED", None)
    fake = FakeFetch(error=ValueError("timeout must be positive"))
    monkeypatch.setattr(_native, "fetch_versions", fake)

    assert _version_fetcher.fetch_all_versions() == {}
    assert _version_fetcher.fetch_all_versions() == {}
    assert fake.timeouts == [10]


# ---------------------------------------------------------------- apply and sync


@pytest.mark.usefixtures("offline")
def test_fetched_versions_are_applied_and_synced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTELE_NO_FETCH")
    monkeypatch.setattr(_version_fetcher, "_CACHED", None)
    monkeypatch.setattr(_native, "fetch_versions", FakeFetch(FULL_PATCH))

    pv = fingerprint.PLATFORM_VERSIONS
    fingerprint._apply_fetched_versions()
    # The fetched desktop version stays in the result and is not applied.
    assert _version_fetcher.fetch_all_versions() == FULL_PATCH
    assert fingerprint.PLATFORM_VERSIONS is pv
    assert dataclasses.asdict(pv) == {
        **dataclasses.asdict(fingerprint.PlatformVersions()),
        **{key: value for key, value in FULL_PATCH.items() if key != "desktop_app_version"},
    }
    assert fingerprint.get_platform_versions().desktop_app_version == "7.3.1"

    api._sync_api_versions()
    assert _app_versions() == {
        "TelegramDesktop": "7.3.1 x64",
        "TelegramAndroid": "14.1.2 (7300)",
        "TelegramAndroidX": "0.30.0.1900",
        "TelegramIOS": "14.1 (36000) ",
        "TelegramMacOS": "14.2 (290001) ",
        "TelegramWeb_A": "12.1.0 A",
        "TelegramWeb_K": "2.3 K",
        "Webogram": "0.7.0",
    }
    assert API.TelegramWeb_Z.app_version == "12.1.0 A"
    # Instances and generated devices take the synced class values.
    assert API.TelegramAndroid().app_version == "14.1.2 (7300)"
    assert API.TelegramIOS.Generate("synced").app_version == "14.1 (36000) "
    # The strict checks compare against the fetched versions.
    assert fingerprint.validate_init_connection_params(
        api_id=6,
        device_model="Samsung SM-S928B",
        system_version="SDK 35",
        app_version="13.0.3",
        system_lang_code="en-US",
        lang_pack="android",
        lang_code="en",
        strict=True,
    ) == ["Android app_version '13.0.3' major does not match latest known '14.1.2'"]


@pytest.mark.usefixtures("offline")
def test_fetched_browser_versions_flow_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTELE_NO_FETCH")
    monkeypatch.setattr(_version_fetcher, "_CACHED", None)
    monkeypatch.setattr(_native, "fetch_versions", FakeFetch(BROWSER_PATCH))

    fetched = _version_fetcher.fetch_all_versions()
    assert fetched == BROWSER_PATCH
    assert _version_fetcher.versions_patch(fetched) == BROWSER_PATCH

    pv = fingerprint.PLATFORM_VERSIONS
    fingerprint._apply_fetched_versions()
    # The patch with both browser fields applies; the Chrome version moves
    # the user agent with it.
    assert pv.chrome_version == "160.0.0.0"
    assert f"Chrome/{pv.chrome_version} " in pv.user_agent
    assert pv.user_agent != fingerprint.PlatformVersions().user_agent
    assert pv.android_app_version == fingerprint.PlatformVersions().android_app_version


@pytest.mark.usefixtures("offline")
def test_sync_honours_an_empty_desktop_suffix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fingerprint.PLATFORM_VERSIONS, "desktop_app_version_suffix", "")
    api._sync_api_versions()
    assert API.TelegramDesktop.app_version == "7.3.1"


@pytest.mark.usefixtures("offline")
def test_a_failing_apply_keeps_the_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTELE_NO_FETCH")
    monkeypatch.setattr(_version_fetcher, "_CACHED", None)
    monkeypatch.setattr(_native, "fetch_versions", FakeFetch(FULL_PATCH))

    def refuse(versions: object, patch: object) -> object:
        raise ValueError("unknown versions patch field")

    monkeypatch.setattr(_native, "apply_versions_patch", refuse)

    fingerprint._apply_fetched_versions()
    assert fingerprint.PLATFORM_VERSIONS == fingerprint.PlatformVersions()


@pytest.mark.usefixtures("offline")
def test_a_failing_sync_keeps_the_class_values(monkeypatch: pytest.MonkeyPatch) -> None:
    before = _app_versions()
    monkeypatch.setattr(fingerprint, "PLATFORM_VERSIONS", object())
    api._sync_api_versions()
    assert _app_versions() == before


# ---------------------------------------------------------------- import time

_IMPORT_PROBE = (
    "import dataclasses, json\n"
    "import opentele2\n"
    "from opentele2 import _version_fetcher, fingerprint\n"
    "from opentele2.api import API\n"
    "print(json.dumps({\n"
    "    'cached': _version_fetcher._CACHED,\n"
    "    'versions': dataclasses.asdict(fingerprint.PLATFORM_VERSIONS),\n"
    "    'android': API.TelegramAndroid.app_version,\n"
    "    'ios': API.TelegramIOS.app_version,\n"
    "    'web_k': API.TelegramWeb_K.app_version,\n"
    "    'desktop': API.TelegramDesktop.app_version,\n"
    "}))\n"
)


def _import_in_a_fresh_process(env: dict[str, str]) -> dict[str, Any]:
    done = subprocess.run(
        [sys.executable, "-c", _IMPORT_PROBE],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return json.loads(done.stdout)


def test_import_skips_the_fetch_with_opentele_no_fetch() -> None:
    probe = _import_in_a_fresh_process({**os.environ, "OPENTELE_NO_FETCH": "1"})
    assert probe["cached"] == {}
    expected = dataclasses.asdict(fingerprint.PlatformVersions())
    assert probe["versions"] == json.loads(json.dumps(expected))
    assert (probe["android"], probe["ios"], probe["web_k"], probe["desktop"]) == (
        "13.0.3 (7183)",
        "13.0 (35303) ",
        "2.2 K",
        "7.3.1 x64",
    )


@pytest.mark.live
def test_import_fetches_applies_and_syncs_the_versions() -> None:
    env = {key: value for key, value in os.environ.items() if key != "OPENTELE_NO_FETCH"}
    probe = _import_in_a_fresh_process(env)
    cached, versions = probe["cached"], probe["versions"]
    assert cached, "no source answered"
    for key, value in cached.items():
        assert value != ""
        if key != "desktop_app_version":
            assert versions[key] == value, key
    assert versions["desktop_app_version"] == "7.3.1"
    assert probe["desktop"] == "7.3.1 x64"
    assert probe["android"] == (
        f"{versions['android_app_version']} ({versions['android_app_version_code']})"
    )
    assert probe["ios"] == f"{versions['ios_app_version']} ({versions['ios_build_number']}) "
    assert probe["web_k"] == versions["web_k_version"]
    if "web_k_version" in cached:
        assert str(cached["web_k_version"]).endswith(" K")
    if "web_a_version" in cached:
        assert str(cached["web_a_version"]).endswith(" A")
