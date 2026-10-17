from __future__ import annotations

import pytest

from src import fingerprint, version_fetcher
from src.api import API
from src.utils import APP_VERSION, APP_VERSION_STR, format_app_version


@pytest.mark.parametrize(
    ("packed", "display"),
    [
        (7000009, "7.0.9"),
        (7003000, "7.3"),
        (7003001, "7.3.1"),
        (6008002, "6.8.2"),
        (10000000, "10.0"),
    ],
)
def test_format_app_version_matches_tdesktop_display(packed: int, display: str) -> None:
    assert format_app_version(packed) == display


def test_advertised_desktop_version_is_derived_from_app_version() -> None:
    assert APP_VERSION_STR == format_app_version(APP_VERSION)
    assert fingerprint.PlatformVersions().desktop_app_version == APP_VERSION_STR
    assert fingerprint.PLATFORM_VERSIONS.desktop_app_version == APP_VERSION_STR


def test_desktop_api_app_version_starts_with_the_tdata_version() -> None:
    assert API.TelegramDesktop.app_version.split(" ")[0] == APP_VERSION_STR


def test_a_fetched_release_cannot_move_the_desktop_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pv = fingerprint.PLATFORM_VERSIONS
    monkeypatch.setattr(pv, "web_k_version", pv.web_k_version)
    monkeypatch.setattr(
        version_fetcher,
        "fetch_all_versions",
        lambda: {"desktop_app_version": "99.9.9", "web_k_version": "9.9 K"},
    )

    fingerprint._apply_fetched_versions()

    assert pv.desktop_app_version == APP_VERSION_STR
    assert pv.web_k_version == "9.9 K"
