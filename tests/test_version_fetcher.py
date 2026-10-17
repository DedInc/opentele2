from __future__ import annotations

import pytest

from src import version_fetcher


def _post(text: str) -> str:
    return (
        '<div class="tgme_widget_message_text js-message_text" dir="auto">'
        f"{text}</div>"
    )


_TGSTABLE_PAGE = "".join(
    [
        _post("Telegram for <b>Android</b> has been updated New <b>version</b>:"
              "<code>12.10.6 (7112)</code> Released"),
        _post("Telegram for <b>iOS</b> has been updated New <b>version</b>:"
              "<code>13.0 (35303)</code> Released"),
        _post("Telegram native client for macOS has been updated New version:"
              "12.8 (build 282010)"),
        _post("Telegram for <b>Android</b> has been updated New <b>version</b>:"
              "<code>13.0.3 (7183)</code> Released"),
    ]
)


def test_posts_are_parsed_from_a_multi_class_div() -> None:
    posts = version_fetcher._parse_tg_messages(_TGSTABLE_PAGE)

    assert [p["version"] for p in posts][:2] == ["12.10.6", "13.0"]


def test_a_platform_filter_drops_other_platforms() -> None:
    posts = version_fetcher._parse_tg_messages(_TGSTABLE_PAGE, "Android")

    assert posts == [
        {"version": "12.10.6", "build_code": 7112},
        {"version": "13.0.3", "build_code": 7183},
    ]


def test_android_fetch_takes_the_newest_post(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(version_fetcher, "_fetch_tg_page", lambda query: _TGSTABLE_PAGE)

    assert version_fetcher._fetch_android() == {
        "android_app_version": "13.0.3",
        "android_app_version_code": 7183,
    }


def test_ios_fetch_ignores_android_posts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(version_fetcher, "_fetch_tg_page", lambda query: _TGSTABLE_PAGE)

    assert version_fetcher._fetch_ios() == {
        "ios_app_version": "13.0",
        "ios_build_number": 35303,
    }


def test_empty_fetched_values_are_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENTELE_NO_FETCH", raising=False)
    monkeypatch.setattr(version_fetcher, "_CACHED", None)
    monkeypatch.setattr(
        version_fetcher,
        "_FETCHERS",
        [
            lambda: {"android_app_version": ""},
            lambda: {"web_k_version": "2.2 K", "web_a_version": None},
        ],
    )

    assert version_fetcher.fetch_all_versions() == {"web_k_version": "2.2 K"}
