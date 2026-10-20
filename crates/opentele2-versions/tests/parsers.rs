//! Tests for `parse`: every parser against response bodies captured from the
//! real sources into `tests/fixtures/` (2026-10-19). The expected values are
//! what the 1.5.0 fetchers of `src/version_fetcher.py` return on the same
//! bodies, plus the synthetic page of `tests/test_version_fetcher.py`.

use opentele2_versions::VersionsPatch;
use opentele2_versions::parse::{self, TgPost};

const TDESKTOP: &str = include_str!("fixtures/tdesktop_latest.json");
const TGSTABLE_ANDROID: &str = include_str!("fixtures/tgstable_android.html");
const PLAY_ANDROID: &str = include_str!("fixtures/play_android.json");
const TELEGRAM_X: &str = include_str!("fixtures/telegram_x_latest.json");
const TGSTABLE_IOS: &str = include_str!("fixtures/tgstable_ios.html");
const ITUNES_IOS: &str = include_str!("fixtures/itunes_ios.json");
const BREW_MACOS: &str = include_str!("fixtures/brew_telegram.json");
const ITUNES_MACOS: &str = include_str!("fixtures/itunes_macos.json");
const WEB_K: &str = include_str!("fixtures/web_k_version");
const WEB_A: &str = include_str!("fixtures/web_a_version.txt");
// Written by hand in the shape of the live Chrome for Testing and Mozilla
// product-details responses, not captured.
const CHROME: &str = include_str!("fixtures/chrome_last_known_good.json");
const FIREFOX: &str = include_str!("fixtures/firefox_versions.json");

fn post(version: &str, build_code: u32) -> TgPost {
    TgPost {
        version: version.to_owned(),
        build_code: Some(build_code),
    }
}

fn message(text: &str) -> String {
    format!(r#"<div class="tgme_widget_message_text js-message_text" dir="auto">{text}</div>"#)
}

/// `_TGSTABLE_PAGE` of `tests/test_version_fetcher.py`.
fn synthetic_page() -> String {
    [
        "Telegram for <b>Android</b> has been updated New <b>version</b>:\
         <code>12.10.6 (7112)</code> Released",
        "Telegram for <b>iOS</b> has been updated New <b>version</b>:\
         <code>13.0 (35303)</code> Released",
        "Telegram native client for macOS has been updated New version:\
         12.8 (build 282010)",
        "Telegram for <b>Android</b> has been updated New <b>version</b>:\
         <code>13.0.3 (7183)</code> Released",
    ]
    .map(message)
    .concat()
}

#[test]
fn tdesktop_release_tag() {
    assert_eq!(
        parse::parse_tdesktop(TDESKTOP),
        Some(VersionsPatch {
            desktop_app_version: Some("7.3.1".to_owned()),
            ..VersionsPatch::default()
        })
    );
}

#[test]
fn telegram_x_release_tag() {
    assert_eq!(
        parse::parse_telegram_x(TELEGRAM_X),
        Some(VersionsPatch {
            android_x_app_version: Some("0.29.1.1817".to_owned()),
            ..VersionsPatch::default()
        })
    );
}

#[test]
fn release_tag_strips_every_leading_v_and_drops_an_empty_tag() {
    assert_eq!(
        parse::parse_tdesktop(r#"{"tag_name": "vv7.3.1"}"#)
            .and_then(|p| p.desktop_app_version)
            .as_deref(),
        Some("7.3.1")
    );
    assert_eq!(parse::parse_tdesktop(r#"{"tag_name": "v"}"#), None);
    assert_eq!(parse::parse_telegram_x("{}"), None);
}

#[test]
fn tgstable_android_page_posts() {
    let all = parse::parse_tgstable(TGSTABLE_ANDROID, None);
    let android = parse::parse_tgstable(TGSTABLE_ANDROID, Some("Android"));

    assert_eq!((all.len(), android.len()), (20, 18));
    assert_eq!(
        android[android.len() - 3..],
        [
            post("13.0.1", 7167),
            post("13.0.2", 7175),
            post("13.0.3", 7183)
        ]
    );
}

#[test]
fn tgstable_ios_page_posts() {
    let all = parse::parse_tgstable(TGSTABLE_IOS, None);
    let ios = parse::parse_tgstable(TGSTABLE_IOS, Some("iOS"));

    assert_eq!((all.len(), ios.len()), (20, 20));
    assert_eq!(
        ios[ios.len() - 3..],
        [
            post("12.9.3", 34622),
            post("12.9.4", 34639),
            post("13.0", 35303)
        ]
    );
}

#[test]
fn android_takes_the_newest_tgstable_post() {
    let expected = Some(VersionsPatch {
        android_app_version: Some("13.0.3".to_owned()),
        android_app_version_code: Some(7183),
        ..VersionsPatch::default()
    });

    assert_eq!(parse::parse_android_tgstable(TGSTABLE_ANDROID), expected);
    assert_eq!(parse::parse_android_tgstable(&synthetic_page()), expected);
}

#[test]
fn ios_takes_the_newest_tgstable_post() {
    let expected = Some(VersionsPatch {
        ios_app_version: Some("13.0".to_owned()),
        ios_build_number: Some(35303),
        ..VersionsPatch::default()
    });

    assert_eq!(parse::parse_ios_tgstable(TGSTABLE_IOS), expected);
    assert_eq!(parse::parse_ios_tgstable(&synthetic_page()), expected);
}

#[test]
fn posts_are_parsed_from_a_multi_class_div() {
    let posts = parse::parse_tgstable(&synthetic_page(), None);

    assert_eq!(posts[..2], [post("12.10.6", 7112), post("13.0", 35303)]);
    // "12.8 (build 282010)": the build is not a bare number in parentheses.
    assert_eq!(
        posts[2],
        TgPost {
            version: "12.8".to_owned(),
            build_code: None
        }
    );
}

#[test]
fn a_platform_filter_drops_other_platforms() {
    assert_eq!(
        parse::parse_tgstable(&synthetic_page(), Some("Android")),
        [post("12.10.6", 7112), post("13.0.3", 7183)]
    );
}

#[test]
fn entities_are_unescaped_before_matching() {
    let page =
        message("Telegram&nbsp;for&#32;Android&#x20;&amp; more: New version:&nbsp;13.1 (7200)");

    assert_eq!(
        parse::parse_tgstable(&page, Some("Android")),
        [post("13.1", 7200)]
    );
}

#[test]
fn a_page_without_posts_sends_to_the_fallback() {
    assert_eq!(parse::parse_android_tgstable("<html></html>"), None);
    assert_eq!(
        parse::parse_ios_tgstable(&message("Telegram for Android")),
        None
    );
}

#[test]
fn play_fallback_drops_its_empty_version() {
    // The captured feed answers `"version": ""`; 1.5.0 returns it and then
    // drops the empty value in `fetch_all_versions`.
    assert_eq!(parse::parse_android_play(PLAY_ANDROID), None);
    assert_eq!(
        parse::parse_android_play(r#"{"version": "13.0.3"}"#)
            .and_then(|p| p.android_app_version)
            .as_deref(),
        Some("13.0.3")
    );
}

#[test]
fn itunes_fallbacks() {
    assert_eq!(
        parse::parse_ios_itunes(ITUNES_IOS),
        Some(VersionsPatch {
            ios_app_version: Some("13.0".to_owned()),
            ..VersionsPatch::default()
        })
    );
    assert_eq!(
        parse::parse_macos_itunes(ITUNES_MACOS),
        Some(VersionsPatch {
            macos_app_version: Some("13.0".to_owned()),
            ..VersionsPatch::default()
        })
    );
    assert_eq!(parse::parse_ios_itunes(r#"{"results": []}"#), None);
}

#[test]
fn macos_brew_version_and_build() {
    assert_eq!(
        parse::parse_macos_brew(BREW_MACOS),
        Some(VersionsPatch {
            macos_app_version: Some("13.0".to_owned()),
            macos_build_number: Some(283_305),
            ..VersionsPatch::default()
        })
    );
}

#[test]
fn macos_brew_edge_cases() {
    let brew = |version: &str| parse::parse_macos_brew(&format!(r#"{{"version": {version}}}"#));
    let patch = |version: Option<&str>, build: Option<u32>| {
        Some(VersionsPatch {
            macos_app_version: version.map(str::to_owned),
            macos_build_number: build,
            ..VersionsPatch::default()
        })
    };

    assert_eq!(brew(r#""13.1""#), patch(Some("13.1"), None));
    assert_eq!(
        brew(r#"" 13.1 , 290000 ""#),
        patch(Some("13.1"), Some(290_000))
    );
    assert_eq!(brew(r#""13.1,beta""#), patch(Some("13.1"), None));
    // These fall back to iTunes in 1.5.0.
    assert_eq!(brew(r#""""#), None);
    assert_eq!(brew("null"), None);
    assert_eq!(parse::parse_macos_brew("{}"), None);
    assert_eq!(parse::parse_macos_brew("not json"), None);
}

#[test]
fn web_versions() {
    assert_eq!(
        parse::parse_web_k(WEB_K),
        Some(VersionsPatch {
            web_k_version: Some("2.2 K".to_owned()),
            ..VersionsPatch::default()
        })
    );
    assert_eq!(
        parse::parse_web_a(WEB_A),
        Some(VersionsPatch {
            web_a_version: Some("12.0.47 A".to_owned()),
            ..VersionsPatch::default()
        })
    );
}

#[test]
fn web_k_skips_merge_conflict_markers() {
    let web_k = |text: &str| parse::parse_web_k(text).and_then(|p| p.web_k_version);

    assert_eq!(
        web_k("\r\n<<<<<<< HEAD\r\n2.3 (700)\r\n=======\r\n2.2 (680)\r\n>>>>>>> x\r\n").as_deref(),
        Some("2.3 K")
    );
    assert_eq!(web_k("<<<<<<< HEAD\n").as_deref(), Some("<<<<<<< HEAD K"));
}

#[test]
fn chrome_stable_version_is_reduced_to_its_major() {
    assert_eq!(
        parse::parse_chrome(CHROME),
        Some(VersionsPatch {
            chrome_version: Some("155.0.0.0".to_owned()),
            ..VersionsPatch::default()
        })
    );
}

#[test]
fn chrome_without_a_numeric_stable_version_is_none() {
    for json in [
        "{}",
        "not json",
        r#"{"channels": {"Beta": {"version": "156.0.1.2"}}}"#,
        r#"{"channels": {"Stable": {"version": 155}}}"#,
        r#"{"channels": {"Stable": {"version": ""}}}"#,
        r#"{"channels": {"Stable": {"version": "x.0.1.2"}}}"#,
    ] {
        assert_eq!(parse::parse_chrome(json), None, "{json}");
    }
}

#[test]
fn firefox_latest_version_is_reduced_to_its_major() {
    assert_eq!(
        parse::parse_firefox(FIREFOX),
        Some(VersionsPatch {
            firefox_version: Some("150.0".to_owned()),
            ..VersionsPatch::default()
        })
    );
    assert_eq!(
        parse::parse_firefox(r#"{"LATEST_FIREFOX_VERSION": "151.0"}"#)
            .and_then(|p| p.firefox_version)
            .as_deref(),
        Some("151.0")
    );
}

#[test]
fn firefox_without_a_numeric_latest_version_is_none() {
    for json in [
        "{}",
        "[]",
        r#"{"FIREFOX_NIGHTLY": "152.0a1"}"#,
        r#"{"LATEST_FIREFOX_VERSION": null}"#,
        r#"{"LATEST_FIREFOX_VERSION": ""}"#,
        r#"{"LATEST_FIREFOX_VERSION": "esr.1"}"#,
    ] {
        assert_eq!(parse::parse_firefox(json), None, "{json}");
    }
}
