//! Pure parsers, one per 1.5.0 source (src/version_fetcher.py:40-201), with
//! the same regexes, JSON paths and fallbacks, plus the Chrome and Firefox
//! release feeds 1.5.0 read for its web fingerprints.
//!
//! Each `parse_*` takes a response body and returns the fields it carries,
//! or `None` when the body yields nothing usable. For a source with a
//! fallback, `None` from the primary parser is what sends 1.5.0 to the
//! fallback URL. Empty strings are never set, matching 1.5.0
//! `fetch_all_versions`, which drops empty values before merging.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::Value;

use crate::VersionsPatch;

/// One version post of the `t.me/s/tgstable` channel page.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TgPost {
    /// The announced version, for example `13.0.3`.
    pub version: String,
    /// The build code in parentheses after it, for example `7183`.
    pub build_code: Option<u32>,
}

static MESSAGE_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    // The div carries more than one class ("tgme_widget_message_text js-...").
    Regex::new(r#"(?s)<div[^>]*class="tgme_widget_message_text(?:\s[^"]*)?"[^>]*>(.*?)</div>"#)
        .expect("valid message regex")
});
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new("<[^>]+>").expect("valid tag regex"));
static NEW_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)New\s+version\s*:\s*([^\s\(\)]+)(?:\s*\((\d+)\))?")
        .expect("valid version regex")
});
static ENTITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("&(?:#([0-9]+);?|#[xX]([0-9a-fA-F]+);?|([A-Za-z]+);)").expect("valid entity regex")
});

/// 1.5.0 `_parse_tg_messages`: the version posts of a `t.me/s` page, oldest
/// first as the page lists them.
///
/// A search for one platform also returns posts for the others, so
/// `platform` keeps only posts announcing "Telegram for `<platform>`".
#[must_use]
pub fn parse_tgstable(html: &str, platform: Option<&str>) -> Vec<TgPost> {
    // `regex::escape` keeps the pattern valid, so `Err` is unreachable.
    let Ok(platform) = platform
        .map(|name| Regex::new(&format!(r"(?i)Telegram\s+for\s+{}\b", regex::escape(name))))
        .transpose()
    else {
        return Vec::new();
    };
    MESSAGE_TEXT
        .captures_iter(html)
        .filter_map(|message| {
            let stripped = TAG.replace_all(&message[1], "");
            let text = unescape(stripped.trim());
            if platform.as_ref().is_some_and(|p| !p.is_match(&text)) {
                return None;
            }
            let found = NEW_VERSION.captures(&text)?;
            Some(TgPost {
                version: found[1].to_owned(),
                build_code: found.get(2).and_then(|code| code.as_str().parse().ok()),
            })
        })
        .collect()
}

/// The newest Android post of a `t.me/s/tgstable` page (1.5.0
/// `_fetch_android`, primary source).
#[must_use]
pub fn parse_android_tgstable(html: &str) -> Option<VersionsPatch> {
    let latest = parse_tgstable(html, Some("Android")).pop()?;
    Some(VersionsPatch {
        android_app_version: Some(latest.version),
        android_app_version_code: latest.build_code,
        ..VersionsPatch::default()
    })
}

/// `version` of the `play.rajkumaar.co.in` JSON (1.5.0 `_fetch_android`,
/// fallback).
#[must_use]
pub fn parse_android_play(json: &str) -> Option<VersionsPatch> {
    let version = non_empty(parse_json(json)?.get("version")?.as_str()?)?;
    Some(VersionsPatch {
        android_app_version: Some(version),
        ..VersionsPatch::default()
    })
}

/// The newest iOS post of a `t.me/s/tgstable` page (1.5.0 `_fetch_ios`,
/// primary source).
#[must_use]
pub fn parse_ios_tgstable(html: &str) -> Option<VersionsPatch> {
    let latest = parse_tgstable(html, Some("iOS")).pop()?;
    Some(VersionsPatch {
        ios_app_version: Some(latest.version),
        ios_build_number: latest.build_code,
        ..VersionsPatch::default()
    })
}

/// `results[0].version` of the iTunes lookup of app 686449807 (1.5.0
/// `_fetch_ios`, fallback).
#[must_use]
pub fn parse_ios_itunes(json: &str) -> Option<VersionsPatch> {
    Some(VersionsPatch {
        ios_app_version: Some(itunes_version(json)?),
        ..VersionsPatch::default()
    })
}

/// `tag_name` without leading `v` of the GitHub latest tdesktop release
/// (1.5.0 `_fetch_tdesktop`).
#[must_use]
pub fn parse_tdesktop(json: &str) -> Option<VersionsPatch> {
    Some(VersionsPatch {
        desktop_app_version: Some(release_tag(json)?),
        ..VersionsPatch::default()
    })
}

/// `tag_name` without leading `v` of the GitHub latest Telegram X release
/// (1.5.0 `_fetch_telegram_x`).
#[must_use]
pub fn parse_telegram_x(json: &str) -> Option<VersionsPatch> {
    Some(VersionsPatch {
        android_x_app_version: Some(release_tag(json)?),
        ..VersionsPatch::default()
    })
}

/// The `version` of the Homebrew `telegram` cask, `"<version>,<build>"`
/// (1.5.0 `_fetch_macos`, primary source).
///
/// A missing, non-string or empty `version` is `None`, the case in which
/// 1.5.0 falls back to iTunes. A non-numeric build is dropped, since
/// [`opentele2_core::api::Versions::macos_build_number`] is numeric.
#[must_use]
pub fn parse_macos_brew(json: &str) -> Option<VersionsPatch> {
    let raw = parse_json(json)?.get("version")?.as_str()?.to_owned();
    if raw.is_empty() {
        return None;
    }
    let Some((version, build)) = raw.split_once(',') else {
        return Some(VersionsPatch {
            macos_app_version: Some(raw),
            ..VersionsPatch::default()
        });
    };
    let build = build.trim();
    Some(VersionsPatch {
        macos_app_version: non_empty(version.trim()),
        macos_build_number: if build.bytes().all(|b| b.is_ascii_digit()) {
            build.parse().ok()
        } else {
            None
        },
        ..VersionsPatch::default()
    })
}

/// `results[0].version` of the iTunes lookup of app 747648890 (1.5.0
/// `_fetch_macos`, fallback).
#[must_use]
pub fn parse_macos_itunes(json: &str) -> Option<VersionsPatch> {
    Some(VersionsPatch {
        macos_app_version: Some(itunes_version(json)?),
        ..VersionsPatch::default()
    })
}

/// tweb `public/version`, for example `2.2 (680)`, as `2.2 K` (1.5.0
/// `_fetch_web_k`): the first non-empty line that is no merge-conflict
/// marker, cut before `(`.
#[must_use]
pub fn parse_web_k(text: &str) -> Option<VersionsPatch> {
    let lines: Vec<&str> = python_lines(text.trim())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let version_line = lines
        .iter()
        .find(|line| !["<<<", "===", ">>>"].iter().any(|m| line.starts_with(m)))
        .or(lines.first())
        .copied()
        .unwrap_or("");
    let version = match version_line.split_once('(') {
        Some((before, _)) => before.trim(),
        None => version_line,
    };
    Some(VersionsPatch {
        web_k_version: Some(format!("{version} K")),
        ..VersionsPatch::default()
    })
}

/// telegram-tt `public/version.txt`, for example `12.0.47`, as `12.0.47 A`
/// (1.5.0 `_fetch_web_a`).
#[must_use]
pub fn parse_web_a(text: &str) -> Option<VersionsPatch> {
    Some(VersionsPatch {
        web_a_version: Some(format!("{} A", text.trim())),
        ..VersionsPatch::default()
    })
}

/// `channels.Stable.version` of the Chrome for Testing
/// `last-known-good-versions.json`, for example `155.0.7790.110`, as the
/// reduced version Chrome's user agent reports, `155.0.0.0`.
///
/// A missing, non-string or non-numeric version is `None`.
#[must_use]
pub fn parse_chrome(json: &str) -> Option<VersionsPatch> {
    let version = parse_json(json)?;
    let major = major_version(version.pointer("/channels/Stable/version")?.as_str()?)?;
    Some(VersionsPatch {
        chrome_version: Some(format!("{major}.0.0.0")),
        ..VersionsPatch::default()
    })
}

/// `LATEST_FIREFOX_VERSION` of Mozilla's `firefox_versions.json`, for example
/// `150.0.1`, as the version Firefox's user agent reports, `150.0`.
///
/// A missing, non-string or non-numeric version is `None`.
#[must_use]
pub fn parse_firefox(json: &str) -> Option<VersionsPatch> {
    let version = parse_json(json)?;
    let major = major_version(version.get("LATEST_FIREFOX_VERSION")?.as_str()?)?;
    Some(VersionsPatch {
        firefox_version: Some(format!("{major}.0")),
        ..VersionsPatch::default()
    })
}

/// The leading `<major>` of a `<major>.<rest>` browser version, all digits
/// and not empty.
fn major_version(version: &str) -> Option<&str> {
    let major = version.trim().split('.').next()?;
    (!major.is_empty() && major.bytes().all(|b| b.is_ascii_digit())).then_some(major)
}

fn parse_json(json: &str) -> Option<Value> {
    serde_json::from_str(json).ok()
}

fn release_tag(json: &str) -> Option<String> {
    non_empty(
        parse_json(json)?
            .get("tag_name")?
            .as_str()?
            .trim_start_matches('v'),
    )
}

fn itunes_version(json: &str) -> Option<String> {
    non_empty(parse_json(json)?.pointer("/results/0/version")?.as_str()?)
}

fn non_empty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

/// Python `str.splitlines` boundaries.
fn python_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split([
        '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}',
    ])
}

/// The part of Python `html.unescape` a `t.me` page needs: decimal and hex
/// character references, and the named entities `amp`, `lt`, `gt`, `quot`,
/// `apos`, `nbsp`. Any other reference is kept verbatim.
fn unescape(text: &str) -> Cow<'_, str> {
    ENTITY.replace_all(text, |entity: &Captures<'_>| {
        let code = if let Some(decimal) = entity.get(1) {
            decimal.as_str().parse::<u32>().ok()
        } else if let Some(hex) = entity.get(2) {
            u32::from_str_radix(hex.as_str(), 16).ok()
        } else {
            let named = match &entity[3] {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                "nbsp" => '\u{a0}',
                _ => return entity[0].to_owned(),
            };
            return named.to_string();
        };
        // Like Python: NUL, surrogates and out-of-range code points become
        // U+FFFD.
        code.filter(|&c| c != 0)
            .and_then(char::from_u32)
            .unwrap_or('\u{fffd}')
            .to_string()
    })
}
