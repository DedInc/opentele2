//! Current official Telegram client versions, fetched from the public release
//! feeds 1.5.0 `src/version_fetcher.py` reads, as a patch onto
//! [`opentele2_core::api::Versions`].
//!
//! [`fetch_all`] queries the seven sources (Telegram Desktop, Android,
//! Telegram X, iOS, macOS, Web K, Web A) in parallel over blocking HTTP with
//! rustls and merges whatever answered into a [`VersionsPatch`]. A source that
//! fails or times out only leaves its fields unset. [`VersionsPatch::apply`]
//! writes the patch onto a [`Versions`] with 1.5.0's field mapping.
//!
//! The parsing of every response lives in [`parse`] as pure functions, so it
//! is testable without the network.

pub mod parse;

use std::thread;
use std::time::Duration;

use opentele2_core::api::Versions;
use ureq::Agent;

/// The per-request timeout of 1.5.0 (`_TIMEOUT`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The user agent 1.5.0 sends to the JSON and plain-text sources.
pub const API_USER_AGENT: &str = "opentele2";

/// The browser user agent 1.5.0 sends to `t.me` (`_TG_UA`).
pub const TG_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";

const API_ACCEPT: &str = "application/json, text/plain, */*";
const TG_ACCEPT: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

const TDESKTOP_URL: &str = "https://api.github.com/repos/telegramdesktop/tdesktop/releases/latest";
const TELEGRAM_X_URL: &str = "https://api.github.com/repos/TGX-Android/Telegram-X/releases/latest";
// `urllib.parse.quote` of "android versions:" and "ios versions:".
const TG_ANDROID_URL: &str = "https://t.me/s/tgstable?q=android%20versions%3A";
const TG_IOS_URL: &str = "https://t.me/s/tgstable?q=ios%20versions%3A";
const PLAY_ANDROID_URL: &str = "https://play.rajkumaar.co.in/json?id=org.telegram.messenger";
const ITUNES_IOS_URL: &str = "https://itunes.apple.com/lookup?id=686449807";
const BREW_MACOS_URL: &str = "https://formulae.brew.sh/api/cask/telegram.json";
const ITUNES_MACOS_URL: &str = "https://itunes.apple.com/lookup?id=747648890";
const WEB_K_URL: &str =
    "https://raw.githubusercontent.com/morethanwords/tweb/master/public/version";
const WEB_A_URL: &str =
    "https://raw.githubusercontent.com/Ajaxy/telegram-tt/refs/heads/master/public/version.txt";

/// The fields of [`Versions`] the sources returned; `None` for every field no
/// source answered with a non-empty value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct VersionsPatch {
    /// Latest Telegram Desktop release. Reported but never applied: the
    /// desktop version is bound to the version written into tdata.
    pub desktop_app_version: Option<String>,
    /// Telegram Android version.
    pub android_app_version: Option<String>,
    /// Telegram Android version code.
    pub android_app_version_code: Option<u32>,
    /// Telegram X version.
    pub android_x_app_version: Option<String>,
    /// Telegram iOS version.
    pub ios_app_version: Option<String>,
    /// Telegram iOS build number.
    pub ios_build_number: Option<u32>,
    /// Telegram for macOS version.
    pub macos_app_version: Option<String>,
    /// Telegram for macOS build number.
    pub macos_build_number: Option<u32>,
    /// Telegram Web K version, with its ` K` suffix.
    pub web_k_version: Option<String>,
    /// Telegram Web A version, with its ` A` suffix.
    pub web_a_version: Option<String>,
}

impl VersionsPatch {
    /// Whether no field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Takes every field `other` sets, keeping the rest of `self`.
    pub fn merge(&mut self, other: Self) {
        fn take<T>(into: &mut Option<T>, from: Option<T>) {
            if from.is_some() {
                *into = from;
            }
        }
        take(&mut self.desktop_app_version, other.desktop_app_version);
        take(&mut self.android_app_version, other.android_app_version);
        take(
            &mut self.android_app_version_code,
            other.android_app_version_code,
        );
        take(&mut self.android_x_app_version, other.android_x_app_version);
        take(&mut self.ios_app_version, other.ios_app_version);
        take(&mut self.ios_build_number, other.ios_build_number);
        take(&mut self.macos_app_version, other.macos_app_version);
        take(&mut self.macos_build_number, other.macos_build_number);
        take(&mut self.web_k_version, other.web_k_version);
        take(&mut self.web_a_version, other.web_a_version);
    }

    /// Writes every set field onto `versions` like 1.5.0
    /// `_apply_fetched_versions` (src/fingerprint.py:122-147): each field
    /// lands on the [`Versions`] field of the same name, except
    /// `desktop_app_version`, which stays bound to the tdata version.
    pub fn apply(&self, versions: &mut Versions) {
        fn set<T: Clone>(into: &mut T, from: Option<&T>) {
            if let Some(value) = from {
                into.clone_from(value);
            }
        }
        set(
            &mut versions.android_app_version,
            self.android_app_version.as_ref(),
        );
        set(
            &mut versions.android_app_version_code,
            self.android_app_version_code.as_ref(),
        );
        set(
            &mut versions.android_x_app_version,
            self.android_x_app_version.as_ref(),
        );
        set(&mut versions.ios_app_version, self.ios_app_version.as_ref());
        set(
            &mut versions.ios_build_number,
            self.ios_build_number.as_ref(),
        );
        set(
            &mut versions.macos_app_version,
            self.macos_app_version.as_ref(),
        );
        set(
            &mut versions.macos_build_number,
            self.macos_build_number.as_ref(),
        );
        set(&mut versions.web_k_version, self.web_k_version.as_ref());
        set(&mut versions.web_a_version, self.web_a_version.as_ref());
    }
}

type Source = fn(&Agent) -> Option<VersionsPatch>;

const SOURCES: [Source; 7] = [
    fetch_tdesktop,
    fetch_android,
    fetch_telegram_x,
    fetch_ios,
    fetch_macos,
    fetch_web_k,
    fetch_web_a,
];

/// Fetches every source in parallel, one thread each, and merges the
/// answers. `timeout` bounds each HTTP request; a source with a fallback
/// makes at most two.
///
/// Never fails: a source that errors, times out, or returns nothing usable
/// leaves its fields `None`, and with no network the patch is empty.
#[must_use]
pub fn fetch_all(timeout: Duration) -> VersionsPatch {
    let agent: Agent = Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into();
    let agent = &agent;
    thread::scope(|scope| {
        let handles: Vec<_> = SOURCES
            .into_iter()
            .map(|source| scope.spawn(move || source(agent)))
            .collect();
        let mut patch = VersionsPatch::default();
        // The sources set disjoint fields, so the merge order is irrelevant;
        // a panicking source is joined as an error and skipped.
        for handle in handles {
            if let Ok(Some(answer)) = handle.join() {
                patch.merge(answer);
            }
        }
        patch
    })
}

fn get(agent: &Agent, url: &str, user_agent: &str, accept: &str) -> Option<String> {
    agent
        .get(url)
        .header("User-Agent", user_agent)
        .header("Accept", accept)
        .call()
        .ok()?
        .body_mut()
        .read_to_string()
        .ok()
}

fn get_api(agent: &Agent, url: &str) -> Option<String> {
    get(agent, url, API_USER_AGENT, API_ACCEPT)
}

fn get_tg(agent: &Agent, url: &str) -> Option<String> {
    get(agent, url, TG_USER_AGENT, TG_ACCEPT)
}

fn fetch_tdesktop(agent: &Agent) -> Option<VersionsPatch> {
    parse::parse_tdesktop(&get_api(agent, TDESKTOP_URL)?)
}

fn fetch_android(agent: &Agent) -> Option<VersionsPatch> {
    get_tg(agent, TG_ANDROID_URL)
        .as_deref()
        .and_then(parse::parse_android_tgstable)
        .or_else(|| parse::parse_android_play(&get_api(agent, PLAY_ANDROID_URL)?))
}

fn fetch_telegram_x(agent: &Agent) -> Option<VersionsPatch> {
    parse::parse_telegram_x(&get_api(agent, TELEGRAM_X_URL)?)
}

fn fetch_ios(agent: &Agent) -> Option<VersionsPatch> {
    get_tg(agent, TG_IOS_URL)
        .as_deref()
        .and_then(parse::parse_ios_tgstable)
        .or_else(|| parse::parse_ios_itunes(&get_api(agent, ITUNES_IOS_URL)?))
}

fn fetch_macos(agent: &Agent) -> Option<VersionsPatch> {
    get_api(agent, BREW_MACOS_URL)
        .as_deref()
        .and_then(parse::parse_macos_brew)
        .or_else(|| parse::parse_macos_itunes(&get_api(agent, ITUNES_MACOS_URL)?))
}

fn fetch_web_k(agent: &Agent) -> Option<VersionsPatch> {
    parse::parse_web_k(&get_api(agent, WEB_K_URL)?)
}

fn fetch_web_a(agent: &Agent) -> Option<VersionsPatch> {
    parse::parse_web_a(&get_api(agent, WEB_A_URL)?)
}
