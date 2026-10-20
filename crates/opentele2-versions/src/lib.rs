//! Current official Telegram client versions, fetched from their public
//! release feeds, plus the stable Chrome and Firefox versions the web
//! fingerprints use, as a patch onto [`opentele2_core::api::Versions`].
//!
//! [`fetch_all`] queries the nine sources (Telegram Desktop, Android,
//! Telegram X, iOS, macOS, Web K, Web A, Chrome, Firefox) in parallel over
//! blocking HTTP with rustls and merges whatever answered into a
//! [`VersionsPatch`]. A source that fails or times out only leaves its fields
//! unset. [`VersionsPatch::apply`] writes the patch onto a [`Versions`] field
//! by field.
//!
//! The parsing of every response lives in [`parse`] as pure functions, so it
//! is testable without the network.

pub mod parse;

use std::thread;
use std::time::Duration;

use opentele2_core::api::Versions;
use serde_json::{Map, Value};
use ureq::Agent;

/// The default per-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The user agent sent to the JSON and plain-text sources.
pub const API_USER_AGENT: &str = "opentele2";

/// The browser user agent sent to `t.me`.
pub const TG_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";

const API_ACCEPT: &str = "application/json, text/plain, */*";
const TG_ACCEPT: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

const TDESKTOP_URL: &str = "https://api.github.com/repos/telegramdesktop/tdesktop/releases/latest";
const TELEGRAM_X_URL: &str = "https://api.github.com/repos/TGX-Android/Telegram-X/releases/latest";
// The percent-encoded searches "android versions:" and "ios versions:".
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
const CHROME_URL: &str =
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json";
const FIREFOX_URL: &str = "https://product-details.mozilla.org/1.0/firefox_versions.json";

/// A [`VersionsPatch`] field type, convertible to and from a JSON value for
/// [`VersionsPatch::to_map`] and [`VersionsPatch::from_map`].
trait PatchField: Sized {
    /// What [`VersionsPatch::from_map`] reports a wrongly typed value as.
    const EXPECTED: &'static str;

    fn to_value(&self) -> Value;

    fn from_value(value: &Value) -> Option<Self>;
}

impl PatchField for String {
    const EXPECTED: &'static str = "a string";

    fn to_value(&self) -> Value {
        Value::String(self.clone())
    }

    fn from_value(value: &Value) -> Option<Self> {
        value.as_str().map(str::to_owned)
    }
}

impl PatchField for u32 {
    const EXPECTED: &'static str = "an unsigned 32-bit integer";

    fn to_value(&self) -> Value {
        Value::from(*self)
    }

    fn from_value(value: &Value) -> Option<Self> {
        value.as_u64().and_then(|n| Self::try_from(n).ok())
    }
}

/// Declares [`VersionsPatch`] from one field list, so the struct,
/// [`VersionsPatch::FIELDS`], `merge`, `to_map` and `from_map` never drift
/// apart.
macro_rules! versions_patch {
    ($($(#[$doc:meta])* $field:ident: $ty:ty,)*) => {
        /// The fields of [`Versions`] the sources returned; `None` for every
        /// field no source answered with a non-empty value.
        #[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
        pub struct VersionsPatch {
            $($(#[$doc])* pub $field: Option<$ty>,)*
        }

        impl VersionsPatch {
            /// Every field name, in declaration order: the keys of
            /// [`VersionsPatch::to_map`] and [`VersionsPatch::from_map`].
            pub const FIELDS: &[&str] = &[$(stringify!($field)),*];

            /// Takes every field `other` sets, keeping the rest of `self`.
            pub fn merge(&mut self, other: Self) {
                $(
                    if other.$field.is_some() {
                        self.$field = other.$field;
                    }
                )*
            }

            /// The set fields keyed by field name, strings as JSON strings
            /// and numbers as JSON numbers; unset fields are absent.
            #[must_use]
            pub fn to_map(&self) -> Map<String, Value> {
                let mut map = Map::new();
                $(
                    if let Some(value) = &self.$field {
                        map.insert(stringify!($field).to_owned(), value.to_value());
                    }
                )*
                map
            }

            /// The patch [`VersionsPatch::to_map`] gives `map`; a missing key
            /// or a JSON `null` leaves the field unset.
            ///
            /// # Errors
            ///
            /// A key that is not in [`VersionsPatch::FIELDS`], or a value of
            /// the wrong type, is an error naming the key.
            pub fn from_map(map: &Map<String, Value>) -> Result<Self, String> {
                let mut patch = Self::default();
                for (key, value) in map {
                    match key.as_str() {
                        $(
                            stringify!($field) => {
                                patch.$field = from_json(key, value)?;
                            }
                        )*
                        _ => return Err(format!("unknown VersionsPatch field `{key}`")),
                    }
                }
                Ok(patch)
            }
        }
    };
}

fn from_json<T: PatchField>(key: &str, value: &Value) -> Result<Option<T>, String> {
    if value.is_null() {
        return Ok(None);
    }
    T::from_value(value)
        .map(Some)
        .ok_or_else(|| format!("VersionsPatch field `{key}` must be {}", T::EXPECTED))
}

versions_patch! {
    /// Latest Telegram Desktop release. Reported but never applied: the
    /// desktop version is bound to the version written into tdata.
    desktop_app_version: String,
    /// Telegram Android version.
    android_app_version: String,
    /// Telegram Android version code.
    android_app_version_code: u32,
    /// Telegram X version.
    android_x_app_version: String,
    /// Telegram iOS version.
    ios_app_version: String,
    /// Telegram iOS build number.
    ios_build_number: u32,
    /// Telegram for macOS version.
    macos_app_version: String,
    /// Telegram for macOS build number.
    macos_build_number: u32,
    /// Telegram Web K version, with its ` K` suffix.
    web_k_version: String,
    /// Telegram Web A version, with its ` A` suffix.
    web_a_version: String,
    /// Stable Chrome version as its user agent reports it, `<major>.0.0.0`.
    chrome_version: String,
    /// Stable Firefox version as its user agent reports it, `<major>.0`.
    firefox_version: String,
}

impl VersionsPatch {
    /// Whether no field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Writes every set field onto `versions`: each field lands on the [`Versions`] field of the same name, except
    /// `desktop_app_version`, which stays bound to the tdata version, and
    /// `chrome_version`, which goes through
    /// [`Versions::set_chrome_version`] so the user agent follows it.
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
        if let Some(chrome_version) = &self.chrome_version {
            versions.set_chrome_version(chrome_version.as_str());
        }
        set(&mut versions.firefox_version, self.firefox_version.as_ref());
    }
}

type Source = fn(&Agent) -> Option<VersionsPatch>;

const SOURCES: [Source; 9] = [
    fetch_tdesktop,
    fetch_android,
    fetch_telegram_x,
    fetch_ios,
    fetch_macos,
    fetch_web_k,
    fetch_web_a,
    fetch_chrome,
    fetch_firefox,
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

fn fetch_chrome(agent: &Agent) -> Option<VersionsPatch> {
    parse::parse_chrome(&get_api(agent, CHROME_URL)?)
}

fn fetch_firefox(agent: &Agent) -> Option<VersionsPatch> {
    parse::parse_firefox(&get_api(agent, FIREFOX_URL)?)
}
