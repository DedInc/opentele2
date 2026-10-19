//! The official Telegram client API profiles of opentele2 1.5.0.
//!
//! 1.5.0 (`src/api.py`) defines one class per official client with its
//! `api_id`, `api_hash`, default device and version fields, then rewrites the
//! app versions from `PlatformVersions` (`src/fingerprint.py`) on import in
//! `_sync_api_versions`. [`profile`] returns a class's values after that
//! rewrite for a given [`Versions`]; [`generate`] and [`generate_desktop`]
//! reproduce the classes' `Generate`, which keeps those values and replaces
//! the device with one picked by [`crate::devices`].
//!
//! 1.5.0 may override [`Versions`] with versions fetched from the network;
//! the core never fetches, so the host passes them in. [`Versions::offline`]
//! is the set 1.5.0 uses when fetching is off (`OPENTELE_NO_FETCH`).
//!
//! [`ApiProfile::from_session_json`] and [`ApiProfile::to_session_json`]
//! read and write the session JSON of 1.5.0 `APIData.from_json` and
//! `APIData.to_json`.

use std::hash::{Hash, Hasher};

use serde_json::{Map, Value};

use crate::devices::{self, Platform, WebClient};
use crate::{Error, Result};

/// The TL schema layer opentele2 advertises to Telegram (1.5.0 `LAYER`,
/// `_ADVERTISED_LAYER`): the `// LAYER 230` of the `api.tl` shipped by
/// Telegram Desktop 7.3.1. It is a fixed property of the targeted schema,
/// independent of the layer any `MTProto` library in use was built for.
pub const LAYER: i32 = 230;

/// The browser user agent of Chrome `chrome_version` on 64-bit Windows, the
/// shape of 1.5.0 `PlatformVersions.user_agent` and `_DEFAULT_WEB_USER_AGENT`.
fn windows_chrome_user_agent(chrome_version: &str) -> String {
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36"
    )
}

/// The `api_id` and `api_hash` shared by every web client.
const WEB_API_ID: i32 = 2496;
const WEB_API_HASH: &str = "8da85b0d5bfe62527e5b244c209159c3";

/// An official Telegram client whose API profile 1.5.0 ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Client {
    /// Telegram Desktop (`API.TelegramDesktop`).
    Desktop,
    /// Telegram Android (`API.TelegramAndroid`).
    Android,
    /// Telegram X for Android (`API.TelegramAndroidX`).
    AndroidX,
    /// Telegram iOS (`API.TelegramIOS`).
    Ios,
    /// Telegram for macOS, the Swift client (`API.TelegramMacOS`).
    MacOS,
    /// Telegram Web A (`API.TelegramWeb_A`); `API.TelegramWeb_Z` is an alias.
    WebA,
    /// Telegram Web K (`API.TelegramWeb_K`).
    WebK,
    /// Webogram (`API.Webogram`).
    Webogram,
}

impl Client {
    /// Every client, in 1.5.0's declaration order.
    pub const ALL: [Self; 8] = [
        Self::Desktop,
        Self::Android,
        Self::AndroidX,
        Self::Ios,
        Self::MacOS,
        Self::WebA,
        Self::WebK,
        Self::Webogram,
    ];

    /// Whether the client is a web client, whose devices are browser
    /// fingerprints picked from the web catalog.
    #[must_use]
    pub fn is_web(self) -> bool {
        matches!(self, Self::WebA | Self::WebK | Self::Webogram)
    }
}

/// Every field of 1.5.0 `PlatformVersions`, in its declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Versions {
    /// Telegram Android version, for example `13.0.3`.
    pub android_app_version: String,
    /// Telegram Android version code, for example `7183`.
    pub android_app_version_code: u32,
    /// Inclusive range of Android SDK levels generated devices run, for
    /// example `(29, 37)`.
    pub android_sdk_range: (u32, u32),
    /// The newest Android SDK level, for example `37`.
    pub android_latest_sdk: u32,
    /// Telegram iOS version, for example `13.0`.
    pub ios_app_version: String,
    /// Telegram iOS build number, for example `35303`.
    pub ios_build_number: u32,
    /// Inclusive range of iOS versions generated devices run, for example
    /// `("18.0", "27.0.1")`.
    pub ios_version_range: (String, String),
    /// The iOS version the default iOS profile reports.
    pub ios_system_version: String,
    /// The macOS version the default macOS profile reports.
    pub macos_system_version: String,
    /// Telegram Desktop version; bound to the version written into tdata.
    pub desktop_app_version: String,
    /// Architecture suffix of the default desktop app version; empty for
    /// none.
    pub desktop_app_version_suffix: String,
    /// Telegram for macOS version, for example `13.0`.
    pub macos_app_version: String,
    /// Telegram for macOS build number, for example `283305`.
    pub macos_build_number: u32,
    /// Telegram X version, for example `0.29.1.1817`.
    pub android_x_app_version: String,
    /// Telegram Web A version, for example `12.0.47 A`.
    pub web_a_version: String,
    /// Telegram Web K version, for example `2.2 K`.
    pub web_k_version: String,
    /// Chrome version of the web user agent, for example `155.0.0.0`.
    pub chrome_version: String,
    /// The browser user agent the web clients report as their device in
    /// their default [`profile`]; [`generate`] picks one from the web catalog
    /// instead.
    pub user_agent: String,
}

impl Versions {
    /// The offline defaults of 1.5.0 `PlatformVersions`.
    ///
    /// The user agent is Chrome [`Versions::chrome_version`] on 64-bit
    /// Windows, which is 1.5.0's default user agent.
    #[must_use]
    pub fn offline() -> Self {
        let chrome_version = "155.0.0.0".to_owned();
        Self {
            android_app_version: "13.0.3".to_owned(),
            android_app_version_code: 7183,
            android_sdk_range: (29, 37),
            android_latest_sdk: 37,
            ios_app_version: "13.0".to_owned(),
            ios_build_number: 35303,
            ios_version_range: ("18.0".to_owned(), "27.0.1".to_owned()),
            ios_system_version: "27.0.1".to_owned(),
            macos_system_version: "27.0.1".to_owned(),
            desktop_app_version: desktop_version_string(crate::tdata::APP_VERSION),
            desktop_app_version_suffix: "x64".to_owned(),
            macos_app_version: "13.0".to_owned(),
            macos_build_number: 283_305,
            android_x_app_version: "0.29.1.1817".to_owned(),
            web_a_version: "12.0.47 A".to_owned(),
            web_k_version: "2.2 K".to_owned(),
            user_agent: windows_chrome_user_agent(&chrome_version),
            chrome_version,
        }
    }
}

/// 1.5.0 `format_app_version`: `major.minor.patch`, without a zero patch.
fn desktop_version_string(version: u32) -> String {
    let major = version / 1_000_000;
    let minor = version / 1000 % 1000;
    let patch = version % 1000;
    if patch == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{major}.{minor}.{patch}")
    }
}

/// The values a client sends in `initConnection`.
///
/// Equality and hashing use `api_id`, `api_hash`, `device_model`,
/// `system_version` and `app_version` only, as 1.5.0 `APIData.__eq__` and
/// `__hash__` do. The language fields are excluded on purpose: profiles
/// that differ only in language are the same client on the same device.
#[derive(Debug, Clone)]
pub struct ApiProfile {
    /// The application id.
    pub api_id: i32,
    /// The application hash.
    pub api_hash: String,
    /// The device model.
    pub device_model: String,
    /// The system version.
    pub system_version: String,
    /// The application version.
    pub app_version: String,
    /// The interface language code.
    pub lang_code: String,
    /// The system language code.
    pub system_lang_code: String,
    /// The language pack name; empty for none.
    pub lang_pack: String,
}

impl ApiProfile {
    /// The fields 1.5.0 compares and hashes.
    fn identity(&self) -> (i32, &str, &str, &str, &str) {
        (
            self.api_id,
            &self.api_hash,
            &self.device_model,
            &self.system_version,
            &self.app_version,
        )
    }

    /// Reads a profile from session JSON as 1.5.0 `APIData.from_json` does.
    ///
    /// `app_id`, `app_hash`, `device`, `sdk` and `app_version` give the
    /// credentials, device and versions. `lang_code` defaults to `en` and
    /// `lang_pack` to empty. `system_lang_code` is taken when it is a
    /// non-empty string, and otherwise falls back to `system_lang_pack`,
    /// which defaults to `en`. A JSON `null` counts as an absent key; every
    /// other key is ignored.
    ///
    /// Unlike 1.5.0, which leaves a missing `sdk` or `app_version` unset and
    /// fills a missing `device` from the local machine, those keys are
    /// required here.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] with [`std::io::ErrorKind::InvalidData`] when `data` is
    /// not an object, `app_id` is absent or not an integer that fits `i32`,
    /// one of `app_hash`, `device`, `sdk` and `app_version` is absent or not a
    /// string, or a language key holds something other than a string or
    /// `null`.
    pub fn from_session_json(data: &Value) -> Result<Self> {
        let Value::Object(data) = data else {
            return Err(invalid_session_json("the session JSON is not an object"));
        };
        let api_id = match data.get("app_id") {
            Some(Value::Number(number)) => number
                .as_i64()
                .and_then(|id| i32::try_from(id).ok())
                .ok_or_else(|| invalid_session_json("app_id is not an i32 integer"))?,
            _ => return Err(invalid_session_json("app_id is missing or not an integer")),
        };
        let required = |key: &str| -> Result<String> {
            optional_text(data, key)?
                .ok_or_else(|| invalid_session_json(&format!("{key} is missing")))
        };
        // 1.5.0 reads `system_lang_code or system_lang_pack`: an empty code
        // falls back too.
        let system_lang_code = match optional_text(data, "system_lang_code")? {
            Some(code) if !code.is_empty() => code,
            _ => optional_text(data, "system_lang_pack")?.unwrap_or_else(|| "en".to_owned()),
        };
        Ok(Self {
            api_id,
            api_hash: required("app_hash")?,
            device_model: required("device")?,
            system_version: required("sdk")?,
            app_version: required("app_version")?,
            lang_code: optional_text(data, "lang_code")?.unwrap_or_else(|| "en".to_owned()),
            system_lang_code,
            lang_pack: optional_text(data, "lang_pack")?.unwrap_or_default(),
        })
    }

    /// The session JSON 1.5.0 `APIData.to_json(extra)` writes, keys in its
    /// order.
    ///
    /// The profile's keys come first: `app_id`, `app_hash`, `device`, `sdk`,
    /// `app_version`, `system_lang_pack` and `system_lang_code` (both the
    /// system language code), `lang_pack`, `lang_code`. The 19 account keys
    /// of 1.5.0 `_DEFAULT_EXTRA_FIELDS` follow with their default values.
    /// `extra` overrides those values in place and appends its other keys in
    /// its own order; an `extra` key naming a profile key overrides that key
    /// in place too.
    #[must_use]
    pub fn to_session_json(&self, extra: Option<&Map<String, Value>>) -> Value {
        let mut result = Map::new();
        result.insert("app_id".to_owned(), self.api_id.into());
        result.insert("app_hash".to_owned(), self.api_hash.clone().into());
        result.insert("device".to_owned(), self.device_model.clone().into());
        result.insert("sdk".to_owned(), self.system_version.clone().into());
        result.insert("app_version".to_owned(), self.app_version.clone().into());
        result.insert(
            "system_lang_pack".to_owned(),
            self.system_lang_code.clone().into(),
        );
        result.insert(
            "system_lang_code".to_owned(),
            self.system_lang_code.clone().into(),
        );
        result.insert("lang_pack".to_owned(), self.lang_pack.clone().into());
        result.insert("lang_code".to_owned(), self.lang_code.clone().into());
        let mut extra_fields = default_extra_fields();
        if let Some(extra) = extra {
            // Inserting an existing key keeps its position, as `dict.update`.
            extra_fields.extend(extra.clone());
        }
        result.extend(extra_fields);
        Value::Object(result)
    }
}

impl PartialEq for ApiProfile {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for ApiProfile {}

impl Hash for ApiProfile {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

/// 1.5.0 `_DEFAULT_EXTRA_FIELDS`, in its order.
fn default_extra_fields() -> Map<String, Value> {
    let fields = [
        ("twoFA", Value::Null),
        ("role", Value::from("")),
        ("id", Value::Null),
        ("phone", Value::Null),
        ("username", Value::Null),
        ("date_of_birth", Value::Null),
        ("date_of_birth_integrity", Value::Null),
        ("is_premium", Value::Bool(false)),
        ("has_profile_pic", Value::Bool(false)),
        ("spamblock", Value::Null),
        ("register_time", Value::Null),
        ("last_check_time", Value::Null),
        ("avatar", Value::Null),
        ("first_name", Value::from("")),
        ("last_name", Value::from("")),
        ("sex", Value::Null),
        ("proxy", Value::Null),
        ("ipv6", Value::Bool(false)),
        ("session_file", Value::from("")),
    ];
    fields
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// The string at `key`, `None` when the key is absent or `null`.
fn optional_text(data: &Map<String, Value>, key: &str) -> Result<Option<String>> {
    match data.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(invalid_session_json(&format!("{key} is not a string"))),
    }
}

/// The error of malformed session JSON, shaped as the core's other malformed
/// JSON errors.
fn invalid_session_json(reason: &str) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("invalid session JSON: {reason}"),
    ))
}

/// The default profile of `client` after 1.5.0 `_sync_api_versions` applied
/// `versions`.
///
/// iOS and macOS app versions end in a space, as in 1.5.0.
#[must_use]
pub fn profile(client: Client, versions: &Versions) -> ApiProfile {
    let (api_id, api_hash, device_model, system_version, app_version, lang_pack) = match client {
        Client::Desktop => (
            2040,
            "b18441a1ff607e10a989891a5462e627",
            "Desktop",
            "Windows 11 x64".to_owned(),
            if versions.desktop_app_version_suffix.is_empty() {
                versions.desktop_app_version.clone()
            } else {
                format!(
                    "{} {}",
                    versions.desktop_app_version, versions.desktop_app_version_suffix
                )
            },
            "tdesktop",
        ),
        Client::Android => (
            6,
            "eb06d4abfb49dc3eeb1aeb98ae0f581e",
            "samsungSM-S938B",
            "SDK 36".to_owned(),
            format!(
                "{} ({})",
                versions.android_app_version, versions.android_app_version_code
            ),
            "android",
        ),
        Client::AndroidX => (
            21724,
            "3e0cb5efcd52300aec5994fdfc5bdc16",
            "samsungSM-S938B",
            "SDK 36".to_owned(),
            versions.android_x_app_version.clone(),
            "android",
        ),
        Client::Ios => (
            10840,
            "33c45224029d59cb3ad0c16134215aeb",
            "iPhone 17 Pro",
            versions.ios_system_version.clone(),
            format!(
                "{} ({}) ",
                versions.ios_app_version, versions.ios_build_number
            ),
            "ios",
        ),
        Client::MacOS => (
            2834,
            "68875f756c9b437a8b916ca3de215815",
            "MacBook Air M4",
            versions.macos_system_version.clone(),
            format!(
                "{} ({}) ",
                versions.macos_app_version, versions.macos_build_number
            ),
            "macos",
        ),
        Client::WebA => (
            WEB_API_ID,
            WEB_API_HASH,
            versions.user_agent.as_str(),
            "Windows".to_owned(),
            versions.web_a_version.clone(),
            "",
        ),
        // 1.5.0 gives Web K the `macos` language pack.
        Client::WebK => (
            WEB_API_ID,
            WEB_API_HASH,
            versions.user_agent.as_str(),
            "Win32".to_owned(),
            versions.web_k_version.clone(),
            "macos",
        ),
        // `_sync_api_versions` leaves Webogram's version alone.
        Client::Webogram => (
            WEB_API_ID,
            WEB_API_HASH,
            versions.user_agent.as_str(),
            "Win32".to_owned(),
            "0.7.0".to_owned(),
            "",
        ),
    };
    ApiProfile {
        api_id,
        api_hash: api_hash.to_owned(),
        device_model: device_model.to_owned(),
        system_version,
        app_version,
        lang_code: "en".to_owned(),
        system_lang_code: "en-US".to_owned(),
        lang_pack: lang_pack.to_owned(),
    }
}

/// The profile 1.5.0 `API.<client>.Generate(seed)` returns: the default
/// profile with a device picked for `seed`, or a random device without one.
///
/// [`Client::Desktop`] behaves as [`generate_desktop`] without a system.
/// The web clients pick a browser from the web catalog instead of 1.5.0's
/// browserforge fingerprints: the user agent becomes the device model and
/// the client's platform string the system version (Web A as
/// [`WebClient::A`], Web K and Webogram as [`WebClient::K`]).
///
/// # Errors
///
/// The errors of [`devices::pick`].
pub fn generate(client: Client, seed: Option<&str>, versions: &Versions) -> Result<ApiProfile> {
    let platform = match client {
        Client::Desktop => return generate_desktop(None, seed, versions),
        Client::Android | Client::AndroidX => Platform::Android,
        Client::Ios => Platform::Ios,
        Client::MacOS => Platform::MacOS { swift: true },
        Client::WebA => Platform::Web {
            client: WebClient::A,
        },
        Client::WebK | Client::Webogram => Platform::Web {
            client: WebClient::K,
        },
    };
    let device = devices::pick(platform, seed)?;
    Ok(ApiProfile {
        device_model: device.model,
        system_version: device.system_version,
        ..profile(client, versions)
    })
}

/// The platform names 1.5.0 `API.TelegramDesktop.Generate` accepts, matched
/// case-sensitively (`_DESKTOP_SYSTEMS`).
fn desktop_platform(system: &str) -> Option<Platform> {
    match system {
        "windows" => Some(Platform::Windows),
        "macos" => Some(Platform::MacOS { swift: false }),
        "linux" => Some(Platform::Linux),
        _ => None,
    }
}

/// The profile 1.5.0 `API.TelegramDesktop.Generate(system, seed)` returns.
///
/// `system` is `windows`, `macos` or `linux`. As in 1.5.0, a `system` that is
/// none of these is taken as the seed when no seed is given, and the
/// platform is then chosen from the seed's hash, as it is when `system` is
/// absent or unknown. The app version gets the architecture the platform's
/// builds report: ` x64` on Windows, ` arm64` on macOS, none on Linux.
///
/// # Errors
///
/// The errors of [`devices::desktop_system`] and [`devices::pick`].
pub fn generate_desktop(
    system: Option<&str>,
    seed: Option<&str>,
    versions: &Versions,
) -> Result<ApiProfile> {
    let (system, seed) = match (system, seed) {
        (Some(name), None) if desktop_platform(name).is_none() => (None, Some(name)),
        other => other,
    };
    let platform = match system.and_then(desktop_platform) {
        Some(platform) => platform,
        None => devices::desktop_system(seed)?,
    };
    let device = devices::pick(platform, seed)?;
    let version = &versions.desktop_app_version;
    let app_version = match platform {
        Platform::Windows => format!("{version} x64"),
        Platform::MacOS { .. } => format!("{version} arm64"),
        _ => version.clone(),
    };
    Ok(ApiProfile {
        device_model: device.model,
        system_version: device.system_version,
        app_version,
        ..profile(Client::Desktop, versions)
    })
}
