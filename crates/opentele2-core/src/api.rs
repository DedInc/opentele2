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

use crate::devices::{self, Platform};
use crate::{Error, Result};

/// The browser user agent the web clients report by default
/// (`_DEFAULT_WEB_USER_AGENT`).
const DEFAULT_WEB_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";

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
    /// fingerprints that only the host can generate.
    #[must_use]
    pub fn is_web(self) -> bool {
        matches!(self, Self::WebA | Self::WebK | Self::Webogram)
    }
}

/// The `PlatformVersions` fields of 1.5.0 that the API profiles use.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Versions {
    /// Telegram Android version, for example `13.0.3`.
    pub android_app_version: String,
    /// Telegram Android version code, for example `7183`.
    pub android_app_version_code: u32,
    /// Telegram iOS version, for example `13.0`.
    pub ios_app_version: String,
    /// Telegram iOS build number, for example `35303`.
    pub ios_build_number: u32,
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
}

impl Versions {
    /// The offline defaults of 1.5.0 `PlatformVersions`.
    #[must_use]
    pub fn offline() -> Self {
        Self {
            android_app_version: "13.0.3".to_owned(),
            android_app_version_code: 7183,
            ios_app_version: "13.0".to_owned(),
            ios_build_number: 35303,
            ios_system_version: "27.0.1".to_owned(),
            macos_system_version: "27.0.1".to_owned(),
            desktop_app_version: desktop_version_string(crate::tdata::APP_VERSION),
            desktop_app_version_suffix: "x64".to_owned(),
            macos_app_version: "13.0".to_owned(),
            macos_build_number: 283_305,
            android_x_app_version: "0.29.1.1817".to_owned(),
            web_a_version: "12.0.47 A".to_owned(),
            web_k_version: "2.2 K".to_owned(),
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
            DEFAULT_WEB_USER_AGENT,
            "Windows".to_owned(),
            versions.web_a_version.clone(),
            "",
        ),
        // 1.5.0 gives Web K the `macos` language pack.
        Client::WebK => (
            WEB_API_ID,
            WEB_API_HASH,
            DEFAULT_WEB_USER_AGENT,
            "Win32".to_owned(),
            versions.web_k_version.clone(),
            "macos",
        ),
        // `_sync_api_versions` leaves Webogram's version alone.
        Client::Webogram => (
            WEB_API_ID,
            WEB_API_HASH,
            DEFAULT_WEB_USER_AGENT,
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
///
/// # Errors
///
/// [`Error::Io`] with [`std::io::ErrorKind::Unsupported`] for the web
/// clients: 1.5.0 fingerprints a browser for them, which needs browser data
/// and the network, so the host generates their devices and the core only
/// offers their default [`profile`]. Otherwise the errors of
/// [`devices::pick`].
pub fn generate(client: Client, seed: Option<&str>, versions: &Versions) -> Result<ApiProfile> {
    let platform = match client {
        Client::Desktop => return generate_desktop(None, seed, versions),
        Client::Android | Client::AndroidX => Platform::Android,
        Client::Ios => Platform::Ios,
        Client::MacOS => Platform::MacOS { swift: true },
        Client::WebA | Client::WebK | Client::Webogram => {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "web client devices are browser fingerprints generated by the host",
            )));
        }
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
