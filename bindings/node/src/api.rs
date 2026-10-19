//! API profiles, device fingerprints, `PlatformVersions` and the session
//! JSON of 1.5.0 `APIData`.

use napi::bindgen_prelude::{BigInt, Either3};
use napi_derive::napi;
use serde_json::{Map, Value};

use opentele2_core::api::{self, ApiProfile as CoreProfile, Client, Versions as CoreVersions};

use crate::convert::to_seed;
use crate::error::{Result, check, invalid_arg};

/// The TL schema layer opentele2 advertises (1.5.0 `LAYER`): the layer of
/// the `api.tl` shipped by Telegram Desktop 7.3.1.
#[napi]
pub const LAYER: i32 = api::LAYER;

/// The 1.5.0 class name of every client, in declaration order.
const CLIENT_NAMES: [(&str, Client); 8] = [
    ("TelegramDesktop", Client::Desktop),
    ("TelegramAndroid", Client::Android),
    ("TelegramAndroidX", Client::AndroidX),
    ("TelegramIOS", Client::Ios),
    ("TelegramMacOS", Client::MacOS),
    ("TelegramWeb_A", Client::WebA),
    ("TelegramWeb_K", Client::WebK),
    ("Webogram", Client::Webogram),
];

/// The client named `name`; an unknown name throws
/// `ERR_INVALID_ARG_VALUE`.
fn client(name: String) -> Result<Client> {
    CLIENT_NAMES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, client)| *client)
        .ok_or_else(move || {
            let known: Vec<&str> = CLIENT_NAMES.iter().map(|(known, _)| *known).collect();
            invalid_arg(format!(
                "unknown client {name:?}; expected one of {}",
                known.join(", ")
            ))
        })
}

/// The values a client sends in `initConnection`, with its API id and hash.
#[napi(object)]
pub struct ApiProfile {
    /// API id.
    pub api_id: i32,
    /// API hash.
    pub api_hash: String,
    /// `initConnection.deviceModel`.
    pub device_model: String,
    /// `initConnection.systemVersion`.
    pub system_version: String,
    /// `initConnection.appVersion`.
    pub app_version: String,
    /// `initConnection.langCode`.
    pub lang_code: String,
    /// `initConnection.systemLangCode`.
    pub system_lang_code: String,
    /// `initConnection.langPack`.
    pub lang_pack: String,
}

impl From<CoreProfile> for ApiProfile {
    fn from(profile: CoreProfile) -> Self {
        Self {
            api_id: profile.api_id,
            api_hash: profile.api_hash,
            device_model: profile.device_model,
            system_version: profile.system_version,
            app_version: profile.app_version,
            lang_code: profile.lang_code,
            system_lang_code: profile.system_lang_code,
            lang_pack: profile.lang_pack,
        }
    }
}

impl From<ApiProfile> for CoreProfile {
    fn from(profile: ApiProfile) -> Self {
        Self {
            api_id: profile.api_id,
            api_hash: profile.api_hash,
            device_model: profile.device_model,
            system_version: profile.system_version,
            app_version: profile.app_version,
            lang_code: profile.lang_code,
            system_lang_code: profile.system_lang_code,
            lang_pack: profile.lang_pack,
        }
    }
}

/// Overrides of the offline `PlatformVersions` fields; every field is
/// optional, and a full `PlatformVersions` is one.
#[napi(object, object_to_js = false)]
pub struct Versions {
    /// Telegram Android version, for example `"11.4.2"`.
    pub android_app_version: Option<String>,
    /// Telegram Android build code.
    pub android_app_version_code: Option<u32>,
    /// Inclusive range of Android SDK levels, as `[low, high]`.
    pub android_sdk_range: Option<(u32, u32)>,
    /// The newest Android SDK level.
    pub android_latest_sdk: Option<u32>,
    /// Telegram iOS version.
    pub ios_app_version: Option<String>,
    /// Telegram iOS build number.
    pub ios_build_number: Option<u32>,
    /// Inclusive range of iOS versions, as `[low, high]`.
    pub ios_version_range: Option<(String, String)>,
    /// iOS system version.
    pub ios_system_version: Option<String>,
    /// macOS system version.
    pub macos_system_version: Option<String>,
    /// Telegram Desktop version.
    pub desktop_app_version: Option<String>,
    /// Telegram Desktop version suffix.
    pub desktop_app_version_suffix: Option<String>,
    /// Telegram for macOS version.
    pub macos_app_version: Option<String>,
    /// Telegram for macOS build number.
    pub macos_build_number: Option<u32>,
    /// Telegram X version.
    pub android_x_app_version: Option<String>,
    /// Telegram Web A version.
    pub web_a_version: Option<String>,
    /// Telegram Web K version.
    pub web_k_version: Option<String>,
    /// Chrome version of the web user agent.
    pub chrome_version: Option<String>,
    /// The browser user agent of the default web profiles; independent of
    /// `chromeVersion`, as in the core.
    pub user_agent: Option<String>,
}

/// Every field of 1.5.0 `PlatformVersions`.
#[napi(object, object_from_js = false)]
pub struct PlatformVersions {
    /// Telegram Android version, for example `"13.0.3"`.
    pub android_app_version: String,
    /// Telegram Android version code, for example `7183`.
    pub android_app_version_code: u32,
    /// Inclusive range of Android SDK levels generated devices run, as
    /// `[low, high]`.
    pub android_sdk_range: (u32, u32),
    /// The newest Android SDK level.
    pub android_latest_sdk: u32,
    /// Telegram iOS version.
    pub ios_app_version: String,
    /// Telegram iOS build number.
    pub ios_build_number: u32,
    /// Inclusive range of iOS versions generated devices run, as
    /// `[low, high]`.
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
    /// Telegram for macOS version.
    pub macos_app_version: String,
    /// Telegram for macOS build number.
    pub macos_build_number: u32,
    /// Telegram X version.
    pub android_x_app_version: String,
    /// Telegram Web A version.
    pub web_a_version: String,
    /// Telegram Web K version.
    pub web_k_version: String,
    /// Chrome version of the web user agent.
    pub chrome_version: String,
    /// The browser user agent the default web profiles report.
    pub user_agent: String,
}

impl From<CoreVersions> for PlatformVersions {
    fn from(versions: CoreVersions) -> Self {
        Self {
            android_app_version: versions.android_app_version,
            android_app_version_code: versions.android_app_version_code,
            android_sdk_range: versions.android_sdk_range,
            android_latest_sdk: versions.android_latest_sdk,
            ios_app_version: versions.ios_app_version,
            ios_build_number: versions.ios_build_number,
            ios_version_range: versions.ios_version_range,
            ios_system_version: versions.ios_system_version,
            macos_system_version: versions.macos_system_version,
            desktop_app_version: versions.desktop_app_version,
            desktop_app_version_suffix: versions.desktop_app_version_suffix,
            macos_app_version: versions.macos_app_version,
            macos_build_number: versions.macos_build_number,
            android_x_app_version: versions.android_x_app_version,
            web_a_version: versions.web_a_version,
            web_k_version: versions.web_k_version,
            chrome_version: versions.chrome_version,
            user_agent: versions.user_agent,
        }
    }
}

/// Replaces `field` with `value` when it is set.
fn set<T>(field: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *field = value;
    }
}

/// The offline `PlatformVersions` with the fields of `overrides` replaced.
pub(crate) fn versions(overrides: Option<Versions>) -> CoreVersions {
    let mut versions = CoreVersions::offline();
    let Some(overrides) = overrides else {
        return versions;
    };
    let v = &mut versions;
    set(&mut v.android_app_version, overrides.android_app_version);
    set(
        &mut v.android_app_version_code,
        overrides.android_app_version_code,
    );
    set(&mut v.android_sdk_range, overrides.android_sdk_range);
    set(&mut v.android_latest_sdk, overrides.android_latest_sdk);
    set(&mut v.ios_app_version, overrides.ios_app_version);
    set(&mut v.ios_build_number, overrides.ios_build_number);
    set(&mut v.ios_version_range, overrides.ios_version_range);
    set(&mut v.ios_system_version, overrides.ios_system_version);
    set(&mut v.macos_system_version, overrides.macos_system_version);
    set(&mut v.desktop_app_version, overrides.desktop_app_version);
    set(
        &mut v.desktop_app_version_suffix,
        overrides.desktop_app_version_suffix,
    );
    set(&mut v.macos_app_version, overrides.macos_app_version);
    set(&mut v.macos_build_number, overrides.macos_build_number);
    set(
        &mut v.android_x_app_version,
        overrides.android_x_app_version,
    );
    set(&mut v.web_a_version, overrides.web_a_version);
    set(&mut v.web_k_version, overrides.web_k_version);
    set(&mut v.chrome_version, overrides.chrome_version);
    set(&mut v.user_agent, overrides.user_agent);
    versions
}

/// The offline `PlatformVersions` of 1.5.0 (`OPENTELE_NO_FETCH`), with the
/// fields of `overrides` replaced.
#[napi]
pub fn platform_versions(overrides: Option<Versions>) -> PlatformVersions {
    versions(overrides).into()
}

/// The default API profile of `client` (a 1.5.0 class name such as
/// `"TelegramDesktop"`), with `versions` overriding the offline
/// `PlatformVersions` fields.
#[napi]
pub fn profile(
    #[napi(
        ts_arg_type = "'TelegramDesktop' | 'TelegramAndroid' | 'TelegramAndroidX' | 'TelegramIOS' | 'TelegramMacOS' | 'TelegramWeb_A' | 'TelegramWeb_K' | 'Webogram'"
    )]
    client: String,
    versions: Option<Versions>,
) -> Result<ApiProfile> {
    let client = self::client(client)?;
    Ok(api::profile(client, &self::versions(versions)).into())
}

/// The profile 1.5.0 `API.<client>.Generate` returns: a device picked for
/// `seed` (a string, or an integer `number` or `bigint` as its decimal
/// text), random without one. `system` applies to `"TelegramDesktop"` only.
/// Web clients get a browser user agent picked from the web catalog.
#[napi]
pub fn generate(
    #[napi(
        ts_arg_type = "'TelegramDesktop' | 'TelegramAndroid' | 'TelegramAndroidX' | 'TelegramIOS' | 'TelegramMacOS' | 'TelegramWeb_A' | 'TelegramWeb_K' | 'Webogram'"
    )]
    client: String,
    seed: Option<Either3<String, f64, BigInt>>,
    #[napi(ts_arg_type = "'windows' | 'macos' | 'linux' | null")] system: Option<String>,
    versions: Option<Versions>,
) -> Result<ApiProfile> {
    let client = self::client(client)?;
    let seed = to_seed(seed)?;
    let versions = self::versions(versions);
    let generated = match (client, system) {
        (Client::Desktop, system) => {
            api::generate_desktop(system.as_deref(), seed.as_deref(), &versions)
        }
        (other, None) => api::generate(other, seed.as_deref(), &versions),
        (_, Some(_)) => return Err(invalid_arg("system applies only to TelegramDesktop")),
    };
    Ok(check(generated)?.into())
}

/// The profile 1.5.0 `APIData.from_json` reads from session JSON, given as
/// its text or as a parsed object. `app_id`, `app_hash`, `device`, `sdk` and
/// `app_version` are required; `lang_code` defaults to `"en"`, `lang_pack`
/// to `""`, and `system_lang_code` falls back to `system_lang_pack`, then
/// `"en"`. Malformed JSON or fields throw `OT_IO`.
#[napi]
pub fn profile_from_session_json(
    #[napi(ts_arg_type = "string | Record<string, unknown>")] json: Value,
) -> Result<ApiProfile> {
    // Session JSON is an object, so a string can only be its text.
    let data = match json {
        Value::String(text) => check(serde_json::from_str::<Value>(&text).map_err(|error| {
            opentele2_core::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid session JSON: {error}"),
            ))
        }))?,
        value => value,
    };
    Ok(check(CoreProfile::from_session_json(&data))?.into())
}

/// The session JSON 1.5.0 `APIData.to_json(extra)` writes, keys in its
/// order: the profile's keys, then the 19 account keys with their defaults.
/// `extra` overrides those keys in place and appends its other keys in its
/// own order. `JSON.stringify` of the result is 1.5.0's compact JSON.
#[napi(ts_return_type = "Record<string, unknown>")]
pub fn profile_to_session_json(
    profile: ApiProfile,
    #[napi(ts_arg_type = "Record<string, unknown> | null")] extra: Option<Map<String, Value>>,
) -> Value {
    // No extra keys write the same JSON as no `extra`.
    let extra = extra.unwrap_or_default();
    CoreProfile::from(profile).to_session_json(Some(&extra))
}

/// Whether `a` and `b` are the same client on the same device, as 1.5.0
/// `APIData.__eq__`: `apiId`, `apiHash`, `deviceModel`, `systemVersion`
/// and `appVersion` are compared; the language fields are not.
#[napi]
pub fn profiles_equal(a: ApiProfile, b: ApiProfile) -> bool {
    CoreProfile::from(a) == CoreProfile::from(b)
}
