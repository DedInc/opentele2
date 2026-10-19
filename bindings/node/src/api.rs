//! API profiles and device fingerprints.

use napi::bindgen_prelude::{BigInt, Either3};
use napi_derive::napi;

use opentele2_core::api::{self, ApiProfile as CoreProfile, Client, Versions as CoreVersions};

use crate::convert::to_seed;
use crate::error::{Result, check, invalid_arg};

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
#[napi(object, object_from_js = false)]
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

/// Overrides of the offline `PlatformVersions` fields; every field is
/// optional.
#[napi(object, object_to_js = false)]
pub struct Versions {
    /// Telegram Android version, for example `"11.4.2"`.
    pub android_app_version: Option<String>,
    /// Telegram Android build code.
    pub android_app_version_code: Option<u32>,
    /// Telegram iOS version.
    pub ios_app_version: Option<String>,
    /// Telegram iOS build number.
    pub ios_build_number: Option<u32>,
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
}

/// Replaces `field` with `value` when it is set.
fn set<T>(field: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *field = value;
    }
}

/// The offline `PlatformVersions` with the fields of `overrides` replaced.
fn versions(overrides: Option<Versions>) -> CoreVersions {
    let mut versions = CoreVersions::offline();
    let Some(overrides) = overrides else {
        return versions;
    };
    set(
        &mut versions.android_app_version,
        overrides.android_app_version,
    );
    set(
        &mut versions.android_app_version_code,
        overrides.android_app_version_code,
    );
    set(&mut versions.ios_app_version, overrides.ios_app_version);
    set(&mut versions.ios_build_number, overrides.ios_build_number);
    set(
        &mut versions.ios_system_version,
        overrides.ios_system_version,
    );
    set(
        &mut versions.macos_system_version,
        overrides.macos_system_version,
    );
    set(
        &mut versions.desktop_app_version,
        overrides.desktop_app_version,
    );
    set(
        &mut versions.desktop_app_version_suffix,
        overrides.desktop_app_version_suffix,
    );
    set(&mut versions.macos_app_version, overrides.macos_app_version);
    set(
        &mut versions.macos_build_number,
        overrides.macos_build_number,
    );
    set(
        &mut versions.android_x_app_version,
        overrides.android_x_app_version,
    );
    set(&mut versions.web_a_version, overrides.web_a_version);
    set(&mut versions.web_k_version, overrides.web_k_version);
    versions
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
