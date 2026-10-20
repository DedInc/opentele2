//! The `initConnection` fingerprint helpers (the Python package's
//! `opentele2.fingerprint`).

use napi::bindgen_prelude::{BigInt, Either, Env};
use napi_derive::napi;

use opentele2_core::api::ApiProfile as CoreProfile;
use opentele2_core::fingerprint::{
    self, FingerprintConfig as CoreConfig, FingerprintConfigOptions as CoreOptions,
    Issue as CoreIssue, IssueKind, RawInitParams, Severity, StrictMode,
};

use crate::api::{ApiProfile, Versions, versions};
use crate::convert::to_i64;
use crate::error::{Result, check, invalid_arg, thrown};

/// The TypeScript type of a strict mode.
const STRICT_MODE_TS: &str = "'off' | 'warn' | 'strict'";

/// One fingerprint finding, with the message reported for it.
#[napi(object)]
pub struct Issue {
    /// The check that failed.
    #[napi(
        ts_type = "'UnknownLangPack' | 'ShortLangCode' | 'MissingRegion' | 'EmptyDeviceModel' | 'EmptySystemVersion' | 'EmptyAppVersion' | 'ApiIdMismatch' | 'AppVersionMajor' | 'AndroidSdkRange'"
    )]
    pub kind: String,
    /// What is done with it: `'note'` is returned only (mode `'off'`),
    /// `'warning'` is warned about (`'warn'`), `'error'` is raised
    /// (`'strict'`).
    #[napi(ts_type = "'note' | 'warning' | 'error'")]
    pub severity: String,
    /// The message, character for character as the Python package words it.
    pub message: String,
}

impl From<CoreIssue> for Issue {
    fn from(issue: CoreIssue) -> Self {
        Self {
            kind: issue.kind.name().to_owned(),
            severity: issue.severity.name().to_owned(),
            message: issue.message,
        }
    }
}

/// The core issue of `issue`; an unknown kind or severity throws
/// `ERR_INVALID_ARG_VALUE`.
fn to_core_issue(issue: Issue) -> Result<CoreIssue> {
    let kind = &issue.kind;
    let severity = &issue.severity;
    Ok(CoreIssue {
        kind: IssueKind::from_name(kind)
            .ok_or_else(|| invalid_arg(format!("unknown issue kind {kind:?}")))?,
        severity: Severity::from_name(severity)
            .ok_or_else(|| invalid_arg(format!("unknown severity {severity:?}")))?,
        message: issue.message,
    })
}

/// `issues` as JavaScript objects.
pub(crate) fn to_js_issues(issues: Vec<CoreIssue>) -> Vec<Issue> {
    issues.into_iter().map(Issue::from).collect()
}

/// The mode named `value`; any other text throws `ERR_INVALID_ARG_VALUE`.
fn strict_mode(value: &str) -> Result<StrictMode> {
    StrictMode::from_value(value).ok_or_else(|| {
        invalid_arg(format!(
            "unknown strict mode {value:?}; expected one of {STRICT_MODE_TS}"
        ))
    })
}

/// The `tz_offset` Telegram Desktop sends in `initConnection` `params` for
/// a local UTC offset of `offsetSeconds` (`tdesktop_tz_offset`):
/// wrapped by whole days into -12 h..+14 h, then rounded to a multiple of
/// 900 seconds, halves away from zero. Pass
/// `-new Date().getTimezoneOffset() * 60` for the local offset.
#[napi]
pub fn tz_offset(offset_seconds: i32) -> f64 {
    fingerprint::tz_offset(offset_seconds)
}

/// The findings of `validate_init_connection_params` for `profile`,
/// with `strict` on exactly when `mode` is `'strict'` (default `'warn'`);
/// each finding has the severity of `mode`. `versions` overrides the
/// offline `PlatformVersions` the strict version check compares with.
#[napi]
pub fn validate_init_params(
    profile: ApiProfile,
    versions: Option<Versions>,
    #[napi(ts_arg_type = "'off' | 'warn' | 'strict'")] mode: Option<String>,
) -> Result<Vec<Issue>> {
    let mode = strict_mode(&mode.unwrap_or_else(|| "warn".to_owned()))?;
    let profile = CoreProfile::from(profile);
    let issues = fingerprint::validate_raw_init_params(
        &RawInitParams::from_profile(&profile),
        &self::versions(versions),
        mode,
    );
    Ok(to_js_issues(issues))
}

/// The findings of `_check_version_consistency` for `profile`, each
/// an `'error'`: the app version major of `android`, `ios`, `tdesktop` and
/// `macos` profiles, and the Android SDK level range.
#[napi]
pub fn check_versions(profile: ApiProfile, versions: Option<Versions>) -> Vec<Issue> {
    to_js_issues(fingerprint::check_versions(
        &profile.into(),
        &self::versions(versions),
    ))
}

/// The message `FingerprintConfig.validate_params` warns or raises
/// with: a header line, then one `  - ` line per issue.
#[napi]
pub fn issues_message(issues: Vec<Issue>) -> Result<String> {
    let issues = issues
        .into_iter()
        .map(to_core_issue)
        .collect::<Result<Vec<_>>>()?;
    Ok(fingerprint::issues_message(&issues))
}

/// The largest offset `msgIdOffset` draws, so a caller can draw from its
/// own random source in the same `0..=MSG_ID_OFFSET_MAX` range.
#[napi]
pub const MSG_ID_OFFSET_MAX: u16 = u16::MAX;

/// A random msg id offset in `0..=0xFFFF` from the operating system's
/// CSPRNG (`generate_msg_id_offset`).
#[napi]
pub fn msg_id_offset(env: Env) -> napi::Result<u32> {
    let offset = check(fingerprint::msg_id_offset_for_os());
    thrown(env, offset.map(u32::from))
}

/// Whether `msgId` is plausible at unix time `nowUnix`
/// (`is_valid_msg_id`): positive, odd when `fromClient` and even otherwise,
/// with its upper 32 bits within 300 seconds of `nowUnix`. `msgId` is a
/// `bigint`, or a `number` that is a safe integer. A fractional `nowUnix`
/// is truncated, as Python's `int(time.time())`.
#[napi]
pub fn is_valid_msg_id(
    msg_id: Either<BigInt, f64>,
    from_client: bool,
    now_unix: i64,
) -> Result<bool> {
    let msg_id = to_i64(msg_id, "msgId")?;
    Ok(fingerprint::is_valid_msg_id(msg_id, from_client, now_unix))
}

/// The fingerprint options of `FingerprintConfig`.
#[napi(object)]
pub struct FingerprintConfig {
    /// How consistency issues are handled.
    #[napi(ts_type = "'off' | 'warn' | 'strict'")]
    pub strict_mode: String,
    /// Whether `validateFingerprint` checks anything.
    pub auto_validate: bool,
    /// Preferred transport: `full`, `intermediate`, `abridged` or
    /// `obfuscated`.
    pub preferred_transport: String,
    /// Whether to warn when the library layer differs from the advertised
    /// one.
    pub warn_on_layer_mismatch: bool,
    /// The layer used in `invokeWithLayer` instead of the default.
    pub layer_override: Option<i32>,
    /// Whether msg ids get a small random offset.
    pub randomize_msg_id_offset: bool,
    /// The msg id offset, in `0..=0xFFFF`.
    pub msg_id_offset: u32,
}

/// Options of `fingerprintConfig`; every field is optional.
#[napi(object, object_to_js = false)]
pub struct FingerprintConfigOptions {
    /// How consistency issues are handled; default `'warn'`.
    #[napi(ts_type = "'off' | 'warn' | 'strict'")]
    pub strict_mode: Option<String>,
    /// Whether `validateFingerprint` checks anything; default `true`.
    pub auto_validate: Option<bool>,
    /// Preferred transport; default `'obfuscated'`.
    pub preferred_transport: Option<String>,
    /// Whether to warn on a layer mismatch; default `true`.
    pub warn_on_layer_mismatch: Option<bool>,
    /// The layer used in `invokeWithLayer`; none by default.
    pub layer_override: Option<i32>,
    /// Whether msg ids get a small random offset; default `true`.
    pub randomize_msg_id_offset: Option<bool>,
    /// The msg id offset; drawn from the OS random source by default.
    pub msg_id_offset: Option<u32>,
}

/// A msg id offset given as a `number`; outside `0..=0xFFFF` throws
/// `ERR_INVALID_ARG_VALUE`.
fn to_offset(value: u32) -> Result<u16> {
    fingerprint::to_offset(i64::from(value))
        .ok_or_else(|| invalid_arg("msgIdOffset must be in 0..=0xFFFF"))
}

impl From<CoreConfig> for FingerprintConfig {
    fn from(config: CoreConfig) -> Self {
        Self {
            strict_mode: config.strict_mode.as_str().to_owned(),
            auto_validate: config.auto_validate,
            preferred_transport: config.preferred_transport,
            warn_on_layer_mismatch: config.warn_on_layer_mismatch,
            layer_override: config.layer_override,
            randomize_msg_id_offset: config.randomize_msg_id_offset,
            msg_id_offset: u32::from(config.msg_id_offset),
        }
    }
}

/// The core config of `config`.
fn to_core_config(config: FingerprintConfig) -> Result<CoreConfig> {
    Ok(CoreConfig {
        strict_mode: strict_mode(&config.strict_mode)?,
        auto_validate: config.auto_validate,
        preferred_transport: config.preferred_transport,
        warn_on_layer_mismatch: config.warn_on_layer_mismatch,
        layer_override: config.layer_override,
        randomize_msg_id_offset: config.randomize_msg_id_offset,
        msg_id_offset: to_offset(config.msg_id_offset)?,
    })
}

/// A `FingerprintConfig` with its defaults (`'warn'`, auto
/// validation, `'obfuscated'`, layer mismatch warnings, no layer override,
/// a randomized offset), each replaced by the option given. Without
/// `msgIdOffset` the offset is drawn from the OS random source.
#[napi]
pub fn fingerprint_config(
    env: Env,
    options: Option<FingerprintConfigOptions>,
) -> napi::Result<FingerprintConfig> {
    thrown(env, configured(options))
}

/// The config of [`fingerprint_config`].
fn configured(options: Option<FingerprintConfigOptions>) -> Result<FingerprintConfig> {
    let options = options.unwrap_or(FingerprintConfigOptions {
        strict_mode: None,
        auto_validate: None,
        preferred_transport: None,
        warn_on_layer_mismatch: None,
        layer_override: None,
        randomize_msg_id_offset: None,
        msg_id_offset: None,
    });
    let msg_id_offset = options.msg_id_offset.map(to_offset).transpose()?;
    let strict_mode = options
        .strict_mode
        .as_deref()
        .map(strict_mode)
        .transpose()?;
    let options = CoreOptions {
        strict_mode,
        auto_validate: options.auto_validate,
        preferred_transport: options.preferred_transport,
        warn_on_layer_mismatch: options.warn_on_layer_mismatch,
        layer_override: options.layer_override,
        randomize_msg_id_offset: options.randomize_msg_id_offset,
        msg_id_offset,
    };
    Ok(check(CoreConfig::from_options(options))?.into())
}

/// The issues `FingerprintConfig.validate_params` warns about or
/// raises for `profile`: none with `autoValidate` off or mode `'off'`,
/// otherwise `validateInitParams` under the configured mode.
#[napi]
pub fn validate_fingerprint(
    config: FingerprintConfig,
    profile: ApiProfile,
    versions: Option<Versions>,
) -> Result<Vec<Issue>> {
    let config = to_core_config(config)?;
    let profile = CoreProfile::from(profile);
    Ok(to_js_issues(config.validate_raw(
        &RawInitParams::from_profile(&profile),
        &self::versions(versions),
    )))
}

/// The layer to invoke with (`get_effective_layer`): `layerOverride`
/// when set, otherwise `LAYER`. Pass the `MTProto` library's layer as the
/// override to match the Python package, which answers with Telethon's
/// layer.
#[napi]
pub fn effective_layer(config: FingerprintConfig) -> Result<i32> {
    Ok(to_core_config(config)?.effective_layer())
}
