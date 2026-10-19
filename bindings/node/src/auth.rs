//! The client-independent login, session admin and consistency pieces of
//! 1.5.0 (`src/tl/telethon.py`, `src/consistency.py`).
//!
//! The SRP check runs PBKDF2 with 100000 iterations, so it is an async task;
//! everything else is pure formatting and runs synchronously.

use napi::bindgen_prelude::{AsyncTask, BigInt, Buffer, Env, Uint8Array};
use napi::{JsString, Task};
use napi_derive::napi;

use opentele2_core::api::LAYER;
use opentele2_core::auth::{
    self, Check, CheckResult as CoreCheckResult, ConsistencyExpectations as CoreExpectations,
    SessionRow as CoreSessionRow, SrpCheck as CoreSrpCheck, SrpError, SrpParams as CoreSrpParams,
};

use crate::api::{ApiProfile, Versions, versions};
use crate::convert::with_text;
use crate::error::{CodedError, Result, invalid_arg, rejection};
use crate::fingerprint::{Issue, to_js_issues};

/// The scheme and query key in front of a QR login token.
#[napi]
pub const QR_LOGIN_URL_PREFIX: &str = auth::QR_LOGIN_URL_PREFIX;

/// The size in bytes of the SRP numbers `p`, `A`, `B` and the secret
/// exponents.
#[napi]
pub const SRP_NUMBER_SIZE: u32 = 256;

/// The 1.5.0 `NoPasswordProvided` message of a QR login that needs 2FA.
#[napi]
pub const NO_PASSWORD_PROVIDED: &str = auth::NO_PASSWORD_PROVIDED;

/// The 1.5.0 `FreshResetAuthorisationForbiddenError` message of
/// `TerminateSession`.
#[napi]
pub const FRESH_RESET_FORBIDDEN: &str = auth::FRESH_RESET_FORBIDDEN;

/// The 1.5.0 `HashInvalidError` message of `TerminateSession`.
#[napi]
pub const HASH_INVALID: &str = auth::HASH_INVALID;

/// The 1.5.0 message of `PrintSessions` when the sessions cannot be fetched.
#[napi]
pub const SESSIONS_UNAVAILABLE: &str = auth::SESSIONS_UNAVAILABLE;

/// The `api_id` of every official profile, without repeats.
#[napi]
pub const OFFICIAL_API_IDS: [i32; 6] = auth::OFFICIAL_API_IDS;

/// The column labels of the 1.5.0 `PrintSessions` table, in order.
#[napi]
pub const SESSION_COLUMNS: [&str; 7] = auth::SESSION_COLUMNS;

/// The largest distance between the library's TL layer and `LAYER` the
/// `layer_match` check passes.
#[napi]
pub const LAYER_TOLERANCE: u32 = auth::LAYER_TOLERANCE;

/// The `current_session` detail when there is no current session.
#[napi]
pub const CURRENT_SESSION_MISSING: &str = auth::CURRENT_SESSION_MISSING;

/// The `lang_pack` detail for an empty `lang_pack`.
#[napi]
pub const LANG_PACK_EMPTY: &str = auth::LANG_PACK_EMPTY;

/// The `app_update` detail for `help.noAppUpdate`.
#[napi]
pub const NO_APP_UPDATE: &str = auth::NO_APP_UPDATE;

/// The `terms_of_service` detail on success.
#[napi]
pub const TERMS_OF_SERVICE_OK: &str = auth::TERMS_OF_SERVICE_OK;

/// The text in front of the summary 1.5.0 warns with when a check fails.
#[napi]
pub const CONSISTENCY_WARNING_PREFIX: &str = auth::CONSISTENCY_WARNING_PREFIX;

/// The URL a QR login code carries for the `auth.exportLoginToken`
/// `token`: `tg://login?token=` and the token in URL-safe base64 without
/// padding, as Telethon `QRLogin.url`.
#[napi]
pub fn qr_login_url(token: &[u8]) -> String {
    auth::qr_login_url(token)
}

/// The `account.Password` fields `srpCheck` needs, for the
/// `passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow`
/// algorithm.
#[napi(object, object_to_js = false)]
pub struct SrpParams {
    /// `account.Password.srp_id`.
    pub srp_id: BigInt,
    /// The algorithm's `g`.
    pub g: i32,
    /// The algorithm's `p`, big-endian in 256 bytes.
    pub p: Uint8Array,
    /// The algorithm's `salt1`.
    pub salt1: Uint8Array,
    /// The algorithm's `salt2`.
    pub salt2: Uint8Array,
    /// `account.Password.srp_B`, big-endian, at most 256 bytes.
    pub srp_b: Uint8Array,
}

/// The values of an `inputCheckPasswordSRP`.
#[napi(object, object_from_js = false)]
pub struct SrpCheck {
    /// The `srpId` of the params.
    pub srp_id: BigInt,
    /// `A = g^a mod p`, big-endian in 256 bytes.
    pub a: Buffer,
    /// The proof `M1`, 32 bytes.
    pub m1: Buffer,
}

/// The `"OT_SRP_"` error of `error`, with Telethon's message where it has
/// one.
fn srp_error(error: SrpError) -> CodedError {
    let code = match error {
        SrpError::BadPrimeOrGenerator => "OT_SRP_BAD_PRIME_OR_GENERATOR",
        SrpError::BadB => "OT_SRP_BAD_B",
        SrpError::NoGoodRandom => "OT_SRP_NO_GOOD_RANDOM",
        SrpError::RandomUnavailable => "OT_SRP_RANDOM_UNAVAILABLE",
        _ => "OT_SRP_FAILED",
    };
    CodedError::new(code.to_owned(), error.to_string())
}

/// One `srpCheck` call, run off the JavaScript thread.
pub struct SrpTask {
    srp_id: i64,
    g: i32,
    p: Vec<u8>,
    salt1: Vec<u8>,
    salt2: Vec<u8>,
    srp_b: Vec<u8>,
    password: String,
    /// The recorded exponents to draw instead of the OS random source.
    exponents: Option<Vec<Vec<u8>>>,
}

impl Drop for SrpTask {
    fn drop(&mut self) {
        // The password and recorded exponents are secrets; clear them.
        let mut bytes = std::mem::take(&mut self.password).into_bytes();
        bytes.fill(0);
        std::hint::black_box(&mut bytes);
        for exponent in self.exponents.iter_mut().flatten() {
            exponent.fill(0);
            std::hint::black_box(exponent);
        }
    }
}

#[napi]
impl Task for SrpTask {
    type Output = std::result::Result<CoreSrpCheck, CodedError>;
    type JsValue = SrpCheck;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let params = CoreSrpParams {
            srp_id: self.srp_id,
            g: self.g,
            p: &self.p,
            salt1: &self.salt1,
            salt2: &self.salt2,
            srp_b: &self.srp_b,
        };
        let Some(exponents) = &self.exponents else {
            return Ok(auth::srp_check_random(&params, &self.password).map_err(srp_error));
        };
        let mut next = 0;
        let mut exhausted = false;
        let check = auth::srp_check(&params, &self.password, &mut |buf| {
            if let Some(exponent) = exponents.get(next) {
                buf.copy_from_slice(exponent);
                next += 1;
            } else {
                // A zero exponent is always refused, so drawing stops.
                buf.fill(0);
                exhausted = true;
            }
        });
        Ok(match check {
            Err(SrpError::NoGoodRandom) if exhausted => Err(invalid_arg(format!(
                "srpCheck needed more than the {} exponents given",
                exponents.len()
            ))),
            other => other.map_err(srp_error),
        })
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<SrpCheck> {
        match output {
            Ok(check) => Ok(SrpCheck {
                srp_id: BigInt::from(check.srp_id),
                a: Buffer::from(check.a.to_vec()),
                m1: Buffer::from(check.m1.to_vec()),
            }),
            Err(error) => Err(rejection(env, error)),
        }
    }
}

/// The `inputCheckPasswordSRP` values for `password` (Telethon
/// `password.compute_check`), UTF-8 encoded. Each 256-byte secret exponent
/// comes from the OS random source, or, to reproduce a recorded check, from
/// `exponents` in order.
///
/// Rejects with `OT_SRP_BAD_PRIME_OR_GENERATOR` for a bad `p` or `g`,
/// `OT_SRP_BAD_B` for a bad `srpB`, `OT_SRP_NO_GOOD_RANDOM` when every draw
/// was unusable, and `ERR_INVALID_ARG_VALUE` when `exponents` runs out or
/// holds an exponent that is not 256 bytes.
#[napi]
pub fn srp_check(
    params: SrpParams,
    password: String,
    exponents: Option<Vec<Uint8Array>>,
) -> Result<AsyncTask<SrpTask>> {
    let SrpParams {
        srp_id,
        g,
        p,
        salt1,
        salt2,
        srp_b,
    } = params;
    let (srp_id, lossless) = srp_id.get_i64();
    if !lossless {
        return Err(invalid_arg("srpId must be a bigint in -(2**63)..2**63"));
    }
    let exponents = exponents
        .map(|list| {
            list.iter()
                .map(|exponent| {
                    if exponent.len() == auth::SRP_NUMBER_SIZE {
                        Ok(exponent.to_vec())
                    } else {
                        Err(invalid_arg("every exponent must be 256 bytes"))
                    }
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    Ok(AsyncTask::new(SrpTask {
        srp_id,
        g,
        p: p.to_vec(),
        salt1: salt1.to_vec(),
        salt2: salt2.to_vec(),
        srp_b: srp_b.to_vec(),
        password,
        exponents,
    }))
}

/// Whether `apiId` is the id of an official profile (`OFFICIAL_API_IDS`).
#[napi]
pub fn is_official_api_id(api_id: i32) -> bool {
    auth::is_official_api_id(api_id)
}

/// The fields of an `authorization` that 1.5.0 `PrintSessions` shows.
#[napi(object, object_to_js = false)]
pub struct SessionRow {
    /// `current`; absent is `false`.
    pub current: Option<bool>,
    /// `device_model`.
    pub device_model: String,
    /// `platform`.
    pub platform: String,
    /// `system_version`.
    pub system_version: String,
    /// `api_id`.
    pub api_id: i32,
    /// `app_name`.
    pub app_name: String,
    /// `app_version`.
    pub app_version: String,
    /// `official_app`; absent is `false`.
    pub official_app: Option<bool>,
}

impl From<SessionRow> for CoreSessionRow {
    fn from(row: SessionRow) -> Self {
        Self {
            current: row.current.unwrap_or(false),
            device_model: row.device_model,
            platform: row.platform,
            system_version: row.system_version,
            api_id: row.api_id,
            app_name: row.app_name,
            app_version: row.app_version,
            official_app: row.official_app.unwrap_or(false),
        }
    }
}

/// The table 1.5.0 `PrintSessions` prints for `rows`, without a trailing
/// newline; with no rows, the header alone.
#[napi]
pub fn format_sessions(rows: Vec<SessionRow>) -> String {
    let rows: Vec<CoreSessionRow> = rows.into_iter().map(CoreSessionRow::from).collect();
    auth::format_sessions(&rows)
}

/// The text of every string in `values`, read as UTF-8.
fn texts(values: Vec<JsString<'_>>) -> Result<Vec<String>> {
    values
        .into_iter()
        .map(|value| with_text(value, str::to_owned))
        .collect()
}

/// 1.5.0 `PrettyTable(table, addSplit)` for a table with the columns
/// `headers`, in order, and the cells of `rows`, already strings; a splitter
/// line goes before every row whose index is in `addSplit`. Columns are as
/// wide as their longest cell plus two, text centred with the odd space on
/// the right; the last line has no newline. A short row gets empty cells
/// and cells past the last header are ignored.
#[napi]
pub fn format_table(
    headers: Vec<JsString<'_>>,
    rows: Vec<Vec<JsString<'_>>>,
    add_split: Option<Vec<u32>>,
) -> Result<String> {
    let headers = texts(headers)?;
    let rows = rows.into_iter().map(texts).collect::<Result<Vec<_>>>()?;
    let add_split = add_split
        .unwrap_or_default()
        .into_iter()
        .map(|index| usize::try_from(index).map_err(|_| invalid_arg("addSplit index too large")))
        .collect::<Result<Vec<_>>>()?;
    Ok(auth::format_table(&headers, &rows, &add_split))
}

/// What the seven 1.5.0 `ConsistencyChecker` checks expect from a session
/// that uses a profile.
#[napi(object, object_from_js = false)]
pub struct ConsistencyExpectations {
    /// The profile's `apiId`, reported by `current_session`.
    pub api_id: i32,
    /// Whether `apiId` is official; other ids fail `current_session`.
    pub official_api_id: bool,
    /// The profile's `langPack`, which `lang_pack` asks the server about.
    pub lang_pack: String,
    /// Whether `lang_pack` passes without asking the server (empty pack).
    pub lang_pack_skipped: bool,
    /// The layer `layer_match` compares the library's layer with.
    pub advertised_layer: i32,
    /// The largest layer distance `layer_match` passes.
    pub layer_tolerance: u32,
    /// The `appVersion` the session sends.
    pub app_version: String,
    /// The app version comparison against the known versions; empty when
    /// the version is current.
    pub version_issues: Vec<Issue>,
    /// Whether the app version is as recent as the known versions.
    pub app_version_current: bool,
}

/// The consistency expectations for a session with `profile`, compared
/// against `versions` (default the offline `PlatformVersions`).
#[napi]
pub fn consistency_expectations(
    profile: ApiProfile,
    versions: Option<Versions>,
) -> ConsistencyExpectations {
    let expectations = CoreExpectations::new(&profile.into(), &self::versions(versions));
    let lang_pack_skipped = expectations.lang_pack_skipped();
    let app_version_current = expectations.app_version_current();
    ConsistencyExpectations {
        api_id: expectations.api_id,
        official_api_id: expectations.official_api_id,
        lang_pack: expectations.lang_pack,
        lang_pack_skipped,
        advertised_layer: expectations.advertised_layer,
        layer_tolerance: expectations.layer_tolerance,
        app_version: expectations.app_version,
        version_issues: to_js_issues(expectations.version_issues),
        app_version_current,
    }
}

/// One entry of a 1.5.0 `ConsistencyReport`.
#[napi(object)]
pub struct CheckResult {
    /// The check name, one of `consistencyChecks()` or the name of a check
    /// that raised.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// The 1.5.0 detail text.
    pub detail: String,
}

/// The names of the seven 1.5.0 `ConsistencyChecker.run_all` checks, in
/// its order.
#[napi]
pub fn consistency_checks() -> Vec<&'static str> {
    Check::ALL.iter().map(|check| check.name()).collect()
}

/// The `layer_match` result for a library built for `libraryLayer`: it
/// passes within `LAYER_TOLERANCE` of `LAYER`.
#[napi]
pub fn layer_result(library_layer: i32) -> CheckResult {
    let passed = library_layer.abs_diff(LAYER) <= auth::LAYER_TOLERANCE;
    CheckResult {
        name: Check::LayerMatch.name().to_owned(),
        passed,
        detail: auth::layer_detail(library_layer, LAYER),
    }
}

/// 1.5.0 `ConsistencyReport.summary`: a count line, then one
/// `  [OK] name: detail` or `  [FAIL] name: detail` line per check.
#[napi]
pub fn consistency_summary(results: Vec<CheckResult>) -> String {
    let results: Vec<CoreCheckResult> = results
        .into_iter()
        .map(|result| CoreCheckResult {
            name: result.name,
            passed: result.passed,
            detail: result.detail,
        })
        .collect();
    auth::consistency_summary(&results)
}

/// The `get_config` detail on success; an absent `thisDc` prints `None`.
#[napi]
pub fn get_config_detail(this_dc: Option<i32>) -> String {
    auth::get_config_detail(this_dc)
}

/// The `get_config` detail when the request fails with `error`.
#[napi]
pub fn get_config_error(error: JsString<'_>) -> Result<String> {
    with_text(error, auth::get_config_error)
}

/// The `nearest_dc` detail on success.
#[napi]
pub fn nearest_dc_detail(country: JsString<'_>, this_dc: i32, nearest_dc: i32) -> Result<String> {
    with_text(country, |country| {
        auth::nearest_dc_detail(country, this_dc, nearest_dc)
    })
}

/// The `nearest_dc` detail when the request fails with `error`.
#[napi]
pub fn nearest_dc_error(error: JsString<'_>) -> Result<String> {
    with_text(error, auth::nearest_dc_error)
}

/// The `current_session` detail for the current session `row`; the check
/// passes when `row.officialApp` is set.
#[napi]
pub fn current_session_detail(row: SessionRow) -> String {
    auth::current_session_detail(&row.into())
}

/// The `layer_match` detail; 1.5.0 names the library layer after Telethon.
#[napi]
pub fn layer_detail(library_layer: i32, advertised_layer: Option<i32>) -> String {
    auth::layer_detail(library_layer, advertised_layer.unwrap_or(LAYER))
}

/// The `lang_pack` detail when the server lists `languages` languages.
#[napi]
pub fn lang_pack_detail(lang_pack: JsString<'_>, languages: u32) -> Result<String> {
    // A `u32` fits `usize` on every target Node runs on.
    let languages = usize::try_from(languages).unwrap_or(usize::MAX);
    with_text(lang_pack, |lang_pack| {
        auth::lang_pack_detail(lang_pack, languages)
    })
}

/// The `lang_pack` detail when the server rejects it with `error`.
#[napi]
pub fn lang_pack_error(lang_pack: JsString<'_>, error: JsString<'_>) -> Result<String> {
    with_text(lang_pack, |lang_pack| {
        with_text(error, |error| auth::lang_pack_error(lang_pack, error))
    })?
}

/// The `app_update` detail when an update is offered; without a version it
/// prints `?`.
#[napi]
pub fn app_update_detail(version: Option<JsString<'_>>) -> Result<String> {
    match version {
        Some(version) => with_text(version, |version| auth::app_update_detail(Some(version))),
        None => Ok(auth::app_update_detail(None)),
    }
}

/// The `app_update` detail when the request fails with `error`.
#[napi]
pub fn app_update_error(error: JsString<'_>) -> Result<String> {
    with_text(error, auth::app_update_error)
}

/// The `current_session` and `terms_of_service` detail when the request
/// fails with `error`.
#[napi]
pub fn check_error(error: JsString<'_>) -> Result<String> {
    with_text(error, auth::check_error)
}

/// The detail of a check that raised `error` out of its own handling.
#[napi]
pub fn check_exception(error: JsString<'_>) -> Result<String> {
    with_text(error, auth::check_exception)
}
