//! The client-independent login, session admin and consistency pieces of
//! 1.5.0 (`src/tl/telethon.py`, `src/consistency.py`).
//!
//! The SRP check runs PBKDF2 with 100000 iterations, so it runs with the
//! thread detached; everything else is pure formatting.

use std::borrow::Cow;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule, PyString, PyTuple};

use opentele2_core::api::LAYER;
use opentele2_core::auth::{
    self, Check, CheckResult, ConsistencyExpectations, SessionRow, SrpCheck, SrpError, SrpParams,
};

use crate::api::{to_profile, versions};
use crate::convert::{dicts, optional, required, required_bytes, to_bytes};
use crate::error::coded_error;
use crate::fingerprint::issue_dicts;

/// The `CoreError` code of an SRP refusal.
fn srp_code(error: SrpError) -> &'static str {
    match error {
        SrpError::BadPrimeOrGenerator => "SRP_BAD_PRIME_OR_GENERATOR",
        SrpError::BadB => "SRP_BAD_B",
        SrpError::NoGoodRandom => "SRP_NO_GOOD_RANDOM",
        SrpError::RandomUnavailable => "SRP_RANDOM_UNAVAILABLE",
        _ => "SRP_FAILED",
    }
}

/// Why one `srp_check` call failed.
enum SrpFailure {
    /// The core refused the parameters or ran out of randomness.
    Refused(SrpError),
    /// The recorded exponents ran out; holds how many there were.
    Exhausted(usize),
}

/// The owned inputs of one `srp_check` call.
struct SrpInput {
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

impl Drop for SrpInput {
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

impl SrpInput {
    /// The check, drawing from the recorded exponents when given.
    fn run(&self) -> Result<SrpCheck, SrpFailure> {
        let params = SrpParams {
            srp_id: self.srp_id,
            g: self.g,
            p: &self.p,
            salt1: &self.salt1,
            salt2: &self.salt2,
            srp_b: &self.srp_b,
        };
        let Some(exponents) = &self.exponents else {
            return auth::srp_check_random(&params, &self.password).map_err(SrpFailure::Refused);
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
        match check {
            Err(SrpError::NoGoodRandom) if exhausted => Err(SrpFailure::Exhausted(exponents.len())),
            other => other.map_err(SrpFailure::Refused),
        }
    }
}

/// The URL a QR login code carries for the `auth.exportLoginToken`
/// `token`: `tg://login?token=` and the token in URL-safe base64 without
/// padding, as Telethon `QRLogin.url`.
#[pyfunction]
fn qr_login_url(token: &Bound<'_, PyAny>) -> PyResult<String> {
    Ok(auth::qr_login_url(&token.extract::<Cow<'_, [u8]>>()?))
}

/// The `inputCheckPasswordSRP` values for `password` (Telethon
/// `password.compute_check`), UTF-8 encoded, as a dict of `srp_id`, `a`
/// and `m1`; runs with the thread detached. `params` holds the
/// `account.Password` fields `srp_id`, `g`, `p`, `salt1`, `salt2` and
/// `srp_b`. Each 256-byte secret exponent comes from the OS random source,
/// or, to reproduce a recorded check, from `exponents` in order.
///
/// Raises `CoreError` `SRP_BAD_PRIME_OR_GENERATOR` for a bad `p` or `g`,
/// `SRP_BAD_B` for a bad `srp_b`, `SRP_NO_GOOD_RANDOM` when every draw was
/// unusable, and `ValueError` when `exponents` runs out or holds an
/// exponent that is not 256 bytes.
#[pyfunction]
#[pyo3(signature = (params, password, exponents = None))]
fn srp_check<'py>(
    py: Python<'py>,
    params: &Bound<'py, PyDict>,
    password: &Bound<'py, PyString>,
    exponents: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyDict>> {
    const WHAT: &str = "the SRP params";
    let exponents = exponents
        .map(|list| {
            list.try_iter()?
                .map(|exponent| {
                    let exponent = crate::convert::owned_bytes(&exponent?)?;
                    if exponent.len() == auth::SRP_NUMBER_SIZE {
                        Ok(exponent)
                    } else {
                        Err(PyValueError::new_err("every exponent must be 256 bytes"))
                    }
                })
                .collect::<PyResult<Vec<_>>>()
        })
        .transpose()?;
    let input = SrpInput {
        srp_id: required(params, "srp_id", WHAT)?,
        g: required(params, "g", WHAT)?,
        p: required_bytes(params, "p", WHAT)?,
        salt1: required_bytes(params, "salt1", WHAT)?,
        salt2: required_bytes(params, "salt2", WHAT)?,
        srp_b: required_bytes(params, "srp_b", WHAT)?,
        password: password.to_cow()?.into_owned(),
        exponents,
    };
    let check = py.detach(move || input.run());
    match check {
        Ok(check) => {
            let dict = PyDict::new(py);
            dict.set_item("srp_id", check.srp_id)?;
            dict.set_item("a", to_bytes(py, &check.a))?;
            dict.set_item("m1", to_bytes(py, &check.m1))?;
            Ok(dict)
        }
        Err(SrpFailure::Refused(error)) => {
            Err(coded_error(py, srp_code(error), &error.to_string()))
        }
        Err(SrpFailure::Exhausted(count)) => Err(PyValueError::new_err(format!(
            "srp_check needed more than the {count} exponents given"
        ))),
    }
}

/// Whether `api_id` is the id of an official profile (`OFFICIAL_API_IDS`).
#[pyfunction]
fn is_official_api_id(api_id: i32) -> bool {
    auth::is_official_api_id(api_id)
}

/// The core row a `SessionRow` dict holds; `current` and `official_app`
/// default to `False`.
fn to_session_row(dict: &Bound<'_, PyDict>) -> PyResult<SessionRow> {
    const WHAT: &str = "the session row";
    Ok(SessionRow {
        current: optional(dict, "current")?.unwrap_or(false),
        device_model: required(dict, "device_model", WHAT)?,
        platform: required(dict, "platform", WHAT)?,
        system_version: required(dict, "system_version", WHAT)?,
        api_id: required(dict, "api_id", WHAT)?,
        app_name: required(dict, "app_name", WHAT)?,
        app_version: required(dict, "app_version", WHAT)?,
        official_app: optional(dict, "official_app")?.unwrap_or(false),
    })
}

/// The table 1.5.0 `PrintSessions` prints for `rows`, without a trailing
/// newline; with no rows, the header alone.
#[pyfunction]
fn format_sessions(rows: &Bound<'_, PyAny>) -> PyResult<String> {
    let rows = dicts(rows, "session row")?
        .iter()
        .map(to_session_row)
        .collect::<PyResult<Vec<_>>>()?;
    Ok(auth::format_sessions(&rows))
}

/// What the seven 1.5.0 `ConsistencyChecker` checks expect from a session
/// with `profile`, compared against `versions` (default the offline
/// `PlatformVersions`).
#[pyfunction]
#[pyo3(signature = (profile, versions = None))]
fn consistency_expectations<'py>(
    py: Python<'py>,
    profile: &Bound<'py, PyDict>,
    versions: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let expectations =
        ConsistencyExpectations::new(&to_profile(profile)?, &self::versions(versions)?);
    let dict = PyDict::new(py);
    dict.set_item("api_id", expectations.api_id)?;
    dict.set_item("official_api_id", expectations.official_api_id)?;
    dict.set_item("lang_pack", &expectations.lang_pack)?;
    dict.set_item("lang_pack_skipped", expectations.lang_pack_skipped())?;
    dict.set_item("advertised_layer", expectations.advertised_layer)?;
    dict.set_item("layer_tolerance", expectations.layer_tolerance)?;
    dict.set_item("app_version", &expectations.app_version)?;
    dict.set_item(
        "version_issues",
        issue_dicts(py, &expectations.version_issues)?,
    )?;
    dict.set_item("app_version_current", expectations.app_version_current())?;
    Ok(dict)
}

/// `result` as a `CheckResult` dict.
fn result_dict<'py>(py: Python<'py>, result: &CheckResult) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("name", &result.name)?;
    dict.set_item("passed", result.passed)?;
    dict.set_item("detail", &result.detail)?;
    Ok(dict)
}

/// The names of the seven 1.5.0 `ConsistencyChecker.run_all` checks, in
/// its order.
#[pyfunction]
fn consistency_checks() -> Vec<&'static str> {
    Check::ALL.iter().map(|check| check.name()).collect()
}

/// The `layer_match` result for a library built for `library_layer`: it
/// passes within `LAYER_TOLERANCE` of `LAYER`.
#[pyfunction]
fn layer_result(py: Python<'_>, library_layer: i32) -> PyResult<Bound<'_, PyDict>> {
    let result = CheckResult {
        name: Check::LayerMatch.name().to_owned(),
        passed: library_layer.abs_diff(LAYER) <= auth::LAYER_TOLERANCE,
        detail: auth::layer_detail(library_layer, LAYER),
    };
    result_dict(py, &result)
}

/// 1.5.0 `ConsistencyReport.summary`: a count line, then one
/// `  [OK] name: detail` or `  [FAIL] name: detail` line per check.
#[pyfunction]
fn consistency_summary(results: &Bound<'_, PyAny>) -> PyResult<String> {
    const WHAT: &str = "the check result";
    let results = dicts(results, "check result")?
        .iter()
        .map(|dict| {
            Ok(CheckResult {
                name: required(dict, "name", WHAT)?,
                passed: required(dict, "passed", WHAT)?,
                detail: required(dict, "detail", WHAT)?,
            })
        })
        .collect::<PyResult<Vec<_>>>()?;
    Ok(auth::consistency_summary(&results))
}

/// The `get_config` detail on success; no `this_dc` prints `None`.
#[pyfunction]
#[pyo3(signature = (this_dc = None))]
fn get_config_detail(this_dc: Option<i32>) -> String {
    auth::get_config_detail(this_dc)
}

/// The `get_config` detail when the request fails with `error`.
#[pyfunction]
fn get_config_error(error: &str) -> String {
    auth::get_config_error(error)
}

/// The `nearest_dc` detail on success.
#[pyfunction]
fn nearest_dc_detail(country: &str, this_dc: i32, nearest_dc: i32) -> String {
    auth::nearest_dc_detail(country, this_dc, nearest_dc)
}

/// The `nearest_dc` detail when the request fails with `error`.
#[pyfunction]
fn nearest_dc_error(error: &str) -> String {
    auth::nearest_dc_error(error)
}

/// The `current_session` detail for the current session `row`; the check
/// passes when `row["official_app"]` is set.
#[pyfunction]
fn current_session_detail(row: &Bound<'_, PyDict>) -> PyResult<String> {
    Ok(auth::current_session_detail(&to_session_row(row)?))
}

/// The `layer_match` detail; 1.5.0 names the library layer after Telethon.
#[pyfunction]
#[pyo3(signature = (library_layer, advertised_layer = None))]
fn layer_detail(library_layer: i32, advertised_layer: Option<i32>) -> String {
    auth::layer_detail(library_layer, advertised_layer.unwrap_or(LAYER))
}

/// The `lang_pack` detail when the server lists `languages` languages.
#[pyfunction]
fn lang_pack_detail(lang_pack: &str, languages: usize) -> String {
    auth::lang_pack_detail(lang_pack, languages)
}

/// The `lang_pack` detail when the server rejects it with `error`.
#[pyfunction]
fn lang_pack_error(lang_pack: &str, error: &str) -> String {
    auth::lang_pack_error(lang_pack, error)
}

/// The `app_update` detail when an update is offered; without a version it
/// prints `?`.
#[pyfunction]
#[pyo3(signature = (version = None))]
fn app_update_detail(version: Option<&str>) -> String {
    auth::app_update_detail(version)
}

/// The `app_update` detail when the request fails with `error`.
#[pyfunction]
fn app_update_error(error: &str) -> String {
    auth::app_update_error(error)
}

/// The `current_session` and `terms_of_service` detail when the request
/// fails with `error`.
#[pyfunction]
fn check_error(error: &str) -> String {
    auth::check_error(error)
}

/// The detail of a check that raised `error` out of its own handling.
#[pyfunction]
fn check_exception(error: &str) -> String {
    auth::check_exception(error)
}

/// Adds the auth constants and functions to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    module.add("QR_LOGIN_URL_PREFIX", auth::QR_LOGIN_URL_PREFIX)?;
    module.add("SRP_NUMBER_SIZE", auth::SRP_NUMBER_SIZE)?;
    module.add("NO_PASSWORD_PROVIDED", auth::NO_PASSWORD_PROVIDED)?;
    module.add("FRESH_RESET_FORBIDDEN", auth::FRESH_RESET_FORBIDDEN)?;
    module.add("HASH_INVALID", auth::HASH_INVALID)?;
    module.add("SESSIONS_UNAVAILABLE", auth::SESSIONS_UNAVAILABLE)?;
    module.add(
        "OFFICIAL_API_IDS",
        PyTuple::new(py, auth::OFFICIAL_API_IDS)?,
    )?;
    module.add("SESSION_COLUMNS", PyTuple::new(py, auth::SESSION_COLUMNS)?)?;
    module.add("LAYER_TOLERANCE", auth::LAYER_TOLERANCE)?;
    module.add("CURRENT_SESSION_MISSING", auth::CURRENT_SESSION_MISSING)?;
    module.add("LANG_PACK_EMPTY", auth::LANG_PACK_EMPTY)?;
    module.add("NO_APP_UPDATE", auth::NO_APP_UPDATE)?;
    module.add("TERMS_OF_SERVICE_OK", auth::TERMS_OF_SERVICE_OK)?;
    module.add(
        "CONSISTENCY_WARNING_PREFIX",
        auth::CONSISTENCY_WARNING_PREFIX,
    )?;
    module.add_function(wrap_pyfunction!(qr_login_url, module)?)?;
    module.add_function(wrap_pyfunction!(srp_check, module)?)?;
    module.add_function(wrap_pyfunction!(is_official_api_id, module)?)?;
    module.add_function(wrap_pyfunction!(format_sessions, module)?)?;
    module.add_function(wrap_pyfunction!(consistency_expectations, module)?)?;
    module.add_function(wrap_pyfunction!(consistency_checks, module)?)?;
    module.add_function(wrap_pyfunction!(layer_result, module)?)?;
    module.add_function(wrap_pyfunction!(consistency_summary, module)?)?;
    module.add_function(wrap_pyfunction!(get_config_detail, module)?)?;
    module.add_function(wrap_pyfunction!(get_config_error, module)?)?;
    module.add_function(wrap_pyfunction!(nearest_dc_detail, module)?)?;
    module.add_function(wrap_pyfunction!(nearest_dc_error, module)?)?;
    module.add_function(wrap_pyfunction!(current_session_detail, module)?)?;
    module.add_function(wrap_pyfunction!(layer_detail, module)?)?;
    module.add_function(wrap_pyfunction!(lang_pack_detail, module)?)?;
    module.add_function(wrap_pyfunction!(lang_pack_error, module)?)?;
    module.add_function(wrap_pyfunction!(app_update_detail, module)?)?;
    module.add_function(wrap_pyfunction!(app_update_error, module)?)?;
    module.add_function(wrap_pyfunction!(check_error, module)?)?;
    module.add_function(wrap_pyfunction!(check_exception, module)?)?;
    Ok(())
}
