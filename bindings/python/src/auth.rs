//! The client-independent login, session admin and consistency pieces of
//! 1.5.0 (`src/tl/telethon.py`, `src/consistency.py`).
//!
//! The SRP check runs PBKDF2 with 100000 iterations, so it runs with the
//! thread detached; `random_delay_ms` draws from the OS random source and
//! everything else is pure formatting or tables.

use std::borrow::Cow;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PyString, PyTuple};

use opentele2_core::api::LAYER;
use opentele2_core::auth::{
    self, Check, CheckOutcome, CheckResult, ConsistencyExpectations, PostLoginStep,
    RawAuthorization, SessionRow, SrpCheck, SrpError, SrpParams,
};

use crate::api::{to_profile, versions};
use crate::convert::{dicts, optional, required, required_bytes, to_bytes};
use crate::error::{check_value, coded_error};
use crate::fingerprint::issue_dicts;

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
        Err(SrpFailure::Refused(error)) => Err(coded_error(py, error.code(), &error.to_string())),
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

/// `row` as a `SessionRow` dict, every key present.
fn session_row_dict<'py>(py: Python<'py>, row: &SessionRow) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("current", row.current)?;
    dict.set_item("device_model", &row.device_model)?;
    dict.set_item("platform", &row.platform)?;
    dict.set_item("system_version", &row.system_version)?;
    dict.set_item("api_id", row.api_id)?;
    dict.set_item("app_name", &row.app_name)?;
    dict.set_item("app_version", &row.app_version)?;
    dict.set_item("official_app", row.official_app)?;
    Ok(dict)
}

/// The `SessionRow` of an `authorization` as a client library returns one,
/// read from its attributes `current`, `device_model`, `platform`,
/// `system_version`, `api_id`, `app_name`, `app_version` and
/// `official_app`: an absent (`None`) `current` or `official_app` flag is
/// `False`, as 1.5.0 reads it.
#[pyfunction]
fn session_row<'py>(
    py: Python<'py>,
    authorization: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    fn flag(authorization: &Bound<'_, PyAny>, name: &str) -> PyResult<Option<bool>> {
        let value = authorization.getattr(name)?;
        if value.is_none() {
            Ok(None)
        } else {
            value.extract().map(Some)
        }
    }
    fn text(authorization: &Bound<'_, PyAny>, name: &str) -> PyResult<String> {
        authorization.getattr(name)?.extract()
    }
    let device_model = text(authorization, "device_model")?;
    let platform = text(authorization, "platform")?;
    let system_version = text(authorization, "system_version")?;
    let app_name = text(authorization, "app_name")?;
    let app_version = text(authorization, "app_version")?;
    let raw = RawAuthorization {
        current: flag(authorization, "current")?,
        device_model: &device_model,
        platform: &platform,
        system_version: &system_version,
        api_id: authorization.getattr("api_id")?.extract()?,
        app_name: &app_name,
        app_version: &app_version,
        official_app: flag(authorization, "official_app")?,
    };
    session_row_dict(py, &SessionRow::from_authorization(&raw))
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

/// 1.5.0 `PrettyTable(table, addSplit)` for a table with the columns
/// `headers`, in order, and the cells of `rows`, already strings; a splitter
/// line goes before every row whose index is in `add_split`. Columns are
/// as wide as their longest cell plus two, text centred with the odd space
/// on the right; the last line has no newline. A short row gets empty cells
/// and cells past the last header are ignored.
#[pyfunction]
#[pyo3(signature = (headers, rows, add_split = None))]
fn format_table(
    headers: &Bound<'_, PyAny>,
    rows: &Bound<'_, PyAny>,
    add_split: Option<&Bound<'_, PyAny>>,
) -> PyResult<String> {
    let headers: Vec<String> = headers.extract()?;
    let rows: Vec<Vec<String>> = rows.extract()?;
    let add_split: Vec<usize> = match add_split {
        Some(indices) => indices.extract()?,
        None => Vec::new(),
    };
    Ok(auth::format_table(&headers, &rows, &add_split))
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
/// passes within `LAYER_TOLERANCE` of `advertised_layer` (default `LAYER`).
#[pyfunction]
#[pyo3(signature = (library_layer, advertised_layer = None))]
fn layer_result(
    py: Python<'_>,
    library_layer: i32,
    advertised_layer: Option<i32>,
) -> PyResult<Bound<'_, PyDict>> {
    let advertised_layer = advertised_layer.unwrap_or(LAYER);
    let result = CheckResult {
        name: Check::LayerMatch.name().to_owned(),
        passed: library_layer.abs_diff(advertised_layer) <= auth::LAYER_TOLERANCE,
        detail: auth::layer_detail(library_layer, advertised_layer),
    };
    result_dict(py, &result)
}

/// The core outcome a `CheckOutcome` dict holds: `{"raised": str(e)}` for a
/// check that raised, else `{"passed": ..., "detail": ...}`.
fn to_check_outcome(dict: &Bound<'_, PyDict>) -> PyResult<CheckOutcome> {
    const WHAT: &str = "the check outcome";
    if let Some(error) = optional::<String>(dict, "raised")? {
        return Ok(CheckOutcome::Raised(error));
    }
    Ok(CheckOutcome::Finished {
        passed: required(dict, "passed", WHAT)?,
        detail: required(dict, "detail", WHAT)?,
    })
}

/// The report 1.5.0 `ConsistencyChecker.run_all` builds from `outcomes`,
/// one per check in `consistency_checks()` order: a dict of the `checks`
/// (`CheckResult` dicts named after their check; one that raised fails with
/// the `check_exception` detail), `all_passed`, `summary` and the
/// `auto_warn` `warning` (`None` when all passed). Raises `ValueError` when
/// `outcomes` does not hold one outcome per check.
#[pyfunction]
fn consistency_report<'py>(
    py: Python<'py>,
    outcomes: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    let outcomes = dicts(outcomes, "check outcome")?
        .iter()
        .map(to_check_outcome)
        .collect::<PyResult<Vec<_>>>()?;
    let count = outcomes.len();
    let outcomes: [CheckOutcome; Check::ALL.len()] = outcomes.try_into().map_err(|_| {
        PyValueError::new_err(format!(
            "consistency_report needs {} outcomes, got {count}",
            Check::ALL.len()
        ))
    })?;
    let report = auth::consistency_report(outcomes);
    let checks = PyList::empty(py);
    for result in &report.checks {
        checks.append(result_dict(py, result)?)?;
    }
    let dict = PyDict::new(py);
    dict.set_item("checks", checks)?;
    dict.set_item("all_passed", report.all_passed())?;
    dict.set_item("summary", report.summary())?;
    dict.set_item("warning", report.warning())?;
    Ok(dict)
}

/// `step` as a `PostLoginStep` dict: the `request` TL name and the
/// inclusive `delay_ms` range of the sleep before it, `None` for none.
fn post_login_step_dict<'py>(
    py: Python<'py>,
    step: &PostLoginStep,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("request", step.request.tl_name())?;
    dict.set_item("delay_ms", step.delay_ms)?;
    Ok(dict)
}

/// The 1.5.0 post-login steps run for a client whose `lang_pack` is
/// `lang_pack`, in order: `langpack.getLanguages` only runs for a
/// non-empty one.
#[pyfunction]
fn post_login_steps<'py>(py: Python<'py>, lang_pack: &str) -> PyResult<Vec<Bound<'py, PyDict>>> {
    auth::post_login_steps(lang_pack)
        .iter()
        .map(|step| post_login_step_dict(py, step))
        .collect()
}

/// A random whole number of milliseconds in `min_ms..=max_ms`, uniform,
/// from the OS random source: the sleep 1.5.0 takes as
/// `random.randint(min_ms, max_ms)`. Raises `ValueError` when
/// `min_ms > max_ms`, as `random.randint` does.
#[pyfunction]
fn random_delay_ms(min_ms: u64, max_ms: u64) -> PyResult<u64> {
    check_value(auth::random_delay_ms(min_ms, max_ms))
}

/// Telethon's `compute_check` `ValueError` text for a 2FA algorithm other
/// than `SRP_ALGORITHM`, named `algorithm`.
#[pyfunction]
fn unsupported_password_algorithm(algorithm: &str) -> String {
    auth::unsupported_password_algorithm(algorithm)
}

/// The 1.5.0 warning of QR login attempt `attempt_number` (from 1) that
/// timed out with an error whose `str(type(e))` is `error_type` (default
/// `QR_TIMEOUT_ERROR_TYPE`).
#[pyfunction]
#[pyo3(signature = (attempt_number, error_type = None))]
fn qr_attempt_timeout_warning(attempt_number: u32, error_type: Option<&str>) -> String {
    auth::qr_attempt_timeout_warning(
        attempt_number,
        error_type.unwrap_or(auth::QR_TIMEOUT_ERROR_TYPE),
    )
}

/// The 1.5.0 warning after QR login attempt `attempt_number` (from 1)
/// failed.
#[pyfunction]
fn qr_attempt_retry_warning(attempt_number: u32) -> String {
    auth::qr_attempt_retry_warning(attempt_number)
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
    module.add("SRP_ALGORITHM", auth::SRP_ALGORITHM)?;
    module.add("QR_LOGIN_ATTEMPTS", auth::QR_LOGIN_ATTEMPTS)?;
    module.add("QR_EXPIRE_SAFETY_SECONDS", auth::QR_EXPIRE_SAFETY_SECONDS)?;
    module.add("QR_LOGIN_TIMEOUT", auth::QR_LOGIN_TIMEOUT)?;
    module.add("QR_TIMEOUT_ERROR_TYPE", auth::QR_TIMEOUT_ERROR_TYPE)?;
    module.add("EXISTING_SESSION_KEPT", auth::EXISTING_SESSION_KEPT)?;
    module.add("EXISTING_SESSION_REPLACED", auth::EXISTING_SESSION_REPLACED)?;
    module.add(
        "POST_LOGIN_APP_UPDATE_SOURCE",
        auth::POST_LOGIN_APP_UPDATE_SOURCE,
    )?;
    module.add(
        "POST_LOGIN_COUNTRIES_LANG_CODE",
        auth::POST_LOGIN_COUNTRIES_LANG_CODE,
    )?;
    let steps = auth::POST_LOGIN_STEPS
        .iter()
        .map(|step| post_login_step_dict(py, step))
        .collect::<PyResult<Vec<_>>>()?;
    module.add("POST_LOGIN_STEPS", PyTuple::new(py, steps)?)?;
    module.add_function(wrap_pyfunction!(qr_login_url, module)?)?;
    module.add_function(wrap_pyfunction!(unsupported_password_algorithm, module)?)?;
    module.add_function(wrap_pyfunction!(qr_attempt_timeout_warning, module)?)?;
    module.add_function(wrap_pyfunction!(qr_attempt_retry_warning, module)?)?;
    module.add_function(wrap_pyfunction!(post_login_steps, module)?)?;
    module.add_function(wrap_pyfunction!(random_delay_ms, module)?)?;
    module.add_function(wrap_pyfunction!(session_row, module)?)?;
    module.add_function(wrap_pyfunction!(consistency_report, module)?)?;
    module.add_function(wrap_pyfunction!(srp_check, module)?)?;
    module.add_function(wrap_pyfunction!(is_official_api_id, module)?)?;
    module.add_function(wrap_pyfunction!(format_sessions, module)?)?;
    module.add_function(wrap_pyfunction!(format_table, module)?)?;
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
