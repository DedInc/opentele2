//! The `initConnection` fingerprint helpers of 1.5.0 `src/fingerprint.py`.

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyInt, PyModule, PyString, PyTuple};

use opentele2_core::Error;
use opentele2_core::fingerprint::{
    self, FingerprintConfig, Issue, IssueKind, Severity, StrictMode,
};

use crate::api::{to_profile, versions};
use crate::convert::{dicts, optional, required};
use crate::error::check;

/// Every issue kind with its name, the Rust variant's.
const KINDS: [(&str, IssueKind); 9] = [
    ("UnknownLangPack", IssueKind::UnknownLangPack),
    ("ShortLangCode", IssueKind::ShortLangCode),
    ("MissingRegion", IssueKind::MissingRegion),
    ("EmptyDeviceModel", IssueKind::EmptyDeviceModel),
    ("EmptySystemVersion", IssueKind::EmptySystemVersion),
    ("EmptyAppVersion", IssueKind::EmptyAppVersion),
    ("ApiIdMismatch", IssueKind::ApiIdMismatch),
    ("AppVersionMajor", IssueKind::AppVersionMajor),
    ("AndroidSdkRange", IssueKind::AndroidSdkRange),
];

/// Every severity with its name.
const SEVERITIES: [(&str, Severity); 3] = [
    ("note", Severity::Note),
    ("warning", Severity::Warning),
    ("error", Severity::Error),
];

/// The config keys `fingerprint_config` takes.
const CONFIG_KEYS: [&str; 7] = [
    "strict_mode",
    "auto_validate",
    "preferred_transport",
    "warn_on_layer_mismatch",
    "layer_override",
    "randomize_msg_id_offset",
    "msg_id_offset",
];

/// The name `table` gives `value`.
fn name_of<T: PartialEq>(table: &[(&'static str, T)], value: &T) -> &'static str {
    table
        .iter()
        .find(|(_, known)| known == value)
        .map_or("", |(name, _)| name)
}

/// The value `table` names `name`; another name raises `ValueError`.
fn named<T: Copy>(table: &[(&'static str, T)], name: &str, what: &str) -> PyResult<T> {
    table
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, value)| *value)
        .ok_or_else(|| PyValueError::new_err(format!("unknown {what} {name:?}")))
}

/// The mode named `value`; any other text raises `ValueError`.
fn strict_mode(value: &str) -> PyResult<StrictMode> {
    StrictMode::from_value(value).ok_or_else(|| {
        PyValueError::new_err(format!(
            "unknown strict mode {value:?}; expected one of 'off', 'warn', 'strict'"
        ))
    })
}

/// A msg id offset; outside `0..=0xFFFF` raises `ValueError`.
fn to_offset(value: i64) -> PyResult<u16> {
    u16::try_from(value).map_err(|_| PyValueError::new_err("msg_id_offset must be in 0..=0xFFFF"))
}

/// `issues` as `Issue` dicts.
pub(crate) fn issue_dicts<'py>(
    py: Python<'py>,
    issues: &[Issue],
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    issues
        .iter()
        .map(|issue| {
            let dict = PyDict::new(py);
            dict.set_item("kind", name_of(&KINDS, &issue.kind))?;
            dict.set_item("severity", name_of(&SEVERITIES, &issue.severity))?;
            dict.set_item("message", &issue.message)?;
            Ok(dict)
        })
        .collect()
}

/// The core issue an `Issue` dict holds.
fn to_issue(dict: &Bound<'_, PyDict>) -> PyResult<Issue> {
    const WHAT: &str = "the issue";
    let kind: String = required(dict, "kind", WHAT)?;
    let severity: String = required(dict, "severity", WHAT)?;
    Ok(Issue {
        kind: named(&KINDS, &kind, "issue kind")?,
        severity: named(&SEVERITIES, &severity, "severity")?,
        message: required(dict, "message", WHAT)?,
    })
}

/// `config` as a `FingerprintConfig` dict.
fn config_dict<'py>(py: Python<'py>, config: &FingerprintConfig) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("strict_mode", config.strict_mode.as_str())?;
    dict.set_item("auto_validate", config.auto_validate)?;
    dict.set_item("preferred_transport", &config.preferred_transport)?;
    dict.set_item("warn_on_layer_mismatch", config.warn_on_layer_mismatch)?;
    dict.set_item("layer_override", config.layer_override)?;
    dict.set_item("randomize_msg_id_offset", config.randomize_msg_id_offset)?;
    dict.set_item("msg_id_offset", config.msg_id_offset)?;
    Ok(dict)
}

/// The core config a `FingerprintConfig` dict holds; `layer_override` may
/// be missing.
fn to_config(dict: &Bound<'_, PyDict>) -> PyResult<FingerprintConfig> {
    const WHAT: &str = "the fingerprint config";
    let mode: String = required(dict, "strict_mode", WHAT)?;
    Ok(FingerprintConfig {
        strict_mode: strict_mode(&mode)?,
        auto_validate: required(dict, "auto_validate", WHAT)?,
        preferred_transport: required(dict, "preferred_transport", WHAT)?,
        warn_on_layer_mismatch: required(dict, "warn_on_layer_mismatch", WHAT)?,
        layer_override: optional(dict, "layer_override")?,
        randomize_msg_id_offset: required(dict, "randomize_msg_id_offset", WHAT)?,
        msg_id_offset: to_offset(required(dict, "msg_id_offset", WHAT)?)?,
    })
}

/// The `tz_offset` Telegram Desktop sends in `initConnection` `params` for
/// a local UTC offset of `offset_seconds` (1.5.0 `tdesktop_tz_offset`):
/// wrapped by whole days into -12 h..+14 h, then rounded to a multiple of
/// 900 seconds, halves away from zero.
#[pyfunction]
fn tz_offset(offset_seconds: i32) -> f64 {
    fingerprint::tz_offset(offset_seconds)
}

/// The findings of 1.5.0 `validate_init_connection_params` for `profile`,
/// with `strict` on exactly when `mode` is `"strict"`; each finding has the
/// severity of `mode`. `versions` overrides the offline `PlatformVersions`
/// the strict version check compares with.
#[pyfunction]
#[pyo3(signature = (profile, versions = None, mode = "warn"))]
fn validate_init_params<'py>(
    py: Python<'py>,
    profile: &Bound<'py, PyDict>,
    versions: Option<&Bound<'py, PyDict>>,
    mode: &str,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let mode = strict_mode(mode)?;
    let issues =
        fingerprint::validate_init_params(&to_profile(profile)?, &self::versions(versions)?, mode);
    issue_dicts(py, &issues)
}

/// The findings of 1.5.0 `_check_version_consistency` for `profile`, each
/// an `"error"`: the app version major of `android`, `ios`, `tdesktop` and
/// `macos` profiles, and the Android SDK level range.
#[pyfunction]
#[pyo3(signature = (profile, versions = None))]
fn check_versions<'py>(
    py: Python<'py>,
    profile: &Bound<'py, PyDict>,
    versions: Option<&Bound<'py, PyDict>>,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let issues = fingerprint::check_versions(&to_profile(profile)?, &self::versions(versions)?);
    issue_dicts(py, &issues)
}

/// The message 1.5.0 `FingerprintConfig.validate_params` warns or raises
/// with: a header line, then one `  - ` line per issue.
#[pyfunction]
fn issues_message(issues: &Bound<'_, PyAny>) -> PyResult<String> {
    let issues = dicts(issues, "issue")?
        .iter()
        .map(to_issue)
        .collect::<PyResult<Vec<_>>>()?;
    Ok(fingerprint::issues_message(&issues))
}

/// Fills `buf` from the operating system's CSPRNG, recording the first
/// failure in `failure`.
fn fill_os(buf: &mut [u8], failure: &mut Option<getrandom::Error>) {
    if failure.is_none()
        && let Err(error) = getrandom::fill(buf)
    {
        *failure = Some(error);
    }
}

/// A random msg id offset in `0..=0xFFFF` from the operating system's
/// CSPRNG (1.5.0 `generate_msg_id_offset`).
#[pyfunction]
fn msg_id_offset(py: Python<'_>) -> PyResult<u16> {
    let mut failure = None;
    let offset = fingerprint::msg_id_offset(&mut |buf| fill_os(buf, &mut failure));
    match failure {
        Some(error) => check(py, Err(Error::Io(std::io::Error::other(error)))),
        None => Ok(offset),
    }
}

/// Whether `msg_id` is plausible at unix time `now_unix` (1.5.0
/// `is_valid_msg_id`): positive, odd when `from_client` and even otherwise,
/// with its upper 32 bits within 300 seconds of `now_unix`. A `float`
/// `now_unix` such as `time.time()` is truncated, as `int(time.time())`.
#[pyfunction]
fn is_valid_msg_id(
    py: Python<'_>,
    msg_id: i64,
    from_client: bool,
    now_unix: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let now_unix: i64 = py.get_type::<PyInt>().call1((now_unix,))?.extract()?;
    Ok(fingerprint::is_valid_msg_id(msg_id, from_client, now_unix))
}

/// A 1.5.0 `FingerprintConfig` with its defaults (`"warn"`, auto
/// validation, `"obfuscated"`, layer mismatch warnings, no layer override,
/// a randomized offset), each replaced by the keyword argument given.
/// Without `msg_id_offset` the offset is drawn from the OS random source.
#[pyfunction]
#[pyo3(signature = (**options))]
fn fingerprint_config<'py>(
    py: Python<'py>,
    options: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let options = match options {
        Some(options) => options.clone(),
        None => PyDict::new(py),
    };
    for key in options.keys() {
        let key = key.cast_into::<PyString>()?;
        let key = key.to_cow()?;
        if !CONFIG_KEYS.contains(&key.as_ref()) {
            return Err(PyTypeError::new_err(format!(
                "fingerprint_config() got an unexpected keyword argument {key:?}"
            )));
        }
    }
    let mut config = match optional::<i64>(&options, "msg_id_offset")? {
        Some(offset) => {
            let bytes = to_offset(offset)?.to_le_bytes();
            FingerprintConfig::new(&mut |buf| buf.copy_from_slice(&bytes))
        }
        None => check(py, FingerprintConfig::from_os_rng())?,
    };
    if let Some(mode) = optional::<String>(&options, "strict_mode")? {
        config.strict_mode = strict_mode(&mode)?;
    }
    if let Some(auto) = optional(&options, "auto_validate")? {
        config.auto_validate = auto;
    }
    if let Some(transport) = optional(&options, "preferred_transport")? {
        config.preferred_transport = transport;
    }
    if let Some(warn) = optional(&options, "warn_on_layer_mismatch")? {
        config.warn_on_layer_mismatch = warn;
    }
    if let Some(layer) = optional(&options, "layer_override")? {
        config.layer_override = Some(layer);
    }
    if let Some(randomize) = optional(&options, "randomize_msg_id_offset")? {
        config.randomize_msg_id_offset = randomize;
    }
    config_dict(py, &config)
}

/// The issues 1.5.0 `FingerprintConfig.validate_params` warns about or
/// raises for `profile`: none with `auto_validate` off or mode `"off"`,
/// otherwise `validate_init_params` under the configured mode.
#[pyfunction]
#[pyo3(signature = (config, profile, versions = None))]
fn validate_fingerprint<'py>(
    py: Python<'py>,
    config: &Bound<'py, PyDict>,
    profile: &Bound<'py, PyDict>,
    versions: Option<&Bound<'py, PyDict>>,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let issues = to_config(config)?.validate(&to_profile(profile)?, &self::versions(versions)?);
    issue_dicts(py, &issues)
}

/// The layer to invoke with (1.5.0 `get_effective_layer`): `layer_override`
/// when set, otherwise `LAYER`. Pass the `MTProto` library's layer as the
/// override to follow 1.5.0, which answers with Telethon's layer.
#[pyfunction]
fn effective_layer(config: &Bound<'_, PyDict>) -> PyResult<i32> {
    Ok(to_config(config)?.effective_layer())
}

/// Adds the fingerprint helpers to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let modes = StrictMode::ALL.map(StrictMode::as_str);
    module.add("STRICT_MODES", PyTuple::new(module.py(), modes)?)?;
    module.add_function(wrap_pyfunction!(tz_offset, module)?)?;
    module.add_function(wrap_pyfunction!(validate_init_params, module)?)?;
    module.add_function(wrap_pyfunction!(check_versions, module)?)?;
    module.add_function(wrap_pyfunction!(issues_message, module)?)?;
    module.add_function(wrap_pyfunction!(msg_id_offset, module)?)?;
    module.add_function(wrap_pyfunction!(is_valid_msg_id, module)?)?;
    module.add_function(wrap_pyfunction!(fingerprint_config, module)?)?;
    module.add_function(wrap_pyfunction!(validate_fingerprint, module)?)?;
    module.add_function(wrap_pyfunction!(effective_layer, module)?)?;
    Ok(())
}
