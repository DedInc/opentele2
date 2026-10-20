//! The `initConnection` fingerprint helpers of 1.5.0 `src/fingerprint.py`.

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyModule, PyString, PyTuple};

use opentele2_core::fingerprint::{
    self, FingerprintConfig, FingerprintConfigOptions, Issue, IssueKind, RawApiId, RawInitParams,
    Severity, StrictMode,
};

use crate::api::{to_profile, versions};
use crate::convert::{dicts, optional, required};
use crate::error::check;

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
    fingerprint::to_offset(value)
        .ok_or_else(|| PyValueError::new_err("msg_id_offset must be in 0..=0xFFFF"))
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
            dict.set_item("kind", issue.kind.name())?;
            dict.set_item("severity", issue.severity.name())?;
            dict.set_item("message", &issue.message)?;
            Ok(dict)
        })
        .collect()
}

/// The core issue an `Issue` dict holds; an unknown kind or severity
/// raises `ValueError`.
fn to_issue(dict: &Bound<'_, PyDict>) -> PyResult<Issue> {
    const WHAT: &str = "the issue";
    let kind: String = required(dict, "kind", WHAT)?;
    let severity: String = required(dict, "severity", WHAT)?;
    Ok(Issue {
        kind: IssueKind::from_name(&kind)
            .ok_or_else(|| PyValueError::new_err(format!("unknown issue kind {kind:?}")))?,
        severity: Severity::from_name(&severity)
            .ok_or_else(|| PyValueError::new_err(format!("unknown severity {severity:?}")))?,
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

/// A config with `options` over the defaults, without drawing an offset:
/// for the checks that never read it.
fn undrawn_config(options: FingerprintConfigOptions) -> FingerprintConfig {
    FingerprintConfig::with_options(
        FingerprintConfigOptions {
            msg_id_offset: Some(0),
            ..options
        },
        &mut |_| {},
    )
}

/// An `api_id` argument as the caller gave it, owned.
enum ApiIdArg {
    Int(i64),
    Float(f64),
    Bool(bool),
    Text(String),
    Missing,
}

impl ApiIdArg {
    /// `value` as the core compares and shows it: `None`, a `bool`, an
    /// `int` (outside `i64` as its decimal text) or a `float` as such, any
    /// other value as its `str()`, which equals no official id.
    fn new(value: &Bound<'_, PyAny>) -> PyResult<Self> {
        if value.is_none() {
            return Ok(Self::Missing);
        }
        if let Ok(flag) = value.cast::<PyBool>() {
            return Ok(Self::Bool(flag.is_true()));
        }
        if value.is_instance_of::<PyInt>()
            && let Ok(number) = value.extract::<i64>()
        {
            return Ok(Self::Int(number));
        }
        if value.is_instance_of::<PyFloat>() {
            return Ok(Self::Float(value.extract()?));
        }
        Ok(Self::Text(value.str()?.to_cow()?.into_owned()))
    }

    fn raw(&self) -> RawApiId<'_> {
        match self {
            Self::Int(value) => RawApiId::Int(*value),
            Self::Float(value) => RawApiId::Float(*value),
            Self::Bool(value) => RawApiId::Bool(*value),
            Self::Text(text) => RawApiId::Text(text),
            Self::Missing => RawApiId::Missing,
        }
    }
}

/// The arguments of 1.5.0 `validate_init_connection_params`, owned.
struct InitArgs {
    api_id: ApiIdArg,
    device_model: Option<String>,
    system_version: Option<String>,
    app_version: Option<String>,
    system_lang_code: Option<String>,
    lang_pack: Option<String>,
    lang_code: Option<String>,
}

/// The keys of a `RawInitParams` dict, the 1.5.0 argument names.
const INIT_PARAM_KEYS: [&str; 7] = [
    "api_id",
    "device_model",
    "system_version",
    "app_version",
    "system_lang_code",
    "lang_pack",
    "lang_code",
];

impl InitArgs {
    /// The arguments a `RawInitParams` dict holds. As a call of 1.5.0
    /// `validate_init_connection_params`, a missing or unknown key raises
    /// `TypeError`; a text may be `None`, and `lang_pack` may be any value,
    /// which 1.5.0 looked up as its `str()`.
    fn new(params: &Bound<'_, PyDict>) -> PyResult<Self> {
        const WHAT: &str = "the init params";
        for key in params.keys() {
            let key = key.cast_into::<PyString>()?;
            let key = key.to_cow()?;
            if !INIT_PARAM_KEYS.contains(&key.as_ref()) {
                return Err(PyTypeError::new_err(format!(
                    "{WHAT} got an unexpected argument {key:?}"
                )));
            }
        }
        let api_id: Bound<'_, PyAny> = required(params, "api_id", WHAT)?;
        let lang_pack: Bound<'_, PyAny> = required(params, "lang_pack", WHAT)?;
        let lang_pack = if lang_pack.is_none() {
            None
        } else {
            Some(lang_pack.str()?.to_cow()?.into_owned())
        };
        Ok(Self {
            api_id: ApiIdArg::new(&api_id)?,
            device_model: required(params, "device_model", WHAT)?,
            system_version: required(params, "system_version", WHAT)?,
            app_version: required(params, "app_version", WHAT)?,
            system_lang_code: required(params, "system_lang_code", WHAT)?,
            lang_pack,
            lang_code: required(params, "lang_code", WHAT)?,
        })
    }

    fn raw(&self) -> RawInitParams<'_> {
        RawInitParams {
            api_id: self.api_id.raw(),
            device_model: self.device_model.as_deref(),
            system_version: self.system_version.as_deref(),
            app_version: self.app_version.as_deref(),
            system_lang_code: self.system_lang_code.as_deref(),
            lang_pack: self.lang_pack.as_deref(),
            lang_code: self.lang_code.as_deref(),
        }
    }
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

/// The findings of 1.5.0 `validate_init_connection_params` for `params`,
/// its seven arguments as the caller gave them (`None` for any text, an
/// `api_id` of any type), with `strict` on exactly when `mode` is
/// `"strict"`. Each message shows the values as 1.5.0 shows them.
#[pyfunction]
#[pyo3(signature = (params, versions = None, mode = "warn"))]
fn validate_raw_init_params<'py>(
    py: Python<'py>,
    params: &Bound<'py, PyDict>,
    versions: Option<&Bound<'py, PyDict>>,
    mode: &str,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let mode = strict_mode(mode)?;
    let args = InitArgs::new(params)?;
    let issues =
        fingerprint::validate_raw_init_params(&args.raw(), &self::versions(versions)?, mode);
    issue_dicts(py, &issues)
}

/// The findings 1.5.0 `FingerprintConfig.validate_params` warns about or
/// raises for `params`, as `validate_raw_init_params` takes them, under a
/// config with `strict_mode` and `auto_validate`: none with `auto_validate`
/// off or mode `"off"`, otherwise those of the mode.
#[pyfunction]
#[pyo3(signature = (strict_mode, auto_validate, params, versions = None))]
fn validate_raw_fingerprint<'py>(
    py: Python<'py>,
    strict_mode: &str,
    auto_validate: bool,
    params: &Bound<'py, PyDict>,
    versions: Option<&Bound<'py, PyDict>>,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let config = undrawn_config(FingerprintConfigOptions {
        strict_mode: Some(self::strict_mode(strict_mode)?),
        auto_validate: Some(auto_validate),
        ..FingerprintConfigOptions::default()
    });
    let args = InitArgs::new(params)?;
    let issues = config.validate_raw(&args.raw(), &self::versions(versions)?);
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

/// A random msg id offset in `0..=0xFFFF` from the operating system's
/// CSPRNG (1.5.0 `generate_msg_id_offset`).
#[pyfunction]
fn msg_id_offset(py: Python<'_>) -> PyResult<u16> {
    check(py, fingerprint::msg_id_offset_for_os())
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
    let msg_id_offset = optional::<i64>(&options, "msg_id_offset")?
        .map(to_offset)
        .transpose()?;
    let strict_mode = optional::<String>(&options, "strict_mode")?
        .as_deref()
        .map(strict_mode)
        .transpose()?;
    let options = FingerprintConfigOptions {
        strict_mode,
        auto_validate: optional(&options, "auto_validate")?,
        preferred_transport: optional(&options, "preferred_transport")?,
        warn_on_layer_mismatch: optional(&options, "warn_on_layer_mismatch")?,
        layer_override: optional(&options, "layer_override")?,
        randomize_msg_id_offset: optional(&options, "randomize_msg_id_offset")?,
        msg_id_offset,
    };
    config_dict(py, &check(py, FingerprintConfig::from_options(options))?)
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

/// 1.5.0 `get_effective_layer` for an `MTProto` library built for
/// `library_layer`, as `(layer, warning)`: `layer_override` and no warning
/// when it is set, otherwise `library_layer` and the
/// `layer_mismatch_warning` of it.
#[pyfunction]
#[pyo3(signature = (library_layer, layer_override = None))]
fn effective_layer_for(library_layer: i32, layer_override: Option<i32>) -> (i32, Option<String>) {
    undrawn_config(FingerprintConfigOptions {
        layer_override,
        ..FingerprintConfigOptions::default()
    })
    .effective_layer_for(library_layer)
}

/// The warning 1.5.0 `get_recommended_layer` emits for an `MTProto`
/// library layer more than `LAYER_TOLERANCE` layers from `LAYER`; `None`
/// within it.
#[pyfunction]
fn layer_mismatch_warning(library_layer: i32) -> Option<String> {
    fingerprint::layer_mismatch_warning(library_layer)
}

/// Adds the fingerprint helpers to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let modes = StrictMode::ALL.map(StrictMode::as_str);
    module.add("STRICT_MODES", PyTuple::new(module.py(), modes)?)?;
    module.add_function(wrap_pyfunction!(tz_offset, module)?)?;
    module.add_function(wrap_pyfunction!(validate_init_params, module)?)?;
    module.add_function(wrap_pyfunction!(validate_raw_init_params, module)?)?;
    module.add_function(wrap_pyfunction!(check_versions, module)?)?;
    module.add_function(wrap_pyfunction!(issues_message, module)?)?;
    // The largest offset `msg_id_offset` draws, so a facade can draw from
    // Python's `random` in the same `0..=MSG_ID_OFFSET_MAX` range.
    module.add("MSG_ID_OFFSET_MAX", u16::MAX)?;
    module.add_function(wrap_pyfunction!(msg_id_offset, module)?)?;
    module.add_function(wrap_pyfunction!(is_valid_msg_id, module)?)?;
    module.add_function(wrap_pyfunction!(fingerprint_config, module)?)?;
    module.add_function(wrap_pyfunction!(validate_fingerprint, module)?)?;
    module.add_function(wrap_pyfunction!(validate_raw_fingerprint, module)?)?;
    module.add_function(wrap_pyfunction!(effective_layer, module)?)?;
    module.add_function(wrap_pyfunction!(effective_layer_for, module)?)?;
    module.add_function(wrap_pyfunction!(layer_mismatch_warning, module)?)?;
    Ok(())
}
