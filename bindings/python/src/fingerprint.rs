//! The `initConnection` fingerprint helpers of 1.5.0 `src/fingerprint.py`,
//! and the browser header and fingerprint generation of `opentele2.browser`.

use pyo3::exceptions::{PyOSError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyModule, PyString, PyTuple};

use opentele2_browser::headers::{
    SUPPORTED_BROWSERS, SUPPORTED_DEVICES, SUPPORTED_OPERATING_SYSTEMS,
};
use opentele2_browser::{
    Browser, FingerprintGenerator, FingerprintOptions, FingerprintOverrides, HeaderGenerator,
    HeaderOptions, HeaderOverrides, Headers, HttpVersion, Rng, Screen,
};
use opentele2_core::fingerprint::{
    self, FingerprintConfig, FingerprintConfigOptions, Issue, IssueKind, RawApiId, RawInitParams,
    Severity, StrictMode,
};

use crate::api::{to_profile, versions};
use crate::convert::{dicts, optional, required, seed};
use crate::error::check;
use crate::json::from_json;

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

/// The option keys `generate_headers` takes, browserforge's
/// `HeaderGenerator` argument names.
const HEADER_KEYS: [&str; 8] = [
    "browser",
    "os",
    "device",
    "locale",
    "http_version",
    "strict",
    "user_agent",
    "request_dependent_headers",
];

/// The option keys `generate_fingerprint` takes; `header` holds the
/// `generate_headers` options.
const FINGERPRINT_KEYS: [&str; 5] = ["screen", "strict", "mock_webrtc", "slim", "header"];

/// The bound keys of a screen constraint dict.
const SCREEN_KEYS: [&str; 4] = ["min_width", "max_width", "min_height", "max_height"];

/// The keys of a browser dict.
const BROWSER_KEYS: [&str; 4] = ["name", "min_version", "max_version", "http_version"];

/// A browser crate error as Python raises it: `OSError` without system
/// entropy, otherwise `ValueError`, as browserforge does.
fn browser_error(error: &opentele2_browser::Error) -> PyErr {
    match error {
        opentele2_browser::Error::Entropy(_) => PyOSError::new_err(error.to_string()),
        _ => PyValueError::new_err(error.to_string()),
    }
}

/// An option error of the browser crate as browserforge raises it: its
/// bare text for invalid options, otherwise as `browser_error`.
fn options_error(error: opentele2_browser::Error) -> PyErr {
    match error {
        opentele2_browser::Error::InvalidOptions(text) => PyValueError::new_err(text),
        other => browser_error(&other),
    }
}

/// Raises `TypeError` naming `what` for a key of `dict` outside `keys`.
fn check_keys(dict: &Bound<'_, PyDict>, keys: &[&str], what: &str) -> PyResult<()> {
    for key in dict.keys() {
        let key = key
            .cast_into::<PyString>()
            .map_err(|_| PyTypeError::new_err(format!("{what} keys must be str")))?;
        let key = key.to_cow()?;
        if !keys.contains(&key.as_ref()) {
            return Err(PyTypeError::new_err(format!(
                "{what} got an unexpected option {key:?}"
            )));
        }
    }
    Ok(())
}

/// `options` updated with `kwargs`, its keys checked against `keys`.
fn merged_options<'py>(
    py: Python<'py>,
    options: Option<&Bound<'py, PyDict>>,
    kwargs: Option<&Bound<'py, PyDict>>,
    keys: &[&str],
    what: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let merged = PyDict::new(py);
    for source in [options, kwargs].into_iter().flatten() {
        merged.update(source.as_mapping())?;
    }
    check_keys(&merged, keys, what)?;
    Ok(merged)
}

/// The value of `key` in `dict`, `None` when it is missing or `None`.
fn present<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
    Ok(dict.get_item(key)?.filter(|value| !value.is_none()))
}

/// A `str` as one text, any other iterable as its `str` items, as
/// browserforge's `tuplify`.
fn texts(value: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    if let Ok(text) = value.cast::<PyString>() {
        return Ok(vec![text.to_cow()?.into_owned()]);
    }
    value
        .try_iter()?
        .map(|item| item?.extract::<String>())
        .collect()
}

/// An HTTP version given as `1`, `2`, `"1"` or `"2"`; another value raises
/// `ValueError`.
fn http_version(value: &Bound<'_, PyAny>) -> PyResult<HttpVersion> {
    let text = if value.is_instance_of::<PyBool>() {
        String::new()
    } else {
        value.str()?.to_cow()?.into_owned()
    };
    match text.as_str() {
        "1" => Ok(HttpVersion::One),
        "2" => Ok(HttpVersion::Two),
        _ => Err(PyValueError::new_err(format!(
            "http_version must be 1 or 2, not {}",
            value.repr()?
        ))),
    }
}

/// The browsers of a `browser` option: names, which speak `default`, or
/// dicts with `name` and optional `min_version`, `max_version` and
/// `http_version` (`default` when absent).
fn browsers(value: &Bound<'_, PyAny>, default: HttpVersion) -> PyResult<Vec<Browser>> {
    let items: Vec<Bound<'_, PyAny>> = if value.is_instance_of::<PyString>() {
        vec![value.clone()]
    } else {
        value.try_iter()?.collect::<PyResult<_>>()?
    };
    items
        .iter()
        .map(|item| {
            if let Ok(name) = item.cast::<PyString>() {
                return Ok(Browser {
                    http_version: default,
                    ..Browser::new(name.to_cow()?.into_owned())
                });
            }
            let dict = item.cast::<PyDict>().map_err(|_| {
                PyTypeError::new_err("every browser must be a str or a dict with a name")
            })?;
            check_keys(dict, &BROWSER_KEYS, "the browser")?;
            let http = present(dict, "http_version")?
                .map(|value| http_version(&value))
                .transpose()?
                .unwrap_or(default);
            Ok(Browser {
                name: required(dict, "name", "the browser")?,
                min_version: optional(dict, "min_version")?,
                max_version: optional(dict, "max_version")?,
                http_version: http,
            })
        })
        .collect()
}

/// The generator options and per-call overrides a `generate_headers`
/// options dict holds, defaulting as browserforge's `HeaderGenerator`.
fn header_request(dict: &Bound<'_, PyDict>) -> PyResult<(HeaderOptions, HeaderOverrides)> {
    check_keys(dict, &HEADER_KEYS, "the header options")?;
    let mut options = HeaderOptions::default();
    if let Some(value) = present(dict, "http_version")? {
        options = options.with_http_version(http_version(&value)?);
    }
    if let Some(value) = present(dict, "browser")? {
        options.browsers = browsers(&value, options.http_version)?;
    }
    if let Some(value) = present(dict, "os")? {
        options.os = texts(&value)?;
    }
    if let Some(value) = present(dict, "device")? {
        options.devices = texts(&value)?;
    }
    if let Some(value) = present(dict, "locale")? {
        options.locales = texts(&value)?;
    }
    if let Some(strict) = optional(dict, "strict")? {
        options.strict = strict;
    }
    let mut overrides = HeaderOverrides::default();
    if let Some(value) = present(dict, "user_agent")? {
        overrides.user_agent = texts(&value)?;
    }
    if let Some(value) = present(dict, "request_dependent_headers")? {
        let headers = value.cast::<PyDict>().map_err(|_| {
            PyTypeError::new_err("request_dependent_headers must be a dict of str to str")
        })?;
        overrides.request_dependent_headers = headers
            .iter()
            .map(|(name, value)| Ok((name.extract::<String>()?, value.extract::<String>()?)))
            .collect::<PyResult<Headers>>()?;
    }
    Ok((options, overrides))
}

/// The screen constraint a dict of `min_width`, `max_width`, `min_height`
/// and `max_height` holds, each optional.
fn screen(value: &Bound<'_, PyAny>) -> PyResult<Screen> {
    let dict = value
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err("the screen must be a dict of its bounds"))?;
    check_keys(dict, &SCREEN_KEYS, "the screen")?;
    Ok(Screen {
        min_width: optional(dict, "min_width")?,
        max_width: optional(dict, "max_width")?,
        min_height: optional(dict, "min_height")?,
        max_height: optional(dict, "max_height")?,
    })
}

/// A generator seeded from the text of `seed`, or from the operating
/// system's entropy without one.
fn rng(seed: Option<&str>) -> opentele2_browser::Result<Rng> {
    seed.map_or_else(Rng::from_entropy, |seed| Ok(Rng::from_seed(seed)))
}

/// `headers` as a dict, in sending order.
fn headers_dict<'py>(py: Python<'py>, headers: &Headers) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (name, value) in headers {
        dict.set_item(name, value)?;
    }
    Ok(dict)
}

/// `browser` as a browser dict, its HTTP version as browserforge spells it.
fn browser_dict<'py>(py: Python<'py>, browser: &Browser) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("name", &browser.name)?;
    dict.set_item("min_version", browser.min_version)?;
    dict.set_item("max_version", browser.max_version)?;
    dict.set_item("http_version", browser.http_version.as_str())?;
    Ok(dict)
}

/// The HTTP version `value` (`1`, `2`, `"1"` or `"2"`) as browserforge
/// spells it, `"1"` or `"2"`; another value raises `ValueError`.
#[pyfunction]
#[pyo3(name = "http_version")]
fn http_version_text(value: &Bound<'_, PyAny>) -> PyResult<&'static str> {
    Ok(http_version(value)?.as_str())
}

/// The browsers of a `browser` option (names or browser dicts, as
/// `generate_headers` takes them), each switched to `http_version`, as
/// browserforge's `generate` applies a new HTTP version to every
/// configured browser. Returns browser dicts.
#[pyfunction]
fn browsers_with_http_version<'py>(
    py: Python<'py>,
    browsers: &Bound<'py, PyAny>,
    http_version: &Bound<'py, PyAny>,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let http = self::http_version(http_version)?;
    let options = HeaderOptions {
        browsers: self::browsers(browsers, http)?,
        ..HeaderOptions::default()
    }
    .with_http_version(http);
    options
        .browsers
        .iter()
        .map(|browser| browser_dict(py, browser))
        .collect()
}

/// Checks the version bounds of a browser as browserforge's
/// `Browser.__post_init__`: a minimum above the maximum raises `ValueError`
/// with the header generator's text.
#[pyfunction]
#[pyo3(signature = (min_version = None, max_version = None))]
fn validate_browser(min_version: Option<u32>, max_version: Option<u32>) -> PyResult<()> {
    // The header generator owns the check; the name plays no part in it.
    let browser = Browser {
        min_version,
        max_version,
        ..Browser::new(SUPPORTED_BROWSERS[0])
    };
    HeaderGenerator::new(HeaderOptions {
        browsers: vec![browser],
        ..HeaderOptions::default()
    })
    .map(drop)
    .map_err(options_error)
}

/// Checks the bounds of a screen constraint as browserforge's
/// `Screen.__post_init__`: a minimum above its maximum raises `ValueError`.
#[pyfunction]
#[pyo3(signature = (min_width = None, max_width = None, min_height = None, max_height = None))]
fn validate_screen(
    min_width: Option<u32>,
    max_width: Option<u32>,
    min_height: Option<u32>,
    max_height: Option<u32>,
) -> PyResult<()> {
    Screen {
        min_width,
        max_width,
        min_height,
        max_height,
    }
    .validate()
    .map_err(options_error)
}

/// One set of browser HTTP headers, name to value in sending order, as
/// browserforge's `HeaderGenerator(...).generate(...)`. The options (a dict,
/// updated by the keyword arguments) are browserforge's: `browser` (names or
/// dicts of `name`, `min_version`, `max_version`, `http_version`), `os`,
/// `device`, `locale` (each a `str` or a list), `http_version` (1 or 2),
/// `strict`, `user_agent` and `request_dependent_headers`. A `seed` (`str`
/// or `int`) makes the draw reproducible; without one it comes from the
/// operating system's entropy. Unsatisfiable or invalid options raise
/// `ValueError`; runs with the thread detached.
#[pyfunction]
#[pyo3(signature = (options = None, *, seed = None, **kwargs))]
fn generate_headers<'py>(
    py: Python<'py>,
    options: Option<&Bound<'py, PyDict>>,
    seed: Option<&Bound<'py, PyAny>>,
    kwargs: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let merged = merged_options(py, options, kwargs, &HEADER_KEYS, "generate_headers()")?;
    let (options, overrides) = header_request(&merged)?;
    let seed = self::seed(seed)?;
    let headers = py
        .detach(move || {
            let mut rng = rng(seed.as_deref())?;
            HeaderGenerator::new(options)?.generate(&mut rng, &overrides)
        })
        .map_err(|error| browser_error(&error))?;
    headers_dict(py, &headers)
}

/// One browser fingerprint with its matching headers, as browserforge's
/// `FingerprintGenerator(...).generate(...)`, as a dict of browserforge's
/// `Fingerprint` fields (`screen`, `navigator`, `headers`, `videoCodecs`,
/// `audioCodecs`, `pluginsData`, `battery`, `videoCard`,
/// `multimediaDevices`, `fonts`, `mockWebRTC`, `slim`). The options (a dict,
/// updated by the keyword arguments) are `screen` (a dict of `min_width`,
/// `max_width`, `min_height`, `max_height`), `strict`, `mock_webrtc`,
/// `slim` and `header`, the `generate_headers` options. `seed` as for
/// `generate_headers`. Unsatisfiable or invalid options raise `ValueError`;
/// runs with the thread detached.
#[pyfunction]
#[pyo3(signature = (options = None, *, seed = None, **kwargs))]
fn generate_fingerprint<'py>(
    py: Python<'py>,
    options: Option<&Bound<'py, PyDict>>,
    seed: Option<&Bound<'py, PyAny>>,
    kwargs: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyAny>> {
    let merged = merged_options(
        py,
        options,
        kwargs,
        &FINGERPRINT_KEYS,
        "generate_fingerprint()",
    )?;
    let (header, header_overrides) = match present(&merged, "header")? {
        Some(value) => header_request(
            value
                .cast::<PyDict>()
                .map_err(|_| PyTypeError::new_err("the header options must be a dict"))?,
        )?,
        None => (HeaderOptions::default(), HeaderOverrides::default()),
    };
    let options = FingerprintOptions {
        screen: present(&merged, "screen")?
            .map(|value| screen(&value))
            .transpose()?,
        strict: optional(&merged, "strict")?.unwrap_or(false),
        mock_webrtc: optional(&merged, "mock_webrtc")?.unwrap_or(false),
        slim: optional(&merged, "slim")?.unwrap_or(false),
        header,
    };
    let overrides = FingerprintOverrides {
        header: header_overrides,
        ..FingerprintOverrides::default()
    };
    let seed = self::seed(seed)?;
    let fingerprint = py
        .detach(move || {
            let mut rng = rng(seed.as_deref())?;
            FingerprintGenerator::new(options)?.generate(&mut rng, &overrides)
        })
        .map_err(|error| browser_error(&error))?;
    let value = serde_json::to_value(&fingerprint)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    from_json(py, &value)
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
    // The 1.5.0 FingerprintConfig defaults, without the drawn offset.
    let defaults = config_dict(
        module.py(),
        &undrawn_config(FingerprintConfigOptions::default()),
    )?;
    defaults.del_item("msg_id_offset")?;
    module.add("FINGERPRINT_CONFIG_DEFAULTS", defaults)?;
    module.add_function(wrap_pyfunction!(validate_fingerprint, module)?)?;
    module.add_function(wrap_pyfunction!(validate_raw_fingerprint, module)?)?;
    module.add_function(wrap_pyfunction!(effective_layer, module)?)?;
    module.add_function(wrap_pyfunction!(effective_layer_for, module)?)?;
    module.add_function(wrap_pyfunction!(layer_mismatch_warning, module)?)?;
    module.add(
        "SUPPORTED_BROWSERS",
        PyTuple::new(module.py(), SUPPORTED_BROWSERS)?,
    )?;
    module.add(
        "SUPPORTED_OPERATING_SYSTEMS",
        PyTuple::new(module.py(), SUPPORTED_OPERATING_SYSTEMS)?,
    )?;
    module.add(
        "SUPPORTED_DEVICES",
        PyTuple::new(module.py(), SUPPORTED_DEVICES)?,
    )?;
    let http_versions = [HttpVersion::One, HttpVersion::Two].map(HttpVersion::as_str);
    module.add(
        "SUPPORTED_HTTP_VERSIONS",
        PyTuple::new(module.py(), http_versions)?,
    )?;
    module.add_function(wrap_pyfunction!(http_version_text, module)?)?;
    module.add_function(wrap_pyfunction!(browsers_with_http_version, module)?)?;
    module.add_function(wrap_pyfunction!(validate_browser, module)?)?;
    module.add_function(wrap_pyfunction!(validate_screen, module)?)?;
    module.add_function(wrap_pyfunction!(generate_headers, module)?)?;
    module.add_function(wrap_pyfunction!(generate_fingerprint, module)?)?;
    Ok(())
}
