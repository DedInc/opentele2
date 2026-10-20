//! API profiles, device fingerprints and their catalogs, `PlatformVersions`
//! and the session JSON of 1.5.0 `APIData`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PyString, PyTuple};

use opentele2_core::Error;
use opentele2_core::api::session_json::{self, JsonDefault};
use opentele2_core::api::{self, ApiProfile, Client, Versions};
use opentele2_core::devices::{self, Platform};

use crate::convert::{required, seed};
use crate::error::check;
use crate::json::{from_json, to_json, to_json_object};

/// The client of the 1.5.0 class name `name`; another name raises
/// `ValueError`.
fn client(name: &str) -> PyResult<Client> {
    Client::from_name(name).ok_or_else(|| {
        let known = Client::ALL.map(Client::name);
        PyValueError::new_err(format!(
            "unknown client {name:?}; expected one of {}",
            known.join(", ")
        ))
    })
}

/// A two-item sequence as a pair; another length raises `ValueError`.
fn pair<'py, T>(value: &Bound<'py, PyAny>, key: &str) -> PyResult<(T, T)>
where
    T: FromPyObjectOwned<'py>,
{
    let items: Vec<T> = value.extract()?;
    let [low, high]: [T; 2] = items
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{key} must hold exactly 2 items")))?;
    Ok((low, high))
}

/// The offline `PlatformVersions` with the fields of `overrides` replaced;
/// an unknown field raises `ValueError`. A full `PlatformVersions` dict is
/// a valid override set.
pub(crate) fn versions(overrides: Option<&Bound<'_, PyDict>>) -> PyResult<Versions> {
    let mut versions = Versions::offline();
    let Some(overrides) = overrides else {
        return Ok(versions);
    };
    let v = &mut versions;
    for (key, value) in overrides.iter() {
        let key = key.cast_into::<PyString>()?;
        let key = key.to_cow()?;
        match key.as_ref() {
            "android_app_version" => v.android_app_version = value.extract()?,
            "android_app_version_code" => v.android_app_version_code = value.extract()?,
            "android_sdk_range" => v.android_sdk_range = pair(&value, &key)?,
            "android_latest_sdk" => v.android_latest_sdk = value.extract()?,
            "ios_app_version" => v.ios_app_version = value.extract()?,
            "ios_build_number" => v.ios_build_number = value.extract()?,
            "ios_version_range" => v.ios_version_range = pair(&value, &key)?,
            "ios_system_version" => v.ios_system_version = value.extract()?,
            "macos_system_version" => v.macos_system_version = value.extract()?,
            "desktop_app_version" => v.desktop_app_version = value.extract()?,
            "desktop_app_version_suffix" => v.desktop_app_version_suffix = value.extract()?,
            "macos_app_version" => v.macos_app_version = value.extract()?,
            "macos_build_number" => v.macos_build_number = value.extract()?,
            "android_x_app_version" => v.android_x_app_version = value.extract()?,
            "web_a_version" => v.web_a_version = value.extract()?,
            "web_k_version" => v.web_k_version = value.extract()?,
            "chrome_version" => v.chrome_version = value.extract()?,
            "user_agent" => v.user_agent = value.extract()?,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown versions field {other:?}"
                )));
            }
        }
    }
    Ok(versions)
}

/// Every field of `versions` as a dict, the ranges as tuples.
pub(crate) fn versions_dict<'py>(
    py: Python<'py>,
    versions: &Versions,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("android_app_version", &versions.android_app_version)?;
    dict.set_item(
        "android_app_version_code",
        versions.android_app_version_code,
    )?;
    dict.set_item("android_sdk_range", versions.android_sdk_range)?;
    dict.set_item("android_latest_sdk", versions.android_latest_sdk)?;
    dict.set_item("ios_app_version", &versions.ios_app_version)?;
    dict.set_item("ios_build_number", versions.ios_build_number)?;
    dict.set_item("ios_version_range", &versions.ios_version_range)?;
    dict.set_item("ios_system_version", &versions.ios_system_version)?;
    dict.set_item("macos_system_version", &versions.macos_system_version)?;
    dict.set_item("desktop_app_version", &versions.desktop_app_version)?;
    dict.set_item(
        "desktop_app_version_suffix",
        &versions.desktop_app_version_suffix,
    )?;
    dict.set_item("macos_app_version", &versions.macos_app_version)?;
    dict.set_item("macos_build_number", versions.macos_build_number)?;
    dict.set_item("android_x_app_version", &versions.android_x_app_version)?;
    dict.set_item("web_a_version", &versions.web_a_version)?;
    dict.set_item("web_k_version", &versions.web_k_version)?;
    dict.set_item("chrome_version", &versions.chrome_version)?;
    dict.set_item("user_agent", &versions.user_agent)?;
    Ok(dict)
}

/// The eight `initConnection` fields of `profile` as a dict.
pub(crate) fn profile_dict<'py>(
    py: Python<'py>,
    profile: &ApiProfile,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("api_id", profile.api_id)?;
    dict.set_item("api_hash", &profile.api_hash)?;
    dict.set_item("device_model", &profile.device_model)?;
    dict.set_item("system_version", &profile.system_version)?;
    dict.set_item("app_version", &profile.app_version)?;
    dict.set_item("lang_code", &profile.lang_code)?;
    dict.set_item("system_lang_code", &profile.system_lang_code)?;
    dict.set_item("lang_pack", &profile.lang_pack)?;
    Ok(dict)
}

/// The profile an `ApiProfile` dict holds; a missing field raises
/// `TypeError`, other keys are ignored.
pub(crate) fn to_profile(dict: &Bound<'_, PyDict>) -> PyResult<ApiProfile> {
    const WHAT: &str = "the profile";
    Ok(ApiProfile {
        api_id: required(dict, "api_id", WHAT)?,
        api_hash: required(dict, "api_hash", WHAT)?,
        device_model: required(dict, "device_model", WHAT)?,
        system_version: required(dict, "system_version", WHAT)?,
        app_version: required(dict, "app_version", WHAT)?,
        lang_code: required(dict, "lang_code", WHAT)?,
        system_lang_code: required(dict, "system_lang_code", WHAT)?,
        lang_pack: required(dict, "lang_pack", WHAT)?,
    })
}

/// The offline `PlatformVersions` of 1.5.0 (`OPENTELE_NO_FETCH`), with the
/// fields of `overrides` replaced.
#[pyfunction]
#[pyo3(signature = (overrides = None))]
fn platform_versions<'py>(
    py: Python<'py>,
    overrides: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    versions_dict(py, &versions(overrides)?)
}

/// The default API profile of `client` (a 1.5.0 class name such as
/// `"TelegramDesktop"`), with `versions` overriding the offline
/// `PlatformVersions` fields.
#[pyfunction]
#[pyo3(signature = (client, versions = None))]
fn profile<'py>(
    py: Python<'py>,
    client: &str,
    versions: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let client = self::client(client)?;
    let versions = self::versions(versions)?;
    profile_dict(py, &api::profile(client, &versions))
}

/// The profile 1.5.0 `API.<client>.Generate` returns: a device picked for
/// `seed` (`str`, or `int` as its decimal string), random without one.
/// `system` (`"windows"`, `"macos"` or `"linux"`) applies to
/// `"TelegramDesktop"` only. Web clients get a browser user agent picked
/// from the web catalog.
#[pyfunction]
#[pyo3(signature = (client, seed = None, system = None, versions = None))]
fn generate<'py>(
    py: Python<'py>,
    client: &str,
    seed: Option<&Bound<'py, PyAny>>,
    system: Option<String>,
    versions: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let client = self::client(client)?;
    let seed = self::seed(seed)?;
    let versions = self::versions(versions)?;
    if system.is_some() && client != Client::Desktop {
        return Err(PyValueError::new_err(
            "system applies only to TelegramDesktop",
        ));
    }
    let generated = py.detach(move || match client {
        Client::Desktop => api::generate_desktop(system.as_deref(), seed.as_deref(), &versions),
        other => api::generate(other, seed.as_deref(), &versions),
    });
    profile_dict(py, &check(py, generated)?)
}

/// The profile 1.5.0 `APIData.from_json` reads from session JSON, given as
/// its text or as a parsed dict. `app_id`, `app_hash`, `device`, `sdk` and
/// `app_version` are required; `lang_code` defaults to `"en"`, `lang_pack`
/// to `""`, and `system_lang_code` falls back to `system_lang_pack`, then
/// `"en"`. Malformed JSON or fields raise `CoreError` `IO`.
#[pyfunction]
fn profile_from_session_json<'py>(
    py: Python<'py>,
    json: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    // Session JSON is an object, so a string can only be its text.
    let data = match json.cast::<PyString>() {
        Ok(text) => {
            let text = text.to_cow()?;
            check(
                py,
                serde_json::from_str(&text).map_err(|error| {
                    Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid session JSON: {error}"),
                    ))
                }),
            )?
        }
        Err(_) => to_json(json)?,
    };
    profile_dict(py, &check(py, ApiProfile::from_session_json(&data))?)
}

/// The session JSON 1.5.0 `APIData.to_json(extra)` writes, keys in its
/// order: the profile's keys, then the 19 account keys with their defaults.
/// `extra` overrides those keys in place and appends its other keys in its
/// own order. `json.dumps(result, separators=(",", ":"))` is 1.5.0's
/// compact JSON.
#[pyfunction]
#[pyo3(signature = (profile, extra = None))]
fn profile_to_session_json<'py>(
    py: Python<'py>,
    profile: &Bound<'py, PyDict>,
    extra: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyAny>> {
    let profile = to_profile(profile)?;
    // No extra keys write the same JSON as no `extra`.
    let extra = extra.map(to_json_object).transpose()?.unwrap_or_default();
    from_json(py, &profile.to_session_json(Some(&extra)))
}

/// Whether `a` and `b` are the same client on the same device, as 1.5.0
/// `APIData.__eq__`: `api_id`, `api_hash`, `device_model`, `system_version`
/// and `app_version` are compared; the language fields are not.
#[pyfunction]
fn profiles_equal(a: &Bound<'_, PyDict>, b: &Bound<'_, PyDict>) -> PyResult<bool> {
    Ok(to_profile(a)? == to_profile(b)?)
}

/// 1.5.0 `format_app_version`: a packed Telegram Desktop version as
/// `major.minor.patch`, without a zero patch, so `7003001` is `"7.3.1"` and
/// `7003000` is `"7.3"`.
#[pyfunction]
fn format_app_version(version: u32) -> String {
    api::format_app_version(version)
}

/// A session JSON default as its Python value: `None`, a `bool` or a `str`.
fn json_default(py: Python<'_>, default: JsonDefault) -> PyResult<Bound<'_, PyAny>> {
    from_json(py, &default.to_value())
}

/// The profile keys of the session JSON, in the order 1.5.0
/// `APIData.to_json` writes them, as `(key, attribute, default, fallback)`
/// tuples: the `APIData` attribute the key reads into and writes from, the
/// value `from_json` takes when the key is absent, and the key read instead
/// when this key's value is falsy (`None` for none).
fn session_json_fields(py: Python<'_>) -> PyResult<Bound<'_, PyList>> {
    let fields = session_json::FIELDS
        .iter()
        .map(|field| {
            PyTuple::new(
                py,
                [
                    PyString::new(py, field.key).into_any(),
                    PyString::new(py, field.attribute).into_any(),
                    json_default(py, field.default)?,
                    field.fallback.into_pyobject(py)?.into_any(),
                ],
            )
        })
        .collect::<PyResult<Vec<_>>>()?;
    PyList::new(py, fields)
}

/// 1.5.0 `list(_DEFAULT_EXTRA_FIELDS.items())`: the account keys
/// `APIData.to_json` writes after the profile keys, with their defaults, as
/// `(key, default)` tuples in order.
fn default_extra_fields(py: Python<'_>) -> PyResult<Bound<'_, PyList>> {
    let fields = session_json::DEFAULT_EXTRA_FIELDS
        .iter()
        .map(|(key, default)| {
            PyTuple::new(
                py,
                [
                    PyString::new(py, key).into_any(),
                    json_default(py, *default)?,
                ],
            )
        })
        .collect::<PyResult<Vec<_>>>()?;
    PyList::new(py, fields)
}

/// The platform of the catalog name `name` (as `catalog_entries`,
/// `device_models` and `system_versions` take it); an unknown name raises
/// `ValueError`.
fn platform(name: &str) -> PyResult<Platform> {
    Platform::from_name(name).ok_or_else(|| {
        let known = Platform::NAMED.map(Platform::name);
        PyValueError::new_err(format!(
            "unknown platform {name:?}; expected one of {}",
            known.join(", ")
        ))
    })
}

/// The catalog of `name`, built on first use; a malformed embedded catalog
/// raises `CoreError` `IO`.
fn catalog(py: Python<'_>, name: &str) -> PyResult<&'static devices::Catalog> {
    let platform = self::platform(name)?;
    check(py, py.detach(move || devices::catalog(platform)))
}

/// The weighted device pairs of the `platform` catalog (`"windows"`,
/// `"linux"`, `"macos"`, `"android"`, `"ios"`, `"web_a"` or `"web_k"`) in
/// 1.5.0's `deviceList` order, as `model`, `system_version` and `weight`
/// dicts: the weight is how many times 1.5.0 repeats the pair. Mac versions
/// are bare, as in 1.5.0 `macOSDevice.deviceList`.
#[pyfunction]
fn catalog_entries<'py>(py: Python<'py>, platform: &str) -> PyResult<Bound<'py, PyList>> {
    let entries = catalog(py, platform)?
        .entries()
        .map(|entry| {
            let dict = PyDict::new(py);
            dict.set_item("model", entry.model)?;
            dict.set_item("system_version", entry.system_version)?;
            dict.set_item("weight", entry.weight)?;
            Ok(dict)
        })
        .collect::<PyResult<Vec<_>>>()?;
    PyList::new(py, entries)
}

/// The models of the `platform` catalog in file order: 1.5.0
/// `device_models` of the desktop, Mac and iOS classes (empty for Android).
#[pyfunction]
fn device_models(py: Python<'_>, platform: &str) -> PyResult<Vec<&'static str>> {
    Ok(catalog(py, platform)?
        .device_models()
        .iter()
        .map(String::as_str)
        .collect())
}

/// The system versions of the `platform` catalog in file order: 1.5.0
/// `system_versions` of the desktop, Mac and iOS classes, `SDK 29` to
/// `SDK 37` for Android, and the client's platform strings for the web.
#[pyfunction]
fn system_versions(py: Python<'_>, platform: &str) -> PyResult<Vec<&'static str>> {
    Ok(catalog(py, platform)?
        .system_versions()
        .iter()
        .map(String::as_str)
        .collect())
}

/// 1.5.0 `WebBrowserDevice.BROWSER_WEIGHTS`, in its order.
fn web_browser_weights(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let dict = PyDict::new(py);
    for (browser, weight) in devices::WEB_BROWSER_WEIGHTS {
        dict.set_item(browser, weight)?;
    }
    Ok(dict)
}

/// Adds the fingerprint functions to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    module.add("LAYER", api::LAYER)?;
    module.add("SESSION_JSON_FIELDS", session_json_fields(py)?)?;
    module.add("DEFAULT_EXTRA_FIELDS", default_extra_fields(py)?)?;
    module.add("WEB_BROWSER_WEIGHTS", web_browser_weights(py)?)?;
    module.add_function(wrap_pyfunction!(format_app_version, module)?)?;
    module.add_function(wrap_pyfunction!(catalog_entries, module)?)?;
    module.add_function(wrap_pyfunction!(device_models, module)?)?;
    module.add_function(wrap_pyfunction!(system_versions, module)?)?;
    module.add_function(wrap_pyfunction!(platform_versions, module)?)?;
    module.add_function(wrap_pyfunction!(profile, module)?)?;
    module.add_function(wrap_pyfunction!(generate, module)?)?;
    module.add_function(wrap_pyfunction!(profile_from_session_json, module)?)?;
    module.add_function(wrap_pyfunction!(profile_to_session_json, module)?)?;
    module.add_function(wrap_pyfunction!(profiles_equal, module)?)?;
    Ok(())
}
