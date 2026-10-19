//! API profiles and device fingerprints.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule, PyString};

use opentele2_core::api::{self, ApiProfile, Client, Versions};

use crate::convert::seed;
use crate::error::check;

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

fn client(name: &str) -> PyResult<Client> {
    CLIENT_NAMES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, client)| *client)
        .ok_or_else(|| {
            let known: Vec<&str> = CLIENT_NAMES.iter().map(|(known, _)| *known).collect();
            PyValueError::new_err(format!(
                "unknown client {name:?}; expected one of {}",
                known.join(", ")
            ))
        })
}

/// The offline `PlatformVersions` with the fields of `overrides` replaced;
/// an unknown field raises `ValueError`.
fn versions(overrides: Option<&Bound<'_, PyDict>>) -> PyResult<Versions> {
    let mut versions = Versions::offline();
    let Some(overrides) = overrides else {
        return Ok(versions);
    };
    for (key, value) in overrides.iter() {
        let key = key.cast_into::<PyString>()?;
        match key.to_cow()?.as_ref() {
            "android_app_version" => versions.android_app_version = value.extract()?,
            "android_app_version_code" => versions.android_app_version_code = value.extract()?,
            "ios_app_version" => versions.ios_app_version = value.extract()?,
            "ios_build_number" => versions.ios_build_number = value.extract()?,
            "ios_system_version" => versions.ios_system_version = value.extract()?,
            "macos_system_version" => versions.macos_system_version = value.extract()?,
            "desktop_app_version" => versions.desktop_app_version = value.extract()?,
            "desktop_app_version_suffix" => {
                versions.desktop_app_version_suffix = value.extract()?;
            }
            "macos_app_version" => versions.macos_app_version = value.extract()?,
            "macos_build_number" => versions.macos_build_number = value.extract()?,
            "android_x_app_version" => versions.android_x_app_version = value.extract()?,
            "web_a_version" => versions.web_a_version = value.extract()?,
            "web_k_version" => versions.web_k_version = value.extract()?,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown versions field {other:?}"
                )));
            }
        }
    }
    Ok(versions)
}

/// The eight `initConnection` fields of `profile` as a dict.
fn profile_dict<'py>(py: Python<'py>, profile: &ApiProfile) -> PyResult<Bound<'py, PyDict>> {
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
/// `"TelegramDesktop"` only. Web clients raise `CoreError` `IO`.
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

/// Adds the fingerprint functions to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(profile, module)?)?;
    module.add_function(wrap_pyfunction!(generate, module)?)?;
    Ok(())
}
