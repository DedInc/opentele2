//! Current official client versions from the public release feeds
//! (opentele2-versions), fetched with the thread detached.

use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule, PyString};

use opentele2_versions::{VersionsPatch, fetch_all};

use crate::api::{versions, versions_dict};

/// The fields `patch` sets as a dict; a field no source answered is absent.
fn patch_dict<'py>(py: Python<'py>, patch: &VersionsPatch) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    let texts = [
        ("desktop_app_version", &patch.desktop_app_version),
        ("android_app_version", &patch.android_app_version),
        ("android_x_app_version", &patch.android_x_app_version),
        ("ios_app_version", &patch.ios_app_version),
        ("macos_app_version", &patch.macos_app_version),
        ("web_k_version", &patch.web_k_version),
        ("web_a_version", &patch.web_a_version),
    ];
    for (key, value) in texts {
        if let Some(value) = value {
            dict.set_item(key, value)?;
        }
    }
    let numbers = [
        ("android_app_version_code", patch.android_app_version_code),
        ("ios_build_number", patch.ios_build_number),
        ("macos_build_number", patch.macos_build_number),
    ];
    for (key, value) in numbers {
        if let Some(value) = value {
            dict.set_item(key, value)?;
        }
    }
    Ok(dict)
}

/// The patch a `VersionsPatch` dict holds; a `None` value is an absent
/// field, an unknown field raises `ValueError`.
fn to_patch(dict: &Bound<'_, PyDict>) -> PyResult<VersionsPatch> {
    let mut patch = VersionsPatch::default();
    for (key, value) in dict.iter() {
        let key = key.cast_into::<PyString>()?;
        let p = &mut patch;
        match key.to_cow()?.as_ref() {
            "desktop_app_version" => p.desktop_app_version = value.extract()?,
            "android_app_version" => p.android_app_version = value.extract()?,
            "android_app_version_code" => p.android_app_version_code = value.extract()?,
            "android_x_app_version" => p.android_x_app_version = value.extract()?,
            "ios_app_version" => p.ios_app_version = value.extract()?,
            "ios_build_number" => p.ios_build_number = value.extract()?,
            "macos_app_version" => p.macos_app_version = value.extract()?,
            "macos_build_number" => p.macos_build_number = value.extract()?,
            "web_k_version" => p.web_k_version = value.extract()?,
            "web_a_version" => p.web_a_version = value.extract()?,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown versions patch field {other:?}"
                )));
            }
        }
    }
    Ok(patch)
}

/// Fetches the current versions from the seven release feeds of 1.5.0
/// `version_fetcher.py` (Telegram Desktop, Android, Telegram X, iOS, macOS,
/// Web K, Web A) in parallel, with the thread detached. `timeout` bounds
/// each HTTP request, in seconds. Never raises for the network: a source
/// that fails or times out leaves its fields absent, and with no network
/// the patch is empty.
#[pyfunction]
#[pyo3(signature = (timeout = 10.0))]
fn fetch_versions(py: Python<'_>, timeout: f64) -> PyResult<Bound<'_, PyDict>> {
    let timeout = Duration::try_from_secs_f64(timeout)
        .ok()
        .filter(|timeout| !timeout.is_zero())
        .ok_or_else(|| PyValueError::new_err("timeout must be a positive number of seconds"))?;
    let patch = py.detach(move || fetch_all(timeout));
    patch_dict(py, &patch)
}

/// `versions` (overrides of the offline `PlatformVersions`, a full
/// `PlatformVersions` included) with every field `patch` sets written onto
/// it, as 1.5.0 `_apply_fetched_versions`: each field lands on the field of
/// the same name, except `desktop_app_version`, which stays bound to the
/// tdata version.
#[pyfunction]
#[pyo3(signature = (versions, patch))]
fn apply_versions_patch<'py>(
    py: Python<'py>,
    versions: Option<&Bound<'py, PyDict>>,
    patch: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyDict>> {
    let mut versions = self::versions(versions)?;
    to_patch(patch)?.apply(&mut versions);
    versions_dict(py, &versions)
}

/// Adds the version functions to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(fetch_versions, module)?)?;
    module.add_function(wrap_pyfunction!(apply_versions_patch, module)?)?;
    Ok(())
}
