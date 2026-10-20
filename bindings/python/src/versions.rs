//! Current official client and browser versions from the public release
//! feeds (opentele2-versions), fetched with the thread detached.

use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};

use opentele2_versions::{DEFAULT_TIMEOUT, VersionsPatch, fetch_all};

use crate::api::{versions, versions_dict};
use crate::json::{from_json_object, to_json_object};

/// The patch a `VersionsPatch` dict holds; a `None` value is an absent
/// field, an unknown field or a wrongly typed value raises `ValueError`.
fn to_patch(dict: &Bound<'_, PyDict>) -> PyResult<VersionsPatch> {
    let map = to_json_object(dict)?;
    if let Some(other) = map
        .keys()
        .find(|key| !VersionsPatch::FIELDS.contains(&key.as_str()))
    {
        return Err(PyValueError::new_err(format!(
            "unknown versions patch field {other:?}"
        )));
    }
    VersionsPatch::from_map(&map).map_err(PyValueError::new_err)
}

/// Fetches the current versions from the nine sources of
/// opentele2-versions (Telegram Desktop, Android, Telegram X, iOS, macOS,
/// Web K, Web A, Chrome, Firefox) in parallel, with the thread detached.
/// `timeout` bounds each HTTP request, in seconds, and defaults to
/// `DEFAULT_TIMEOUT`. Never raises for the network: a source that fails or
/// times out leaves its fields absent, and with no network the patch is
/// empty.
#[pyfunction]
#[pyo3(signature = (timeout = DEFAULT_TIMEOUT.as_secs_f64()))]
fn fetch_versions(py: Python<'_>, timeout: f64) -> PyResult<Bound<'_, PyDict>> {
    let timeout = Duration::try_from_secs_f64(timeout)
        .ok()
        .filter(|timeout| !timeout.is_zero())
        .ok_or_else(|| PyValueError::new_err("timeout must be a positive number of seconds"))?;
    let patch = py.detach(move || fetch_all(timeout));
    from_json_object(py, &patch.to_map())
}

/// `versions` (overrides of the offline `PlatformVersions`, a full
/// `PlatformVersions` included) with every field `patch` sets written onto
/// it, as 1.5.0 `_apply_fetched_versions`: each field lands on the field of
/// the same name, except `desktop_app_version`, which stays bound to the
/// tdata version, and `chrome_version`, which rebuilds `user_agent` too.
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

/// Adds the version functions and `DEFAULT_TIMEOUT` (seconds) to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("DEFAULT_TIMEOUT", DEFAULT_TIMEOUT.as_secs_f64())?;
    module.add_function(wrap_pyfunction!(fetch_versions, module)?)?;
    module.add_function(wrap_pyfunction!(apply_versions_patch, module)?)?;
    Ok(())
}
