//! The pure pieces of the Telethon `.session` file and its `.json`
//! companion (1.5.0 `src/tl/session_io.py`): the `sessions` row, the SQL
//! 1.5.0 runs, the pair paths and the companion JSON. Writing the file is
//! left to `sqlite3`.

use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};

use opentele2_core::session::telethon_file::{self, SessionRows};

use crate::api::to_profile;
use crate::convert::{path_text, to_bytes};
use crate::error::check;
use crate::json::{from_json, to_json_object};
use crate::tdata::PyAccount;

/// The version 8 tables in 1.5.0's order (`_V8_SCHEMA`), each a dict of
/// `name`, the `ddl` 1.5.0 runs and the `columns` in declaration order.
#[pyfunction]
fn telethon_schema(py: Python<'_>) -> PyResult<Vec<Bound<'_, PyDict>>> {
    telethon_file::SCHEMA
        .iter()
        .map(|table| {
            let dict = PyDict::new(py);
            dict.set_item("name", table.name)?;
            dict.set_item("ddl", table.ddl)?;
            dict.set_item("columns", table.columns.to_vec())?;
            Ok(dict)
        })
        .collect()
}

/// The `sessions` row 1.5.0 saves for `account` (`ToTelethon`, then
/// `SaveSessionJson`): the endpoint and key `telethon_string_session` uses,
/// with the address text 1.5.0 writes (the stored config's IP text, else
/// the built-in table's, IPv6 with all eight groups as four hex digits),
/// and no takeout id. Raises `CoreError` `TDATA_BAD_CONFIG_DATA` when the
/// main DC has no endpoint.
#[pyfunction]
#[pyo3(signature = (account, ipv6 = false))]
fn telethon_session_rows<'py>(
    py: Python<'py>,
    account: &Bound<'py, PyAccount>,
    ipv6: bool,
) -> PyResult<Bound<'py, PyDict>> {
    let rows = check(py, SessionRows::from_account(&account.get().inner, ipv6))?;
    let dict = PyDict::new(py);
    dict.set_item("dc_id", rows.dc_id)?;
    dict.set_item("server_address", &rows.server_address)?;
    dict.set_item("port", rows.port)?;
    dict.set_item("auth_key", to_bytes(py, rows.auth_key.as_bytes()))?;
    dict.set_item("takeout_id", rows.takeout_id)?;
    Ok(dict)
}

/// The `(session, json)` paths of `base` (1.5.0 `_normalize_base_path`):
/// one trailing `.session` is removed, then one trailing `.json`, and each
/// suffix is appended to what is left. The path is treated as text.
#[pyfunction]
fn session_pair_paths(base: PathBuf) -> PyResult<(String, String)> {
    let (session, json) = telethon_file::pair_paths(base);
    Ok((path_text(session)?, path_text(json)?))
}

/// The session file path of `path` (1.5.0 `write_session_file`): `path`
/// itself when it ends with `.session`, else `path` with it appended.
#[pyfunction]
fn session_path(path: PathBuf) -> PyResult<String> {
    path_text(telethon_file::session_path(path))
}

/// The `.json` companion 1.5.0 `save_session_json` writes for `profile`
/// (`APIData.to_json(extra)`), keys in its order; 1.5.0's `extra` holds
/// `session_file` and, when known, `id`. 1.5.0 writes it with
/// `json.dump(..., indent=2, ensure_ascii=False)`.
#[pyfunction]
#[pyo3(signature = (profile, extra = None))]
fn session_companion_json<'py>(
    py: Python<'py>,
    profile: &Bound<'py, PyDict>,
    extra: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyAny>> {
    let profile = to_profile(profile)?;
    // No extra keys write the same JSON as no `extra`.
    let extra = extra.map(to_json_object).transpose()?.unwrap_or_default();
    from_json(py, &telethon_file::companion_json(&profile, Some(&extra)))
}

/// Adds the Telethon session file constants and functions to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("TELETHON_SESSION_VERSION", telethon_file::VERSION)?;
    module.add("TELETHON_SESSION_SUFFIX", telethon_file::SESSION_SUFFIX)?;
    module.add("TELETHON_JSON_SUFFIX", telethon_file::JSON_SUFFIX)?;
    module.add("TELETHON_DELETE_VERSION", telethon_file::DELETE_VERSION)?;
    module.add("TELETHON_INSERT_VERSION", telethon_file::INSERT_VERSION)?;
    module.add("TELETHON_DELETE_SESSIONS", telethon_file::DELETE_SESSIONS)?;
    module.add("TELETHON_INSERT_SESSION", telethon_file::INSERT_SESSION)?;
    module.add_function(wrap_pyfunction!(telethon_schema, module)?)?;
    module.add_function(wrap_pyfunction!(telethon_session_rows, module)?)?;
    module.add_function(wrap_pyfunction!(session_pair_paths, module)?)?;
    module.add_function(wrap_pyfunction!(session_path, module)?)?;
    module.add_function(wrap_pyfunction!(session_companion_json, module)?)?;
    Ok(())
}
