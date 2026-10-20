//! The Telethon `.session` file and its `.json` companion (1.5.0
//! `src/tl/session_io.py`): the `sessions` row, the SQL 1.5.0 runs, the
//! pair paths, the file itself (the core's `telethon-sqlite` feature) and
//! the companion JSON and its text.

use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};

use opentele2_core::Error;
use opentele2_core::session::telethon_file::{self, SessionRows};

use crate::api::{profile_dict, to_profile};
use crate::convert::{path_text, to_auth_key, to_bytes};
use crate::error::{check, core_error, core_error_type};
use crate::json::{from_json, from_json_object, to_json_object};
use crate::tdata::PyAccount;

/// `rows` as the dict `telethon_session_rows` and `read_session_file` give.
fn rows_dict<'py>(py: Python<'py>, rows: &SessionRows) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("dc_id", rows.dc_id)?;
    dict.set_item("server_address", &rows.server_address)?;
    dict.set_item("port", rows.port)?;
    dict.set_item("auth_key", to_bytes(py, rows.auth_key.as_bytes()))?;
    dict.set_item("takeout_id", rows.takeout_id)?;
    Ok(dict)
}

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
    rows_dict(py, &rows)
}

/// Writes the version 8 session file 1.5.0 `write_session_file` writes and
/// returns its path (`session_path(path)`): a schema that is not already
/// the version 8 layout is dropped and rebuilt, a current one keeps its
/// other rows, and the version and sessions rows are replaced in one
/// transaction, `tmp_auth_key` NULL. `auth_key` must be 256 bytes, else
/// `CoreError` `BAD_LENGTH`; SQLite failures raise `CoreError` `IO`.
#[pyfunction]
#[pyo3(signature = (path, dc_id, server_address, port, auth_key, takeout_id = None))]
fn write_session_file(
    py: Python<'_>,
    path: PathBuf,
    dc_id: i32,
    server_address: String,
    port: u16,
    auth_key: &Bound<'_, PyAny>,
    takeout_id: Option<i64>,
) -> PyResult<String> {
    let rows = SessionRows {
        dc_id,
        server_address,
        port,
        auth_key: to_auth_key(py, auth_key)?,
        takeout_id,
    };
    let written = py.detach(move || telethon_file::write_session_file(path, &rows));
    path_text(check(py, written)?)
}

/// The sessions row of the version 8 file at `session_path(path)`, as
/// `telethon_session_rows` gives it; the file is opened read-only. Raises
/// `CoreError`: `TFILE_NOT_FOUND` for no file, `IO` when it is not a
/// database, `QDATASTREAM_FAILED` for another layout or version,
/// `TDATA_AUTH_KEY_NOT_FOUND` for no row or key, `BAD_LENGTH` for a
/// key that is not 256 bytes and `TDATA_BAD_CONFIG_DATA` for a NULL or
/// out-of-range endpoint.
#[pyfunction]
fn read_session_file(py: Python<'_>, path: PathBuf) -> PyResult<Bound<'_, PyDict>> {
    let rows = py.detach(move || telethon_file::read_session_file(path));
    rows_dict(py, &check(py, rows)?)
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

/// The `.json` companion text 1.5.0 `save_session_json` writes for
/// `profile` and `extra`, byte for byte: `session_companion_json` as
/// `json.dump(..., ensure_ascii=False, indent=2)` prints it, with no
/// trailing newline.
#[pyfunction]
#[pyo3(signature = (profile, extra = None))]
fn session_companion_text(
    profile: &Bound<'_, PyDict>,
    extra: Option<&Bound<'_, PyDict>>,
) -> PyResult<String> {
    let profile = to_profile(profile)?;
    let extra = extra.map(to_json_object).transpose()?.unwrap_or_default();
    Ok(telethon_file::companion_text(&profile, Some(&extra)))
}

/// The `CoreError` of a companion that `read_session_companion` rejects,
/// its `legacy_message` the `SessionFileInvalid` text of 1.5.0
/// `from_session_json`: `Invalid JSON file: {e}` when the text is not JSON
/// (the `INVALID_INPUT` message), the bare `Missing required field '{f}'
/// in JSON` when `app_id` or `app_hash` is missing or null.
fn companion_error(py: Python<'_>, error: &Error) -> PyErr {
    if let Error::InvalidInput { reason, .. } = error
        && reason.starts_with("Missing required field ")
    {
        let value = core_error_type(py)
            .and_then(|class| class.call1((error.code(), error.to_string(), reason.as_str())));
        return match value {
            Ok(value) => PyErr::from_value(value),
            Err(failure) => failure,
        };
    }
    core_error(py, error)
}

/// Reads `.json` companion text as 1.5.0 `from_session_json` does: the
/// text must parse as JSON and hold `app_id` and `app_hash`, not null.
/// Returns `(profile, data)`: the typed profile of the companion, `None`
/// when its profile keys are not the strict form `profile_from_session_json`
/// reads (1.5.0 reads those as `APIData.from_json` does), and the whole
/// object, keys in order. A rejected companion raises `CoreError`
/// `INVALID_INPUT` whose `legacy_message` is 1.5.0's `SessionFileInvalid`
/// message.
#[pyfunction]
fn read_session_companion<'py>(
    py: Python<'py>,
    text: &str,
) -> PyResult<(Option<Bound<'py, PyDict>>, Bound<'py, PyDict>)> {
    match telethon_file::read_companion(text) {
        Ok((profile, data)) => Ok((
            Some(profile_dict(py, &profile)?),
            from_json_object(py, &data)?,
        )),
        // Only the profile read gives `Io`, after the text parsed as an
        // object with both required fields.
        Err(Error::Io(_)) => {
            let data: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(text).map_err(|error| {
                    companion_error(
                        py,
                        &Error::InvalidInput {
                            what: "JSON file",
                            reason: error.to_string(),
                        },
                    )
                })?;
            Ok((None, from_json_object(py, &data)?))
        }
        Err(error) => Err(companion_error(py, &error)),
    }
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
    module.add_function(wrap_pyfunction!(session_companion_text, module)?)?;
    module.add_function(wrap_pyfunction!(read_session_companion, module)?)?;
    module.add_function(wrap_pyfunction!(write_session_file, module)?)?;
    module.add_function(wrap_pyfunction!(read_session_file, module)?)?;
    Ok(())
}
