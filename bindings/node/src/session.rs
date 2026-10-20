//! The Telethon `.session` file and its `.json` companion (1.5.0
//! `src/tl/session_io.py`): the `sessions` row, the SQL 1.5.0 runs, the
//! pair paths, the file itself (the core's `telethon-sqlite` feature, a
//! bundled SQLite) and the companion JSON, its text and its reading.

use std::path::PathBuf;

use napi::bindgen_prelude::{AsyncTask, BigInt, Buffer, Env, Uint8Array};
use napi::{JsString, Task};
use napi_derive::napi;
use serde_json::{Map, Number, Value};

use opentele2_core::session::telethon_file::{self, SessionRows};

use crate::api::ApiProfile;
use crate::convert::{to_auth_key, with_text};
use crate::error::{Result, check, core_error, invalid_arg, rejection, thrown};
use crate::tdata::{AccountInput, to_account};

/// The database version 1.5.0 stamps (Telethon's `CURRENT_VERSION`).
#[napi]
pub const TELETHON_SESSION_VERSION: i64 = telethon_file::VERSION;

/// The suffix of a session file.
#[napi]
pub const TELETHON_SESSION_SUFFIX: &str = telethon_file::SESSION_SUFFIX;

/// The suffix of the JSON companion.
#[napi]
pub const TELETHON_JSON_SUFFIX: &str = telethon_file::JSON_SUFFIX;

/// Clears the version row before `TELETHON_INSERT_VERSION`.
#[napi]
pub const TELETHON_DELETE_VERSION: &str = telethon_file::DELETE_VERSION;

/// Inserts `TELETHON_SESSION_VERSION`.
#[napi]
pub const TELETHON_INSERT_VERSION: &str = telethon_file::INSERT_VERSION;

/// Clears the sessions row before `TELETHON_INSERT_SESSION`.
#[napi]
pub const TELETHON_DELETE_SESSIONS: &str = telethon_file::DELETE_SESSIONS;

/// Inserts the `telethonSessionRows` values in column order: `dcId`,
/// `serverAddress`, `port`, `authKey`, `takeoutId`, and `tmp_auth_key`,
/// always NULL.
#[napi]
pub const TELETHON_INSERT_SESSION: &str = telethon_file::INSERT_SESSION;

/// One table of the version 8 layout.
#[napi(object, object_from_js = false)]
pub struct TelethonTable {
    /// Table name.
    pub name: String,
    /// The `create table` statement 1.5.0 runs.
    pub ddl: String,
    /// Column names in declaration order, as `pragma table_info` lists them.
    pub columns: Vec<String>,
}

/// The version 8 tables in 1.5.0's order (`_V8_SCHEMA`).
#[napi]
pub fn telethon_schema() -> Vec<TelethonTable> {
    telethon_file::SCHEMA
        .iter()
        .map(|table| TelethonTable {
            name: table.name.to_owned(),
            ddl: table.ddl.to_owned(),
            columns: table
                .columns
                .iter()
                .map(|&column| column.to_owned())
                .collect(),
        })
        .collect()
}

/// The `sessions` row of a version 8 file.
#[napi(object, object_from_js = false)]
pub struct TelethonSessionRows {
    /// DC id (`dc_id`).
    pub dc_id: i32,
    /// Server address text (`server_address`), as 1.5.0 passes it to
    /// `set_dc`.
    pub server_address: String,
    /// Port (`port`).
    pub port: u32,
    /// The 256-byte auth key (`auth_key`).
    pub auth_key: Buffer,
    /// Takeout session id (`takeout_id`); absent is NULL.
    pub takeout_id: Option<i64>,
}

/// The `sessions` row 1.5.0 saves for `account` (`ToTelethon`, then
/// `SaveSessionJson`): the endpoint and key `telethonStringSession` uses,
/// with the address text 1.5.0 writes (the stored config's IP text, else
/// the built-in table's, IPv6 with all eight groups as four hex digits),
/// and no takeout id. Throws `OT_TDATA_BAD_CONFIG_DATA` when the main DC
/// has no endpoint.
#[napi]
pub fn telethon_session_rows(
    env: Env,
    account: AccountInput,
    ipv6: Option<bool>,
) -> napi::Result<TelethonSessionRows> {
    thrown(env, session_rows(account, ipv6))
}

/// The rows of [`telethon_session_rows`].
fn session_rows(account: AccountInput, ipv6: Option<bool>) -> Result<TelethonSessionRows> {
    let account = to_account(account)?;
    let rows = check(SessionRows::from_account(&account, ipv6.unwrap_or(false)))?;
    Ok(TelethonSessionRows {
        dc_id: rows.dc_id,
        server_address: rows.server_address,
        port: u32::from(rows.port),
        auth_key: Buffer::from(rows.auth_key.as_bytes().to_vec()),
        takeout_id: rows.takeout_id,
    })
}

/// The `.session` and `.json` paths of a pair.
#[napi(object, object_from_js = false)]
pub struct SessionPairPaths {
    /// The session file.
    pub session: String,
    /// The JSON companion.
    pub json: String,
}

/// `path` as a string; every path built from a string is one.
fn path_text(path: PathBuf) -> Result<String> {
    path.into_os_string()
        .into_string()
        .map_err(|_| invalid_arg("the path is not valid Unicode"))
}

/// The pair paths of `base` (1.5.0 `_normalize_base_path`): one trailing
/// `.session` is removed, then one trailing `.json`, and each suffix is
/// appended to what is left. The path is treated as text.
#[napi]
pub fn session_pair_paths(base: String) -> Result<SessionPairPaths> {
    let (session, json) = telethon_file::pair_paths(base);
    Ok(SessionPairPaths {
        session: path_text(session)?,
        json: path_text(json)?,
    })
}

/// The session file path of `path` (1.5.0 `write_session_file`): `path`
/// itself when it ends with `.session`, else `path` with it appended.
#[napi]
pub fn session_path(path: String) -> Result<String> {
    path_text(telethon_file::session_path(path))
}

/// The `.json` companion 1.5.0 `save_session_json` writes for `profile`
/// (`APIData.to_json(extra)`), keys in its order; 1.5.0's `extra` holds
/// `session_file` and, when known, `id`. 1.5.0 writes it with
/// `JSON.stringify(json, null, 2)` indentation.
#[napi(ts_return_type = "Record<string, unknown>")]
pub fn session_companion_json(
    profile: ApiProfile,
    #[napi(ts_arg_type = "Record<string, unknown> | null")] extra: Option<Map<String, Value>>,
) -> Value {
    // No extra keys write the same JSON as no `extra`.
    let extra = extra.unwrap_or_default();
    telethon_file::companion_json(&profile.into(), Some(&extra))
}

/// The rows `writeTelethonSessionFile` writes.
#[napi(object, object_to_js = false)]
pub struct TelethonSessionRowsInput {
    /// DC id (`dc_id`).
    pub dc_id: i32,
    /// Server address text (`server_address`), kept verbatim.
    pub server_address: String,
    /// Port (`port`), in `0..65535`.
    pub port: u32,
    /// The 256-byte auth key (`auth_key`).
    pub auth_key: Uint8Array,
    /// Takeout session id (`takeout_id`), in `-(2**63)..2**63`; absent is
    /// NULL.
    pub takeout_id: Option<BigInt>,
}

/// The core rows of `input`: `OT_BAD_LENGTH` for a key that is not 256
/// bytes, `ERR_INVALID_ARG_VALUE` for a port or takeout id out of range.
fn to_session_rows(input: TelethonSessionRowsInput) -> Result<SessionRows> {
    let port = u16::try_from(input.port)
        .map_err(|_| invalid_arg("rows.port must be an integer in 0..65535"))?;
    let auth_key = to_auth_key(&input.auth_key)?;
    let takeout_id = match &input.takeout_id {
        None => None,
        Some(big) => match big.get_i64() {
            (id, true) => Some(id),
            (_, false) => return Err(invalid_arg("rows.takeoutId must be a 64-bit integer")),
        },
    };
    Ok(SessionRows {
        dc_id: input.dc_id,
        server_address: input.server_address,
        port,
        auth_key,
        takeout_id,
    })
}

/// The `sessions` row `readTelethonSessionFile` read.
#[napi(object, object_from_js = false)]
pub struct TelethonFileRows {
    /// DC id (`dc_id`).
    pub dc_id: i32,
    /// Server address text (`server_address`).
    pub server_address: String,
    /// Port (`port`).
    pub port: u32,
    /// The 256-byte auth key (`auth_key`).
    pub auth_key: Buffer,
    /// Takeout session id (`takeout_id`), exact; absent is NULL.
    pub takeout_id: Option<BigInt>,
}

/// `write_session_file` off the JavaScript thread.
pub struct WriteSessionFileTask {
    path: PathBuf,
    rows: SessionRows,
}

#[napi]
impl Task for WriteSessionFileTask {
    type Output = opentele2_core::Result<PathBuf>;
    type JsValue = String;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(telethon_file::write_session_file(&self.path, &self.rows))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<String> {
        thrown(env, check(output).and_then(path_text))
    }
}

/// Writes `rows` as 1.5.0 `write_session_file` does, over the bundled
/// SQLite, and resolves to the file path (`sessionPath(path)`). A schema
/// that is not already the version 8 layout is dropped and rebuilt; a
/// current one keeps its tables and their other rows. The version row
/// becomes 8 and the sessions row `rows`, `tmp_auth_key` NULL, in one
/// transaction. Throws `OT_BAD_LENGTH` for a key that is not 256 bytes and
/// `ERR_INVALID_ARG_VALUE` for a port or takeout id out of range; rejects
/// with `OT_IO` when SQLite fails.
#[napi]
pub fn write_telethon_session_file(
    env: Env,
    path: String,
    rows: TelethonSessionRowsInput,
) -> napi::Result<AsyncTask<WriteSessionFileTask>> {
    let rows = thrown(env, to_session_rows(rows))?;
    Ok(AsyncTask::new(WriteSessionFileTask {
        path: PathBuf::from(path),
        rows,
    }))
}

/// `read_session_file` off the JavaScript thread.
pub struct ReadSessionFileTask {
    path: PathBuf,
}

#[napi]
impl Task for ReadSessionFileTask {
    type Output = opentele2_core::Result<SessionRows>;
    type JsValue = TelethonFileRows;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(telethon_file::read_session_file(&self.path))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<TelethonFileRows> {
        let rows = output.map_err(|error| rejection(env, core_error(&error)))?;
        Ok(TelethonFileRows {
            dc_id: rows.dc_id,
            server_address: rows.server_address,
            port: u32::from(rows.port),
            auth_key: Buffer::from(rows.auth_key.as_bytes().to_vec()),
            takeout_id: rows.takeout_id.map(BigInt::from),
        })
    }
}

/// Reads the sessions row of the version 8 file at `sessionPath(path)`,
/// written by 1.5.0, by `writeTelethonSessionFile`, or by Telethon itself,
/// over the bundled SQLite; the file is opened read-only. Rejects with
/// `OT_TFILE_NOT_FOUND` for no file, `OT_IO` when it is not a database,
/// `OT_QDATASTREAM_FAILED` for another layout, version or column type,
/// `OT_TDATA_AUTH_KEY_NOT_FOUND` for no row or key, `OT_BAD_LENGTH` for a
/// key that is not 256 bytes and `OT_TDATA_BAD_CONFIG_DATA` for a NULL or
/// out-of-range DC id, address or port.
#[napi]
pub fn read_telethon_session_file(path: String) -> AsyncTask<ReadSessionFileTask> {
    AsyncTask::new(ReadSessionFileTask {
        path: PathBuf::from(path),
    })
}

/// `value` with every integral `number` that JavaScript handed over as a
/// float (outside the 32-bit range) as the integer `JSON.stringify` prints.
fn integral_numbers(value: Value) -> Value {
    match value {
        Value::Number(number) => Value::Number(integral_number(number)),
        Value::Array(items) => Value::Array(items.into_iter().map(integral_numbers).collect()),
        Value::Object(entries) => Value::Object(
            entries
                .into_iter()
                .map(|(key, item)| (key, integral_numbers(item)))
                .collect(),
        ),
        other => other,
    }
}

/// `number` as an integer when it is an integral float in the 64-bit range.
fn integral_number(number: Number) -> Number {
    // 2**63, the first float outside the i64 range.
    const LIMIT: f64 = 9_223_372_036_854_775_808.0;
    match number.as_f64() {
        Some(float)
            if number.is_f64()
                && float.is_finite()
                && float.fract() == 0.0
                && float.abs() < LIMIT =>
        {
            // An integral f64 prints its exact digits with no fraction.
            format!("{float:.0}")
                .parse::<i64>()
                .map_or(number, Number::from)
        }
        _ => number,
    }
}

/// The `.json` companion text 1.5.0 `save_session_json` writes for
/// `profile` and `extra`, byte for byte: `sessionCompanionJson(profile,
/// extra)` as Python's `json.dump(..., indent=2, ensure_ascii=False)`
/// prints it, with no trailing newline. A `bigint` in `extra` prints its
/// exact digits, and an integral `number` prints as an integer.
#[napi]
pub fn session_companion_text(
    profile: ApiProfile,
    #[napi(ts_arg_type = "Record<string, unknown> | null")] extra: Option<Map<String, Value>>,
) -> String {
    let extra = extra
        .unwrap_or_default()
        .into_iter()
        .map(|(key, item)| (key, integral_numbers(item)))
        .collect();
    telethon_file::companion_text(&profile.into(), Some(&extra))
}

/// The `.json` companion `readSessionCompanion` read.
#[napi(object, object_from_js = false)]
pub struct SessionCompanion {
    /// The profile of the companion (`profileFromSessionJson`); absent when
    /// its profile keys are not the strict form that function reads.
    pub profile: Option<ApiProfile>,
    /// The whole companion object, keys in order; an integer outside the
    /// safe range is a `bigint`.
    #[napi(ts_type = "Record<string, unknown>")]
    pub json: Value,
}

/// The companion of `text`, as the Python binding's
/// `read_session_companion` reads it.
fn session_companion(text: &str) -> Result<SessionCompanion> {
    match telethon_file::read_companion(text) {
        Ok((profile, json)) => Ok(SessionCompanion {
            profile: Some(profile.into()),
            json: Value::Object(json),
        }),
        // Only the profile read gives `Io`, after the text parsed as an
        // object holding both required fields; the core returns no object
        // with it, so the object is read here.
        Err(opentele2_core::Error::Io(_)) => {
            let json: Map<String, Value> = serde_json::from_str(text).map_err(|error| {
                core_error(&opentele2_core::Error::InvalidInput {
                    what: "JSON file",
                    reason: error.to_string(),
                })
            })?;
            Ok(SessionCompanion {
                profile: None,
                json: Value::Object(json),
            })
        }
        Err(error) => Err(core_error(&error)),
    }
}

/// Reads `.json` companion text as 1.5.0 `from_session_json` does: the
/// text must parse as a JSON object holding `app_id` and `app_hash`, not
/// null, else `OT_INVALID_INPUT`. The profile is then read as
/// `profileFromSessionJson` reads it, and is absent when a profile key is
/// missing or has the wrong type (1.5.0 reads those as `APIData.from_json`
/// does), as the Python binding's `read_session_companion` returns `None`;
/// `json` is the whole object either way.
#[napi]
pub fn read_session_companion(env: Env, text: JsString<'_>) -> napi::Result<SessionCompanion> {
    thrown(
        env,
        with_text(text, session_companion).and_then(std::convert::identity),
    )
}

/// Whether `unit` separates path components for Python's `os.path` on this
/// platform: `/`, and `\` on Windows.
fn is_separator(unit: char) -> bool {
    unit == '/' || (cfg!(windows) && unit == '\\')
}

/// The length of the drive of `path` as Python's `ntpath.splitroot` (3.12)
/// splits it: a UNC or device prefix (`\\server\share`, `\\?\UNC\server\share`,
/// `\\.\device`) up to the separator after its second component, else a
/// one-character drive and its colon (`C:`), else none.
fn windows_drive_len(path: &str) -> usize {
    let units: Vec<(usize, char)> = path.char_indices().collect();
    let separator_at = |at: usize| units.get(at).is_some_and(|&(_, unit)| is_separator(unit));
    if separator_at(0) && separator_at(1) {
        let normal: String = path
            .chars()
            .take(8)
            .map(|unit| {
                if unit == '/' {
                    '\\'
                } else {
                    unit.to_ascii_uppercase()
                }
            })
            .collect();
        let start = if normal == "\\\\?\\UNC\\" { 8 } else { 2 };
        let mut found = units
            .iter()
            .skip(start)
            .filter(|&&(_, unit)| is_separator(unit));
        return match (found.next(), found.next()) {
            (Some(_), Some(&(at, _))) => at,
            _ => path.len(),
        };
    }
    match units.get(1) {
        Some(&(at, ':')) => at + 1,
        _ => 0,
    }
}

/// `path` as Python's `os.path.basename` gives it on this platform: the
/// text after the last separator (`/`; on Windows also `\`, with the drive
/// `ntpath.splitdrive` gives removed first), empty when `path` ends with one.
fn python_basename(path: &str) -> &str {
    let path = if cfg!(windows) {
        &path[windows_drive_len(path)..]
    } else {
        path
    };
    path.rfind(is_separator).map_or(path, |at| &path[at + 1..])
}

/// The `session_file` value 1.5.0 `save_session_json` writes for the pair at
/// `base`: Python's `os.path.basename`, for the platform Node runs on, of the
/// pair's session path (`sessionPairPaths(base).session`) without its
/// `.session` suffix. On POSIX only `/` separates; on Windows `/` and `\`
/// do, after a drive (`C:`, `\\server\share`) is removed.
#[napi]
pub fn session_file_name(base: String) -> Result<String> {
    let (session, _) = telethon_file::pair_paths(base);
    let session = path_text(session)?;
    let stem = session
        .strip_suffix(telethon_file::SESSION_SUFFIX)
        .unwrap_or(&session);
    Ok(python_basename(stem).to_owned())
}
