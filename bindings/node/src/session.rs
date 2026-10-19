//! The pure pieces of the Telethon `.session` file and its `.json`
//! companion (1.5.0 `src/tl/session_io.py`): the `sessions` row, the SQL
//! 1.5.0 runs, the pair paths and the companion JSON. Writing the file is
//! left to `node:sqlite`.

use std::path::PathBuf;

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use serde_json::{Map, Value};

use opentele2_core::session::telethon_file::{self, SessionRows};

use crate::api::ApiProfile;
use crate::error::{Result, check, invalid_arg};
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
    account: AccountInput,
    ipv6: Option<bool>,
) -> Result<TelethonSessionRows> {
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
