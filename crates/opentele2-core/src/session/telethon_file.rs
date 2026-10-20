//! Telethon `SQLiteSession` files (database `CURRENT_VERSION = 8`,
//! `refs/telethon/telethon/sessions/sqlite.py`) as 1.5.0 writes them
//! (`src/tl/session_io.py`, `write_session_file`), and the `.session` +
//! `.json` pair of its `SaveSessionJson` / `FromSessionJson`.
//!
//! Everything here is pure: [`SessionRows`] holds the one `sessions` row,
//! [`SCHEMA`] and the statement constants hold the SQL 1.5.0 runs,
//! [`pair_paths`] and [`session_path`] apply its suffix rules, and
//! [`companion_json`] builds the `.json` companion, [`companion_text`]
//! prints it as 1.5.0 writes it and [`read_companion`] reads it back. The
//! optional feature
//! `telethon-sqlite` (off by default; rusqlite with a bundled SQLite, so the
//! default build links no C code) adds `write_session_file` and
//! `read_session_file`.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::api::ApiProfile;
use crate::crypto::AuthKey;
use crate::session::codecs::account_target;
use crate::tdata::account::Account;
use crate::{Error, Result};

/// The database version 1.5.0 stamps (`SESSION_VERSION`, Telethon's
/// `CURRENT_VERSION`).
pub const VERSION: i64 = 8;

/// The suffix of a session file (Telethon's `EXTENSION`).
pub const SESSION_SUFFIX: &str = ".session";

/// The suffix of the JSON companion.
pub const JSON_SUFFIX: &str = ".json";

/// One table of the version 8 layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    /// Table name.
    pub name: &'static str,
    /// The `create table` statement 1.5.0 runs (`"create table " + ddl`).
    pub ddl: &'static str,
    /// Column names in declaration order, as `pragma table_info` lists them.
    pub columns: &'static [&'static str],
}

/// The version 8 tables in 1.5.0's order (`_V8_SCHEMA`); Telethon creates
/// the same columns in the same order.
pub const SCHEMA: [Table; 5] = [
    Table {
        name: "version",
        ddl: "create table version (version integer primary key)",
        columns: &["version"],
    },
    Table {
        name: "sessions",
        ddl: "create table sessions (dc_id integer primary key, server_address text, \
              port integer, auth_key blob, takeout_id integer, tmp_auth_key blob)",
        columns: &[
            "dc_id",
            "server_address",
            "port",
            "auth_key",
            "takeout_id",
            "tmp_auth_key",
        ],
    },
    Table {
        name: "entities",
        ddl: "create table entities (id integer primary key, hash integer not null, \
              username text, phone integer, name text, date integer)",
        columns: &["id", "hash", "username", "phone", "name", "date"],
    },
    Table {
        name: "sent_files",
        ddl: "create table sent_files (md5_digest blob, file_size integer, type integer, \
              id integer, hash integer, primary key(md5_digest, file_size, type))",
        columns: &["md5_digest", "file_size", "type", "id", "hash"],
    },
    Table {
        name: "update_state",
        ddl: "create table update_state (id integer primary key, pts integer, qts integer, \
              date integer, seq integer)",
        columns: &["id", "pts", "qts", "date", "seq"],
    },
];

/// Clears the version row before [`INSERT_VERSION`].
pub const DELETE_VERSION: &str = "delete from version";

/// Inserts [`VERSION`].
pub const INSERT_VERSION: &str = "insert into version values (?)";

/// Clears the sessions row before [`INSERT_SESSION`].
pub const DELETE_SESSIONS: &str = "delete from sessions";

/// Inserts the [`SessionRows`] values in column order: `dc_id`,
/// `server_address`, `port`, `auth_key`, `takeout_id`, and `tmp_auth_key`,
/// which is always NULL.
pub const INSERT_SESSION: &str = "insert into sessions values (?, ?, ?, ?, ?, ?)";

/// The `sessions` row of a version 8 file.
///
/// 1.5.0 writes `takeout_id` and `tmp_auth_key` as NULL: Telethon 1.44.0
/// unpacks `select *` in the opposite order to its DDL while 1.45.0 follows
/// the DDL, and NULL in both reads back the same under either order. A
/// `takeout_id` other than `None` keeps that symmetry only for 1.45.0.
#[derive(Debug, Clone)]
pub struct SessionRows {
    /// DC id (`dc_id`).
    pub dc_id: i32,
    /// Server address text (`server_address`), kept verbatim.
    pub server_address: String,
    /// Port (`port`).
    pub port: u16,
    /// The auth key (`auth_key`).
    pub auth_key: AuthKey,
    /// Takeout session id (`takeout_id`); `None` is NULL.
    pub takeout_id: Option<i64>,
}

impl SessionRows {
    /// The row 1.5.0 saves for `account` (`ToTelethon`, then
    /// `SaveSessionJson`): the endpoint and key of
    /// [`crate::session::telethon::StringSession::from_account`], with the
    /// address text 1.5.0 passes to `set_dc` (the stored config's IP text
    /// verbatim, else the built-in table's text, IPv6 with all eight groups
    /// as four hex digits), and no takeout id.
    ///
    /// # Errors
    /// - [`crate::Error::BadConfigData`] when the main DC has no usable
    ///   endpoint.
    /// - [`crate::Error::AuthKeyNotFound`] when the account has no main DC
    ///   key.
    pub fn from_account(account: &Account, ipv6: bool) -> Result<Self> {
        let (addr, server_address, _, key) = account_target(account, ipv6)?;
        Ok(Self {
            dc_id: account.main_dc,
            server_address,
            port: addr.port(),
            auth_key: key.clone(),
            takeout_id: None,
        })
    }
}

/// `path` without `suffix`, compared code unit by code unit as Python's
/// `str.endswith`; `None` when `path` does not end with it.
fn strip_suffix(path: &OsStr, suffix: &str) -> Option<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        path.as_bytes()
            .strip_suffix(suffix.as_bytes())
            .map(|head| OsString::from_vec(head.to_vec()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let wide: Vec<u16> = path.encode_wide().collect();
        let suffix: Vec<u16> = suffix.encode_utf16().collect();
        wide.strip_suffix(suffix.as_slice())
            .map(OsString::from_wide)
    }
    #[cfg(not(any(unix, windows)))]
    {
        path.to_str()?.strip_suffix(suffix).map(OsString::from)
    }
}

fn with_suffix(base: &OsStr, suffix: &str) -> PathBuf {
    let mut path = base.to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

/// The session file path of `path`: `path` itself when it ends with
/// [`SESSION_SUFFIX`], else `path` with the suffix appended (1.5.0
/// `write_session_file`, Telethon `SQLiteSession`).
#[must_use]
pub fn session_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref().as_os_str();
    if path.as_encoded_bytes().ends_with(SESSION_SUFFIX.as_bytes()) {
        PathBuf::from(path)
    } else {
        with_suffix(path, SESSION_SUFFIX)
    }
}

/// The `(session, json)` paths of `base` (1.5.0 `_normalize_base_path`):
/// one trailing [`SESSION_SUFFIX`] is removed, then one trailing
/// [`JSON_SUFFIX`], and each suffix is appended to what is left. The path is
/// treated as text, with no separator handling, as in 1.5.0.
#[must_use]
pub fn pair_paths(base: impl AsRef<Path>) -> (PathBuf, PathBuf) {
    let mut stem = base.as_ref().as_os_str().to_os_string();
    for suffix in [SESSION_SUFFIX, JSON_SUFFIX] {
        if let Some(head) = strip_suffix(&stem, suffix) {
            stem = head;
        }
    }
    (
        with_suffix(&stem, SESSION_SUFFIX),
        with_suffix(&stem, JSON_SUFFIX),
    )
}

/// The `.json` companion 1.5.0 `save_session_json` writes
/// (`APIData.to_json(extra)`), built by [`ApiProfile::to_session_json`].
/// 1.5.0's `extra` holds `session_file`, the file name of the pair's base
/// path, and `id` when the user id is known; it is written with two-space
/// indentation and non-ASCII text kept.
#[must_use]
pub fn companion_json(profile: &ApiProfile, extra: Option<&Map<String, Value>>) -> Value {
    profile.to_session_json(extra)
}

/// The `.json` companion text 1.5.0 `save_session_json` writes, byte for
/// byte: [`companion_json`] as Python's `json.dump(data, f,
/// ensure_ascii=False, indent=2)` prints it, through [`py_json_text`].
#[must_use]
pub fn companion_text(profile: &ApiProfile, extra: Option<&Map<String, Value>>) -> String {
    py_json_text(&companion_json(profile, extra))
}

/// Any JSON value exactly as Python's `json.dumps(value, indent=2,
/// ensure_ascii=False)` prints it (the same text `json.dump` writes).
///
/// Objects and arrays open a line per item, indented two spaces per level,
/// items separated by `,` and keys by `: `, keys in the value's order; an
/// empty array is `[]` and an empty object `{}`. Strings escape `"`, `\`,
/// `\n`, `\r`, `\t`, `\b`, `\f` and other control characters as `\u00xx`,
/// and keep every other character, non-ASCII included. Integers print in
/// full and floats as Python's `repr`. A scalar prints on its own, and
/// there is no trailing newline.
#[must_use]
pub fn py_json_text(value: &Value) -> String {
    let mut text = String::new();
    push_py_json(&mut text, value, 0);
    text
}

/// Reads `.json` companion text as 1.5.0 `from_session_json` does: the
/// text must parse as JSON, and `app_id` and `app_hash` must be present
/// and not `null`. The profile is then read by
/// [`ApiProfile::from_session_json`], and the whole object is returned
/// beside it, so the caller can read the account keys (`id` and the rest).
///
/// # Errors
/// - [`Error::InvalidInput`] with `what` `JSON file` when the text is not
///   JSON (`reason` is the parser's message, so the legacy message is
///   1.5.0's `Invalid JSON file: {e}` shape, with the parser's wording), or
///   when a required field is missing or `null`, or the JSON is not an
///   object (`reason` is 1.5.0's `Missing required field '{field}' in
///   JSON`, `app_id` checked first).
/// - [`Error::Io`] as [`ApiProfile::from_session_json`] gives it, when a
///   profile key is missing or has the wrong type.
pub fn read_companion(text: &str) -> Result<(ApiProfile, Map<String, Value>)> {
    let data: Value = serde_json::from_str(text).map_err(|error| Error::InvalidInput {
        what: "JSON file",
        reason: error.to_string(),
    })?;
    for field in ["app_id", "app_hash"] {
        let present = data
            .as_object()
            .and_then(|object| object.get(field))
            .is_some_and(|value| !value.is_null());
        if !present {
            return Err(Error::InvalidInput {
                what: "JSON file",
                reason: format!("Missing required field '{field}' in JSON"),
            });
        }
    }
    let profile = ApiProfile::from_session_json(&data)?;
    let Value::Object(object) = data else {
        unreachable!("the required fields were found in an object");
    };
    Ok((profile, object))
}

fn push_py_indent(out: &mut String, depth: usize) {
    out.push('\n');
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// `value` as Python's `json.dump(..., ensure_ascii=False, indent=2)`
/// prints it at nesting `depth`.
fn push_py_json(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => push_py_number(out, number),
        Value::String(text) => push_py_string(out, text),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                push_py_indent(out, depth + 1);
                push_py_json(out, item, depth + 1);
            }
            push_py_indent(out, depth);
            out.push(']');
        }
        Value::Object(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                push_py_indent(out, depth + 1);
                push_py_string(out, key);
                out.push_str(": ");
                push_py_json(out, item, depth + 1);
            }
            push_py_indent(out, depth);
            out.push('}');
        }
    }
}

/// A string as Python's `encode_basestring` (the `ensure_ascii=False`
/// encoder) prints it.
fn push_py_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            // Python writes `\u{0:04x}`: lowercase hex.
            '\0'..='\u{1f}' => {
                // Writing to a `String` cannot fail.
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
}

fn push_py_number(out: &mut String, number: &serde_json::Number) {
    if let Some(int) = number.as_i64() {
        out.push_str(&int.to_string());
    } else if let Some(int) = number.as_u64() {
        out.push_str(&int.to_string());
    } else if let Some(float) = number.as_f64() {
        push_py_float(out, float);
    } else {
        out.push_str(&number.to_string());
    }
}

/// A float as Python's `float.__repr__` prints it: the shortest digits that
/// round-trip, in positional form when the decimal exponent is in
/// `-5 < e < 16`, else as `d.ddde±XX`. `json.dump` prints non-finite
/// values as `NaN`, `Infinity` and `-Infinity`.
fn push_py_float(out: &mut String, value: f64) {
    if value.is_nan() {
        out.push_str("NaN");
        return;
    }
    if value.is_infinite() {
        out.push_str(if value > 0.0 { "Infinity" } else { "-Infinity" });
        return;
    }
    if value.is_sign_negative() {
        out.push('-');
    }
    // `{:e}` gives the same shortest round-trip digits as Python's repr.
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i64 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|&c| c != '.').collect();
    // The decimal point sits `point` digits into `digits` (Python's `decpt`).
    let point = exponent + 1;
    if !(-4 < point && point <= 16) {
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        let sign = if exponent < 0 { '-' } else { '+' };
        // Writing to a `String` cannot fail.
        let _ = write!(out, "e{sign}{:02}", exponent.unsigned_abs());
    } else if point <= 0 {
        out.push_str("0.");
        for _ in point..0 {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        let point = usize::try_from(point).unwrap_or(0);
        if point >= digits.len() {
            out.push_str(&digits);
            for _ in digits.len()..point {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            let (whole, fraction) = digits.split_at(point);
            out.push_str(whole);
            out.push('.');
            out.push_str(fraction);
        }
    }
}

#[cfg(feature = "telethon-sqlite")]
pub use file::{read_session_file, write_session_file};

#[cfg(feature = "telethon-sqlite")]
mod file {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    use rusqlite::types::Value;
    use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

    use super::{
        DELETE_SESSIONS, DELETE_VERSION, INSERT_SESSION, INSERT_VERSION, SCHEMA, SessionRows,
        VERSION, session_path,
    };
    use crate::crypto::AuthKey;
    use crate::{ConfigFailure, Error, Result};

    /// A failure of SQLite itself, as an I/O error on the caller's path.
    #[allow(clippy::needless_pass_by_value)] // Used as `map_err(sqlite_error)`.
    fn sqlite_error(error: rusqlite::Error) -> Error {
        Error::Io(std::io::Error::other(error))
    }

    /// Whether every table of [`SCHEMA`] exists with its version 8 columns
    /// (1.5.0 `_schema_is_current`).
    fn schema_is_current(conn: &Connection) -> Result<bool> {
        let mut statement = conn
            .prepare("select name from sqlite_master where type='table'")
            .map_err(sqlite_error)?;
        let present = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite_error)?
            .collect::<rusqlite::Result<HashSet<String>>>()
            .map_err(sqlite_error)?;
        if !SCHEMA.iter().all(|table| present.contains(table.name)) {
            return Ok(false);
        }
        for table in &SCHEMA {
            let mut statement = conn
                .prepare(&format!("pragma table_info({})", table.name))
                .map_err(sqlite_error)?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(sqlite_error)?
                .collect::<rusqlite::Result<Vec<String>>>()
                .map_err(sqlite_error)?;
            if !columns
                .iter()
                .map(String::as_str)
                .eq(table.columns.iter().copied())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Writes `rows` as 1.5.0 `write_session_file` does and returns the file
    /// path ([`session_path`] of `path`).
    ///
    /// The file is created when missing. A schema that is not already the
    /// version 8 layout is dropped and rebuilt with [`SCHEMA`]; a current
    /// one keeps its tables and their other rows. The version row becomes
    /// [`VERSION`] and the sessions row becomes `rows`, `tmp_auth_key` NULL,
    /// in one transaction.
    ///
    /// # Errors
    /// [`Error::Io`] when SQLite cannot open or write the file, or the file
    /// is not a database.
    pub fn write_session_file(path: impl AsRef<Path>, rows: &SessionRows) -> Result<PathBuf> {
        let full_path = session_path(path);
        let mut conn = Connection::open(&full_path).map_err(sqlite_error)?;
        let tx = conn.transaction().map_err(sqlite_error)?;
        if !schema_is_current(&tx)? {
            for table in &SCHEMA {
                tx.execute(&format!("drop table if exists {}", table.name), [])
                    .map_err(sqlite_error)?;
            }
            for table in &SCHEMA {
                tx.execute(table.ddl, []).map_err(sqlite_error)?;
            }
        }
        tx.execute(DELETE_VERSION, []).map_err(sqlite_error)?;
        tx.execute(INSERT_VERSION, [VERSION])
            .map_err(sqlite_error)?;
        tx.execute(DELETE_SESSIONS, []).map_err(sqlite_error)?;
        tx.execute(
            INSERT_SESSION,
            params![
                rows.dc_id,
                rows.server_address,
                rows.port,
                rows.auth_key.as_bytes().as_slice(),
                rows.takeout_id,
                Value::Null,
            ],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)?;
        conn.close().map_err(|(_, error)| sqlite_error(error))?;
        Ok(full_path)
    }

    /// Reads the sessions row of a version 8 file at [`session_path`] of
    /// `path`, written by 1.5.0, by [`write_session_file`], or by Telethon
    /// itself (whose multi-line DDL and empty `tmp_auth_key` are accepted).
    /// Columns are read by name, so the 1.44.0 / 1.45.0 order question of
    /// [`SessionRows`] does not arise; `tmp_auth_key` is not read. The file
    /// is opened read-only.
    ///
    /// # Errors
    /// - [`Error::FileNotFound`] when the file does not exist.
    /// - [`Error::Io`] when SQLite cannot read it or it is not a database.
    /// - [`Error::QDataStreamFailed`] when its tables are not the version 8
    ///   layout, its version row is not [`VERSION`], or a column holds a
    ///   value of the wrong type.
    /// - [`Error::AuthKeyNotFound`] when it has no sessions row or the
    ///   auth key is NULL or empty (Telethon writes `b''` for no key).
    /// - [`Error::BadLength`] when the auth key is not [`AuthKey::SIZE`]
    ///   bytes.
    /// - [`Error::BadConfigData`] when the DC id, address, or port is NULL
    ///   or out of range.
    pub fn read_session_file(path: impl AsRef<Path>) -> Result<SessionRows> {
        let full_path = session_path(path);
        if !full_path.is_file() {
            return Err(Error::FileNotFound {
                file: full_path.display().to_string(),
            });
        }
        let conn = Connection::open_with_flags(
            &full_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sqlite_error)?;
        if !schema_is_current(&conn)? {
            return Err(Error::QDataStreamFailed { context: None });
        }
        let version = conn
            .query_row("select version from version", [], |row| {
                row.get::<_, Value>(0)
            })
            .optional()
            .map_err(sqlite_error)?;
        if version != Some(Value::Integer(VERSION)) {
            return Err(Error::QDataStreamFailed { context: None });
        }
        let row = conn
            .query_row(
                "select dc_id, server_address, port, auth_key, takeout_id from sessions",
                [],
                |row| {
                    Ok([
                        row.get::<_, Value>(0)?,
                        row.get::<_, Value>(1)?,
                        row.get::<_, Value>(2)?,
                        row.get::<_, Value>(3)?,
                        row.get::<_, Value>(4)?,
                    ])
                },
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or(Error::AuthKeyNotFound)?;
        let [dc_id, server_address, port, auth_key, takeout_id] = row;
        let auth_key = match auth_key {
            Value::Null => return Err(Error::AuthKeyNotFound),
            Value::Blob(bytes) if bytes.is_empty() => return Err(Error::AuthKeyNotFound),
            Value::Blob(bytes) => AuthKey::from_slice(&bytes)?,
            _ => return Err(Error::QDataStreamFailed { context: None }),
        };
        let null = |column| Error::BadConfigData {
            context: ConfigFailure::NullSessionColumn { column },
        };
        let dc_id = match dc_id {
            Value::Integer(id) => i32::try_from(id).map_err(|_| Error::BadConfigData {
                context: ConfigFailure::DcIdOutOfRange { dc_id: id },
            })?,
            Value::Null => return Err(null("dc_id")),
            _ => return Err(Error::QDataStreamFailed { context: None }),
        };
        let server_address = match server_address {
            Value::Text(text) => text,
            Value::Null => return Err(null("server_address")),
            _ => return Err(Error::QDataStreamFailed { context: None }),
        };
        let port = match port {
            Value::Integer(port) => u16::try_from(port).map_err(|_| Error::BadConfigData {
                context: ConfigFailure::PortOutOfRange { port },
            })?,
            Value::Null => return Err(null("port")),
            _ => return Err(Error::QDataStreamFailed { context: None }),
        };
        let takeout_id = match takeout_id {
            Value::Integer(id) => Some(id),
            Value::Null => None,
            _ => return Err(Error::QDataStreamFailed { context: None }),
        };
        Ok(SessionRows {
            dc_id,
            server_address,
            port,
            auth_key,
            takeout_id,
        })
    }
}
