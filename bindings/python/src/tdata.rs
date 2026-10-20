//! `TData`, `Account`, `load_many`, the draw plans of the folder writers
//! and the accounts' MTP configs.

use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyModule, PyTuple};
use serde_json::{Map, Value};

use opentele2_core::Error;
use opentele2_core::batch::{self, BatchOptions, LoadRequest};
use opentele2_core::crypto::AuthKey;
use opentele2_core::tdata::account::Account;
use opentele2_core::tdata::mtp_config::{self, Environment, MtpConfig};
use opentele2_core::tdata::{self, DrawOperation, DrawSource, NEW_FOLDER_ACTIVE_INDEX, TData};

use crate::convert::{optional, owned_bytes, to_auth_key, to_bytes, to_passcode};
use crate::error::{core_error_type, core_error_value};
use crate::json::from_json;

/// The `CoreError` value of `error`, with its `detail_code` attribute
/// ([`Error::detail_code`], `None` for most errors).
fn tdata_error_value<'py>(py: Python<'py>, error: &Error) -> PyResult<Bound<'py, PyAny>> {
    let value = core_error_value(py, error)?;
    value.setattr("detail_code", error.detail_code())?;
    Ok(value)
}

/// `error` as a raisable `CoreError` carrying its `detail_code`.
fn tdata_error(py: Python<'_>, error: &Error) -> PyErr {
    match tdata_error_value(py, error) {
        Ok(value) => PyErr::from_value(value),
        Err(failure) => failure,
    }
}

/// Maps a core result onto a Python result raising `CoreError` with its
/// `detail_code`.
fn check<T>(py: Python<'_>, result: opentele2_core::Result<T>) -> PyResult<T> {
    result.map_err(|error| tdata_error(py, &error))
}

/// As [`check`], but a replay that does not match the draws raises
/// `ValueError` `draws: {reason}`.
fn check_draws<T>(py: Python<'_>, result: opentele2_core::Result<T>) -> PyResult<T> {
    result.map_err(|error| match error {
        Error::InvalidInput {
            what: "draws",
            reason,
        } => PyValueError::new_err(format!("draws: {reason}")),
        error => tdata_error(py, &error),
    })
}

/// A `draws` argument: `None` for the OS random source, or an iterable of
/// `bytes`/`bytearray` replayed in order.
fn to_draws(value: Option<&Bound<'_, PyAny>>) -> PyResult<DrawSource> {
    let Some(value) = value.filter(|value| !value.is_none()) else {
        return Ok(DrawSource::os());
    };
    value
        .try_iter()?
        .map(|item| owned_bytes(&item?))
        .collect::<PyResult<Vec<_>>>()
        .map(DrawSource::replay)
}

/// One Telegram Desktop account: its index, user id, main DC and
/// authorization keys. `repr()` never shows key bytes.
#[pyclass(frozen, module = "opentele2._native", name = "Account")]
pub(crate) struct PyAccount {
    pub(crate) inner: Account,
}

#[pymethods]
impl PyAccount {
    /// A new account the way 1.5.0 builds one before saving; `keys` is a
    /// list of `(dc_id, auth_key)` pairs and must hold a key of `main_dc`.
    /// `config` is the serialized MTP config of the account (its `configs`
    /// file); the session functions take their endpoints from it.
    #[new]
    #[pyo3(signature = (index, user_id, main_dc, keys, config = None))]
    fn new(
        py: Python<'_>,
        index: i32,
        user_id: u64,
        main_dc: i32,
        keys: &Bound<'_, PyAny>,
        config: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let mut parsed: Vec<(i32, AuthKey)> = Vec::new();
        for item in keys.try_iter()? {
            let (dc, key): (i32, Bound<'_, PyAny>) = item?.extract()?;
            parsed.push((dc, to_auth_key(py, &key)?));
        }
        let config = config
            .filter(|config| !config.is_none())
            .map(owned_bytes)
            .transpose()?;
        let mut inner = check(py, Account::new(index, user_id, main_dc, parsed))?;
        inner.config = config;
        Ok(Self { inner })
    }

    /// The serialized MTP config the folder stored for the account (its
    /// `configs` file); `None` when there is none.
    #[getter]
    fn config<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .config
            .as_deref()
            .map(|config| to_bytes(py, config))
    }

    /// Index of the account in the accounts info.
    #[getter]
    fn index(&self) -> i32 {
        self.inner.index
    }

    /// Telegram user id.
    #[getter]
    fn user_id(&self) -> u64 {
        self.inner.user_id
    }

    /// Main DC id.
    #[getter]
    fn main_dc(&self) -> i32 {
        self.inner.main_dc
    }

    /// The 256-byte authorization key of the main DC.
    #[getter]
    fn auth_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let key = check(py, self.inner.auth_key().ok_or(Error::AuthKeyNotFound))?;
        Ok(to_bytes(py, key.as_bytes()))
    }

    /// Every authorization key as `(dc_id, auth_key)`, in file order.
    #[getter]
    fn keys<'py>(&self, py: Python<'py>) -> Vec<(i32, Bound<'py, PyBytes>)> {
        self.inner
            .keys
            .iter()
            .map(|(dc, key)| (*dc, to_bytes(py, key.as_bytes())))
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "Account(index={}, user_id={}, main_dc={})",
            self.inner.index, self.inner.user_id, self.inner.main_dc
        )
    }
}

/// A Telegram Desktop `tdata` folder, loaded from disk or created for
/// writing. `repr()` never shows key bytes.
#[pyclass(frozen, module = "opentele2._native", name = "TData")]
pub(crate) struct PyTData {
    /// The folder; `migrate` replaces it with the migrated folder, every
    /// other operation works on a snapshot.
    inner: RwLock<Arc<TData>>,
}

impl PyTData {
    /// A `TData` holding `folder`.
    fn holding(folder: TData) -> Self {
        Self {
            inner: RwLock::new(Arc::new(folder)),
        }
    }

    /// The folder this `TData` holds now.
    fn folder(&self) -> Arc<TData> {
        // Nothing panics while holding the lock, so a poisoned lock still
        // holds a whole folder.
        Arc::clone(&self.inner.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Applies `change` to the folder and returns its result; snapshots
    /// taken before keep the folder as it was.
    fn update<T>(&self, change: impl FnOnce(&mut TData) -> T) -> T {
        let mut folder = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        change(Arc::make_mut(&mut folder))
    }
}

#[pymethods]
impl PyTData {
    /// Most accounts one folder holds (1.5.0's `kMaxAccounts`); `add_account`
    /// refuses more.
    #[classattr]
    const MAX_ACCOUNTS: usize = TData::MAX_ACCOUNTS;

    /// Loads the folder at `path`; `passcode` is the local passcode (`str`
    /// is UTF-8 encoded) and `key_file` the key file data name, `"data"` by
    /// default.
    #[staticmethod]
    #[pyo3(signature = (path, passcode = None, key_file = None))]
    fn load(
        py: Python<'_>,
        path: PathBuf,
        passcode: Option<&Bound<'_, PyAny>>,
        key_file: Option<String>,
    ) -> PyResult<Self> {
        let passcode = to_passcode(passcode)?;
        let loaded = py.detach(move || TData::load(&path, &passcode, key_file.as_deref()));
        Ok(Self::holding(check(py, loaded)?))
    }

    /// A new folder for `accounts` the way 1.5.0's `SaveTData` creates one,
    /// with keys from the OS random source, storing `active_index` (1.5.0's
    /// `-1` by default).
    ///
    /// `draws`, a testing hook, replaces the OS random source with exactly
    /// these byte strings in order, as 1.5.0's `os.urandom` calls were
    /// recorded; a draw of another size, a missing draw or an unused one
    /// raises `ValueError`.
    #[staticmethod]
    #[pyo3(signature = (
        accounts, passcode = None, performance_mode = true, active_index = NEW_FOLDER_ACTIVE_INDEX,
        draws = None
    ))]
    fn new(
        py: Python<'_>,
        accounts: Vec<Bound<'_, PyAccount>>,
        passcode: Option<&Bound<'_, PyAny>>,
        performance_mode: bool,
        active_index: i32,
        draws: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let passcode = to_passcode(passcode)?;
        let draws = to_draws(draws)?;
        let accounts: Vec<Account> = accounts
            .into_iter()
            .map(|account| account.get().inner.clone())
            .collect();
        let created = py.detach(move || {
            TData::new_with_draws(accounts, &passcode, performance_mode, active_index, draws)
        });
        Ok(Self::holding(check_draws(py, created)?))
    }

    /// Writes the folder into `path`, with padding from the OS random
    /// source. `performance_mode`, when given, applies to this save only:
    /// on, no `configs` files are written.
    ///
    /// `draws`, a testing hook, replays exactly these byte strings in order
    /// instead (see `new`); on a mismatch the written files are not usable
    /// and `ValueError` is raised.
    #[pyo3(signature = (path, performance_mode = None, draws = None))]
    fn save(
        &self,
        py: Python<'_>,
        path: PathBuf,
        performance_mode: Option<bool>,
        draws: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let draws = to_draws(draws)?;
        let folder = self.folder();
        let saved = py.detach(move || folder.save_with_draws(&path, performance_mode, draws));
        check_draws(py, saved)
    }

    /// Installs 7.3 key data in place of a legacy (pre-7.3) key file, as the
    /// first save would, with keys from the OS random source, and returns
    /// whether it did. Later saves write that key data instead of migrating
    /// afresh, so the key file keeps one wrap across saves. A 7.3 key file
    /// is left alone (`False`); under a passcode the new wrap runs Argon2id.
    ///
    /// `draws`, a testing hook, replays exactly these byte strings in order
    /// instead (see `new`); on a mismatch the folder stays as it was and
    /// `ValueError` is raised.
    #[pyo3(signature = (draws = None))]
    fn migrate(&self, py: Python<'_>, draws: Option<&Bound<'_, PyAny>>) -> PyResult<bool> {
        let draws = to_draws(draws)?;
        let mut folder = TData::clone(&self.folder());
        let (folder, migrated) = py.detach(move || {
            let migrated = folder.migrate_with_draws(draws);
            (folder, migrated)
        });
        let migrated = check_draws(py, migrated)?;
        if migrated {
            *self.inner.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(folder);
        }
        Ok(migrated)
    }

    /// Adds an account with `auth_key` as the key of `main_dc`, as 1.5.0's
    /// `Account.FromTelethon` does, and returns its index: the lowest one
    /// below `MAX_ACCOUNTS` no account holds. The active index is not
    /// changed. A full folder raises `CoreError` `MAX_ACCOUNT_LIMIT` and is
    /// left as it was.
    fn add_account(
        &self,
        py: Python<'_>,
        user_id: u64,
        main_dc: i32,
        auth_key: &Bound<'_, PyAny>,
    ) -> PyResult<i32> {
        let auth_key = to_auth_key(py, auth_key)?;
        check(
            py,
            self.update(|folder| folder.add_account(user_id, main_dc, auth_key)),
        )
    }

    /// Telegram Desktop version in the key file's `TDF$` header; saving
    /// always writes 1.5.0's 7003001.
    #[getter]
    fn app_version(&self) -> u32 {
        self.folder().app_version
    }

    /// The 256-byte local key every file but the key file is encrypted
    /// with.
    #[getter]
    fn local_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        to_bytes(py, self.folder().local_key.as_bytes())
    }

    /// The 256-byte open or passcode key the local key is wrapped under.
    #[getter]
    fn passcode_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        to_bytes(py, self.folder().passcode_key.as_bytes())
    }

    /// 1.5.0's `kPerformanceMode`: when on, saving writes no `configs`
    /// files. Loading turns it on, the 1.5.0 default.
    #[getter]
    fn performance_mode(&self) -> bool {
        self.folder().performance_mode
    }

    #[setter]
    fn set_performance_mode(&self, value: bool) {
        self.update(|folder| folder.performance_mode = value);
    }

    /// The accounts, in accounts-info order.
    #[getter]
    fn accounts(&self) -> Vec<PyAccount> {
        self.folder()
            .accounts
            .iter()
            .map(|account| PyAccount {
                inner: account.clone(),
            })
            .collect()
    }

    /// Replaces the accounts later saves write, keeping the local key, the
    /// key data and its salts, as 1.5.0 writes an edited `accounts` list
    /// under the loaded local key. Up to `MAX_ACCOUNTS` accounts are
    /// accepted, or as many as were loaded when that is more. More raises
    /// `CoreError` `MAX_ACCOUNT_LIMIT`, two accounts of one index `CoreError`
    /// `TDATA_SAVE_FAILED`; the folder is then left as it was.
    #[setter]
    fn set_accounts(&self, py: Python<'_>, value: Vec<Bound<'_, PyAccount>>) -> PyResult<()> {
        let accounts: Vec<Account> = value
            .into_iter()
            .map(|account| account.get().inner.clone())
            .collect();
        check(py, self.update(|folder| folder.set_accounts(accounts)))
    }

    /// The active index stored in the accounts info; saving writes it.
    #[getter]
    fn active_index(&self) -> i32 {
        self.folder().active_index
    }

    #[setter]
    fn set_active_index(&self, value: i32) {
        self.update(|folder| folder.active_index = value);
    }

    /// The account at the active index, else the first one.
    #[getter]
    fn main_account(&self) -> Option<PyAccount> {
        self.folder().main_account().map(|account| PyAccount {
            inner: account.clone(),
        })
    }

    /// The data name of the key file, `"data"` unless loaded otherwise.
    /// Setting it renames the key file and the account files of later saves
    /// (1.5.0's `SaveTData(keyFile=...)`); an empty name raises `CoreError`
    /// `TDATA_SAVE_FAILED` and keeps the old one.
    #[getter]
    fn key_file(&self) -> String {
        self.folder().key_file.clone()
    }

    #[setter]
    fn set_key_file(&self, py: Python<'_>, value: &str) -> PyResult<()> {
        check(py, self.update(|folder| folder.set_key_file(value)))
    }

    /// Whether the key file has the pre-7.3 layout, which every save
    /// migrates afresh until `migrate` migrates it once.
    #[getter]
    fn legacy_key_file(&self) -> bool {
        self.folder().key_data.trailer.is_none()
    }

    fn __repr__(&self) -> String {
        let folder = self.folder();
        format!(
            "TData(accounts={}, active_index={})",
            folder.accounts.len(),
            folder.active_index
        )
    }
}

/// One `load_many` request: a path, or a `(path, passcode)` or
/// `(path, passcode, key_file)` tuple.
fn load_request(item: &Bound<'_, PyAny>) -> PyResult<LoadRequest> {
    let Ok(tuple) = item.cast::<PyTuple>() else {
        return Ok(LoadRequest::new(
            item.extract::<PathBuf>()?,
            Vec::new(),
            None,
        ));
    };
    let len = tuple.len();
    if !(1..=3).contains(&len) {
        return Err(PyTypeError::new_err(format!(
            "a load request tuple has 1 to 3 items, not {len}"
        )));
    }
    let passcode = if len > 1 {
        to_passcode(Some(&tuple.get_item(1)?))?
    } else {
        Vec::new()
    };
    let key_file = if len > 2 {
        tuple.get_item(2)?.extract()?
    } else {
        None
    };
    Ok(LoadRequest::new(
        tuple.get_item(0)?.extract::<PathBuf>()?,
        passcode,
        key_file,
    ))
}

/// Loads many folders on a dedicated thread pool and returns, in input
/// order, a `TData` or the `CoreError` of each request; `threads` caps the
/// pool (about 64 MiB of Argon2id memory per thread).
#[pyfunction]
#[pyo3(signature = (requests, threads = None))]
fn load_many<'py>(
    py: Python<'py>,
    requests: &Bound<'py, PyAny>,
    threads: Option<usize>,
) -> PyResult<Bound<'py, PyList>> {
    let options = BatchOptions::from_threads(threads).map_err(|error| match error {
        Error::InvalidInput {
            what: "threads",
            reason,
        } => PyValueError::new_err(reason),
        error => tdata_error(py, &error),
    })?;
    let requests = requests
        .try_iter()?
        .map(|item| load_request(&item?))
        .collect::<PyResult<Vec<_>>>()?;
    let results = py.detach(move || batch::load_many(&requests, &options));
    let out = PyList::empty(py);
    for result in results {
        match result {
            Ok(inner) => out.append(Bound::new(py, PyTData::holding(inner))?)?,
            Err(error) => out.append(tdata_error_value(py, &error)?)?,
        }
    }
    Ok(out)
}

/// The sizes, in bytes and in order, of the random draws an operation will
/// make, so recorded `os.urandom` draws can be replayed through `draws`
/// without hand-coded counts; nothing is drawn and no file is touched.
///
/// `operation` is `"new"` with a dict of `has_passcode` (default `False`)
/// and `performance_mode` (default `True`), the arguments of `TData.new`;
/// or `"migrate"` or `"save"` with the `TData` in its current state. A save
/// the folder would refuse raises its `CoreError`, such as
/// `TDATA_SAVE_FAILED` for a folder without accounts.
#[pyfunction]
fn draw_plan(py: Python<'_>, operation: &str, target: &Bound<'_, PyAny>) -> PyResult<Vec<usize>> {
    /// The text 1.5.0-compatible callers see when `"new"` gets no dict.
    const NEW_TAKES_A_DICT: &str =
        "the \"new\" plan takes a dict of has_passcode and performance_mode";
    let folder = target
        .cast::<PyTData>()
        .ok()
        .map(|target| target.get().folder());
    // `Error::InvalidInput` of `from_name`: an unknown name raises
    // `ValueError`, a target of the wrong kind `TypeError`.
    let refused = |error: Error| match error {
        Error::InvalidInput {
            what: "operation",
            reason,
        } => PyValueError::new_err(reason),
        // Only "new" refuses a TData.
        Error::InvalidInput { what: "target", .. } if folder.is_some() => {
            PyTypeError::new_err(NEW_TAKES_A_DICT)
        }
        Error::InvalidInput {
            what: "target",
            reason,
        } => PyTypeError::new_err(reason),
        error => tdata_error(py, &error),
    };
    let named = DrawOperation::from_name(operation, None, None, folder.as_deref());
    let named = named.map_err(refused)?;
    let operation = if let DrawOperation::New { .. } = named {
        let params = target
            .cast::<PyDict>()
            .map_err(|_| PyTypeError::new_err(NEW_TAKES_A_DICT))?;
        DrawOperation::from_name(
            operation,
            optional(params, "has_passcode")?,
            optional(params, "performance_mode")?,
            None,
        )
        .map_err(refused)?
    } else {
        named
    };
    check(py, tdata::draw_plan(operation))
}

/// The Telethon string session of `account`: the first production endpoint
/// of its main DC, IPv6 when `ipv6` is set, and its main DC key.
#[pyfunction]
#[pyo3(signature = (account, ipv6 = false))]
fn telethon_string_session(
    py: Python<'_>,
    account: &Bound<'_, PyAccount>,
    ipv6: bool,
) -> PyResult<String> {
    let session =
        opentele2_core::session::telethon::StringSession::from_account(&account.get().inner, ipv6);
    Ok(check(py, session)?.encode())
}

/// The mtcute v3 string session of `account`: the first production IPv4
/// endpoint of its main DC, its user id, and its main DC key.
#[pyfunction]
fn mtcute_string_session(py: Python<'_>, account: &Bound<'_, PyAccount>) -> PyResult<String> {
    let session =
        opentele2_core::session::mtcute::StringSession::from_account(&account.get().inner, false);
    Ok(check(py, session)?.encode())
}

/// The keys whose values the core MTP config maps give as lists of 0 to
/// 255: an endpoint `secret` and a CDN key's `n` and `e`, Python `bytes`.
const BYTES_KEYS: [&str; 3] = ["secret", "n", "e"];

/// `value`, the value of `key` in an MTP config map, as Python: a byte list
/// under [`BYTES_KEYS`] as `bytes`, maps and lists item by item, the rest
/// as JSON values.
fn config_value<'py>(py: Python<'py>, key: &str, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Value::Array(items) if BYTES_KEYS.contains(&key) => {
            let bytes = items
                .iter()
                .map(|item| {
                    item.as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or_else(|| PyValueError::new_err(format!("{key} is not a byte list")))
                })
                .collect::<PyResult<Vec<u8>>>()?;
            Ok(to_bytes(py, &bytes).into_any())
        }
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(config_value(py, key, item)?)?;
            }
            Ok(list.into_any())
        }
        Value::Object(map) => Ok(config_dict(py, map)?.into_any()),
        value => from_json(py, value),
    }
}

/// An MTP config map of the core as a dict, keys in its order.
fn config_dict<'py>(py: Python<'py>, map: &Map<String, Value>) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (key, value) in map {
        dict.set_item(key, config_value(py, key, value)?)?;
    }
    Ok(dict)
}

/// The MTP config of an account, or the production default 1.5.0 starts
/// every account with (`StorageAccount.__init__`).
fn config_of(account: Option<&Bound<'_, PyAccount>>) -> MtpConfig {
    account.map_or_else(
        || MtpConfig::new(Environment::Production),
        |account| account.get().inner.mtp_config(),
    )
}

/// The MTP config of `account` (1.5.0 `_readMtpConfig`): its stored
/// `config` parsed, or the production default when there is none or it
/// does not parse. No account, one never loaded, has the production
/// default.
#[pyfunction]
#[pyo3(signature = (account = None))]
fn account_mtp_config<'py>(
    py: Python<'py>,
    account: Option<&Bound<'py, PyAccount>>,
) -> PyResult<Bound<'py, PyDict>> {
    config_dict(py, &config_of(account).to_map())
}

/// The endpoints of DC `dc_id` (default the main DC) in the MTP config of
/// `account`, by address family and protocol (1.5.0
/// `MTP.Config.endpoints`), with the endpoints the session conversions
/// select; `None` when the config has no such DC. No account reads the
/// production default, whose main DC is 0, a DC no config lists.
#[pyfunction]
#[pyo3(signature = (account = None, dc_id = None))]
fn account_endpoints<'py>(
    py: Python<'py>,
    account: Option<&Bound<'py, PyAccount>>,
    dc_id: Option<i32>,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let main_dc = account.map_or(0, |account| account.get().inner.main_dc);
    config_of(account)
        .endpoints(dc_id.unwrap_or(main_dc))
        .map(|endpoints| config_dict(py, &endpoints.to_map()))
        .transpose()
}

/// Adds the tdata classes and functions to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    // Every `CoreError` has a `detail_code`; the tdata errors set their own.
    core_error_type(module.py())?.setattr("detail_code", module.py().None())?;
    // The 1.5.0 texts the Python layer raises without a `CoreError`.
    module.add("SAVE_FAILED_MESSAGE", Error::SaveFailed.legacy_message())?;
    module.add(
        "MAX_ACCOUNT_LIMIT_MESSAGE",
        Error::MaxAccountLimit.legacy_message(),
    )?;
    module.add_class::<PyAccount>()?;
    module.add_class::<PyTData>()?;
    module.add_function(wrap_pyfunction!(load_many, module)?)?;
    module.add("TDF_MAGIC", PyBytes::new(module.py(), &tdata::TDF_MAGIC))?;
    module.add_function(wrap_pyfunction!(draw_plan, module)?)?;
    module.add_function(wrap_pyfunction!(telethon_string_session, module)?)?;
    module.add_function(wrap_pyfunction!(mtcute_string_session, module)?)?;
    module.add("MTP_FLAG_IPV6", mtp_config::FLAG_IPV6)?;
    module.add("MTP_FLAG_MEDIA_ONLY", mtp_config::FLAG_MEDIA_ONLY)?;
    module.add("MTP_FLAG_TCPO_ONLY", mtp_config::FLAG_TCPO_ONLY)?;
    module.add("MTP_FLAG_CDN", mtp_config::FLAG_CDN)?;
    module.add("MTP_FLAG_STATIC", mtp_config::FLAG_STATIC)?;
    module.add("MTP_FLAG_THIS_PORT_ONLY", mtp_config::FLAG_THIS_PORT_ONLY)?;
    module.add("MTP_FLAG_SECRET", mtp_config::FLAG_SECRET)?;
    module.add_function(wrap_pyfunction!(account_mtp_config, module)?)?;
    module.add_function(wrap_pyfunction!(account_endpoints, module)?)?;
    Ok(())
}
