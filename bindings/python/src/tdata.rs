//! `TData`, `Account`, `load_many`, the draw plans of the folder writers
//! and the accounts' MTP configs.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyModule, PyTuple};

use opentele2_core::Error;
use opentele2_core::batch::{self, BatchOptions, LoadRequest};
use opentele2_core::crypto::AuthKey;
use opentele2_core::tdata::account::Account;
use opentele2_core::tdata::mtp_config::{
    self, ConfigFields, Endpoint, Environment, MtpConfig, ProtocolEndpoints,
};
use opentele2_core::tdata::{self, DrawOperation, NEW_FOLDER_ACTIVE_INDEX, TData};

use crate::convert::{optional, owned_bytes, to_auth_key, to_bytes, to_passcode};
use crate::draws::{Draws, to_draws};
use crate::error::{check, core_error_value};

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
        let draws = Draws::new(to_draws(draws)?);
        let accounts: Vec<Account> = accounts
            .into_iter()
            .map(|account| account.get().inner.clone())
            .collect();
        let (created, replayed) = py.detach(move || {
            let mut draws = draws;
            let created = TData::new(accounts, &passcode, performance_mode, &mut |buf| {
                draws.fill(buf);
            });
            (created, draws.finish())
        });
        // A failed draw leaves the buffer unspecified, so the folder is
        // discarded rather than returned with weak keys.
        replayed.map_err(|failure| failure.into_err(py))?;
        let mut created = check(py, created)?;
        created.active_index = active_index;
        Ok(Self::holding(created))
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
        let draws = Draws::new(to_draws(draws)?);
        let mut folder = self.folder();
        if let Some(mode) = performance_mode
            && mode != folder.performance_mode
        {
            Arc::make_mut(&mut folder).performance_mode = mode;
        }
        if !draws.is_replay() {
            return check(py, py.detach(move || folder.save_random(&path)));
        }
        let (saved, replayed) = py.detach(move || {
            let mut draws = draws;
            let saved = folder.save(&path, &mut |buf| draws.fill(buf));
            (saved, draws.finish())
        });
        replayed.map_err(|failure| failure.into_err(py))?;
        check(py, saved)
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
        let draws = Draws::new(to_draws(draws)?);
        let mut folder = TData::clone(&self.folder());
        let (folder, migrated, replayed) = py.detach(move || {
            let mut draws = draws;
            let migrated = folder.migrate(&mut |buf| draws.fill(buf));
            (folder, migrated, draws.finish())
        });
        // A failed draw leaves the new wrap unspecified, so the folder
        // stays as it was.
        replayed.map_err(|failure| failure.into_err(py))?;
        let migrated = check(py, migrated)?;
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
        return Ok(LoadRequest {
            dir: item.extract()?,
            passcode: Vec::new(),
            key_file: None,
        });
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
    Ok(LoadRequest {
        dir: tuple.get_item(0)?.extract()?,
        passcode,
        key_file,
    })
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
    let threads = match threads {
        None => None,
        Some(count) => Some(
            NonZeroUsize::new(count)
                .ok_or_else(|| PyValueError::new_err("threads must be at least 1"))?,
        ),
    };
    let requests = requests
        .try_iter()?
        .map(|item| load_request(&item?))
        .collect::<PyResult<Vec<_>>>()?;
    let options = BatchOptions { threads };
    let results = py.detach(move || batch::load_many(&requests, &options));
    let out = PyList::empty(py);
    for result in results {
        match result {
            Ok(inner) => out.append(Bound::new(py, PyTData::holding(inner))?)?,
            Err(error) => out.append(core_error_value(py, &error)?)?,
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
    if operation == "new" {
        let params = target.cast::<PyDict>().map_err(|_| {
            PyTypeError::new_err(
                "the \"new\" plan takes a dict of has_passcode and performance_mode",
            )
        })?;
        let has_passcode = optional(params, "has_passcode")?.unwrap_or(false);
        let performance_mode = optional(params, "performance_mode")?.unwrap_or(true);
        return check(
            py,
            tdata::draw_plan(DrawOperation::New {
                has_passcode,
                performance_mode,
            }),
        );
    }
    if operation != "migrate" && operation != "save" {
        return Err(PyValueError::new_err(format!(
            "unknown operation {operation:?}; expected one of new, migrate, save"
        )));
    }
    let folder = target
        .cast::<PyTData>()
        .map_err(|_| PyTypeError::new_err(format!("the {operation:?} plan takes a TData")))?
        .get()
        .folder();
    let plan = if operation == "migrate" {
        tdata::draw_plan(DrawOperation::Migrate(&folder))
    } else {
        tdata::draw_plan(DrawOperation::Save(&folder))
    };
    check(py, plan)
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

/// `endpoint` as an `Endpoint` dict.
fn endpoint_dict<'py>(py: Python<'py>, endpoint: &Endpoint) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("id", endpoint.id)?;
    dict.set_item("flags", endpoint.flags)?;
    dict.set_item("ip", &endpoint.ip)?;
    dict.set_item("port", endpoint.port)?;
    dict.set_item("secret", to_bytes(py, &endpoint.secret))?;
    Ok(dict)
}

/// `endpoints` as a list of `Endpoint` dicts.
fn endpoint_list<'py>(
    py: Python<'py>,
    endpoints: &[Endpoint],
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    endpoints
        .iter()
        .map(|endpoint| endpoint_dict(py, endpoint))
        .collect()
}

/// `family` as a `ProtocolEndpoints` dict.
fn family_dict<'py>(py: Python<'py>, family: &ProtocolEndpoints) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("tcp", endpoint_list(py, &family.tcp)?)?;
    dict.set_item("http", endpoint_list(py, &family.http)?)?;
    Ok(dict)
}

/// `fields` as an `MtpConfigFields` dict, in serialization order.
fn fields_dict<'py>(py: Python<'py>, fields: &ConfigFields) -> PyResult<Bound<'py, PyDict>> {
    let f = fields;
    let dict = PyDict::new(py);
    let numbers = [
        ("chat_size_max", f.chat_size_max),
        ("megagroup_size_max", f.megagroup_size_max),
        ("forwarded_count_max", f.forwarded_count_max),
        ("online_update_period", f.online_update_period),
        ("offline_blur_timeout", f.offline_blur_timeout),
        ("offline_idle_timeout", f.offline_idle_timeout),
        ("online_focus_timeout", f.online_focus_timeout),
        ("online_cloud_timeout", f.online_cloud_timeout),
        ("notify_cloud_delay", f.notify_cloud_delay),
        ("notify_default_delay", f.notify_default_delay),
        ("saved_gifs_limit", f.saved_gifs_limit),
        ("edit_time_limit", f.edit_time_limit),
        ("revoke_time_limit", f.revoke_time_limit),
        ("revoke_private_time_limit", f.revoke_private_time_limit),
    ];
    for (key, value) in numbers {
        dict.set_item(key, value)?;
    }
    dict.set_item("revoke_private_inbox", f.revoke_private_inbox)?;
    dict.set_item("stickers_recent_limit", f.stickers_recent_limit)?;
    dict.set_item("stickers_faved_limit", f.stickers_faved_limit)?;
    dict.set_item("pinned_dialogs_count_max", f.pinned_dialogs_count_max)?;
    dict.set_item(
        "pinned_dialogs_in_folder_max",
        f.pinned_dialogs_in_folder_max,
    )?;
    dict.set_item("internal_links_domain", &f.internal_links_domain)?;
    dict.set_item("channels_read_media_period", f.channels_read_media_period)?;
    dict.set_item("call_receive_timeout_ms", f.call_receive_timeout_ms)?;
    dict.set_item("call_ring_timeout_ms", f.call_ring_timeout_ms)?;
    dict.set_item("call_connect_timeout_ms", f.call_connect_timeout_ms)?;
    dict.set_item("call_packet_timeout_ms", f.call_packet_timeout_ms)?;
    dict.set_item("web_file_dc_id", f.web_file_dc_id)?;
    dict.set_item("txt_domain_string", &f.txt_domain_string)?;
    dict.set_item("phone_calls_enabled", f.phone_calls_enabled)?;
    dict.set_item("blocked_mode", f.blocked_mode)?;
    dict.set_item("caption_length_max", f.caption_length_max)?;
    dict.set_item("reaction_default_emoji", &f.reaction_default_emoji)?;
    dict.set_item("reaction_default_custom", f.reaction_default_custom)?;
    dict.set_item("rating_decay", f.rating_decay)?;
    dict.set_item("gif_search_username", &f.gif_search_username)?;
    dict.set_item("venue_search_username", &f.venue_search_username)?;
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
    let config = config_of(account);
    let environment = match config.environment {
        Environment::Production => "production",
        Environment::Test => "test",
    };
    let dcs = config
        .dc_options
        .dcs()
        .map(|(dc_id, endpoints)| {
            let dc = PyDict::new(py);
            dc.set_item("dc_id", dc_id)?;
            dc.set_item("endpoints", endpoint_list(py, endpoints)?)?;
            Ok(dc)
        })
        .collect::<PyResult<Vec<_>>>()?;
    let cdn_public_keys = config
        .dc_options
        .cdn_public_keys
        .iter()
        .map(|key| {
            let dict = PyDict::new(py);
            dict.set_item("dc_id", key.dc_id)?;
            dict.set_item("n", to_bytes(py, &key.n))?;
            dict.set_item("e", to_bytes(py, &key.e))?;
            Ok(dict)
        })
        .collect::<PyResult<Vec<_>>>()?;
    let dict = PyDict::new(py);
    dict.set_item("environment", environment)?;
    dict.set_item("dcs", dcs)?;
    dict.set_item("cdn_public_keys", cdn_public_keys)?;
    dict.set_item("fields", fields_dict(py, &config.fields)?)?;
    Ok(dict)
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
    let Some(endpoints) = config_of(account).endpoints(dc_id.unwrap_or(main_dc)) else {
        return Ok(None);
    };
    let selected = |ipv6| {
        endpoints
            .select(ipv6)
            .map(|endpoint| endpoint_dict(py, endpoint))
            .transpose()
    };
    let dict = PyDict::new(py);
    dict.set_item("ipv4", family_dict(py, &endpoints.ipv4)?)?;
    dict.set_item("ipv6", family_dict(py, &endpoints.ipv6)?)?;
    dict.set_item("selected_ipv4", selected(false)?)?;
    dict.set_item("selected_ipv6", selected(true)?)?;
    Ok(Some(dict))
}

/// Adds the tdata classes and functions to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
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
