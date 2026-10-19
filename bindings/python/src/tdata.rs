//! `TData`, `Account` and `load_many`.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyModule, PyTuple};

use opentele2_core::Error;
use opentele2_core::batch::{self, BatchOptions, LoadRequest};
use opentele2_core::crypto::AuthKey;
use opentele2_core::tdata::TData;
use opentele2_core::tdata::account::Account;

use crate::convert::{to_auth_key, to_bytes, to_passcode};
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
    #[new]
    fn new(
        py: Python<'_>,
        index: i32,
        user_id: u64,
        main_dc: i32,
        keys: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let mut parsed: Vec<(i32, AuthKey)> = Vec::new();
        for item in keys.try_iter()? {
            let (dc, key): (i32, Bound<'_, PyAny>) = item?.extract()?;
            parsed.push((dc, to_auth_key(py, &key)?));
        }
        let inner = check(py, Account::new(index, user_id, main_dc, parsed))?;
        Ok(Self { inner })
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
    inner: TData,
}

#[pymethods]
impl PyTData {
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
        Ok(Self {
            inner: check(py, loaded)?,
        })
    }

    /// A new folder for `accounts` the way 1.5.0's `SaveTData` creates one,
    /// with keys from the OS random source.
    #[staticmethod]
    #[pyo3(signature = (accounts, passcode = None, performance_mode = true))]
    fn new(
        py: Python<'_>,
        accounts: Vec<Bound<'_, PyAccount>>,
        passcode: Option<&Bound<'_, PyAny>>,
        performance_mode: bool,
    ) -> PyResult<Self> {
        let passcode = to_passcode(passcode)?;
        let accounts: Vec<Account> = accounts
            .into_iter()
            .map(|account| account.get().inner.clone())
            .collect();
        let created = py.detach(move || {
            let mut failure = None;
            let created = TData::new(accounts, &passcode, performance_mode, &mut |buf| {
                if failure.is_none()
                    && let Err(error) = getrandom::fill(buf)
                {
                    failure = Some(error);
                }
            });
            // A failed draw leaves the buffer unspecified, so the folder is
            // discarded rather than returned with weak keys.
            match failure {
                Some(error) => Err(Error::Io(std::io::Error::other(error))),
                None => created,
            }
        });
        Ok(Self {
            inner: check(py, created)?,
        })
    }

    /// Writes the folder into `path`, with padding from the OS random
    /// source.
    fn save(&self, py: Python<'_>, path: PathBuf) -> PyResult<()> {
        let inner = &self.inner;
        check(py, py.detach(move || inner.save_random(&path)))
    }

    /// The accounts, in accounts-info order.
    #[getter]
    fn accounts(&self) -> Vec<PyAccount> {
        self.inner
            .accounts
            .iter()
            .map(|account| PyAccount {
                inner: account.clone(),
            })
            .collect()
    }

    /// The active index stored in the accounts info.
    #[getter]
    fn active_index(&self) -> i32 {
        self.inner.active_index
    }

    /// The account at the active index, else the first one.
    #[getter]
    fn main_account(&self) -> Option<PyAccount> {
        self.inner.main_account().map(|account| PyAccount {
            inner: account.clone(),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "TData(accounts={}, active_index={})",
            self.inner.accounts.len(),
            self.inner.active_index
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
            Ok(inner) => out.append(Bound::new(py, PyTData { inner })?)?,
            Err(error) => out.append(core_error_value(py, &error)?)?,
        }
    }
    Ok(out)
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

/// Adds the tdata classes and functions to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyAccount>()?;
    module.add_class::<PyTData>()?;
    module.add_function(wrap_pyfunction!(load_many, module)?)?;
    module.add_function(wrap_pyfunction!(telethon_string_session, module)?)?;
    module.add_function(wrap_pyfunction!(mtcute_string_session, module)?)?;
    Ok(())
}
