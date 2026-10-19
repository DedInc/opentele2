//! `TData`, accounts as plain objects, and the string sessions.
//!
//! Loading, creating and saving folders run as async tasks on the libuv
//! pool; `loadMany` runs its folders on the core's dedicated thread pool
//! from one such task.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use napi::Task;
use napi::bindgen_prelude::{AsyncTask, BigInt, Buffer, Either, Env, Uint8Array};
use napi_derive::napi;

use opentele2_core::Error;
use opentele2_core::batch::{self, BatchOptions, LoadRequest as CoreLoadRequest};
use opentele2_core::crypto::AuthKey;
use opentele2_core::session::{mtcute, telethon};
use opentele2_core::tdata::TData as CoreTData;
use opentele2_core::tdata::account::Account as CoreAccount;

use crate::convert::{to_auth_key, to_passcode, to_user_id};
use crate::error::{CodedError, Result, check, core_error, invalid_arg, rejection};

/// One authorization key of an account.
#[napi(object, object_from_js = false)]
pub struct DcKey {
    /// DC id the key belongs to.
    pub dc_id: i32,
    /// The 256-byte authorization key.
    pub auth_key: Buffer,
}

/// One Telegram Desktop account as a plain object.
#[napi(object, object_from_js = false)]
pub struct Account {
    /// Index of the account in the accounts info.
    pub index: i32,
    /// Telegram user id.
    pub user_id: u64,
    /// Main DC id.
    pub main_dc: i32,
    /// The 256-byte authorization key of the main DC.
    pub auth_key: Buffer,
    /// Every authorization key, in file order.
    pub keys: Vec<DcKey>,
}

/// One authorization key given to `newTdata` or a session function.
#[napi(object, object_to_js = false)]
pub struct DcKeyInput {
    /// DC id the key belongs to.
    pub dc_id: i32,
    /// The 256-byte authorization key.
    pub auth_key: Uint8Array,
}

/// An account given to `newTdata` or a session function; every `Account`
/// is one. `keys`, when present, is the full key list and `authKey` is
/// ignored; otherwise `authKey` is the one key, of `mainDc`.
#[napi(object, object_to_js = false)]
pub struct AccountInput {
    /// Index of the account in the accounts info.
    pub index: i32,
    /// Telegram user id, in `0..2**64`.
    pub user_id: BigInt,
    /// Main DC id; a key of this DC must be present.
    pub main_dc: i32,
    /// The 256-byte authorization key of the main DC.
    pub auth_key: Option<Uint8Array>,
    /// Every authorization key, in file order.
    pub keys: Option<Vec<DcKeyInput>>,
}

/// The core account for `input`: `OT_BAD_LENGTH` for a key that is not 256
/// bytes, `OT_TDATA_AUTH_KEY_NOT_FOUND` without a key of the main DC.
fn to_account(input: AccountInput) -> Result<CoreAccount> {
    let keys: Vec<(i32, AuthKey)> = match (input.keys, input.auth_key) {
        (Some(keys), _) => keys
            .into_iter()
            .map(|key| Ok((key.dc_id, to_auth_key(&key.auth_key)?)))
            .collect::<Result<_>>()?,
        (None, Some(key)) => vec![(input.main_dc, to_auth_key(&key)?)],
        (None, None) => Vec::new(),
    };
    let user_id = to_user_id(&input.user_id)?;
    check(CoreAccount::new(input.index, user_id, input.main_dc, keys))
}

/// `account` as a plain object; key bytes are copied into new buffers.
fn to_js_account(account: &CoreAccount) -> Result<Account> {
    let auth_key = check(account.auth_key().ok_or(Error::AuthKeyNotFound))?;
    Ok(Account {
        index: account.index,
        user_id: account.user_id,
        main_dc: account.main_dc,
        auth_key: Buffer::from(auth_key.as_bytes().to_vec()),
        keys: account
            .keys
            .iter()
            .map(|(dc_id, key)| DcKey {
                dc_id: *dc_id,
                auth_key: Buffer::from(key.as_bytes().to_vec()),
            })
            .collect(),
    })
}

/// A Telegram Desktop `tdata` folder, loaded from disk or created for
/// writing. Its keys stay in Rust; only `accounts` copies key bytes out.
#[napi]
pub struct TData {
    inner: Arc<CoreTData>,
}

#[napi]
impl TData {
    /// The accounts, in accounts-info order.
    #[napi(getter)]
    pub fn accounts(&self) -> Result<Vec<Account>> {
        self.inner.accounts.iter().map(to_js_account).collect()
    }

    /// The active index stored in the accounts info.
    #[napi(getter)]
    pub fn active_index(&self) -> i32 {
        self.inner.active_index
    }

    /// The account at the active index, else the first one; `null` for a
    /// folder without accounts.
    #[napi(getter)]
    pub fn main_account(&self) -> Result<Option<Account>> {
        self.inner.main_account().map(to_js_account).transpose()
    }

    /// The data name of the key file, `"data"` unless loaded otherwise.
    #[napi(getter)]
    pub fn key_file(&self) -> String {
        self.inner.key_file.clone()
    }

    /// The account count and active index; never key bytes.
    #[napi(js_name = "toString")]
    pub fn to_js_string(&self) -> String {
        format!(
            "TData(accounts={}, activeIndex={})",
            self.inner.accounts.len(),
            self.inner.active_index
        )
    }
}

/// The JS value of one core folder result.
fn folder_or_error(result: opentele2_core::Result<CoreTData>) -> Either<TData, CodedError> {
    match result {
        Ok(inner) => Either::A(TData {
            inner: Arc::new(inner),
        }),
        Err(error) => Either::B(core_error(&error)),
    }
}

/// Settles a task that produced one folder.
fn settle_folder(env: Env, output: opentele2_core::Result<CoreTData>) -> napi::Result<TData> {
    match folder_or_error(output) {
        Either::A(tdata) => Ok(tdata),
        Either::B(error) => Err(rejection(env, error)),
    }
}

/// `TData::load` off the JavaScript thread.
pub struct LoadTask {
    request: CoreLoadRequest,
}

#[napi]
impl Task for LoadTask {
    type Output = opentele2_core::Result<CoreTData>;
    type JsValue = TData;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let request = &self.request;
        Ok(CoreTData::load(
            &request.dir,
            &request.passcode,
            request.key_file.as_deref(),
        ))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<TData> {
        settle_folder(env, output)
    }
}

/// `TData::new` off the JavaScript thread, with keys from the OS random
/// source.
pub struct NewTask {
    accounts: Vec<CoreAccount>,
    passcode: Vec<u8>,
    performance_mode: bool,
}

#[napi]
impl Task for NewTask {
    type Output = opentele2_core::Result<CoreTData>;
    type JsValue = TData;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let mut failure = None;
        let created = CoreTData::new(
            std::mem::take(&mut self.accounts),
            &self.passcode,
            self.performance_mode,
            &mut |buf| {
                if failure.is_none()
                    && let Err(error) = getrandom::fill(buf)
                {
                    failure = Some(error);
                }
            },
        );
        // A failed draw leaves the buffer unspecified, so the folder is
        // discarded rather than returned with weak keys.
        Ok(match failure {
            Some(error) => Err(Error::Io(std::io::Error::other(error))),
            None => created,
        })
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<TData> {
        settle_folder(env, output)
    }
}

/// `TData::save_random` off the JavaScript thread.
pub struct SaveTask {
    tdata: Arc<CoreTData>,
    dir: PathBuf,
}

#[napi]
impl Task for SaveTask {
    type Output = opentele2_core::Result<()>;
    type JsValue = ();

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(self.tdata.save_random(&self.dir))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<()> {
        output.map_err(|error| rejection(env, core_error(&error)))
    }
}

/// `batch::load_many` off the JavaScript thread.
pub struct LoadManyTask {
    requests: Vec<CoreLoadRequest>,
    options: BatchOptions,
}

#[napi]
impl Task for LoadManyTask {
    type Output = Vec<opentele2_core::Result<CoreTData>>;
    type JsValue = Vec<Either<TData, napi::Error<String>>>;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(batch::load_many(&self.requests, &self.options))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output.into_iter().map(folder_or_error).collect())
    }
}

/// Loads the folder at `path`; `passcode` is the local passcode (a string
/// is UTF-8 encoded) and `keyFile` the key file data name, `"data"` by
/// default. A wrong passcode rejects with `OT_TDATA_BAD_DECRYPT_KEY`, a
/// missing folder with `OT_TFILE_NOT_FOUND`.
#[napi]
pub fn load_tdata(
    path: String,
    passcode: Option<Either<String, Uint8Array>>,
    key_file: Option<String>,
) -> AsyncTask<LoadTask> {
    AsyncTask::new(LoadTask {
        request: CoreLoadRequest {
            dir: PathBuf::from(path),
            passcode: to_passcode(passcode),
            key_file,
        },
    })
}

/// Writes `tdata` into the folder `path`, with padding from the OS random
/// source.
#[napi]
pub fn save_tdata(tdata: &TData, path: String) -> AsyncTask<SaveTask> {
    AsyncTask::new(SaveTask {
        tdata: Arc::clone(&tdata.inner),
        dir: PathBuf::from(path),
    })
}

/// A new folder for `accounts` the way 1.5.0's `SaveTData` creates one, with
/// keys from the OS random source; `performanceMode` (default `true`) skips
/// the `configs` files on save. Account errors throw synchronously.
#[napi]
pub fn new_tdata(
    accounts: Vec<AccountInput>,
    passcode: Option<Either<String, Uint8Array>>,
    performance_mode: Option<bool>,
) -> Result<AsyncTask<NewTask>> {
    let accounts = accounts
        .into_iter()
        .map(to_account)
        .collect::<Result<Vec<_>>>()?;
    Ok(AsyncTask::new(NewTask {
        accounts,
        passcode: to_passcode(passcode),
        performance_mode: performance_mode.unwrap_or(true),
    }))
}

/// One `loadMany` request given as an object.
#[napi(object, object_to_js = false)]
pub struct LoadRequest {
    /// The tdata folder.
    pub path: String,
    /// The local passcode; a string is UTF-8 encoded.
    pub passcode: Option<Either<String, Uint8Array>>,
    /// The key file data name, `"data"` by default.
    pub key_file: Option<String>,
}

/// Loads many folders on a dedicated thread pool and resolves, in input
/// order, to a `TData` or the `Error` of each request; `threads` caps the
/// pool (about 64 MiB of Argon2id memory per thread).
#[napi]
pub fn load_many(
    requests: Vec<Either<String, LoadRequest>>,
    threads: Option<u32>,
) -> Result<AsyncTask<LoadManyTask>> {
    let threads = match threads {
        None => None,
        Some(count) => Some(
            usize::try_from(count)
                .ok()
                .and_then(NonZeroUsize::new)
                .ok_or_else(|| invalid_arg("threads must be at least 1"))?,
        ),
    };
    let requests = requests
        .into_iter()
        .map(|request| match request {
            Either::A(path) => CoreLoadRequest {
                dir: PathBuf::from(path),
                passcode: Vec::new(),
                key_file: None,
            },
            Either::B(request) => CoreLoadRequest {
                dir: PathBuf::from(request.path),
                passcode: to_passcode(request.passcode),
                key_file: request.key_file,
            },
        })
        .collect();
    Ok(AsyncTask::new(LoadManyTask {
        requests,
        options: BatchOptions { threads },
    }))
}

/// The Telethon string session of `account`: the first production endpoint
/// of its main DC, IPv6 when `ipv6` is set, and its main DC key.
#[napi]
pub fn telethon_string_session(account: AccountInput, ipv6: Option<bool>) -> Result<String> {
    let account = to_account(account)?;
    let session = telethon::StringSession::from_account(&account, ipv6.unwrap_or(false));
    Ok(check(session)?.encode())
}

/// The mtcute v3 string session of `account`: the first production IPv4
/// endpoint of its main DC, its user id, and its main DC key.
#[napi]
pub fn mtcute_string_session(account: AccountInput) -> Result<String> {
    let account = to_account(account)?;
    let session = mtcute::StringSession::from_account(&account, false);
    Ok(check(session)?.encode())
}
