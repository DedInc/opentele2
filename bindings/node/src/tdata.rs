//! `TData`, accounts as plain objects, their MTP configs, and the string
//! sessions.
//!
//! Loading, creating, migrating and saving folders run as async tasks on
//! the libuv pool; `loadMany` runs its folders on the core's dedicated
//! thread pool from one such task.

use std::convert::identity;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};

use napi::bindgen_prelude::{
    AsyncTask, BigInt, Buffer, ClassInstance, Either, Env, Object, ToNapiValue, Uint8Array, Unknown,
};
use napi::{JsString, Task};
use napi_derive::napi;
use serde_json::{Map, Value};

use opentele2_core::Error;
use opentele2_core::batch::{self, BatchOptions, LoadRequest as CoreLoadRequest};
use opentele2_core::crypto::AuthKey;
use opentele2_core::session::{mtcute, telethon};
use opentele2_core::tdata::account::Account as CoreAccount;
use opentele2_core::tdata::mtp_config::{self, Environment, MtpConfig as CoreMtpConfig};
use opentele2_core::tdata::{
    self, DrawOperation, DrawSource, NEW_FOLDER_ACTIVE_INDEX, TData as CoreTData,
};

use crate::convert::{to_auth_key, to_passcode, to_user_id, with_text};
use crate::error::{CodedError, Result, check, core_error, invalid_arg, rejection, thrown};

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
    /// The serialized MTP config the folder stored for the account (its
    /// `configs` file); absent when there is none.
    pub config: Option<Buffer>,
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
    /// The serialized MTP config of the account; the session functions take
    /// their endpoints from it, falling back to the production table.
    pub config: Option<Uint8Array>,
}

/// The core account for `input`: `OT_BAD_LENGTH` for a key that is not 256
/// bytes, `OT_TDATA_AUTH_KEY_NOT_FOUND` without a key of the main DC.
pub(crate) fn to_account(input: AccountInput) -> Result<CoreAccount> {
    let keys: Vec<(i32, AuthKey)> = match (input.keys, input.auth_key) {
        (Some(keys), _) => keys
            .into_iter()
            .map(|key| Ok((key.dc_id, to_auth_key(&key.auth_key)?)))
            .collect::<Result<_>>()?,
        (None, Some(key)) => vec![(input.main_dc, to_auth_key(&key)?)],
        (None, None) => Vec::new(),
    };
    let user_id = to_user_id(&input.user_id)?;
    let mut account = check(CoreAccount::new(input.index, user_id, input.main_dc, keys))?;
    account.config = input.config.map(|config| config.to_vec());
    Ok(account)
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
        config: account.config.clone().map(Buffer::from),
    })
}

/// The folder a [`TData`] holds. `migrateTdata` replaces it with the
/// migrated folder; every other operation works on a snapshot.
type Shared = Arc<RwLock<Arc<CoreTData>>>;

/// The folder `shared` holds now.
fn snapshot(shared: &Shared) -> Arc<CoreTData> {
    // Nothing panics while holding the lock, so a poisoned lock still holds
    // a whole folder.
    Arc::clone(&shared.read().unwrap_or_else(PoisonError::into_inner))
}

/// A Telegram Desktop `tdata` folder, loaded from disk or created for
/// writing. Its keys stay in Rust; `accounts`, `localKey` and `passcodeKey`
/// copy key bytes out into new buffers.
#[napi]
pub struct TData {
    inner: Shared,
}

impl TData {
    /// A `TData` holding `folder`.
    fn holding(folder: CoreTData) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(folder))),
        }
    }

    /// The folder this `TData` holds now.
    fn folder(&self) -> Arc<CoreTData> {
        snapshot(&self.inner)
    }

    /// Applies `change` to the folder and returns its result; snapshots
    /// taken before, such as a save in flight, keep the folder as it was.
    fn update<T>(&self, change: impl FnOnce(&mut CoreTData) -> T) -> T {
        let mut folder = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        change(Arc::make_mut(&mut folder))
    }
}

#[napi]
impl TData {
    /// The accounts, in accounts-info order.
    #[napi(getter)]
    pub fn accounts(&self, env: Env) -> napi::Result<Vec<Account>> {
        thrown(
            env,
            self.folder().accounts.iter().map(to_js_account).collect(),
        )
    }

    /// The active index stored in the accounts info; saving writes it.
    #[napi(getter)]
    pub fn active_index(&self) -> i32 {
        self.folder().active_index
    }

    /// Sets the active index the next save writes.
    #[napi(setter)]
    pub fn set_active_index(&self, value: i32) {
        self.update(|folder| folder.active_index = value);
    }

    /// 1.5.0's `kPerformanceMode`: when on, saving writes no `configs`
    /// files. Loading turns it on, the 1.5.0 default.
    #[napi(getter)]
    pub fn performance_mode(&self) -> bool {
        self.folder().performance_mode
    }

    /// Sets the performance mode of later saves.
    #[napi(setter)]
    pub fn set_performance_mode(&self, value: bool) {
        self.update(|folder| folder.performance_mode = value);
    }

    /// Telegram Desktop version in the key file's `TDF$` header; saving
    /// always writes 1.5.0's 7003001.
    #[napi(getter)]
    pub fn app_version(&self) -> u32 {
        self.folder().app_version
    }

    /// The 256-byte local key every file but the key file is encrypted
    /// with, copied into a new buffer.
    #[napi(getter)]
    pub fn local_key(&self) -> Buffer {
        Buffer::from(self.folder().local_key.as_bytes().to_vec())
    }

    /// The 256-byte open or passcode key the local key is wrapped under,
    /// copied into a new buffer.
    #[napi(getter)]
    pub fn passcode_key(&self) -> Buffer {
        Buffer::from(self.folder().passcode_key.as_bytes().to_vec())
    }

    /// The account at the active index, else the first one; `null` for a
    /// folder without accounts.
    #[napi(getter)]
    pub fn main_account(&self, env: Env) -> napi::Result<Option<Account>> {
        thrown(
            env,
            self.folder().main_account().map(to_js_account).transpose(),
        )
    }

    /// The data name of the key file, `"data"` unless loaded otherwise.
    #[napi(getter)]
    pub fn key_file(&self) -> String {
        self.folder().key_file.clone()
    }

    /// Renames the key file and the account files of later saves, as
    /// 1.5.0's `SaveTData(keyFile=...)` does; an empty name throws
    /// `OT_TDATA_SAVE_FAILED` and keeps the old one.
    #[napi(setter)]
    pub fn set_key_file(&self, env: Env, value: String) -> napi::Result<()> {
        thrown(
            env,
            check(self.update(move |folder| folder.set_key_file(&value))),
        )
    }

    /// Whether the key file has the pre-7.3 layout, which every save
    /// migrates afresh until `migrateTdata` migrates it once.
    #[napi(getter)]
    pub fn legacy_key_file(&self) -> bool {
        self.folder().key_data.trailer.is_none()
    }

    /// The account count and active index; never key bytes.
    #[napi(js_name = "toString")]
    pub fn to_js_string(&self) -> String {
        let folder = self.folder();
        format!(
            "TData(accounts={}, activeIndex={})",
            folder.accounts.len(),
            folder.active_index
        )
    }
}

/// The JS value of one core folder result.
fn folder_or_error(result: opentele2_core::Result<CoreTData>) -> Either<TData, CodedError> {
    match result {
        Ok(folder) => Either::A(TData::holding(folder)),
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

/// `error` of a call with a `draws` argument: a replay that does not match
/// the draws is `ERR_INVALID_ARG_VALUE` `draws: {reason}`, any other error
/// `OT_<CODE>`.
fn draws_error(error: &Error) -> CodedError {
    match error {
        Error::InvalidInput {
            what: "draws",
            reason,
        } => invalid_arg(format!("draws: {reason}")),
        error => core_error(error),
    }
}

/// Settles a task that may also have failed to replay its draws.
fn settle<T>(env: Env, output: opentele2_core::Result<T>) -> napi::Result<T> {
    output.map_err(|error| rejection(env, draws_error(&error)))
}

/// The `draws` argument copied into owned bytes.
fn to_draws(draws: Option<Vec<Uint8Array>>) -> Option<Vec<Vec<u8>>> {
    draws.map(|draws| draws.iter().map(|draw| draw.to_vec()).collect())
}

/// `TData::new_with_draws` off the JavaScript thread, with keys from the OS
/// random source or the replayed draws.
pub struct NewTask {
    accounts: Vec<CoreAccount>,
    passcode: Vec<u8>,
    performance_mode: bool,
    active_index: i32,
    draws: Option<Vec<Vec<u8>>>,
}

#[napi]
impl Task for NewTask {
    type Output = opentele2_core::Result<CoreTData>;
    type JsValue = TData;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(CoreTData::new_with_draws(
            std::mem::take(&mut self.accounts),
            &self.passcode,
            self.performance_mode,
            self.active_index,
            DrawSource::new(self.draws.take()),
        ))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<TData> {
        settle(env, output).map(TData::holding)
    }
}

/// `TData::save_with_draws` off the JavaScript thread, with padding from
/// the OS random source or the replayed draws.
pub struct SaveTask {
    tdata: Arc<CoreTData>,
    dir: PathBuf,
    performance_mode: Option<bool>,
    draws: Option<Vec<Vec<u8>>>,
}

#[napi]
impl Task for SaveTask {
    type Output = opentele2_core::Result<()>;
    type JsValue = ();

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(self.tdata.save_with_draws(
            &self.dir,
            self.performance_mode,
            DrawSource::new(self.draws.take()),
        ))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<()> {
        settle(env, output)
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
    type JsValue = Vec<Either<TData, napi::Error>>;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(batch::load_many(&self.requests, &self.options))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output
            .into_iter()
            .map(|result| match folder_or_error(result) {
                Either::A(tdata) => Either::A(tdata),
                Either::B(error) => Either::B(rejection(env, error)),
            })
            .collect())
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
        request: CoreLoadRequest::new(path, to_passcode(passcode), key_file),
    })
}

/// Writes `tdata` into the folder `path`, with padding from the OS random
/// source. `performanceMode`, when given, applies to this save only: on, no
/// `configs` files are written.
///
/// `draws`, a testing hook, replays exactly these byte arrays in order
/// instead (see `newTdata`); on a mismatch the written files are not usable
/// and the promise rejects with `ERR_INVALID_ARG_VALUE`.
#[napi]
pub fn save_tdata(
    tdata: &TData,
    path: String,
    performance_mode: Option<bool>,
    draws: Option<Vec<Uint8Array>>,
) -> AsyncTask<SaveTask> {
    AsyncTask::new(SaveTask {
        tdata: tdata.folder(),
        dir: PathBuf::from(path),
        performance_mode,
        draws: to_draws(draws),
    })
}

/// `TData::migrate_with_draws` off the JavaScript thread, with keys from the
/// OS random source or the replayed draws.
pub struct MigrateTask {
    tdata: Shared,
    draws: Option<Vec<Vec<u8>>>,
}

#[napi]
impl Task for MigrateTask {
    type Output = opentele2_core::Result<bool>;
    type JsValue = bool;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let mut folder = CoreTData::clone(&snapshot(&self.tdata));
        // A failed draw leaves `folder` as it was, so only a migration that
        // happened replaces the shared folder.
        let migrated = folder.migrate_with_draws(DrawSource::new(self.draws.take()));
        if let Ok(true) = migrated {
            *self.tdata.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(folder);
        }
        Ok(migrated)
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<bool> {
        settle(env, output)
    }
}

/// Installs 7.3 key data in place of a legacy (pre-7.3) key file, as the
/// first save would, and resolves to whether it did. Later saves write that
/// key data instead of migrating afresh, so the key file keeps one wrap
/// across saves. A 7.3 key file is left alone (`false`); under a passcode
/// the new wrap runs Argon2id.
///
/// `draws`, a testing hook, replays exactly these byte arrays in order
/// instead of the OS random source (see `newTdata`); on a mismatch the
/// folder stays as it was and the promise rejects with
/// `ERR_INVALID_ARG_VALUE`.
#[napi]
pub fn migrate_tdata(tdata: &TData, draws: Option<Vec<Uint8Array>>) -> AsyncTask<MigrateTask> {
    AsyncTask::new(MigrateTask {
        tdata: Arc::clone(&tdata.inner),
        draws: to_draws(draws),
    })
}

/// A new folder for `accounts` the way 1.5.0's `SaveTData` creates one, with
/// keys from the OS random source; `performanceMode` (default `true`) skips
/// the `configs` files on save, and `activeIndex` (default 1.5.0's `-1`) is
/// the active index saves write. Account errors throw synchronously.
///
/// `draws`, a testing hook, replaces the OS random source with exactly
/// these byte arrays in order, as 1.5.0's `os.urandom` calls were recorded;
/// a draw of another size, a missing draw or an unused one rejects with
/// `ERR_INVALID_ARG_VALUE`.
#[napi]
pub fn new_tdata(
    env: Env,
    accounts: Vec<AccountInput>,
    passcode: Option<Either<String, Uint8Array>>,
    performance_mode: Option<bool>,
    active_index: Option<i32>,
    draws: Option<Vec<Uint8Array>>,
) -> napi::Result<AsyncTask<NewTask>> {
    let accounts = thrown(
        env,
        accounts
            .into_iter()
            .map(to_account)
            .collect::<Result<Vec<_>>>(),
    )?;
    Ok(AsyncTask::new(NewTask {
        accounts,
        passcode: to_passcode(passcode),
        performance_mode: performance_mode.unwrap_or(true),
        active_index: active_index.unwrap_or(NEW_FOLDER_ACTIVE_INDEX),
        draws: to_draws(draws),
    }))
}

/// Most accounts one folder holds (1.5.0's `kMaxAccounts`);
/// `addTdataAccount` refuses more.
#[napi]
pub const TDATA_MAX_ACCOUNTS: u32 = 6;

// napi exports a literal; the build fails if the core limit moves.
const _: () = assert!(CoreTData::MAX_ACCOUNTS == 6);

/// The magic every `TDF$` file starts with (1.5.0 `TDF_MAGIC`), as the
/// text of its four ASCII bytes.
#[napi]
pub const TDF_MAGIC: &str = match std::str::from_utf8(&tdata::TDF_MAGIC) {
    Ok(text) => text,
    Err(_) => panic!("the TDF$ magic is ASCII"),
};

/// The `newTdata` arguments the draws of a new folder depend on.
#[napi(object, object_to_js = false)]
pub struct NewDrawPlan {
    /// Whether the passcode is non-empty; `false` by default.
    pub has_passcode: Option<bool>,
    /// The `performanceMode` argument; `true` by default.
    pub performance_mode: Option<bool>,
}

/// The draw plan of [`draw_plan`].
fn planned(
    operation: &str,
    target: Either<ClassInstance<'_, TData>, NewDrawPlan>,
) -> Result<Vec<u32>> {
    let (folder, params) = match target {
        Either::A(tdata) => (Some(tdata.folder()), None),
        Either::B(params) => (None, Some(params)),
    };
    let named = DrawOperation::from_name(
        operation,
        params.as_ref().and_then(|params| params.has_passcode),
        params.as_ref().and_then(|params| params.performance_mode),
        folder.as_deref(),
    );
    // `Error::InvalidInput` of `from_name`: an unknown name or a target of
    // the wrong kind, `ERR_INVALID_ARG_VALUE` with the core's text, except
    // that the "new" plan names its JavaScript options.
    let named = named.map_err(|error| match error {
        Error::InvalidInput { what: "target", .. } if folder.is_some() => {
            invalid_arg("the 'new' plan takes the hasPasscode and performanceMode options")
        }
        Error::InvalidInput { reason, .. } => invalid_arg(reason),
        error => core_error(&error),
    })?;
    check(tdata::draw_plan(named))?
        .into_iter()
        .map(|size| {
            u32::try_from(size).map_err(|_| core_error(&Error::QDataStreamFailed { context: None }))
        })
        .collect()
}

/// The sizes, in bytes and in order, of the random draws an operation will
/// make, so recorded `os.urandom` draws can be replayed through `draws`
/// without hand-coded counts; nothing is drawn and no file is touched.
///
/// `operation` is `'new'` with the `newTdata` options the draws depend on,
/// or `'migrate'` or `'save'` with the `TData` in its current state. A save
/// the folder would refuse throws its error, such as `OT_TDATA_SAVE_FAILED`
/// for a folder without accounts.
#[napi]
pub fn draw_plan(
    env: Env,
    #[napi(ts_arg_type = "'new' | 'migrate' | 'save'")] operation: JsString<'_>,
    target: Either<ClassInstance<'_, TData>, NewDrawPlan>,
) -> napi::Result<Vec<u32>> {
    let plan = with_text(operation, |operation| planned(operation, target));
    thrown(env, plan.and_then(identity))
}

/// Adds an account to `tdata` with `authKey` as the key of `mainDc`, as
/// 1.5.0's `Account.FromTelethon` does, and returns its index: the lowest
/// one below `TDATA_MAX_ACCOUNTS` no account holds. The active index is not
/// changed. A full folder throws `OT_MAX_ACCOUNT_LIMIT`, a key that is not
/// 256 bytes `OT_BAD_LENGTH`; `tdata` is then left as it was.
#[napi]
pub fn add_tdata_account(
    env: Env,
    tdata: &TData,
    user_id: BigInt,
    main_dc: i32,
    auth_key: &[u8],
) -> napi::Result<i32> {
    // napi has no borrowed `BigInt` argument, so the owned one is moved
    // into the conversion and dropped there.
    let added = to_user_id(&{ user_id }).and_then(|user_id| {
        let auth_key = to_auth_key(auth_key)?;
        check(tdata.update(|folder| folder.add_account(user_id, main_dc, auth_key)))
    });
    thrown(env, added)
}

/// Replaces the accounts later saves of `tdata` write, keeping its local
/// key, key data and salts, as 1.5.0 writes an edited `accounts` list under
/// the loaded local key. Up to `TDATA_MAX_ACCOUNTS` accounts are accepted,
/// or as many as were loaded when that is more. More throw
/// `OT_MAX_ACCOUNT_LIMIT`, two of one index `OT_TDATA_SAVE_FAILED`, and a bad
/// account the error `newTdata` throws for it; `tdata` is then left as it
/// was.
#[napi]
pub fn set_tdata_accounts(
    env: Env,
    tdata: &TData,
    accounts: Vec<AccountInput>,
) -> napi::Result<()> {
    let replaced = accounts
        .into_iter()
        .map(to_account)
        .collect::<Result<Vec<_>>>()
        .and_then(|accounts| check(tdata.update(|folder| folder.set_accounts(accounts))));
    thrown(env, replaced)
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
    let options = BatchOptions::from_threads(threads).map_err(|error| match error {
        Error::InvalidInput {
            what: "threads",
            reason,
        } => invalid_arg(reason),
        error => core_error(&error),
    })?;
    let requests = requests
        .into_iter()
        .map(|request| match request {
            Either::A(path) => CoreLoadRequest::new(path, Vec::new(), None),
            Either::B(request) => CoreLoadRequest::new(
                request.path,
                to_passcode(request.passcode),
                request.key_file,
            ),
        })
        .collect();
    Ok(AsyncTask::new(LoadManyTask { requests, options }))
}

/// The Telethon string session of `account`: the first production endpoint
/// of its main DC, IPv6 when `ipv6` is set, and its main DC key.
#[napi]
pub fn telethon_string_session(
    env: Env,
    account: AccountInput,
    ipv6: Option<bool>,
) -> napi::Result<String> {
    let encoded = to_account(account).and_then(|account| {
        let session = telethon::StringSession::from_account(&account, ipv6.unwrap_or(false));
        Ok(check(session)?.encode())
    });
    thrown(env, encoded)
}

/// The mtcute v3 string session of `account`: the first production IPv4
/// endpoint of its main DC, its user id, and its main DC key.
#[napi]
pub fn mtcute_string_session(env: Env, account: AccountInput) -> napi::Result<String> {
    let encoded = to_account(account).and_then(|account| {
        let session = mtcute::StringSession::from_account(&account, false);
        Ok(check(session)?.encode())
    });
    thrown(env, encoded)
}

/// Endpoint flag: an IPv6 address.
#[napi]
pub const MTP_FLAG_IPV6: i32 = mtp_config::FLAG_IPV6;
/// Endpoint flag: for media only.
#[napi]
pub const MTP_FLAG_MEDIA_ONLY: i32 = mtp_config::FLAG_MEDIA_ONLY;
/// Endpoint flag: TCP only, never HTTP.
#[napi]
pub const MTP_FLAG_TCPO_ONLY: i32 = mtp_config::FLAG_TCPO_ONLY;
/// Endpoint flag: a CDN DC.
#[napi]
pub const MTP_FLAG_CDN: i32 = mtp_config::FLAG_CDN;
/// Endpoint flag: a built-in endpoint.
#[napi]
pub const MTP_FLAG_STATIC: i32 = mtp_config::FLAG_STATIC;
/// Endpoint flag: only this port of the address.
#[napi]
pub const MTP_FLAG_THIS_PORT_ONLY: i32 = mtp_config::FLAG_THIS_PORT_ONLY;
/// Endpoint flag: the endpoint has a secret.
#[napi]
pub const MTP_FLAG_SECRET: i32 = mtp_config::FLAG_SECRET;

// The TypeScript shapes of `accountMtpConfig` and `accountEndpoints` live in
// tdata-types.d.ts: the values are the core's MTP config maps, keys in
// camelCase, built by `config_object`.

/// The keys whose values the core MTP config maps give as lists of 0 to
/// 255: an endpoint `secret` and a CDN key's `n` and `e`, Node `Buffer`s.
const BYTES_KEYS: [&str; 3] = ["secret", "n", "e"];

/// The key whose value the core MTP config maps give as a `u64` number, a
/// JavaScript `bigint` since it may exceed `2**53`.
const BIGINT_KEY: &str = "reaction_default_custom";

/// `key`, a `snake_case` key of a core MTP config map, in camelCase.
fn camel_case(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut upper = false;
    for ch in key.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            out.push(ch.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// `value`, the value of `key` in a core MTP config map, as JavaScript: a
/// byte list under [`BYTES_KEYS`] as a `Buffer`, the [`BIGINT_KEY`] number
/// as a `bigint`, maps and lists item by item, the rest as JSON values.
fn config_value<'env>(env: &'env Env, key: &str, value: &Value) -> napi::Result<Unknown<'env>> {
    match value {
        Value::Array(items) if BYTES_KEYS.contains(&key) => {
            let bytes = items
                .iter()
                .map(|item| {
                    item.as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or_else(|| {
                            napi::Error::from_reason(format!("{key} is not a byte list"))
                        })
                })
                .collect::<napi::Result<Vec<u8>>>()?;
            Buffer::from(bytes).into_unknown(env)
        }
        Value::Array(items) => {
            let length = u32::try_from(items.len())
                .map_err(|_| napi::Error::from_reason(format!("{key} lists too many items")))?;
            let mut array = env.create_array(length)?;
            for (index, item) in (0..length).zip(items) {
                array.set(index, config_value(env, key, item)?)?;
            }
            array.into_unknown(env)
        }
        Value::Object(map) => config_object(env, map)?.into_unknown(env),
        Value::Number(number) if key == BIGINT_KEY => {
            let number = number
                .as_u64()
                .ok_or_else(|| napi::Error::from_reason(format!("{key} is not a u64")))?;
            BigInt::from(number).into_unknown(env)
        }
        value => env.to_js_value(value),
    }
}

/// A core MTP config map as a JavaScript object with camelCase keys, in its
/// order. A `null` value, an endpoint `selected_ipv4`/`selected_ipv6` the
/// config has none for, is left out.
fn config_object<'env>(env: &'env Env, map: &Map<String, Value>) -> napi::Result<Object<'env>> {
    let mut object = Object::new(env)?;
    for (key, value) in map {
        if !value.is_null() {
            object.set(camel_case(key), config_value(env, key, value)?)?;
        }
    }
    Ok(object)
}

/// The MTP config of an account, or the production default 1.5.0 starts
/// every account with (`StorageAccount.__init__`).
fn config_of(account: Option<&CoreAccount>) -> CoreMtpConfig {
    account.map_or_else(
        || CoreMtpConfig::new(Environment::Production),
        CoreAccount::mtp_config,
    )
}

/// The core account of an optional `account` argument.
fn to_optional_account(
    env: Env,
    account: Option<AccountInput>,
) -> napi::Result<Option<CoreAccount>> {
    thrown(env, account.map(to_account).transpose())
}

/// The MTP config of `account` (1.5.0 `_readMtpConfig`): its stored
/// `config` parsed, or the production default when there is none or it
/// does not parse. No account, one never loaded, has the production
/// default.
#[napi(ts_return_type = "import('./tdata-types').MtpConfig")]
pub fn account_mtp_config(env: &Env, account: Option<AccountInput>) -> napi::Result<Object<'_>> {
    let account = to_optional_account(*env, account)?;
    config_object(env, &config_of(account.as_ref()).to_map())
}

/// The endpoints of DC `dcId` (default the main DC) in the MTP config of
/// `account`, by address family and protocol (1.5.0
/// `MTP.Config.endpoints`); `null` when the config has no such DC. No
/// account reads the production default, whose main DC is 0, a DC no
/// config lists.
#[napi(ts_return_type = "import('./tdata-types').Endpoints | null")]
pub fn account_endpoints(
    env: &Env,
    account: Option<AccountInput>,
    dc_id: Option<i32>,
) -> napi::Result<Option<Object<'_>>> {
    let account = to_optional_account(*env, account)?;
    let main_dc = account.as_ref().map_or(0, |account| account.main_dc);
    config_of(account.as_ref())
        .endpoints(dc_id.unwrap_or(main_dc))
        .map(|endpoints| config_object(env, &endpoints.to_map()))
        .transpose()
}
