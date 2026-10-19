//! `TData`, accounts as plain objects, their MTP configs, and the string
//! sessions.
//!
//! Loading, creating, migrating and saving folders run as async tasks on
//! the libuv pool; `loadMany` runs its folders on the core's dedicated
//! thread pool from one such task.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};

use napi::Task;
use napi::bindgen_prelude::{AsyncTask, BigInt, Buffer, Either, Env, Uint8Array};
use napi_derive::napi;

use opentele2_core::Error;
use opentele2_core::batch::{self, BatchOptions, LoadRequest as CoreLoadRequest};
use opentele2_core::crypto::AuthKey;
use opentele2_core::session::{mtcute, telethon};
use opentele2_core::tdata::account::Account as CoreAccount;
use opentele2_core::tdata::mtp_config::{
    self, ConfigFields, Endpoint as CoreEndpoint, Endpoints as CoreEndpoints, Environment,
    MtpConfig as CoreMtpConfig, ProtocolEndpoints as CoreProtocolEndpoints,
};
use opentele2_core::tdata::{NEW_FOLDER_ACTIVE_INDEX, TData as CoreTData};

use crate::convert::{to_auth_key, to_passcode, to_user_id};
use crate::draws::{Draws, Failure};
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

    /// Applies `change` to the folder; snapshots taken before, such as a
    /// save in flight, keep the folder as it was.
    fn update(&self, change: impl FnOnce(&mut CoreTData)) {
        let mut folder = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        change(Arc::make_mut(&mut folder));
    }
}

#[napi]
impl TData {
    /// The accounts, in accounts-info order.
    #[napi(getter)]
    pub fn accounts(&self) -> Result<Vec<Account>> {
        self.folder().accounts.iter().map(to_js_account).collect()
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
    pub fn main_account(&self) -> Result<Option<Account>> {
        self.folder().main_account().map(to_js_account).transpose()
    }

    /// The data name of the key file, `"data"` unless loaded otherwise.
    #[napi(getter)]
    pub fn key_file(&self) -> String {
        self.folder().key_file.clone()
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

/// Settles a task that may also have failed to replay its draws.
fn settle<T>(env: Env, output: std::result::Result<T, Failure>) -> napi::Result<T> {
    output.map_err(|failure| rejection(env, failure.into_error()))
}

/// The `draws` argument copied into owned bytes.
fn to_draws(draws: Option<Vec<Uint8Array>>) -> Option<Vec<Vec<u8>>> {
    draws.map(|draws| draws.iter().map(|draw| draw.to_vec()).collect())
}

/// `TData::new` off the JavaScript thread, with keys from the OS random
/// source or the replayed draws.
pub struct NewTask {
    accounts: Vec<CoreAccount>,
    passcode: Vec<u8>,
    performance_mode: bool,
    active_index: i32,
    draws: Option<Vec<Vec<u8>>>,
}

#[napi]
impl Task for NewTask {
    type Output = std::result::Result<CoreTData, Failure>;
    type JsValue = TData;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let mut draws = Draws::new(self.draws.take());
        let created = CoreTData::new(
            std::mem::take(&mut self.accounts),
            &self.passcode,
            self.performance_mode,
            &mut |buf| draws.fill(buf),
        );
        // A failed draw leaves the buffer unspecified, so the folder is
        // discarded rather than returned with weak keys.
        if let Err(failure) = draws.finish() {
            return Ok(Err(failure));
        }
        Ok(created.map_err(Failure::from).map(|mut created| {
            created.active_index = self.active_index;
            created
        }))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<TData> {
        settle(env, output).map(TData::holding)
    }
}

/// `TData::save_random`, or `TData::save` with the replayed draws, off the
/// JavaScript thread.
pub struct SaveTask {
    tdata: Arc<CoreTData>,
    dir: PathBuf,
    draws: Option<Vec<Vec<u8>>>,
}

#[napi]
impl Task for SaveTask {
    type Output = std::result::Result<(), Failure>;
    type JsValue = ();

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let mut draws = Draws::new(self.draws.take());
        if !draws.is_replay() {
            return Ok(self.tdata.save_random(&self.dir).map_err(Failure::from));
        }
        let saved = self.tdata.save(&self.dir, &mut |buf| draws.fill(buf));
        Ok(draws.finish().and(saved.map_err(Failure::from)))
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
    let mut folder = tdata.folder();
    if let Some(mode) = performance_mode
        && mode != folder.performance_mode
    {
        Arc::make_mut(&mut folder).performance_mode = mode;
    }
    AsyncTask::new(SaveTask {
        tdata: folder,
        dir: PathBuf::from(path),
        draws: to_draws(draws),
    })
}

/// `TData::migrate` off the JavaScript thread, with keys from the OS random
/// source or the replayed draws.
pub struct MigrateTask {
    tdata: Shared,
    draws: Option<Vec<Vec<u8>>>,
}

#[napi]
impl Task for MigrateTask {
    type Output = std::result::Result<bool, Failure>;
    type JsValue = bool;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let mut folder = CoreTData::clone(&snapshot(&self.tdata));
        let mut draws = Draws::new(self.draws.take());
        let migrated = folder.migrate(&mut |buf| draws.fill(buf));
        // A failed draw leaves the new wrap unspecified, so the folder
        // stays as it was.
        if let Err(failure) = draws.finish() {
            return Ok(Err(failure));
        }
        Ok(match migrated {
            Ok(true) => {
                *self.tdata.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(folder);
                Ok(true)
            }
            other => other.map_err(Failure::from),
        })
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
    accounts: Vec<AccountInput>,
    passcode: Option<Either<String, Uint8Array>>,
    performance_mode: Option<bool>,
    active_index: Option<i32>,
    draws: Option<Vec<Uint8Array>>,
) -> Result<AsyncTask<NewTask>> {
    let accounts = accounts
        .into_iter()
        .map(to_account)
        .collect::<Result<Vec<_>>>()?;
    Ok(AsyncTask::new(NewTask {
        accounts,
        passcode: to_passcode(passcode),
        performance_mode: performance_mode.unwrap_or(true),
        active_index: active_index.unwrap_or(NEW_FOLDER_ACTIVE_INDEX),
        draws: to_draws(draws),
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

/// One DC endpoint (`MTP.DcOptions.Endpoint`).
#[napi(object, object_from_js = false)]
pub struct Endpoint {
    /// DC id, as stored.
    pub id: i32,
    /// `MTP_FLAG_*` bits.
    pub flags: i32,
    /// IP address text, kept verbatim.
    pub ip: String,
    /// Port.
    pub port: i32,
    /// Secret; empty for none.
    pub secret: Buffer,
}

impl From<&CoreEndpoint> for Endpoint {
    fn from(endpoint: &CoreEndpoint) -> Self {
        Self {
            id: endpoint.id,
            flags: endpoint.flags,
            ip: endpoint.ip.clone(),
            port: endpoint.port,
            secret: Buffer::from(endpoint.secret.clone()),
        }
    }
}

/// `endpoints` as JavaScript objects.
fn to_js_endpoints(endpoints: &[CoreEndpoint]) -> Vec<Endpoint> {
    endpoints.iter().map(Endpoint::from).collect()
}

/// The endpoints of one address family, by protocol.
#[napi(object, object_from_js = false)]
pub struct ProtocolEndpoints {
    /// Every endpoint of the family, in insertion order.
    pub tcp: Vec<Endpoint>,
    /// The endpoints without `MTP_FLAG_TCPO_ONLY` and `MTP_FLAG_SECRET`.
    pub http: Vec<Endpoint>,
}

impl From<&CoreProtocolEndpoints> for ProtocolEndpoints {
    fn from(family: &CoreProtocolEndpoints) -> Self {
        Self {
            tcp: to_js_endpoints(&family.tcp),
            http: to_js_endpoints(&family.http),
        }
    }
}

/// The endpoints of one DC by address family and protocol, as 1.5.0
/// `MTP.Config.endpoints` returns them.
#[napi(object, object_from_js = false)]
pub struct Endpoints {
    /// Endpoints without `MTP_FLAG_IPV6`.
    pub ipv4: ProtocolEndpoints,
    /// Endpoints with `MTP_FLAG_IPV6`.
    pub ipv6: ProtocolEndpoints,
    /// The endpoint 1.5.0's session conversions connect to over IPv4: the
    /// first IPv4 TCP endpoint; absent without one.
    pub selected_ipv4: Option<Endpoint>,
    /// The endpoint they connect to when IPv6 is asked for: the first IPv6
    /// TCP endpoint, else the IPv4 one; absent without either.
    pub selected_ipv6: Option<Endpoint>,
}

impl From<&CoreEndpoints> for Endpoints {
    fn from(endpoints: &CoreEndpoints) -> Self {
        Self {
            ipv4: (&endpoints.ipv4).into(),
            ipv6: (&endpoints.ipv6).into(),
            selected_ipv4: endpoints.select(false).map(Endpoint::from),
            selected_ipv6: endpoints.select(true).map(Endpoint::from),
        }
    }
}

/// The endpoints of one DC of a config.
#[napi(object, object_from_js = false)]
pub struct DcEndpoints {
    /// DC id.
    pub dc_id: i32,
    /// Its endpoints, in insertion order.
    pub endpoints: Vec<Endpoint>,
}

/// One CDN RSA public key (`MTP.RSAPublicKey`).
#[napi(object, object_from_js = false)]
pub struct RsaPublicKey {
    /// DC id of the CDN.
    pub dc_id: i32,
    /// Modulus bytes.
    pub n: Buffer,
    /// Exponent bytes.
    pub e: Buffer,
}

/// The config fields (`MTP.ConfigFields`), in serialization order.
#[napi(object, object_from_js = false)]
pub struct MtpConfigFields {
    /// `chatSizeMax`.
    pub chat_size_max: i32,
    /// `megagroupSizeMax`.
    pub megagroup_size_max: i32,
    /// `forwardedCountMax`.
    pub forwarded_count_max: i32,
    /// `onlineUpdatePeriod`.
    pub online_update_period: i32,
    /// `offlineBlurTimeout`.
    pub offline_blur_timeout: i32,
    /// `offlineIdleTimeout`.
    pub offline_idle_timeout: i32,
    /// `onlineFocusTimeout`.
    pub online_focus_timeout: i32,
    /// `onlineCloudTimeout`.
    pub online_cloud_timeout: i32,
    /// `notifyCloudDelay`.
    pub notify_cloud_delay: i32,
    /// `notifyDefaultDelay`.
    pub notify_default_delay: i32,
    /// `savedGifsLimit`.
    pub saved_gifs_limit: i32,
    /// `editTimeLimit`.
    pub edit_time_limit: i32,
    /// `revokeTimeLimit`.
    pub revoke_time_limit: i32,
    /// `revokePrivateTimeLimit`.
    pub revoke_private_time_limit: i32,
    /// `revokePrivateInbox`.
    pub revoke_private_inbox: bool,
    /// `stickersRecentLimit`.
    pub stickers_recent_limit: i32,
    /// `stickersFavedLimit`.
    pub stickers_faved_limit: i32,
    /// `pinnedDialogsCountMax`.
    pub pinned_dialogs_count_max: i32,
    /// `pinnedDialogsInFolderMax`.
    pub pinned_dialogs_in_folder_max: i32,
    /// `internalLinksDomain`.
    pub internal_links_domain: String,
    /// `channelsReadMediaPeriod`.
    pub channels_read_media_period: i32,
    /// `callReceiveTimeoutMs`.
    pub call_receive_timeout_ms: i32,
    /// `callRingTimeoutMs`.
    pub call_ring_timeout_ms: i32,
    /// `callConnectTimeoutMs`.
    pub call_connect_timeout_ms: i32,
    /// `callPacketTimeoutMs`.
    pub call_packet_timeout_ms: i32,
    /// `webFileDcId`.
    pub web_file_dc_id: i32,
    /// `txtDomainString`.
    pub txt_domain_string: String,
    /// `phoneCallsEnabled`.
    pub phone_calls_enabled: bool,
    /// `blockedMode`.
    pub blocked_mode: bool,
    /// `captionLengthMax`.
    pub caption_length_max: i32,
    /// `reactionDefaultEmoji`.
    pub reaction_default_emoji: String,
    /// `reactionDefaultCustom`.
    pub reaction_default_custom: u64,
    /// `ratingDecay`.
    pub rating_decay: i32,
    /// `gifSearchUsername`.
    pub gif_search_username: String,
    /// `venueSearchUsername`.
    pub venue_search_username: String,
}

impl From<ConfigFields> for MtpConfigFields {
    fn from(fields: ConfigFields) -> Self {
        Self {
            chat_size_max: fields.chat_size_max,
            megagroup_size_max: fields.megagroup_size_max,
            forwarded_count_max: fields.forwarded_count_max,
            online_update_period: fields.online_update_period,
            offline_blur_timeout: fields.offline_blur_timeout,
            offline_idle_timeout: fields.offline_idle_timeout,
            online_focus_timeout: fields.online_focus_timeout,
            online_cloud_timeout: fields.online_cloud_timeout,
            notify_cloud_delay: fields.notify_cloud_delay,
            notify_default_delay: fields.notify_default_delay,
            saved_gifs_limit: fields.saved_gifs_limit,
            edit_time_limit: fields.edit_time_limit,
            revoke_time_limit: fields.revoke_time_limit,
            revoke_private_time_limit: fields.revoke_private_time_limit,
            revoke_private_inbox: fields.revoke_private_inbox,
            stickers_recent_limit: fields.stickers_recent_limit,
            stickers_faved_limit: fields.stickers_faved_limit,
            pinned_dialogs_count_max: fields.pinned_dialogs_count_max,
            pinned_dialogs_in_folder_max: fields.pinned_dialogs_in_folder_max,
            internal_links_domain: fields.internal_links_domain,
            channels_read_media_period: fields.channels_read_media_period,
            call_receive_timeout_ms: fields.call_receive_timeout_ms,
            call_ring_timeout_ms: fields.call_ring_timeout_ms,
            call_connect_timeout_ms: fields.call_connect_timeout_ms,
            call_packet_timeout_ms: fields.call_packet_timeout_ms,
            web_file_dc_id: fields.web_file_dc_id,
            txt_domain_string: fields.txt_domain_string,
            phone_calls_enabled: fields.phone_calls_enabled,
            blocked_mode: fields.blocked_mode,
            caption_length_max: fields.caption_length_max,
            reaction_default_emoji: fields.reaction_default_emoji,
            reaction_default_custom: fields.reaction_default_custom,
            rating_decay: fields.rating_decay,
            gif_search_username: fields.gif_search_username,
            venue_search_username: fields.venue_search_username,
        }
    }
}

/// An account's MTP config (`MTP.Config`).
#[napi(object, object_from_js = false)]
pub struct MtpConfig {
    /// Server environment.
    #[napi(ts_type = "'production' | 'test'")]
    pub environment: String,
    /// Every DC with its endpoints, in first-seen order.
    pub dcs: Vec<DcEndpoints>,
    /// CDN public keys, in file order.
    pub cdn_public_keys: Vec<RsaPublicKey>,
    /// Every config field.
    pub fields: MtpConfigFields,
}

impl From<CoreMtpConfig> for MtpConfig {
    fn from(config: CoreMtpConfig) -> Self {
        let environment = match config.environment {
            Environment::Production => "production",
            Environment::Test => "test",
        };
        Self {
            environment: environment.to_owned(),
            dcs: config
                .dc_options
                .dcs()
                .map(|(dc_id, endpoints)| DcEndpoints {
                    dc_id,
                    endpoints: to_js_endpoints(endpoints),
                })
                .collect(),
            cdn_public_keys: config
                .dc_options
                .cdn_public_keys
                .iter()
                .map(|key| RsaPublicKey {
                    dc_id: key.dc_id,
                    n: Buffer::from(key.n.clone()),
                    e: Buffer::from(key.e.clone()),
                })
                .collect(),
            fields: config.fields.into(),
        }
    }
}

/// The MTP config of `account` (1.5.0 `_readMtpConfig`): its stored
/// `config` parsed, or the production default when there is none or it
/// does not parse.
#[napi]
pub fn account_mtp_config(account: AccountInput) -> Result<MtpConfig> {
    Ok(to_account(account)?.mtp_config().into())
}

/// The endpoints of DC `dcId` (default the main DC) in the MTP config of
/// `account`, by address family and protocol (1.5.0
/// `MTP.Config.endpoints`); `null` when the config has no such DC.
#[napi]
pub fn account_endpoints(account: AccountInput, dc_id: Option<i32>) -> Result<Option<Endpoints>> {
    let account = to_account(account)?;
    let dc_id = dc_id.unwrap_or(account.main_dc);
    Ok(account
        .mtp_config()
        .endpoints(dc_id)
        .as_ref()
        .map(Endpoints::from))
}
