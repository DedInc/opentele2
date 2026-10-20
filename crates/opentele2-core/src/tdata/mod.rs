//! Telegram Desktop `tdata` folder formats, built on the [`crate::tdf`]
//! container, the [`crate::qt`] stream encoding, and the [`crate::crypto`]
//! and [`crate::kdf`] primitives.
//!
//! - [`key_data`]: the `key_<dataName>` file that holds the local key and the
//!   list of accounts.
//! - [`account`]: the per-account files and the `MtpAuthorization` blob.
//! - [`map`]: the per-account `maps` file.
//! - [`mtp_config`]: the MTP config and DC options of the per-account
//!   `configs` file.
//! - [`TData`]: a whole folder, loaded and saved the way 1.5.0's `TDesktop`
//!   does; [`draw_plan`] lists the random draws its writers make, and
//!   [`DrawSource`] serves them from the OS or replays recorded ones.

pub mod account;
pub mod key_data;
pub mod map;
pub mod mtp_config;

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use crate::crypto::{self, AuthKey};
use crate::kdf;
use crate::tdata::account::Account;
use crate::tdata::key_data::{
    AccountsInfo, DEFAULT_KEY_FILE, KeyData, KeyDataTrailer, LOCAL_ENCRYPT_SALT_SIZE,
};
use crate::tdf::TdfFile;
use crate::{Error, Result, tdf};

/// Telegram Desktop version 1.5.0 writes into the `TDF$` header of every
/// file it saves (`APP_VERSION` in `src/utils.py`), whatever version the
/// folder was read with.
pub const APP_VERSION: u32 = 7_003_001;

/// The magic every `TDF$` file starts with (1.5.0 `TDF_MAGIC`), re-exported
/// from [`crate::tdf::MAGIC`] next to [`APP_VERSION`], as 1.5.0 keeps both
/// in `src/utils.py`.
pub use crate::tdf::MAGIC as TDF_MAGIC;

/// Index 1.5.0 stores as the active account of a folder it creates
/// (`TDesktop.__active_index` before any load); loading it falls back to the
/// first account.
pub const NEW_FOLDER_ACTIVE_INDEX: i32 = -1;

/// A fallible fill of a buffer with random bytes; the writers draw padding,
/// salts, and generated keys through it in 1.5.0's `os.urandom` order.
pub(crate) type FillRandom<'a> = dyn FnMut(&mut [u8]) -> Result<()> + 'a;

/// Decodes a lowercase hex literal at compile time; a bad literal fails the
/// build.
pub(crate) const fn hex_bytes<const N: usize>(hex: &str) -> [u8; N] {
    const fn nibble(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => panic!("hex constant holds a non-hex digit"),
        }
    }
    let hex = hex.as_bytes();
    assert!(hex.len() == 2 * N, "hex constant has the wrong length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

// The four performance-mode constants are copied from 1.5.0
// src/td/tdesktop.py:44-82 (_PERF_LOCAL_KEY, _PERF_PASSCODE_KEY_SALT,
// _PERF_PASSCODE_KEY, _PERF_PASSCODE_KEY_ENCRYPTED). 1.5.0 uses them instead
// of a fresh PBKDF2 local key when performance mode is on and no passcode is
// set, so such folders are written without key derivation.
const PERF_LOCAL_KEY: [u8; AuthKey::SIZE] = hex_bytes(concat!(
    "d8745944519e0d2d71309d6c8d272dc64948f5e3eba7685324d5c691ad810c20",
    "3b31d19d29aed6ac33c014be6e09843293f6fa32dbe42b6a04e00481fae99511",
    "4caf6342bd98e96d293dd062c458689b3abd23a5cf230c75527c05bf5f90f38c",
    "d93952cf61aaac1cfeaae4608592e363ded35f8d8c45234def53231decb35592",
    "afc40d0601bbed11090969f74d9ab0cc97827546f441242d2cfb8e05a0610e97",
    "669c0da1adccb56e39e10c69e2942387ff4922f8c55dcb8890e345ef318266f4",
    "b3831430ea210c863c17624c0494cdead81f523430b5f74c15da323d766bd01c",
    "b5b88b9d2a731f6d853380ad306a8647fa614cc4017f08902c1e1f997ee12e3c",
));

const PERF_PASSCODE_KEY_SALT: [u8; LOCAL_ENCRYPT_SALT_SIZE] =
    hex_bytes("aed1e082994281d975760e729560d2c8d008f2a9dd3ff4d83245e22eedb66716");

const PERF_PASSCODE_KEY: [u8; AuthKey::SIZE] = hex_bytes(concat!(
    "273e6483b313c9dbc4acd9173864c0422f172881bfe1c6649ca5538654d0bd6e",
    "bcfbcc8dabbb669717ce53b41ca8afbf9d15c23fa2b06a6e166cc61f62e99805",
    "58cd42cf1022e05b466811ea29e9359fc1f94668e5c85155bce638fe7aa42aa8",
    "80ca83e0d2e534198a0a890139c8f679a57d3ba06d75fe5faa6e250101a58bc6",
    "e42b9696604de1e34ae40f6bba144a284f3ad8843253ec9b3971863a2c409208",
    "c2563967b3587e509b42a42a6040d23ff696ad552a240084fa3f950240f499b2",
    "3cd6d27e7010cbde07daae0667a7df8a5115a60b265c58f5d9291f7a98fc3c60",
    "1e2a4a32f1881b8218c855239d7b532959609e6ab52e48ad691c2583b566c8f9",
));

const PERF_PASSCODE_KEY_ENCRYPTED: [u8; 288] = hex_bytes(concat!(
    "97df0cd2e3109149b77b5287994d9c1ca240c51e87488e79dd029bea65fb9d27",
    "89bb5abcfe65e871d752bd938d83313c794c8993a734ce1216f2e660473f3143",
    "af9a333610a17995876e1721ce1f611d1c69d8c1a2f59f9493119704274e2cb5",
    "f36c20df439d156deff7a34371dc44bc86f8730cebf9b028eb7a1ed6621d99ad",
    "b62b3b2cf2295dbbb24bf132d37fffc17a0bdccc84bbea6ea34737a236b58248",
    "a7ab4c14363c20541cb45338677f339782b205e355189658dd45ea3e8005f851",
    "148e7e15f431904fa79c6827ee426d3ab9cba936eb33d485db88a6f0ff9722a6",
    "d62ff788347e27c82e9e139eb03ae521539bf3d363b4baea76e5e884cf66fe6b",
    "cd8a9e089d36405db99d01db20464fb6cabbdce4f67e4ec3742f913a1dd2dac5",
));

/// Fills `buf` from the operating system's CSPRNG.
fn os_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Io(std::io::Error::other(e)))
}

/// `len` bytes from `rng` (`Storage.RandomGenerate`).
pub(crate) fn random_bytes(rng: &mut FillRandom<'_>, len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    rng(&mut bytes)?;
    Ok(bytes)
}

/// [`crypto::encrypt_local`] with padding from `rng`; like 1.5.0's
/// `PrepareEncrypted`, no draw is made when no padding is needed.
pub(crate) fn encrypt(
    data: &[u8],
    local_key: &AuthKey,
    rng: &mut FillRandom<'_>,
) -> Result<Vec<u8>> {
    let len = crypto::local_padding_len(data.len());
    let padding = if len == 0 {
        Vec::new()
    } else {
        random_bytes(rng, len)?
    };
    crypto::encrypt_local(data, local_key, move |_| padding)
}

/// Writes `payload` to `dir` as the `TDF$` file `name` with [`APP_VERSION`].
pub(crate) fn write_tdf(dir: &Path, name: &str, payload: Vec<u8>) -> Result<()> {
    tdf::write(
        dir,
        name,
        &TdfFile {
            version: APP_VERSION,
            payload,
        },
    )
}

/// The local passcode a [`TData`] was loaded or created with (1.5.0's
/// `TDesktop.__passcodeBytes`). It has no `Debug`, and its bytes are
/// overwritten when it is dropped.
#[derive(Clone)]
struct Passcode(Vec<u8>);

impl Drop for Passcode {
    fn drop(&mut self) {
        self.0.fill(0);
        // Keeps the fill from being removed as a store nobody reads.
        std::hint::black_box(&mut self.0);
    }
}

/// A tdata folder, loaded from disk or created for writing.
///
/// `Debug` prints key ids only, never key material, and never the passcode.
#[derive(Clone)]
pub struct TData {
    /// Telegram Desktop version stored in the key file's `TDF$` header;
    /// [`TData::save`] always writes [`APP_VERSION`], as 1.5.0 does.
    pub app_version: u32,
    /// The data name of the key file, for example [`DEFAULT_KEY_FILE`];
    /// [`TData::set_key_file`] changes it after checking the name.
    pub key_file: String,
    /// The parsed key file; as in 1.5.0 only the live passcode wraps are
    /// kept, so stale wraps are not written back. [`TData::save`] writes it
    /// with a freshly encrypted accounts info, migrated first when it has
    /// the legacy layout.
    pub key_data: KeyData,
    /// The local key every other file is encrypted with.
    pub local_key: AuthKey,
    /// The open or passcode key the local key was wrapped under.
    pub passcode_key: AuthKey,
    /// The accounts that loaded, in accounts-info order without duplicates.
    pub accounts: Vec<Account>,
    /// The active index stored in the accounts info, 0 when absent.
    pub active_index: i32,
    /// 1.5.0's `TDesktop.kPerformanceMode`: when on, [`TData::save`] writes
    /// no `configs` file. [`TData::load`] turns it on, the 1.5.0 default.
    pub performance_mode: bool,
    /// The passcode given to [`TData::new`] or [`TData::load`]; a legacy
    /// key file is migrated under it on [`TData::save`].
    passcode: Passcode,
    /// How many accounts [`TData::load`] loaded; 0 for [`TData::new`].
    /// [`TData::set_accounts`] accepts up to this many when it is above
    /// [`TData::MAX_ACCOUNTS`].
    loaded_accounts: usize,
}

impl fmt::Debug for TData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TData")
            .field("app_version", &self.app_version)
            .field("key_file", &self.key_file)
            .field("key_data", &self.key_data)
            .field("local_key", &self.local_key)
            .field("passcode_key", &self.passcode_key)
            .field("accounts", &self.accounts)
            .field("active_index", &self.active_index)
            .field("performance_mode", &self.performance_mode)
            .finish_non_exhaustive()
    }
}

impl TData {
    /// Most accounts one folder holds (1.5.0's `TDesktop.kMaxAccounts`);
    /// [`TData::add_account`] refuses more. [`TData::load`] reads a folder
    /// that lists more, as 1.5.0 does.
    pub const MAX_ACCOUNTS: usize = 6;

    /// Creates a folder for `accounts` the way 1.5.0's `SaveTData` does for a
    /// `TDesktop` that was not loaded (`__generateLocalKey`), drawing random
    /// bytes from `rng` in 1.5.0's `os.urandom` order.
    ///
    /// - Performance mode on and an empty passcode: the fixed 1.5.0
    ///   performance-mode local key and open wrap; nothing is drawn.
    /// - Otherwise: a 256-byte random pass and a 32-byte salt make the local
    ///   key (`create_local_key(pass, salt)`), then a 32-byte open salt is
    ///   drawn. Without a passcode the local key is wrapped under
    ///   `create_local_key("", open salt)`; with one, a 32-byte wrap salt is
    ///   drawn, the open wrap is null, and the only wrap is a
    ///   [`key_data::default_passcode_kdf`] wrap of generation 1, committed.
    ///   Each wrap draws its 12 padding bytes.
    ///
    /// The folder uses [`DEFAULT_KEY_FILE`] and [`NEW_FOLDER_ACTIVE_INDEX`];
    /// both fields can be changed before saving.
    ///
    /// # Errors
    /// As [`key_data::create_passcode_key`] and [`key_data::wrap_local_key`].
    pub fn new(
        accounts: Vec<Account>,
        passcode: &[u8],
        performance_mode: bool,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Self> {
        Self::generate(accounts, passcode, performance_mode, &mut |buf| {
            rng(buf);
            Ok(())
        })
    }

    fn generate(
        accounts: Vec<Account>,
        passcode: &[u8],
        performance_mode: bool,
        rng: &mut FillRandom<'_>,
    ) -> Result<Self> {
        let (key_data, local_key, passcode_key) = if performance_mode && passcode.is_empty() {
            let data = KeyData {
                salt: PERF_PASSCODE_KEY_SALT.to_vec(),
                key_encrypted: Some(PERF_PASSCODE_KEY_ENCRYPTED.to_vec()),
                info_encrypted: Vec::new(),
                trailer: Some(KeyDataTrailer {
                    committed: 0,
                    wraps: Vec::new(),
                }),
            };
            (
                data,
                AuthKey::new(PERF_LOCAL_KEY),
                AuthKey::new(PERF_PASSCODE_KEY),
            )
        } else {
            let pass = random_bytes(rng, AuthKey::SIZE)?;
            let salt = random_bytes(rng, LOCAL_ENCRYPT_SALT_SIZE)?;
            let local_key = kdf::create_local_key(&pass, &salt);
            let (data, passcode_key) = key_data::install(&local_key, passcode, rng)?;
            (data, local_key, passcode_key)
        };
        Ok(Self {
            app_version: APP_VERSION,
            key_file: DEFAULT_KEY_FILE.to_owned(),
            key_data,
            local_key,
            passcode_key,
            accounts,
            active_index: NEW_FOLDER_ACTIVE_INDEX,
            performance_mode,
            passcode: Passcode(passcode.to_vec()),
            loaded_accounts: 0,
        })
    }

    /// Writes the folder into `dir` the way 1.5.0's `__writeAccounts` does,
    /// drawing every padding from `rng` in 1.5.0's `os.urandom` order.
    ///
    /// Per account, in order: `<folder>/maps` (two null arrays and the
    /// encrypted map, see [`map::MapData::encode_entries`]), then, with
    /// performance mode off, `<folder>/configs` (the loaded config or
    /// [`account::MTP_CONFIG_PRODUCTION`]), then the `<folder>s` MTP data
    /// ([`Account::encode_mtp_data`]). Last the key file: the open salt, the
    /// open wrap, the accounts info ([`AccountsInfo::encode`]) encrypted
    /// under the local key, and the 7.3 trailer. Every file carries
    /// [`APP_VERSION`].
    ///
    /// A legacy key file (no trailer) is migrated first, as 1.5.0's
    /// `SaveTData` does (`__installKeyData`): before any other draw, the same
    /// local key is wrapped in a fresh 7.3 key file under the passcode this
    /// [`TData`] was loaded or created with, as [`TData::new`] describes
    /// after the local key (open salt, then wrap salt with a passcode, then
    /// the wrap padding). The account files stay valid. `self` is not
    /// changed, so every save of a still-legacy [`TData`] migrates afresh;
    /// [`TData::migrate`] first keeps one migration for every later save,
    /// as 1.5.0 keeps the key data its first save installed.
    ///
    /// # Errors
    /// - [`Error::SaveFailed`] when there is no account, or when an account
    ///   map encodes to nothing (1.5.0 cannot encrypt it either).
    /// - As [`key_data::create_passcode_key`] when migrating under a
    ///   passcode.
    /// - [`Error::Io`] when a directory or file cannot be written.
    /// - [`Error::QDataStreamFailed`] when a blob does not fit a `u32` length.
    pub fn save(&self, dir: impl AsRef<Path>, rng: &mut dyn FnMut(&mut [u8])) -> Result<()> {
        self.save_with(dir.as_ref(), self.performance_mode, &mut |buf| {
            rng(buf);
            Ok(())
        })
    }

    /// [`TData::save`] with padding from the operating system's CSPRNG.
    ///
    /// # Errors
    /// [`Error::Io`] when the system random source fails, otherwise as
    /// [`TData::save`].
    pub fn save_random(&self, dir: impl AsRef<Path>) -> Result<()> {
        self.save_with(dir.as_ref(), self.performance_mode, &mut os_random)
    }

    /// [`TData::new`] with its draws from `draws`, storing `active_index`
    /// (1.5.0's [`NEW_FOLDER_ACTIVE_INDEX`] when the caller has none).
    ///
    /// A failed or mismatched draw leaves the keys unspecified, so the folder
    /// is discarded and the draw failure is returned, before any failure of
    /// [`TData::new`] itself.
    ///
    /// # Errors
    /// As [`DrawSource::finish`], otherwise as [`TData::new`].
    pub fn new_with_draws(
        accounts: Vec<Account>,
        passcode: &[u8],
        performance_mode: bool,
        active_index: i32,
        mut draws: DrawSource,
    ) -> Result<Self> {
        let created = Self::new(accounts, passcode, performance_mode, &mut |buf| {
            draws.fill(buf);
        });
        draws.finish()?;
        let mut created = created?;
        created.active_index = active_index;
        Ok(created)
    }

    /// [`TData::save`] with its padding from `draws`, and with
    /// `performance_mode`, when given, in place of
    /// [`TData::performance_mode`] for this save only (on: no `configs`
    /// files are written). `self` is not changed.
    ///
    /// The operating system source fails fast as [`TData::save_random`]
    /// does. A replay runs the whole save; on a mismatch the written files
    /// are not usable and the draw failure is returned, before any failure
    /// of the save itself.
    ///
    /// # Errors
    /// As [`DrawSource::finish`], otherwise as [`TData::save_random`].
    pub fn save_with_draws(
        &self,
        dir: impl AsRef<Path>,
        performance_mode: Option<bool>,
        mut draws: DrawSource,
    ) -> Result<()> {
        let dir = dir.as_ref();
        let performance_mode = performance_mode.unwrap_or(self.performance_mode);
        if !draws.is_replay() {
            return self.save_with(dir, performance_mode, &mut os_random);
        }
        let saved = self.save_with(dir, performance_mode, &mut |buf| {
            draws.fill(buf);
            Ok(())
        });
        draws.finish()?;
        saved
    }

    /// [`TData::migrate`] with its draws from `draws`. A failed or
    /// mismatched draw leaves the new wrap unspecified, so `self` stays as
    /// it was and the draw failure is returned.
    ///
    /// # Errors
    /// As [`DrawSource::finish`], otherwise as [`TData::migrate`]; `self` is
    /// then unchanged.
    pub fn migrate_with_draws(&mut self, mut draws: DrawSource) -> Result<bool> {
        let migration = self.migration(&mut |buf| {
            draws.fill(buf);
            Ok(())
        });
        draws.finish()?;
        let Some(migration) = migration? else {
            return Ok(false);
        };
        self.commit_migration(migration);
        Ok(true)
    }

    /// Installs 7.3 key data in place of a legacy key file (no trailer),
    /// drawing from `rng` exactly what [`TData::save`] draws to migrate, and
    /// returns whether it did. The local key and the accounts stay as they
    /// are; the passcode key becomes the new wrap key, and the stored
    /// accounts info, still valid under the same local key, is kept.
    ///
    /// Later saves then write this key data instead of migrating afresh,
    /// so two saves with the same padding write the same files. A key file
    /// that already has the 7.3 layout is left alone and nothing is drawn.
    ///
    /// # Errors
    /// As [`key_data::create_passcode_key`] when migrating under a
    /// passcode; `self` is then unchanged.
    pub fn migrate(&mut self, rng: &mut dyn FnMut(&mut [u8])) -> Result<bool> {
        let Some(migration) = self.migration(&mut |buf| {
            rng(buf);
            Ok(())
        })?
        else {
            return Ok(false);
        };
        self.commit_migration(migration);
        Ok(true)
    }

    /// The 7.3 key data and wrap key [`TData::migrate`] installs, drawn
    /// from `rng`; `None` for a key file that already has the 7.3 layout.
    fn migration(&self, rng: &mut FillRandom<'_>) -> Result<Option<(KeyData, AuthKey)>> {
        if self.key_data.trailer.is_some() {
            return Ok(None);
        }
        key_data::install(&self.local_key, &self.passcode.0, rng).map(Some)
    }

    /// Installs a [`TData::migration`], keeping the stored accounts info.
    fn commit_migration(&mut self, (data, passcode_key): (KeyData, AuthKey)) {
        self.key_data = KeyData {
            info_encrypted: std::mem::take(&mut self.key_data.info_encrypted),
            ..data
        };
        self.passcode_key = passcode_key;
    }

    fn save_with(
        &self,
        dir: &Path,
        performance_mode: bool,
        rng: &mut FillRandom<'_>,
    ) -> Result<()> {
        if self.accounts.is_empty() {
            return Err(Error::SaveFailed);
        }
        // tdesktop 7.3 migrates a pre-7.3 key file on start; 1.5.0 writes
        // the migrated shape directly, before the accounts draw padding.
        let migrated = if self.key_data.trailer.is_none() {
            Some(key_data::install(&self.local_key, &self.passcode.0, rng)?.0)
        } else {
            None
        };
        let base = migrated.as_ref().unwrap_or(&self.key_data);
        for account in &self.accounts {
            account.write(dir, &self.key_file, &self.local_key, performance_mode, rng)?;
        }
        let info = self.accounts_info();
        let key_data = KeyData {
            info_encrypted: encrypt(&info.encode()?, &self.local_key, rng)?,
            ..base.clone()
        };
        write_tdf(
            dir,
            &key_data::file_name(&self.key_file),
            key_data.encode()?,
        )
    }

    /// Loads the folder `dir` (`TDesktop.__loadFromTData`).
    ///
    /// `key_file` defaults to [`DEFAULT_KEY_FILE`]. Each listed index is
    /// loaded once; negative indices are skipped, and an account whose files
    /// fail to read is skipped silently, as in 1.5.0.
    ///
    /// # Errors
    /// - As [`tdf::read`] and [`KeyData::parse`] for the key file.
    /// - As [`key_data::open_local_key`] and
    ///   [`key_data::decrypt_accounts_info`]; a wrong passcode is
    ///   [`Error::BadDecryptKey`].
    /// - [`Error::AuthKeyNotFound`] when no account loads.
    pub fn load(dir: impl AsRef<Path>, passcode: &[u8], key_file: Option<&str>) -> Result<Self> {
        let dir = dir.as_ref();
        let key_file = key_file.unwrap_or(DEFAULT_KEY_FILE);
        let file = tdf::read(dir, &key_data::file_name(key_file))?;
        let mut data = KeyData::parse(&file.payload)?;
        let opened = key_data::open_local_key(&data, passcode)?;
        let info = key_data::decrypt_accounts_info(&data, &opened.local_key, passcode)?;
        // startModern keeps only the committed generation.
        data.trailer = data.trailer.map(|trailer| KeyDataTrailer {
            committed: trailer.committed,
            wraps: trailer.live_wraps().cloned().collect(),
        });

        let mut seen = HashSet::new();
        let accounts: Vec<Account> = info
            .indices
            .iter()
            .filter(|&&index| seen.insert(index) && index >= 0)
            .filter_map(|&index| Account::read(dir, key_file, index, &opened.local_key).ok())
            .collect();
        if accounts.is_empty() {
            return Err(Error::AuthKeyNotFound);
        }
        Ok(Self {
            app_version: file.version,
            key_file: key_file.to_owned(),
            key_data: data,
            local_key: opened.local_key,
            passcode_key: opened.passcode_key,
            loaded_accounts: accounts.len(),
            accounts,
            active_index: info.active_index,
            performance_mode: true,
            passcode: Passcode(passcode.to_vec()),
        })
    }

    /// Replaces the accounts later saves write, keeping the local key, the
    /// key data with its salts, and the active index, as 1.5.0 writes an
    /// edited `accounts` list under the loaded local key.
    ///
    /// Up to [`TData::MAX_ACCOUNTS`] accounts are accepted, or as many as
    /// [`TData::load`] loaded when that is more: 1.5.0 loads a folder that
    /// lists more than six and saves it back under the same local key.
    ///
    /// # Errors
    /// - [`Error::MaxAccountLimit`] for more accounts than that limit.
    /// - [`Error::SaveFailed`] when two accounts share an index, whose files
    ///   one save would overwrite.
    ///
    /// `self` is then unchanged.
    pub fn set_accounts(&mut self, accounts: Vec<Account>) -> Result<()> {
        if accounts.len() > Self::MAX_ACCOUNTS.max(self.loaded_accounts) {
            return Err(Error::MaxAccountLimit);
        }
        let mut seen = HashSet::new();
        if !accounts.iter().all(|account| seen.insert(account.index)) {
            return Err(Error::SaveFailed);
        }
        self.accounts = accounts;
        Ok(())
    }

    /// Adds an account with `auth_key` as the key of `main_dc`, as 1.5.0's
    /// `Account.FromTelethon` adds one to an owner: it gets the map of
    /// [`MapData::new_account`](map::MapData::new_account) and no config,
    /// and it is appended (`_addSingleAccount`). The active index is not
    /// changed, so [`TData::main_account`] stays the first account of a
    /// folder that had none. Returns the new index.
    ///
    /// The index is the lowest one in `0..MAX_ACCOUNTS` that no account
    /// holds, tdesktop's own rule. This deliberately differs from 1.5.0,
    /// which uses the account count: with loaded indices `[0, 2]` the count
    /// gives a second account 2, whose files would overwrite the first; here
    /// the new account gets 1. Without gaps both rules agree.
    ///
    /// # Errors
    /// [`Error::MaxAccountLimit`] when the folder already holds
    /// [`TData::MAX_ACCOUNTS`] accounts or every index below it is taken
    /// (1.5.0: `You can't have more than 6 accounts in one TDesktop
    /// client`); `self` is then unchanged.
    pub fn add_account(&mut self, user_id: u64, main_dc: i32, auth_key: AuthKey) -> Result<i32> {
        if self.accounts.len() >= Self::MAX_ACCOUNTS {
            return Err(Error::MaxAccountLimit);
        }
        let index = (0..)
            .take(Self::MAX_ACCOUNTS)
            .find(|index| self.accounts.iter().all(|account| account.index != *index))
            .ok_or(Error::MaxAccountLimit)?;
        let account = Account::new(index, user_id, main_dc, vec![(main_dc, auth_key)])?;
        self.accounts.push(account);
        Ok(index)
    }

    /// Changes the data name of the key file, as 1.5.0's
    /// `SaveTData(keyFile=name)` does: [`TData::save`] then writes
    /// `key_<name>s` and every account under the data name
    /// [`account::data_name`]`(name, index)`.
    ///
    /// # Errors
    /// [`Error::SaveFailed`] when `name` is empty; `self` is then unchanged.
    pub fn set_key_file(&mut self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(Error::SaveFailed);
        }
        name.clone_into(&mut self.key_file);
        Ok(())
    }

    /// The main account: the one whose index is the active index, else the
    /// first one; `None` only when [`TData::accounts`] was emptied.
    #[must_use]
    pub fn main_account(&self) -> Option<&Account> {
        self.accounts
            .iter()
            .find(|account| account.index == self.active_index)
            .or_else(|| self.accounts.first())
    }
}

/// Recorded draws served in order.
struct Replay {
    draws: Vec<Vec<u8>>,
    next: usize,
}

/// The random source of [`TData::new_with_draws`],
/// [`TData::save_with_draws`] and [`TData::migrate_with_draws`]: the
/// operating system's CSPRNG, or, as a testing hook, recorded draws (1.5.0's
/// `os.urandom` calls, sized by [`draw_plan`]) replayed in order.
///
/// The first failure is kept and every later draw is zero-filled, so the
/// caller discards whatever was built; [`DrawSource::finish`] reports it.
/// `Debug` prints draw counts only, never draw bytes, and replayed bytes are
/// overwritten when the source is dropped.
pub struct DrawSource {
    replay: Option<Replay>,
    failure: Option<Error>,
}

impl DrawSource {
    /// The operating system's CSPRNG.
    #[must_use]
    pub fn os() -> Self {
        Self {
            replay: None,
            failure: None,
        }
    }

    /// A replay of exactly `draws`, in order.
    #[must_use]
    pub fn replay(draws: Vec<Vec<u8>>) -> Self {
        Self {
            replay: Some(Replay { draws, next: 0 }),
            failure: None,
        }
    }

    /// The replay of `draws` when given, else the operating system's CSPRNG:
    /// the optional `draws` argument of the bindings.
    #[must_use]
    pub fn new(draws: Option<Vec<Vec<u8>>>) -> Self {
        draws.map_or_else(Self::os, Self::replay)
    }

    /// Whether the draws are a replay rather than the operating system's
    /// CSPRNG.
    #[must_use]
    pub fn is_replay(&self) -> bool {
        self.replay.is_some()
    }

    /// Fills `buf` with the next draw; after a failure, and on the failing
    /// draw, `buf` is zero-filled instead.
    pub fn fill(&mut self, buf: &mut [u8]) {
        if self.failure.is_some() {
            buf.fill(0);
            return;
        }
        let Some(replay) = self.replay.as_mut() else {
            if let Err(error) = os_random(buf) {
                self.failure = Some(error);
                buf.fill(0);
            }
            return;
        };
        match replay.draws.get(replay.next) {
            Some(draw) if draw.len() == buf.len() => {
                buf.copy_from_slice(draw);
                replay.next += 1;
            }
            Some(draw) => {
                self.failure = Some(replay_mismatch(format!(
                    "draw {} has {} bytes, but {} were drawn",
                    replay.next,
                    draw.len(),
                    buf.len()
                )));
                buf.fill(0);
            }
            None => {
                self.failure = Some(replay_mismatch(format!(
                    "draw {} of {} bytes was not given ({} draws given)",
                    replay.next,
                    buf.len(),
                    replay.draws.len()
                )));
                buf.fill(0);
            }
        }
    }

    /// The first failure, else a replay whose draws were not all used.
    ///
    /// # Errors
    /// - [`Error::Io`] when the operating system's CSPRNG failed.
    /// - [`Error::InvalidInput`] with `what` `"draws"` when the replay did
    ///   not match what was drawn; `reason` is one of `draw {i} has {n}
    ///   bytes, but {m} were drawn`, `draw {i} of {m} bytes was not given
    ///   ({n} draws given)` and `{k} of {n} draws were left unused`, the
    ///   texts the bindings show after `draws: `.
    pub fn finish(mut self) -> Result<()> {
        if let Some(failure) = self.failure.take() {
            return Err(failure);
        }
        match &self.replay {
            Some(replay) if replay.next != replay.draws.len() => Err(replay_mismatch(format!(
                "{} of {} draws were left unused",
                replay.draws.len() - replay.next,
                replay.draws.len()
            ))),
            _ => Ok(()),
        }
    }
}

impl fmt::Debug for DrawSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("DrawSource");
        match &self.replay {
            Some(replay) => out
                .field("replay_draws", &replay.draws.len())
                .field("next", &replay.next),
            None => out.field("source", &"os"),
        };
        out.field("failed", &self.failure.is_some()).finish()
    }
}

impl Drop for DrawSource {
    fn drop(&mut self) {
        if let Some(replay) = self.replay.as_mut() {
            for draw in &mut replay.draws {
                draw.fill(0);
            }
            // Keeps the fill from being removed as a store nobody reads.
            std::hint::black_box(&mut replay.draws);
        }
    }
}

/// The [`Error::InvalidInput`] of a replay that does not match the draws.
fn replay_mismatch(reason: String) -> Error {
    Error::InvalidInput {
        what: "draws",
        reason,
    }
}

/// A call whose random draws [`draw_plan`] lists.
#[derive(Clone, Copy, Debug)]
pub enum DrawOperation<'a> {
    /// [`TData::new`] with or without a passcode, and with performance mode
    /// on or off.
    New {
        /// Whether the passcode is non-empty.
        has_passcode: bool,
        /// The `performance_mode` argument.
        performance_mode: bool,
    },
    /// [`TData::migrate`] of this folder.
    Migrate(&'a TData),
    /// [`TData::save`] of this folder, in its current state.
    Save(&'a TData),
}

impl<'a> DrawOperation<'a> {
    /// The operation names [`DrawOperation::from_name`] accepts, in order.
    pub const NAMES: [&'static str; 3] = ["new", "migrate", "save"];

    /// The operation the bindings name `name`: `"new"` with `has_passcode`
    /// (default `false`) and `performance_mode` (default `true`), the
    /// arguments of [`TData::new`], or `"migrate"` or `"save"` of `folder`.
    /// `has_passcode` and `performance_mode` are ignored for `"migrate"`
    /// and `"save"`.
    ///
    /// # Errors
    /// [`Error::InvalidInput`], whose `reason` is:
    /// - `unknown operation {name:?}; expected one of new, migrate, save`
    ///   (`what` `"operation"`) for any other name;
    /// - `the {name:?} plan takes a TData` (`what` `"target"`) for
    ///   `"migrate"` or `"save"` without `folder`;
    /// - `the "new" plan takes has_passcode and performance_mode, not a
    ///   TData` (`what` `"target"`) for `"new"` with `folder`.
    pub fn from_name(
        name: &str,
        has_passcode: Option<bool>,
        performance_mode: Option<bool>,
        folder: Option<&'a TData>,
    ) -> Result<Self> {
        match (name, folder) {
            ("new", None) => Ok(Self::New {
                has_passcode: has_passcode.unwrap_or(false),
                performance_mode: performance_mode.unwrap_or(true),
            }),
            ("new", Some(_)) => Err(Error::InvalidInput {
                what: "target",
                reason: "the \"new\" plan takes has_passcode and performance_mode, not a TData"
                    .to_owned(),
            }),
            ("migrate", Some(folder)) => Ok(Self::Migrate(folder)),
            ("save", Some(folder)) => Ok(Self::Save(folder)),
            ("migrate" | "save", None) => Err(Error::InvalidInput {
                what: "target",
                reason: format!("the {name:?} plan takes a TData"),
            }),
            _ => Err(Error::InvalidInput {
                what: "operation",
                reason: format!(
                    "unknown operation {name:?}; expected one of {}",
                    Self::NAMES.join(", ")
                ),
            }),
        }
    }

    /// The name [`DrawOperation::from_name`] accepts for this operation.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::New { .. } => "new",
            Self::Migrate(_) => "migrate",
            Self::Save(_) => "save",
        }
    }
}

/// The sizes, in bytes and in order, of the buffers `operation` will hand
/// its random source; a replay of recorded `os.urandom` draws needs no
/// hand-coded counts. Nothing is drawn and no file is touched.
///
/// - [`DrawOperation::New`]: none in performance mode without a passcode;
///   otherwise the 256-byte pass, the 32-byte salt, then the key data
///   install: the 32-byte open salt, a 32-byte wrap salt with a passcode,
///   and the 12-byte wrap padding.
/// - [`DrawOperation::Migrate`]: the key data install under the folder's
///   passcode when its key file has the legacy layout, else none.
/// - [`DrawOperation::Save`]: the migration draws of a legacy key file,
///   then per account the padding of its map, of its config unless
///   performance mode is on, and of its MTP data, then the padding of the
///   accounts info. A padding of zero bytes is not drawn.
///
/// # Errors
/// [`DrawOperation::Save`] fails as [`TData::save`] would before writing:
/// [`Error::SaveFailed`] for a folder without accounts or with an account
/// whose map encodes to nothing, [`Error::QDataStreamFailed`] when a blob
/// does not fit a `u32` length.
pub fn draw_plan(operation: DrawOperation<'_>) -> Result<Vec<usize>> {
    match operation {
        DrawOperation::New {
            has_passcode,
            performance_mode,
        } => {
            if performance_mode && !has_passcode {
                return Ok(Vec::new());
            }
            let mut draws = vec![AuthKey::SIZE, LOCAL_ENCRYPT_SALT_SIZE];
            draws.extend(key_data::install_draws(has_passcode));
            Ok(draws)
        }
        DrawOperation::Migrate(tdata) => Ok(tdata.migration_draws()),
        DrawOperation::Save(tdata) => {
            if tdata.accounts.is_empty() {
                return Err(Error::SaveFailed);
            }
            let mut draws = tdata.migration_draws();
            let mut padding = |len: usize| {
                let padding = crypto::local_padding_len(len);
                // `encrypt` draws nothing for a zero padding.
                if padding > 0 {
                    draws.push(padding);
                }
            };
            for account in &tdata.accounts {
                for plaintext in account.write_plaintexts(tdata.performance_mode)? {
                    padding(plaintext.len());
                }
            }
            padding(tdata.accounts_info().encode()?.len());
            Ok(draws)
        }
    }
}

impl TData {
    /// The draws [`TData::migrate`] makes, which [`TData::save`] makes first
    /// for a legacy key file.
    fn migration_draws(&self) -> Vec<usize> {
        if self.key_data.trailer.is_some() {
            Vec::new()
        } else {
            key_data::install_draws(!self.passcode.0.is_empty())
        }
    }

    /// The accounts info [`TData::save`] encrypts into the key file.
    fn accounts_info(&self) -> AccountsInfo {
        AccountsInfo {
            indices: self.accounts.iter().map(|account| account.index).collect(),
            active_index: self.active_index,
        }
    }
}
