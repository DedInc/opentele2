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
//!   does.

pub mod account;
pub mod key_data;
pub mod map;
pub mod mtp_config;

use std::collections::HashSet;
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

/// A tdata folder, loaded from disk or created for writing.
///
/// `Debug` prints key ids only, never key material.
#[derive(Debug, Clone)]
pub struct TData {
    /// Telegram Desktop version stored in the key file's `TDF$` header;
    /// [`TData::save`] always writes [`APP_VERSION`], as 1.5.0 does.
    pub app_version: u32,
    /// The data name of the key file, for example [`DEFAULT_KEY_FILE`].
    pub key_file: String,
    /// The parsed key file; as in 1.5.0 only the live passcode wraps are
    /// kept, so stale wraps are not written back. [`TData::save`] writes it
    /// with a freshly encrypted accounts info.
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
}

impl TData {
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
    /// # Errors
    /// - [`Error::SaveFailed`] when there is no account, when an account map
    ///   encodes to nothing (1.5.0 cannot encrypt it either), or when the key
    ///   file has the legacy layout: 1.5.0 migrates it with the passcode,
    ///   which a loaded [`TData`] does not keep.
    /// - [`Error::Io`] when a directory or file cannot be written.
    /// - [`Error::QDataStreamFailed`] when a blob does not fit a `u32` length.
    pub fn save(&self, dir: impl AsRef<Path>, rng: &mut dyn FnMut(&mut [u8])) -> Result<()> {
        self.save_with(dir.as_ref(), &mut |buf| {
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
        self.save_with(dir.as_ref(), &mut |buf| {
            getrandom::fill(buf).map_err(|e| Error::Io(std::io::Error::other(e)))
        })
    }

    fn save_with(&self, dir: &Path, rng: &mut FillRandom<'_>) -> Result<()> {
        if self.accounts.is_empty() || self.key_data.trailer.is_none() {
            return Err(Error::SaveFailed);
        }
        for account in &self.accounts {
            account.write(
                dir,
                &self.key_file,
                &self.local_key,
                self.performance_mode,
                rng,
            )?;
        }
        let info = AccountsInfo {
            indices: self.accounts.iter().map(|account| account.index).collect(),
            active_index: self.active_index,
        };
        let key_data = KeyData {
            info_encrypted: encrypt(&info.encode()?, &self.local_key, rng)?,
            ..self.key_data.clone()
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
            accounts,
            active_index: info.active_index,
            performance_mode: true,
        })
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
