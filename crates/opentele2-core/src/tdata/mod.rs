//! Telegram Desktop `tdata` folder formats, built on the [`crate::tdf`]
//! container, the [`crate::qt`] stream encoding, and the [`crate::crypto`]
//! and [`crate::kdf`] primitives.
//!
//! - [`key_data`]: the `key_<dataName>` file that holds the local key and the
//!   list of accounts.
//! - [`account`]: the per-account files and the `MtpAuthorization` blob.
//! - [`map`]: the per-account `maps` file.
//! - [`TData`]: a whole folder, loaded the way 1.5.0's `TDesktop` does.

pub mod account;
pub mod key_data;
pub mod map;

use std::collections::HashSet;
use std::path::Path;

use crate::crypto::AuthKey;
use crate::tdata::account::Account;
use crate::tdata::key_data::{DEFAULT_KEY_FILE, KeyData, KeyDataTrailer};
use crate::{Error, Result, tdf};

/// A loaded tdata folder.
///
/// `Debug` prints key ids only, never key material.
#[derive(Debug, Clone)]
pub struct TData {
    /// Telegram Desktop version stored in the key file's `TDF$` header.
    pub app_version: u32,
    /// The data name of the key file, for example [`DEFAULT_KEY_FILE`].
    pub key_file: String,
    /// The parsed key file; as in 1.5.0 only the live passcode wraps are
    /// kept, so stale wraps are not written back.
    pub key_data: KeyData,
    /// The local key every other file is encrypted with.
    pub local_key: AuthKey,
    /// The open or passcode key the local key was wrapped under.
    pub passcode_key: AuthKey,
    /// The accounts that loaded, in accounts-info order without duplicates.
    pub accounts: Vec<Account>,
    /// The active index stored in the accounts info, 0 when absent.
    pub active_index: i32,
}

impl TData {
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
