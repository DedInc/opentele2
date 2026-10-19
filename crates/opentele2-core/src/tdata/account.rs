//! One account of a tdata folder (`Main::Account` and `Storage::Account`).
//!
//! Account `index` of a folder whose key file is `key_file` has the data name
//! [`data_name`]; its files live under [`folder_name`] of that data name, as
//! in 1.5.0 (`src/td/storage.py`, `src/td/storage_account.py`):
//!
//! - `<folder>s`: the MTP data, a `TDF$` file whose payload is one
//!   `QByteArray` encrypted under the local key. The decrypted stream is a
//!   list of `u32` dbi blocks; only [`DBI_MTP_AUTHORIZATION`] is handled.
//! - `<folder>/maps`: the account map (see [`crate::tdata::map`]).
//! - `<folder>/configs`: the serialized MTP config, written only when
//!   performance mode is off; kept as raw bytes.
//!
//! The `MtpAuthorization` blob (`src/td/account.py`) is the wide-ids tag
//! `i64 -1`, `i64` user id, `i32` main DC, then the keys and the keys to
//! destroy, each an `i32` count followed by `i32` DC id and 256 raw key bytes
//! per key.

use std::path::Path;

use md5::{Digest, Md5};

use crate::crypto::{self, AuthKey};
use crate::qt::QReader;
use crate::tdata::map::MapData;
use crate::{Error, Result, tdf};

/// dbi block id of the `MtpAuthorization` blob in the MTP data.
pub const DBI_MTP_AUTHORIZATION: u32 = 0x4B;

/// Tag that marks the wide-ids layout of `MtpAuthorization` (`kWideIdsTag`).
pub const WIDE_IDS_TAG: i64 = -1;

/// Name of the MTP config file inside an account folder; on disk `configs`.
pub const CONFIG_FILE: &str = "config";

/// The data name of account `index` (`ComposeDataString`): `key_file`
/// without `#`, plus `#<index + 1>` when `index` is positive.
#[must_use]
pub fn data_name(key_file: &str, index: i32) -> String {
    let name = key_file.replace('#', "");
    if index > 0 {
        format!("{name}#{}", i64::from(index) + 1)
    } else {
        name
    }
}

/// The key of a data name (`ComputeDataNameKey`): the low 64 bits of
/// `md5(data_name)` read as little-endian, which is all [`file_part`] uses.
#[must_use]
pub fn data_name_key(data_name: &str) -> u64 {
    let digest = Md5::digest(data_name.as_bytes());
    let mut low = [0; 8];
    low.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(low)
}

/// The file part of `key` (`ToFilePart`): 16 uppercase hex nibbles, low
/// nibble first.
#[must_use]
pub fn file_part(key: u64) -> String {
    (0..16)
        .map(|i| {
            let nibble = u32::try_from((key >> (4 * i)) & 0xF).unwrap_or_default();
            char::from_digit(nibble, 16)
                .unwrap_or('0')
                .to_ascii_uppercase()
        })
        .collect()
}

/// The folder name of a data name, for example `D877F783D5D3EF8C` for
/// `data`; the MTP data file is this name plus a `TDF$` suffix.
#[must_use]
pub fn folder_name(data_name: &str) -> String {
    file_part(data_name_key(data_name))
}

/// Reads the first `QByteArray` of the `TDF$` file `name` in `dir` and
/// decrypts it under `local_key` (`ReadEncryptedFile`).
///
/// As in 1.5.0 a blob that cannot be read is treated as empty, which fails
/// decryption with [`Error::BadEncryptedDataSize`].
fn read_encrypted(dir: &Path, name: &str, local_key: &AuthKey) -> Result<Vec<u8>> {
    let file = tdf::read(dir, name)?;
    let encrypted = QReader::new(&file.payload)
        .read_bytearray()
        .ok()
        .flatten()
        .unwrap_or_default();
    crypto::decrypt_local(encrypted, local_key)
}

/// A reader that also hands out raw bytes, which [`QReader`] does not.
struct RawReader<'a> {
    rest: &'a [u8],
}

impl<'a> RawReader<'a> {
    fn with<T>(&mut self, read: impl FnOnce(&mut QReader<'a>) -> Result<T>) -> Result<T> {
        let mut reader = QReader::new(self.rest);
        let value = read(&mut reader)?;
        let used = self.rest.len() - reader.remaining();
        self.rest = &self.rest[used..];
        Ok(value)
    }

    fn i32(&mut self) -> Result<i32> {
        self.with(QReader::read_i32)
    }

    fn key(&mut self) -> Result<AuthKey> {
        let bytes = self
            .rest
            .get(..AuthKey::SIZE)
            .ok_or(Error::QDataStreamFailed)?;
        self.rest = &self.rest[AuthKey::SIZE..];
        AuthKey::from_slice(bytes)
    }

    fn keys(&mut self) -> Result<Vec<(i32, AuthKey)>> {
        // A negative count reads no key, as in 1.5.0; the count is never
        // preallocated, so a forged one fails at the first short key.
        let count = self.i32()?;
        let mut keys = Vec::new();
        for _ in 0..count {
            let dc = self.i32()?;
            keys.push((dc, self.key()?));
        }
        Ok(keys)
    }
}

fn write_keys(out: &mut Vec<u8>, keys: &[(i32, AuthKey)]) -> Result<()> {
    let count = i32::try_from(keys.len()).map_err(|_| Error::QDataStreamFailed)?;
    out.extend_from_slice(&count.to_be_bytes());
    for (dc, key) in keys {
        out.extend_from_slice(&dc.to_be_bytes());
        out.extend_from_slice(key.as_bytes());
    }
    Ok(())
}

/// One loaded account.
///
/// `Debug` prints key ids only, never key material.
#[derive(Debug, Clone)]
pub struct Account {
    /// Index of the account in the accounts info.
    pub index: i32,
    /// Telegram user id.
    pub user_id: u64,
    /// Main DC id; [`Account::auth_key`] is the key of this DC.
    pub main_dc: i32,
    /// Authorization keys as (DC id, key), in file order.
    pub keys: Vec<(i32, AuthKey)>,
    /// Keys queued for destruction as (DC id, key), in file order.
    pub keys_to_destroy: Vec<(i32, AuthKey)>,
    /// The account map; empty for an account parsed from a blob alone.
    pub map: MapData,
    /// The serialized MTP config from `configs`; `None` when the file is
    /// missing or unreadable, as with performance mode on.
    pub config: Option<Vec<u8>>,
}

impl Account {
    /// Decodes an `MtpAuthorization` blob (`_setMtpAuthorization`) for
    /// account `index`, with an empty map and no config.
    ///
    /// Without the wide-ids tag the first two `i32` are the user id and the
    /// main DC; the tag test is tdesktop's
    /// `(uint64(userId) << 32) | uint64(mainDc) == kWideIdsTag`, sign
    /// extension included. Bytes after the keys to destroy are ignored.
    ///
    /// # Errors
    /// - [`Error::QDataStreamFailed`] when the blob is cut short.
    /// - [`Error::AuthKeyNotFound`] when no key belongs to the main DC.
    pub fn parse_mtp_authorization(index: i32, serialized: &[u8]) -> Result<Self> {
        let mut reader = RawReader { rest: serialized };
        let legacy_user = reader.i32()?;
        let legacy_dc = reader.i32()?;
        let (user_id, main_dc) =
            if (i64::from(legacy_user) << 32) | i64::from(legacy_dc) == WIDE_IDS_TAG {
                (reader.with(QReader::read_u64)?, reader.i32()?)
            } else {
                (i64::from(legacy_user).cast_unsigned(), legacy_dc)
            };
        let keys = reader.keys()?;
        let keys_to_destroy = reader.keys()?;
        let account = Self {
            index,
            user_id,
            main_dc,
            keys,
            keys_to_destroy,
            map: MapData::default(),
            config: None,
        };
        if account.auth_key().is_none() {
            return Err(Error::AuthKeyNotFound);
        }
        Ok(account)
    }

    /// Encodes the `MtpAuthorization` blob (`serializeMtpAuthorization`),
    /// always in the wide-ids layout.
    ///
    /// # Errors
    /// [`Error::QDataStreamFailed`] when a key list does not fit an `i32`
    /// count.
    pub fn encode_mtp_authorization(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&WIDE_IDS_TAG.to_be_bytes());
        out.extend_from_slice(&self.user_id.to_be_bytes());
        out.extend_from_slice(&self.main_dc.to_be_bytes());
        write_keys(&mut out, &self.keys)?;
        write_keys(&mut out, &self.keys_to_destroy)?;
        Ok(out)
    }

    /// The first key of the main DC (`_findMainAuthKey`).
    #[must_use]
    pub fn auth_key(&self) -> Option<&AuthKey> {
        self.keys
            .iter()
            .find(|(dc, _)| *dc == self.main_dc)
            .map(|(_, key)| key)
    }

    /// Reads the `MtpAuthorization` blob of the account whose data name is
    /// `data_name` from the MTP data file in `dir` (`_readMtpData`). The last
    /// block wins; an empty or null blob counts as none.
    ///
    /// # Errors
    /// - As [`tdf::read`] for the `<folder>s` file.
    /// - As [`crypto::decrypt_local`] when the data does not decrypt.
    /// - [`Error::QDataStreamFailed`] when a block is cut short.
    /// - [`Error::InvalidMagic`] for a block id other than
    ///   [`DBI_MTP_AUTHORIZATION`], the error 1.5.0 names for an unsupported
    ///   block.
    /// - [`Error::AuthKeyNotFound`] when no blob is present.
    pub fn read_mtp_authorization(
        dir: impl AsRef<Path>,
        data_name: &str,
        local_key: &AuthKey,
    ) -> Result<Vec<u8>> {
        let data = read_encrypted(dir.as_ref(), &folder_name(data_name), local_key)?;
        let mut reader = QReader::new(&data);
        let mut serialized: &[u8] = &[];
        while !reader.is_empty() {
            if reader.read_u32()? != DBI_MTP_AUTHORIZATION {
                return Err(Error::InvalidMagic);
            }
            serialized = reader.read_bytearray()?.unwrap_or_default();
        }
        if serialized.is_empty() {
            return Err(Error::AuthKeyNotFound);
        }
        Ok(serialized.to_vec())
    }

    /// Loads account `index` of the folder `dir` whose key file is
    /// `key_file` (`prepareToStart`): the map, then the MTP data, then the
    /// optional config.
    ///
    /// # Errors
    /// - As [`MapData::read`] for the `<folder>/maps` file.
    /// - As [`Account::read_mtp_authorization`] and
    ///   [`Account::parse_mtp_authorization`].
    ///
    /// A config that cannot be read is `None`, never an error.
    pub fn read(
        dir: impl AsRef<Path>,
        key_file: &str,
        index: i32,
        local_key: &AuthKey,
    ) -> Result<Self> {
        let dir = dir.as_ref();
        let name = data_name(key_file, index);
        let folder = dir.join(folder_name(&name));
        let map = MapData::read(&folder, local_key)?;
        let serialized = Self::read_mtp_authorization(dir, &name, local_key)?;
        let mut account = Self::parse_mtp_authorization(index, &serialized)?;
        account.map = map;
        account.config = read_encrypted(&folder, CONFIG_FILE, local_key)
            .ok()
            .and_then(|data| {
                QReader::new(&data)
                    .read_bytearray()
                    .ok()
                    .flatten()
                    .filter(|blob| !blob.is_empty())
                    .map(<[u8]>::to_vec)
            });
        Ok(account)
    }
}
