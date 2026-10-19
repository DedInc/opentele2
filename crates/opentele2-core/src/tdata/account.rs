//! One account of a tdata folder (`Main::Account` and `Storage::Account`).
//!
//! Account `index` of a folder whose key file is `key_file` has the data name
//! [`data_name`]; its files live under [`folder_name`] of that data name, as
//! in 1.5.0 (`src/td/storage.py`, `src/td/storage_account.py`):
//!
//! - `<folder>s`: the MTP data, a `TDF$` file whose payload is one
//!   `QByteArray` encrypted under the local key. The decrypted stream is a
//!   list of `u32` dbi blocks: [`DBI_MTP_AUTHORIZATION`] and the legacy
//!   blocks 1.5.0's `Storage.ReadSetting` reads (see
//!   [`Account::parse_mtp_data`]).
//! - `<folder>/maps`: the account map (see [`crate::tdata::map`]).
//! - `<folder>/configs`: the serialized MTP config, written only when
//!   performance mode is off; kept as raw bytes and parsed by
//!   [`Account::mtp_config`].
//!
//! The `MtpAuthorization` blob (`src/td/account.py`) is the wide-ids tag
//! `i64 -1`, `i64` user id, `i32` main DC, then the keys and the keys to
//! destroy, each an `i32` count followed by `i32` DC id and 256 raw key bytes
//! per key.

use std::path::Path;

use md5::{Digest, Md5};

use crate::crypto::{self, AuthKey};
use crate::qt::{QReader, QWriter};
use crate::tdata::map::MapData;
use crate::tdata::mtp_config::{DcOptions, Environment, MtpConfig};
use crate::tdata::{FillRandom, encrypt, hex_bytes, write_tdf};
use crate::{Error, MagicContext, Result, tdf};

/// The 1.5.0 message of an `MtpAuthorization` blob cut short in its user id
/// and main DC.
const MTP_MAIN_FIELDS_FAILED: &str = "Could not read main fields from mtp authorization.";

/// The 1.5.0 message of an `MtpAuthorization` blob cut short in a key count.
const MTP_KEY_COUNT_FAILED: &str = "Could not read keys count from mtp authorization.";

/// dbi block id of the `MtpAuthorization` blob in the MTP data.
pub const DBI_MTP_AUTHORIZATION: u32 = 0x4B;

/// Legacy dbi block `dbiKey`: `i32` DC id and 256 raw key bytes.
pub const DBI_KEY: u32 = 0x00;
/// Legacy dbi block `dbiUser`: `i32` user id and `u32` main DC id.
pub const DBI_USER: u32 = 0x01;
/// Legacy dbi block `dbiDcOptionOldOld`: `u32` DC id, an unused `QString`,
/// the IP as `QString`, and a `u32` port.
pub const DBI_DC_OPTION_OLD_OLD: u32 = 0x02;
/// Legacy dbi block `dbiChatSizeMaxOld`: one `i32`.
pub const DBI_CHAT_SIZE_MAX_OLD: u32 = 0x03;
/// Legacy dbi block `dbiDcOptionOld`: `u32` shifted DC id, `i32` flags, the
/// IP as `QString`, and a `u32` port.
pub const DBI_DC_OPTION_OLD: u32 = 0x27;
/// Legacy dbi block `dbiMegagroupSizeMaxOld`: one `i32`.
pub const DBI_MEGAGROUP_SIZE_MAX_OLD: u32 = 0x32;
/// Legacy dbi block `dbiSavedGifsLimitOld`: one `i32`.
pub const DBI_SAVED_GIFS_LIMIT_OLD: u32 = 0x35;
/// Legacy dbi block `dbiStickersRecentLimitOld`: one `i32`.
pub const DBI_STICKERS_RECENT_LIMIT_OLD: u32 = 0x43;
/// Legacy dbi block `dbiDcOptionsOld`: serialized DC options as
/// `QByteArray`.
pub const DBI_DC_OPTIONS_OLD: u32 = 0x4A;
/// Legacy dbi block `dbiStickersFavedLimitOld`: one `i32`.
pub const DBI_STICKERS_FAVED_LIMIT_OLD: u32 = 0x50;
/// dbi block `dbiApplicationSettings`: a `QByteArray`.
pub const DBI_APPLICATION_SETTINGS: u32 = 0x5E;

/// The serialized default MTP config: the exact bytes of 1.5.0's
/// `td.MTP.Config(td.MTP.Environment.Production).Serialize()` (production DC
/// options and the default config fields), which
/// [`MtpConfig::new`] for [`Environment::Production`] serializes to.
/// [`crate::tdata::TData::save`] writes it into `configs` for an account
/// without loaded config bytes.
pub const MTP_CONFIG_PRODUCTION: [u8; 748] = hex_bytes(concat!(
    "0000000100000000000001fefffffffe0000000b0000000100000010000001bb",
    "0000000e3134392e3135342e3137352e35300000000000000001000000110000",
    "01bb00000027323030313a306232383a663233643a663030313a303030303a30",
    "3030303a303030303a30303061000000000000000200000010000001bb000000",
    "0e3134392e3135342e3136372e3531000000000000000200000010000001bb00",
    "00000d39352e3136312e37362e313030000000000000000200000011000001bb",
    "00000027323030313a303637633a303465383a663030323a303030303a303030",
    "303a303030303a30303061000000000000000300000010000001bb0000000f31",
    "34392e3135342e3137352e313030000000000000000300000011000001bb0000",
    "0027323030313a306232383a663233643a663030333a303030303a303030303a",
    "303030303a30303061000000000000000400000010000001bb0000000e313439",
    "2e3135342e3136372e3931000000000000000400000011000001bb0000002732",
    "3030313a303637633a303465383a663030343a303030303a303030303a303030",
    "303a30303061000000000000000500000010000001bb0000000d3134392e3135",
    "342e3137312e35000000000000000500000011000001bb00000027323030313a",
    "306232383a663233663a663030353a303030303a303030303a303030303a3030",
    "30610000000000000000000000c800002710000000640001d4c0000013880000",
    "7530000003e8000493e000007530000005dc000000c80002a3000002a3000002",
    "a300000000000000001e0000000500000005000000640000001a006800740074",
    "00700073003a002f002f0074002e006d0065002f00093a8000004e2000015f90",
    "0000753000002710000000040000001a0061007000760033002e007300740065",
    "006c002e0063006f006d00000001000000000000040000000004d83ddc4d0000",
    "0000000000000024ea0000000006006700690066000000140066006f00750072",
    "007300710075006100720065",
));

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

/// Encrypts `data` under `local_key` and writes it as the only `QByteArray`
/// of the `TDF$` file `name` in `dir` (`FileWriteDescriptor.writeEncrypted`).
fn write_encrypted(
    dir: &Path,
    name: &str,
    data: &[u8],
    local_key: &AuthKey,
    rng: &mut FillRandom<'_>,
) -> Result<()> {
    let mut payload = QWriter::new();
    payload.write_bytearray(Some(&encrypt(data, local_key, rng)?))?;
    write_tdf(dir, name, payload.into_bytes())
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
            .ok_or(Error::QDataStreamFailed { context: None })?;
        self.rest = &self.rest[AuthKey::SIZE..];
        AuthKey::from_slice(bytes)
    }

    /// The user id and main DC of an `MtpAuthorization` blob.
    ///
    /// Without the wide-ids tag the first two `i32` are the user id and the
    /// main DC; the tag test is tdesktop's
    /// `(uint64(userId) << 32) | uint64(mainDc) == kWideIdsTag`, sign
    /// extension included.
    fn main_fields(&mut self) -> Result<(u64, i32)> {
        let legacy_user = self.i32()?;
        let legacy_dc = self.i32()?;
        if (i64::from(legacy_user) << 32) | i64::from(legacy_dc) == WIDE_IDS_TAG {
            Ok((self.with(QReader::read_u64)?, self.i32()?))
        } else {
            Ok((i64::from(legacy_user).cast_unsigned(), legacy_dc))
        }
    }

    fn keys(&mut self) -> Result<Vec<(i32, AuthKey)>> {
        // A negative count reads no key, as in 1.5.0; the count is never
        // preallocated, so a forged one fails at the first short key.
        let count = self.i32().map_err(|_| Error::QDataStreamFailed {
            context: Some(MTP_KEY_COUNT_FAILED),
        })?;
        let mut keys = Vec::new();
        for _ in 0..count {
            let dc = self.i32()?;
            keys.push((dc, self.key()?));
        }
        Ok(keys)
    }
}

/// What 1.5.0 keeps from the dbi blocks of the MTP data
/// (`Storage.ReadSettingsContext`); the legacy DC options and limits are
/// read and dropped, as `_applyReadContext` never uses them.
#[derive(Default)]
struct MtpData<'a> {
    /// The last `MtpAuthorization` blob; empty for none.
    authorization: &'a [u8],
    /// `mtpLegacyUserId`.
    legacy_user_id: i32,
    /// `mtpLegacyMainDcId`.
    legacy_main_dc: u32,
    /// `mtpLegacyKeys`, in block order.
    legacy_keys: Vec<(i32, AuthKey)>,
}

impl<'a> MtpData<'a> {
    /// Reads every dbi block (`_readMtpData` with `Storage.ReadSetting`).
    fn parse(data: &'a [u8]) -> Result<Self> {
        let mut reader = RawReader { rest: data };
        let mut out = Self::default();
        while !reader.rest.is_empty() {
            let block_id =
                reader
                    .with(QReader::read_u32)
                    .map_err(|_| Error::QDataStreamFailed {
                        context: Some("Could not read a block id from MtpData"),
                    })?;
            match block_id {
                DBI_MTP_AUTHORIZATION => {
                    out.authorization = reader.with(QReader::read_bytearray)?.unwrap_or_default();
                }
                DBI_KEY => {
                    let dc = reader.i32()?;
                    out.legacy_keys.push((dc, reader.key()?));
                }
                DBI_USER => {
                    out.legacy_user_id = reader.i32()?;
                    out.legacy_main_dc = reader.with(QReader::read_u32)?;
                }
                DBI_DC_OPTION_OLD_OLD => {
                    reader.with(|r| {
                        r.read_u32()?;
                        r.read_qstring()?;
                        r.read_qstring()?;
                        r.read_u32()
                    })?;
                }
                DBI_DC_OPTION_OLD => {
                    reader.with(|r| {
                        r.read_u32()?;
                        r.read_i32()?;
                        r.read_qstring()?;
                        r.read_u32()
                    })?;
                }
                DBI_DC_OPTIONS_OLD => {
                    // 1.5.0 parses the blob into a throwaway DcOptions, so a
                    // malformed one fails the read.
                    let blob = reader.with(QReader::read_bytearray)?.unwrap_or_default();
                    DcOptions::parse(blob)?;
                }
                DBI_APPLICATION_SETTINGS => {
                    reader.with(QReader::read_bytearray)?;
                }
                DBI_CHAT_SIZE_MAX_OLD
                | DBI_SAVED_GIFS_LIMIT_OLD
                | DBI_STICKERS_RECENT_LIMIT_OLD
                | DBI_STICKERS_FAVED_LIMIT_OLD
                | DBI_MEGAGROUP_SIZE_MAX_OLD => {
                    reader.i32()?;
                }
                _ => {
                    return Err(Error::InvalidMagic {
                        context: MagicContext::MtpDataBlock { block_id },
                    });
                }
            }
        }
        Ok(out)
    }
}

fn write_keys(out: &mut Vec<u8>, keys: &[(i32, AuthKey)]) -> Result<()> {
    let count =
        i32::try_from(keys.len()).map_err(|_| Error::QDataStreamFailed { context: None })?;
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
    /// A new account the way 1.5.0 builds one before saving
    /// (`Account(owner, index)` then `_setMtpAuthorizationCustom`): the given
    /// keys, no keys to destroy, the map of [`MapData::new_account`], and no
    /// config.
    ///
    /// # Errors
    /// [`Error::AuthKeyNotFound`] when no key belongs to `main_dc`.
    pub fn new(index: i32, user_id: u64, main_dc: i32, keys: Vec<(i32, AuthKey)>) -> Result<Self> {
        let account = Self {
            index,
            user_id,
            main_dc,
            keys,
            keys_to_destroy: Vec::new(),
            map: MapData::new_account(),
            config: None,
        };
        if account.auth_key().is_none() {
            return Err(Error::AuthKeyNotFound);
        }
        Ok(account)
    }

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
        let (user_id, main_dc) = reader.main_fields().map_err(|_| Error::QDataStreamFailed {
            context: Some(MTP_MAIN_FIELDS_FAILED),
        })?;
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

    /// Encodes the decrypted MTP data (`_writeMtpData`): the `u32` block id
    /// [`DBI_MTP_AUTHORIZATION`] followed by
    /// [`Account::encode_mtp_authorization`] as a `QByteArray`.
    ///
    /// # Errors
    /// [`Error::QDataStreamFailed`] as [`Account::encode_mtp_authorization`].
    pub fn encode_mtp_data(&self) -> Result<Vec<u8>> {
        let mut writer = QWriter::new();
        writer.write_u32(DBI_MTP_AUTHORIZATION);
        writer.write_bytearray(Some(&self.encode_mtp_authorization()?))?;
        Ok(writer.into_bytes())
    }

    /// Writes the account files under `dir` (`Account._writeData`): the map,
    /// then the config unless `performance_mode` is on, then the MTP data.
    pub(crate) fn write(
        &self,
        dir: &Path,
        key_file: &str,
        local_key: &AuthKey,
        performance_mode: bool,
        rng: &mut FillRandom<'_>,
    ) -> Result<()> {
        let part = folder_name(&data_name(key_file, self.index));
        let folder = dir.join(&part);
        self.map.write(&folder, local_key, rng)?;
        if !performance_mode {
            write_encrypted(&folder, CONFIG_FILE, &self.config_data()?, local_key, rng)?;
        }
        write_encrypted(dir, &part, &self.encode_mtp_data()?, local_key, rng)
    }

    /// The plaintexts [`Account::write`] encrypts, in its order: the map,
    /// the config unless `performance_mode` is on, and the MTP data.
    pub(crate) fn write_plaintexts(&self, performance_mode: bool) -> Result<Vec<Vec<u8>>> {
        let mut out = vec![self.map.plaintext()?];
        if !performance_mode {
            out.push(self.config_data()?);
        }
        out.push(self.encode_mtp_data()?);
        Ok(out)
    }

    /// The `configs` plaintext: the loaded config, or
    /// [`MTP_CONFIG_PRODUCTION`], as one `QByteArray`.
    fn config_data(&self) -> Result<Vec<u8>> {
        let config = self.config.as_deref().unwrap_or(&MTP_CONFIG_PRODUCTION);
        let mut data = QWriter::new();
        data.write_bytearray(Some(config))?;
        Ok(data.into_bytes())
    }

    /// The first key of the main DC (`_findMainAuthKey`).
    #[must_use]
    pub fn auth_key(&self) -> Option<&AuthKey> {
        self.keys
            .iter()
            .find(|(dc, _)| *dc == self.main_dc)
            .map(|(_, key)| key)
    }

    /// Decodes the decrypted MTP data (`_readMtpData` and
    /// `_applyReadContext`) for account `index`, with an empty map and no
    /// config.
    ///
    /// Besides [`DBI_MTP_AUTHORIZATION`] the stream may hold the legacy
    /// blocks 1.5.0 reads: [`DBI_KEY`] and [`DBI_USER`], whose keys, user id
    /// and main DC make the account when no `MtpAuthorization` blob is
    /// present (the last blob wins; an empty or null one counts as none),
    /// and [`DBI_DC_OPTION_OLD_OLD`], [`DBI_DC_OPTION_OLD`],
    /// [`DBI_DC_OPTIONS_OLD`], [`DBI_APPLICATION_SETTINGS`] and the five
    /// legacy limits, which are read and have no effect on the account. A
    /// legacy user id is read as `i32` and sign-extended, as in
    /// [`Account::parse_mtp_authorization`].
    ///
    /// # Errors
    /// - [`Error::QDataStreamFailed`] when a block is cut short.
    /// - [`Error::InvalidMagic`] for any other block id, the error 1.5.0
    ///   names for an unsupported block.
    /// - As [`DcOptions::parse`] for a [`DBI_DC_OPTIONS_OLD`] blob.
    /// - As [`Account::parse_mtp_authorization`] for the blob.
    /// - [`Error::AuthKeyNotFound`] when there is neither a blob nor a legacy
    ///   key or main DC, or no legacy key belongs to the legacy main DC.
    pub fn parse_mtp_data(index: i32, data: &[u8]) -> Result<Self> {
        let mtp = MtpData::parse(data)?;
        if !mtp.authorization.is_empty() {
            return Self::parse_mtp_authorization(index, mtp.authorization);
        }
        if mtp.legacy_keys.is_empty() && mtp.legacy_main_dc == 0 {
            return Err(Error::AuthKeyNotFound);
        }
        let account = Self {
            index,
            user_id: i64::from(mtp.legacy_user_id).cast_unsigned(),
            main_dc: mtp.legacy_main_dc.cast_signed(),
            keys: mtp.legacy_keys,
            keys_to_destroy: Vec::new(),
            map: MapData::default(),
            config: None,
        };
        if account.auth_key().is_none() {
            return Err(Error::AuthKeyNotFound);
        }
        Ok(account)
    }

    /// Reads and decrypts the MTP data of the account whose data name is
    /// `data_name` from its `<folder>s` file in `dir`.
    fn read_mtp_data(dir: &Path, data_name: &str, local_key: &AuthKey) -> Result<Vec<u8>> {
        read_encrypted(dir, &folder_name(data_name), local_key)
    }

    /// Reads the `MtpAuthorization` blob of the account whose data name is
    /// `data_name` from the MTP data file in `dir`. The blocks are read as
    /// in [`Account::parse_mtp_data`]; the last blob wins, and an empty or
    /// null one counts as none.
    ///
    /// # Errors
    /// - As [`tdf::read`] for the `<folder>s` file.
    /// - As [`crypto::decrypt_local`] when the data does not decrypt.
    /// - As [`Account::parse_mtp_data`] for a block that cannot be read.
    /// - [`Error::AuthKeyNotFound`] when no blob is present, even when
    ///   legacy key blocks are.
    pub fn read_mtp_authorization(
        dir: impl AsRef<Path>,
        data_name: &str,
        local_key: &AuthKey,
    ) -> Result<Vec<u8>> {
        let data = Self::read_mtp_data(dir.as_ref(), data_name, local_key)?;
        let mtp = MtpData::parse(&data)?;
        if mtp.authorization.is_empty() {
            return Err(Error::AuthKeyNotFound);
        }
        Ok(mtp.authorization.to_vec())
    }

    /// The account's MTP config: [`Account::config`] parsed with
    /// [`MtpConfig::parse`], or the production default
    /// ([`MtpConfig::new`]) when there is none or it does not parse, as
    /// 1.5.0's `_readMtpConfig` falls back to it.
    ///
    /// 1.5.0 catches only its own exceptions there, so a config whose IP is
    /// not ASCII or whose environment is unknown fails its whole load; here
    /// it falls back like any other bad config.
    #[must_use]
    pub fn mtp_config(&self) -> MtpConfig {
        self.config
            .as_deref()
            .and_then(|serialized| MtpConfig::parse(serialized).ok())
            .unwrap_or_else(|| MtpConfig::new(Environment::Production))
    }

    /// Loads account `index` of the folder `dir` whose key file is
    /// `key_file` (`prepareToStart`): the map, then the MTP data, then the
    /// optional config.
    ///
    /// # Errors
    /// - As [`MapData::read`] for the `<folder>/maps` file.
    /// - As [`tdf::read`] and [`crypto::decrypt_local`] for the `<folder>s`
    ///   file, and as [`Account::parse_mtp_data`] for its contents.
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
        let data = Self::read_mtp_data(dir, &name, local_key)?;
        let mut account = Self::parse_mtp_data(index, &data)?;
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
