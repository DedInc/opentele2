//! The `key_<dataName>` file of Telegram Desktop 7.3 (`Storage::Domain`).
//!
//! The file is a `TDF$` container (see [`crate::tdf`]) whose payload is a
//! `QDataStream` of `QByteArray` blobs:
//!
//! 1. the open salt, [`LOCAL_ENCRYPT_SALT_SIZE`] bytes;
//! 2. the local key wrapped under `create_local_key("", salt)` (or, before
//!    7.3, under the passcode), null when the app lock is on;
//! 3. the accounts info encrypted under the local key (see [`AccountsInfo`]);
//! 4. since 7.3, an optional trailer holding the passcode wraps
//!    ([`KeyDataTrailer`]). Files without it are the legacy three-blob layout.
//!
//! The trailer is itself a `QDataStream`: magic [`KEY_DATA_MAGIC`], format
//! version, committed generation, wrap count, then per wrap the KDF kind,
//! generation, memory, time, and parallelism as `u32`, followed by the wrap
//! salt and the wrapped local key as `QByteArray`s.

use crate::crypto::{self, AuthKey};
use crate::kdf;
use crate::qt::{QReader, QWriter};
use crate::tdata::{FillRandom, random_bytes};
use crate::{Error, KeyDataFailure, Result};

/// Default `dataName` of a tdata folder; the key file is `key_data`.
pub const DEFAULT_KEY_FILE: &str = "data";

/// Magic number that starts the 7.3 trailer.
pub const KEY_DATA_MAGIC: u32 = 0x4B44_3200;
/// Trailer format version this crate writes and fully understands.
pub const KEY_DATA_FORMAT_VERSION: u32 = 2;
/// Highest wrap count accepted for a format up to [`KEY_DATA_FORMAT_VERSION`].
pub const MAX_WRAP_COUNT: u32 = 2;
/// Sanity bound on the wrap count of a newer trailer format, whose known
/// prefix is still read.
pub const MAX_NEWER_FORMAT_WRAP_COUNT: u32 = 16;
/// Size of the open salt, in bytes.
pub const LOCAL_ENCRYPT_SALT_SIZE: usize = 32;

/// KDF kind of the PBKDF2 local key; never valid inside a passcode wrap.
pub const KDF_PBKDF2: u32 = 0;
/// KDF kind of an Argon2id passcode wrap.
pub const KDF_ARGON2ID: u32 = 1;
/// KDF kind of a scrypt passcode wrap.
pub const KDF_SCRYPT: u32 = 2;

/// Argon2id memory cost [`default_passcode_kdf`] writes, in KiB.
pub const ARGON2_MEMORY_KIB: u32 = 65_536;
/// Argon2id time cost [`default_passcode_kdf`] writes.
pub const ARGON2_TIME: u32 = 8;
/// Argon2id lane count [`default_passcode_kdf`] writes.
pub const ARGON2_LANES: u32 = 1;
/// Generation [`default_passcode_kdf`] gives a fresh wrap.
pub const DEFAULT_WRAP_GENERATION: u32 = 1;

/// The name of the key file for `key_file`, for example `key_data`.
#[must_use]
pub fn file_name(key_file: &str) -> String {
    format!("key_{key_file}")
}

/// Parameters of one passcode wrap.
///
/// For Argon2id `memory` is the memory cost in KiB, `time` the pass count,
/// and `parallelism` the lane count; for scrypt they are `N`, `r`, and `p`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasscodeKdf {
    /// KDF family: [`KDF_ARGON2ID`] or [`KDF_SCRYPT`].
    pub kind: u32,
    /// Generation of the wrap; only wraps of the committed generation are live.
    pub generation: u32,
    /// Argon2id memory in KiB, or scrypt `N`.
    pub memory: u32,
    /// Argon2id passes, or scrypt `r`.
    pub time: u32,
    /// Argon2id lanes, or scrypt `p`.
    pub parallelism: u32,
}

impl PasscodeKdf {
    /// Whether the parameters describe a derivation the KDF accepts.
    #[must_use]
    pub fn valid(&self) -> bool {
        if self.time == 0 || self.parallelism == 0 {
            return false;
        }
        match self.kind {
            KDF_ARGON2ID => u64::from(self.memory) >= 8 * u64::from(self.parallelism),
            KDF_SCRYPT => self.memory >= 2 && self.memory.is_power_of_two(),
            _ => false,
        }
    }

    /// Whether the cost is inside the read caps of [`crate::kdf`]; other
    /// kinds have no cost and are always within limits.
    #[must_use]
    pub fn cost_within_limits(&self) -> bool {
        match self.kind {
            KDF_ARGON2ID => {
                self.memory <= kdf::ARGON2_MAX_MEMORY_KIB
                    && self.time <= kdf::ARGON2_MAX_TIME
                    && self.parallelism <= kdf::ARGON2_MAX_LANES
            }
            // Stricter than tdesktop, which bounds scrypt only by memory.
            KDF_SCRYPT => {
                self.time <= kdf::SCRYPT_MAX_R
                    && self.parallelism <= kdf::SCRYPT_MAX_P
                    && self.memory <= kdf::SCRYPT_MAX_N
            }
            _ => true,
        }
    }
}

/// The KDF Telegram Desktop picks for a new passcode wrap: Argon2id with
/// [`ARGON2_MEMORY_KIB`], [`ARGON2_TIME`], [`ARGON2_LANES`], generation
/// [`DEFAULT_WRAP_GENERATION`].
#[must_use]
pub fn default_passcode_kdf() -> PasscodeKdf {
    PasscodeKdf {
        kind: KDF_ARGON2ID,
        generation: DEFAULT_WRAP_GENERATION,
        memory: ARGON2_MEMORY_KIB,
        time: ARGON2_TIME,
        parallelism: ARGON2_LANES,
    }
}

/// One passcode wrap of the local key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasscodeWrap {
    /// KDF parameters and generation.
    pub kdf: PasscodeKdf,
    /// Salt of the passcode derivation, at least
    /// [`kdf::PASSCODE_SALT_MIN_SIZE`] bytes.
    pub salt: Vec<u8>,
    /// The local key encrypted under the passcode key.
    pub key_encrypted: Vec<u8>,
}

/// The 7.3 trailer: the committed generation and the passcode wraps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDataTrailer {
    /// Generation whose wraps are live; others are crash leftovers.
    pub committed: u32,
    /// Every wrap in file order, live or not.
    pub wraps: Vec<PasscodeWrap>,
}

impl KeyDataTrailer {
    /// Decodes the trailer blob (`ReadKeyData`).
    ///
    /// A newer format is read by its known prefix with up to
    /// [`MAX_NEWER_FORMAT_WRAP_COUNT`] wraps. A wrap whose cost is above the
    /// read caps is kept; [`open_local_key`] refuses it later.
    ///
    /// # Errors
    /// - [`Error::QDataStreamFailed`] when the blob is cut short.
    /// - [`Error::KeyDataInvalid`] for a bad magic, a wrap count above the
    ///   format limit, an invalid KDF (kind 0 included), a wrap salt shorter
    ///   than [`kdf::PASSCODE_SALT_MIN_SIZE`], or a duplicate generation.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let mut reader = QReader::new(blob);
        let [magic, format, committed, count] = streamed(
            (|| {
                Ok([
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                    reader.read_u32()?,
                ])
            })(),
            TRAILER_HEADER_STREAM_FAILED,
        )?;
        if magic != KEY_DATA_MAGIC {
            return Err(invalid(KeyDataFailure::BadTrailerMagic));
        }
        let limit = if format > KEY_DATA_FORMAT_VERSION {
            MAX_NEWER_FORMAT_WRAP_COUNT
        } else {
            MAX_WRAP_COUNT
        };
        if count > limit {
            return Err(invalid(KeyDataFailure::BadWrapCount { count }));
        }

        let mut wraps: Vec<PasscodeWrap> = Vec::new();
        for _ in 0..count {
            let (kdf, salt, key_encrypted) = streamed(
                (|| {
                    let kdf = PasscodeKdf {
                        kind: reader.read_u32()?,
                        generation: reader.read_u32()?,
                        memory: reader.read_u32()?,
                        time: reader.read_u32()?,
                        parallelism: reader.read_u32()?,
                    };
                    let salt = reader.read_bytearray()?.unwrap_or_default().to_vec();
                    let key_encrypted = reader.read_bytearray()?.unwrap_or_default().to_vec();
                    Ok((kdf, salt, key_encrypted))
                })(),
                WRAP_STREAM_FAILED,
            )?;
            // An over-cost wrap only makes the passcode unusable; a malformed
            // one fails the whole file.
            if kdf.cost_within_limits() && !kdf.valid() {
                return Err(invalid(KeyDataFailure::BadKdfFamily { kind: kdf.kind }));
            }
            if salt.len() < kdf::PASSCODE_SALT_MIN_SIZE {
                return Err(invalid(KeyDataFailure::BadWrapSaltSize {
                    size: salt.len(),
                }));
            }
            if wraps.iter().any(|w| w.kdf.generation == kdf.generation) {
                return Err(invalid(KeyDataFailure::DuplicateWrapGeneration {
                    generation: kdf.generation,
                }));
            }
            wraps.push(PasscodeWrap {
                kdf,
                salt,
                key_encrypted,
            });
        }
        Ok(Self { committed, wraps })
    }

    /// Encodes the trailer blob in format [`KEY_DATA_FORMAT_VERSION`]
    /// (`WriteKeyData`).
    ///
    /// # Errors
    /// [`Error::QDataStreamFailed`] when a count or blob does not fit a `u32`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let count = u32::try_from(self.wraps.len())
            .map_err(|_| Error::QDataStreamFailed { context: None })?;
        let mut writer = QWriter::new();
        writer.write_u32(KEY_DATA_MAGIC);
        writer.write_u32(KEY_DATA_FORMAT_VERSION);
        writer.write_u32(self.committed);
        writer.write_u32(count);
        for wrap in &self.wraps {
            writer.write_u32(wrap.kdf.kind);
            writer.write_u32(wrap.kdf.generation);
            writer.write_u32(wrap.kdf.memory);
            writer.write_u32(wrap.kdf.time);
            writer.write_u32(wrap.kdf.parallelism);
            writer.write_bytearray(Some(&wrap.salt))?;
            writer.write_bytearray(Some(&wrap.key_encrypted))?;
        }
        Ok(writer.into_bytes())
    }

    /// Wraps of the committed generation.
    pub fn live_wraps(&self) -> impl Iterator<Item = &PasscodeWrap> {
        self.wraps
            .iter()
            .filter(move |w| w.kdf.generation == self.committed)
    }
}

/// The decoded payload of a key file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyData {
    /// The open salt, [`LOCAL_ENCRYPT_SALT_SIZE`] bytes.
    pub salt: Vec<u8>,
    /// The open wrap of the local key; `None` when stored as a null array,
    /// which 7.3 writes while the app lock is on.
    pub key_encrypted: Option<Vec<u8>>,
    /// The accounts info encrypted under the local key.
    pub info_encrypted: Vec<u8>,
    /// The 7.3 trailer; `None` for the legacy three-blob layout.
    pub trailer: Option<KeyDataTrailer>,
}

impl KeyData {
    /// Decodes a key file payload (the bytes inside its `TDF$` container).
    ///
    /// # Errors
    /// - [`Error::QDataStreamFailed`] when a blob is cut short.
    /// - [`Error::KeyDataInvalid`] when the salt is not
    ///   [`LOCAL_ENCRYPT_SALT_SIZE`] bytes or the trailer is malformed (see
    ///   [`KeyDataTrailer::parse`]).
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut reader = QReader::new(payload);
        let (salt, key_encrypted, info_encrypted) = streamed(
            (|| {
                let salt = reader.read_bytearray()?.unwrap_or_default().to_vec();
                let key_encrypted = reader.read_bytearray()?.map(<[u8]>::to_vec);
                let info_encrypted = reader.read_bytearray()?.unwrap_or_default().to_vec();
                Ok((salt, key_encrypted, info_encrypted))
            })(),
            KEY_DATA_STREAM_FAILED,
        )?;
        if salt.len() != LOCAL_ENCRYPT_SALT_SIZE {
            return Err(invalid(KeyDataFailure::BadSalt { size: salt.len() }));
        }
        let trailer = if reader.is_empty() {
            None
        } else {
            let blob =
                streamed(reader.read_bytearray(), TRAILER_STREAM_FAILED)?.unwrap_or_default();
            Some(KeyDataTrailer::parse(blob)?)
        };
        Ok(Self {
            salt,
            key_encrypted,
            info_encrypted,
            trailer,
        })
    }

    /// Encodes the key file payload; a trailer is written in format
    /// [`KEY_DATA_FORMAT_VERSION`].
    ///
    /// # Errors
    /// [`Error::QDataStreamFailed`] when a blob does not fit a `u32` length.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = QWriter::new();
        writer.write_bytearray(Some(&self.salt))?;
        writer.write_bytearray(self.key_encrypted.as_deref())?;
        writer.write_bytearray(Some(&self.info_encrypted))?;
        if let Some(trailer) = &self.trailer {
            writer.write_bytearray(Some(&trailer.encode()?))?;
        }
        Ok(writer.into_bytes())
    }

    /// Number of wraps of the committed generation; 0 without a trailer.
    #[must_use]
    pub fn live_wrap_count(&self) -> usize {
        self.trailer
            .as_ref()
            .map_or(0, |trailer| trailer.live_wraps().count())
    }
}

/// The local key recovered from a key file and the key that unwrapped it.
#[derive(Debug, Clone)]
pub struct OpenedKey {
    /// The local key every other tdata file is encrypted with.
    pub local_key: AuthKey,
    /// The open or passcode key the local key was wrapped under.
    pub passcode_key: AuthKey,
}

/// Derives the key of one passcode wrap (`CreatePasscodeKey`).
///
/// # Errors
/// - [`Error::KeyDataInvalid`] for an empty passcode, a salt shorter than
///   [`kdf::PASSCODE_SALT_MIN_SIZE`], or parameters that are above the caps
///   or not [`PasscodeKdf::valid`].
/// - [`Error::BadDecryptKey`] when the derivation itself fails, which
///   Telegram Desktop reports as a wrong passcode.
pub fn create_passcode_key(passcode: &[u8], salt: &[u8], params: &PasscodeKdf) -> Result<AuthKey> {
    if passcode.is_empty()
        || salt.len() < kdf::PASSCODE_SALT_MIN_SIZE
        || !params.cost_within_limits()
        || !params.valid()
    {
        return Err(invalid(KeyDataFailure::UnusableWrapParameters {
            kind: params.kind,
            memory: params.memory,
            time: params.time,
            parallelism: params.parallelism,
        }));
    }
    let derived = if params.kind == KDF_ARGON2ID {
        kdf::argon2id(
            passcode,
            salt,
            params.memory,
            params.time,
            params.parallelism,
        )
    } else {
        kdf::scrypt(
            passcode,
            salt,
            params.memory,
            params.time,
            params.parallelism,
        )
    };
    derived.map(AuthKey::new).map_err(|_| Error::BadDecryptKey)
}

/// Wraps the local key under `wrap_key` (`PrepareEncrypted` of the raw
/// 256 key bytes), with `padding` as the 12 bytes of local padding.
///
/// # Errors
/// [`Error::BadLength`] when `padding` is not
/// [`crypto::local_padding_len`]`(256)` bytes.
pub fn wrap_local_key(local_key: &AuthKey, wrap_key: &AuthKey, padding: &[u8]) -> Result<Vec<u8>> {
    crypto::encrypt_local(local_key.as_bytes(), wrap_key, |_| padding.to_vec())
}

/// Unwraps a local key written by [`wrap_local_key`].
///
/// # Errors
/// [`Error::BadDecryptKey`] on any decryption failure or when the plaintext
/// is not exactly [`AuthKey::SIZE`] bytes; both mean a wrong passcode.
pub fn unwrap_local_key(key_encrypted: &[u8], wrap_key: &AuthKey) -> Result<AuthKey> {
    let inner = crypto::decrypt_local(key_encrypted, wrap_key).map_err(|_| Error::BadDecryptKey)?;
    AuthKey::from_slice(&inner).map_err(|_| Error::BadDecryptKey)
}

/// Recovers the local key the way `Domain::startModern` does.
///
/// - Legacy layout: the open wrap under `create_local_key(passcode, salt)`.
/// - Empty passcode: the open wrap under `create_local_key("", salt)`.
/// - Otherwise: the one live passcode wrap under [`create_passcode_key`].
///
/// # Errors
/// - [`Error::BadDecryptKey`] for a wrong passcode, a wrap above the KDF read
///   caps, an empty passcode while the open wrap is empty (app lock on), or a
///   passcode without exactly one live wrap.
/// - [`Error::KeyDataInvalid`] when the live wrap's parameters cannot make a
///   passcode key.
pub fn open_local_key(data: &KeyData, passcode: &[u8]) -> Result<OpenedKey> {
    let open_wrap = data.key_encrypted.as_deref().unwrap_or_default();
    let Some(trailer) = &data.trailer else {
        let wrap_key = kdf::create_local_key(passcode, &data.salt);
        return opened(open_wrap, wrap_key);
    };
    if trailer.wraps.iter().any(|w| !w.kdf.cost_within_limits()) {
        return Err(Error::BadDecryptKey);
    }
    if passcode.is_empty() {
        if open_wrap.is_empty() {
            return Err(Error::BadDecryptKey);
        }
        return opened(open_wrap, kdf::create_local_key(&[], &data.salt));
    }
    // A typed passcode must open the one live passcode wrap, never the open
    // wrap, or a later save would keep a passcode the file never had.
    let mut live = trailer.live_wraps();
    let (Some(wrap), None) = (live.next(), live.next()) else {
        return Err(Error::BadDecryptKey);
    };
    let wrap_key = create_passcode_key(passcode, &wrap.salt, &wrap.kdf)?;
    opened(&wrap.key_encrypted, wrap_key)
}

/// The sizes [`install`] draws, in order: the open salt, the wrap salt when
/// there is a passcode, and the wrap padding.
pub(crate) fn install_draws(has_passcode: bool) -> Vec<usize> {
    let padding = crypto::local_padding_len(AuthKey::SIZE);
    if has_passcode {
        vec![LOCAL_ENCRYPT_SALT_SIZE, LOCAL_ENCRYPT_SALT_SIZE, padding]
    } else {
        vec![LOCAL_ENCRYPT_SALT_SIZE, padding]
    }
}

/// Wraps `local_key` in a fresh 7.3 key file (`TDesktop.__installKeyData`,
/// `Domain::generateLocalKey`) and returns it with the wrap key.
///
/// Draws a [`LOCAL_ENCRYPT_SALT_SIZE`] open salt. Without a passcode the
/// local key is wrapped under `create_local_key("", salt)` with no passcode
/// wrap; otherwise the open wrap is null, a second salt is drawn, and the one
/// wrap uses [`default_passcode_kdf`] and is committed. The info is left
/// empty for the writer to fill.
pub(crate) fn install(
    local_key: &AuthKey,
    passcode: &[u8],
    rng: &mut FillRandom<'_>,
) -> Result<(KeyData, AuthKey)> {
    let salt = random_bytes(rng, LOCAL_ENCRYPT_SALT_SIZE)?;
    let padding_len = crypto::local_padding_len(AuthKey::SIZE);
    if passcode.is_empty() {
        let wrap_key = kdf::create_local_key(&[], &salt);
        let padding = random_bytes(rng, padding_len)?;
        let data = KeyData {
            key_encrypted: Some(wrap_local_key(local_key, &wrap_key, &padding)?),
            salt,
            info_encrypted: Vec::new(),
            trailer: Some(KeyDataTrailer {
                committed: 0,
                wraps: Vec::new(),
            }),
        };
        return Ok((data, wrap_key));
    }
    let params = default_passcode_kdf();
    let wrap_salt = random_bytes(rng, LOCAL_ENCRYPT_SALT_SIZE)?;
    let wrap_key = create_passcode_key(passcode, &wrap_salt, &params)?;
    let padding = random_bytes(rng, padding_len)?;
    let wrap = PasscodeWrap {
        kdf: params,
        salt: wrap_salt,
        key_encrypted: wrap_local_key(local_key, &wrap_key, &padding)?,
    };
    let data = KeyData {
        salt,
        key_encrypted: None,
        info_encrypted: Vec::new(),
        trailer: Some(KeyDataTrailer {
            committed: params.generation,
            wraps: vec![wrap],
        }),
    };
    Ok((data, wrap_key))
}

fn opened(key_encrypted: &[u8], wrap_key: AuthKey) -> Result<OpenedKey> {
    Ok(OpenedKey {
        local_key: unwrap_local_key(key_encrypted, &wrap_key)?,
        passcode_key: wrap_key,
    })
}

/// The decrypted accounts info: account indices and the active index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountsInfo {
    /// Account indices in file order, duplicates included.
    pub indices: Vec<i32>,
    /// Index of the active account; 0 when the stream ends before it.
    pub active_index: i32,
}

impl AccountsInfo {
    /// Decodes `count: i32`, `count` indices as `i32`, and an optional
    /// `active: i32`.
    ///
    /// # Errors
    /// - [`Error::QDataStreamFailed`] when the stream is cut short.
    /// - [`Error::KeyDataInvalid`] when the count is not positive.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader = QReader::new(data);
        let count = reader.read_i32()?;
        if count <= 0 {
            return Err(invalid(KeyDataFailure::BadAccountsCount { count }));
        }
        let mut indices = Vec::new();
        for _ in 0..count {
            indices.push(reader.read_i32()?);
        }
        let active_index = if reader.is_empty() {
            0
        } else {
            reader.read_i32()?
        };
        Ok(Self {
            indices,
            active_index,
        })
    }

    /// Encodes `count: i32`, the indices as `i32`, and `active: i32`, the
    /// plaintext [`TData::save`](super::TData::save) encrypts.
    ///
    /// # Errors
    /// [`Error::QDataStreamFailed`] when the count does not fit an `i32`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let count = i32::try_from(self.indices.len())
            .map_err(|_| Error::QDataStreamFailed { context: None })?;
        let mut writer = QWriter::new();
        writer.write_i32(count);
        for &index in &self.indices {
            writer.write_i32(index);
        }
        writer.write_i32(self.active_index);
        Ok(writer.into_bytes())
    }
}

/// Decrypts and decodes the accounts info of `data` with `local_key`.
///
/// `passcode` is the one [`open_local_key`] was given; it decides how a
/// decryption failure is reported, as in `Domain::startModern`.
///
/// # Errors
/// - [`Error::BadDecryptKey`] when decryption fails, no passcode was given,
///   and exactly one live passcode wrap exists.
/// - [`Error::KeyDataInvalid`] for any other decryption failure, or as
///   [`AccountsInfo::parse`].
/// - [`Error::QDataStreamFailed`] as [`AccountsInfo::parse`].
pub fn decrypt_accounts_info(
    data: &KeyData,
    local_key: &AuthKey,
    passcode: &[u8],
) -> Result<AccountsInfo> {
    let info = crypto::decrypt_local(&data.info_encrypted, local_key).map_err(|_| {
        if passcode.is_empty() && data.live_wrap_count() == 1 {
            Error::BadDecryptKey
        } else {
            invalid(KeyDataFailure::AccountsInfoDecrypt)
        }
    })?;
    AccountsInfo::parse(&info)
}

/// The `ExpectStreamStatus` message after the three key file blobs.
const KEY_DATA_STREAM_FAILED: &str = "Could not stream the key data";
/// The message when the trailer blob is cut short.
const TRAILER_STREAM_FAILED: &str = "Could not stream the key data trailer";
/// The message when the trailer header is cut short.
const TRAILER_HEADER_STREAM_FAILED: &str = "Could not stream the key data trailer header";
/// The message when a passcode wrap is cut short.
const WRAP_STREAM_FAILED: &str = "Could not stream a key data wrap";

/// `result` with a stream failure named by the `context` of the
/// reads it covers; other errors pass through.
fn streamed<T>(result: Result<T>, context: &'static str) -> Result<T> {
    result.map_err(|error| match error {
        Error::QDataStreamFailed { context: None } => Error::QDataStreamFailed {
            context: Some(context),
        },
        other => other,
    })
}

const fn invalid(context: KeyDataFailure) -> Error {
    Error::KeyDataInvalid { context }
}
