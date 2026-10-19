//! The single error type of the core and its stable codes.

/// Result alias used by every fallible operation in the core.
pub type Result<T> = std::result::Result<T, Error>;

/// What an [`Error::InvalidMagic`] was raised for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MagicContext {
    /// A `TDF$` file started with other bytes (1.5.0 `Storage.ReadFile`).
    File {
        /// The file name without its suffix, as 1.5.0 reports it.
        file: String,
        /// The bytes found where the magic belongs, at most four.
        magic: Vec<u8>,
    },
    /// The MTP data held a block id the reader does not know.
    MtpDataBlock {
        /// The unknown block id.
        block_id: u32,
    },
}

/// What an [`Error::ReadMapDataFailed`] was raised for (1.5.0
/// `MapData.read`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MapReadFailure {
    /// The `maps` file is missing or is not a valid `TDF$` file.
    Open,
    /// The legacy salt of the `maps` file has the wrong size.
    BadSalt {
        /// The size of the salt found, in bytes.
        size: usize,
    },
    /// The map does not decrypt under the local key.
    Decrypt,
}

/// What an [`Error::KeyDataInvalid`] was raised for (1.5.0
/// `src/td/key_data.py` and `TDesktop.__loadFromTData`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyDataFailure {
    /// The parameters of a passcode wrap cannot make a passcode key
    /// (`create_passcode_key`), or the passcode is empty.
    UnusableWrapParameters {
        /// KDF family.
        kind: u32,
        /// Argon2id memory in KiB, or scrypt `N`.
        memory: u32,
        /// Argon2id passes, or scrypt `r`.
        time: u32,
        /// Argon2id lanes, or scrypt `p`.
        parallelism: u32,
    },
    /// The open salt of the key file has the wrong size.
    BadSalt {
        /// The size of the salt found, in bytes.
        size: usize,
    },
    /// The trailer does not start with the key data magic.
    BadTrailerMagic,
    /// The trailer holds more wraps than its format allows.
    BadWrapCount {
        /// The wrap count found.
        count: u32,
    },
    /// A wrap within the cost caps has parameters its KDF does not accept.
    BadKdfFamily {
        /// The KDF kind of the wrap.
        kind: u32,
    },
    /// A wrap salt is shorter than the passcode salt minimum.
    BadWrapSaltSize {
        /// The size of the wrap salt, in bytes.
        size: usize,
    },
    /// Two wraps share a generation.
    DuplicateWrapGeneration {
        /// The repeated generation.
        generation: u32,
    },
    /// The accounts info does not decrypt under the local key.
    AccountsInfoDecrypt,
    /// The accounts info lists no account (1.5.0 raises a plain
    /// `OpenTeleException` with this text).
    BadAccountsCount {
        /// The count found.
        count: i32,
    },
}

/// Every failure the core can report.
///
/// Variants map 1:1 onto the tdata exceptions of the Python package
/// (`src/exception.py`), plus [`Error::BadLength`] and [`Error::Io`]. Bindings
/// dispatch on [`Error::code`], which is stable across releases; the
/// `Display` text is for humans and may change. [`Error::legacy_message`]
/// is the message 1.5.0 gave the matching exception, built from the context
/// the variants carry.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A required tdata file does not exist (`TFileNotFound`).
    #[error("tdata file not found")]
    FileNotFound {
        /// The file name without its suffix, or the path that was looked
        /// for.
        file: String,
    },

    /// A tdata file does not start with the `TDF$` magic, or the MTP data
    /// holds an unknown block (`TDataInvalidMagic`).
    #[error("tdata file has an invalid magic")]
    InvalidMagic {
        /// Where the bad magic was found.
        context: MagicContext,
    },

    /// A tdata file's MD5 checksum does not match its contents
    /// (`TDataInvalidCheckSum`).
    #[error("tdata file has an invalid checksum")]
    InvalidCheckSum {
        /// The file name without its suffix; empty when the bytes were
        /// parsed without a name ([`crate::tdf::TdfFile::parse`]).
        file: String,
        /// The MD5 computed over the contents, which the stored one does not
        /// match.
        computed: [u8; 16],
    },

    /// Decryption produced data that does not match its key (`TDataBadDecryptKey`).
    #[error("tdata decrypt key is bad")]
    BadDecryptKey,

    /// The local passcode does not unlock the tdata (`TDataWrongPasscode`).
    #[error("tdata passcode is wrong")]
    WrongPasscode,

    /// Encrypted data has a size that is not valid for AES-IGE
    /// (`TDataBadEncryptedDataSize`).
    #[error("tdata encrypted data has a bad size")]
    BadEncryptedDataSize {
        /// The size of the encrypted data, in bytes.
        size: usize,
    },

    /// Decrypted data declares a size that does not fit the buffer
    /// (`TDataBadDecryptedDataSize`).
    #[error("tdata decrypted data has a bad size")]
    BadDecryptedDataSize {
        /// The size of the encrypted data, in bytes.
        encrypted_size: usize,
        /// The encrypted size without the 16-byte message key.
        full_len: usize,
        /// The size of the decrypted buffer, in bytes.
        decrypted_size: usize,
    },

    /// The config block of a tdata file cannot be parsed (`TDataBadConfigData`).
    #[error("tdata config data is bad")]
    BadConfigData,

    /// A `QDataStream` read or write failed (`QDataStreamFailed`).
    #[error("QDataStream operation failed")]
    QDataStreamFailed {
        /// The 1.5.0 message of the failed read, when the read is one 1.5.0
        /// names; `None` gives its default `Could not stream data`.
        context: Option<&'static str>,
    },

    /// The account map data cannot be read (`TDataReadMapDataFailed`).
    #[error("failed to read tdata map data")]
    ReadMapDataFailed {
        /// Which step of the read failed.
        context: MapReadFailure,
    },

    /// The account map data was read with an incorrect passcode
    /// (`TDataReadMapDataIncorrectPasscode`).
    #[error("tdata map data passcode is incorrect")]
    ReadMapDataIncorrectPasscode,

    /// No authorization key was found in the tdata (`TDataAuthKeyNotFound`).
    #[error("tdata auth key not found")]
    AuthKeyNotFound,

    /// The account limit of Telegram Desktop is reached (`MaxAccountLimit`).
    #[error("maximum number of accounts reached")]
    MaxAccountLimit,

    /// Writing the tdata failed (`TDataSaveFailed`).
    #[error("failed to save tdata")]
    SaveFailed,

    /// The `key_<dataName>` file is malformed or uses parameters that cannot
    /// make a passcode key (`TDataKeyDataInvalid`).
    #[error("tdata key data is invalid")]
    KeyDataInvalid {
        /// Which check of the key data failed.
        context: KeyDataFailure,
    },

    /// A buffer, key, or IV has the wrong length.
    #[error("{what} has a bad length: expected {expected}, got {actual}")]
    BadLength {
        /// Name of the value whose length is wrong.
        what: &'static str,
        /// Length the operation requires, in bytes.
        expected: usize,
        /// Length the caller supplied, in bytes.
        actual: usize,
    },

    /// An I/O operation on a caller-supplied path failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Stable `SCREAMING_SNAKE` code identifying the variant, for example
    /// `"TDATA_WRONG_PASSCODE"`. Bindings map this code onto their own error
    /// types; it never changes for an existing variant.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::FileNotFound { .. } => "TFILE_NOT_FOUND",
            Self::InvalidMagic { .. } => "TDATA_INVALID_MAGIC",
            Self::InvalidCheckSum { .. } => "TDATA_INVALID_CHECKSUM",
            Self::BadDecryptKey => "TDATA_BAD_DECRYPT_KEY",
            Self::WrongPasscode => "TDATA_WRONG_PASSCODE",
            Self::BadEncryptedDataSize { .. } => "TDATA_BAD_ENCRYPTED_DATA_SIZE",
            Self::BadDecryptedDataSize { .. } => "TDATA_BAD_DECRYPTED_DATA_SIZE",
            Self::BadConfigData => "TDATA_BAD_CONFIG_DATA",
            Self::QDataStreamFailed { .. } => "QDATASTREAM_FAILED",
            Self::ReadMapDataFailed { .. } => "TDATA_READ_MAP_DATA_FAILED",
            Self::ReadMapDataIncorrectPasscode => "TDATA_READ_MAP_DATA_INCORRECT_PASSCODE",
            Self::AuthKeyNotFound => "TDATA_AUTH_KEY_NOT_FOUND",
            Self::MaxAccountLimit => "MAX_ACCOUNT_LIMIT",
            Self::SaveFailed => "TDATA_SAVE_FAILED",
            Self::KeyDataInvalid { .. } => "TDATA_KEY_DATA_INVALID",
            Self::BadLength { .. } => "BAD_LENGTH",
            Self::Io(_) => "IO",
        }
    }

    /// The message 1.5.0 gave the matching exception (its `message`
    /// attribute, without the class name and caller `str()` adds), for
    /// example `Invalid magic b'ABCD' in file maps`.
    ///
    /// - [`Error::FileNotFound`]: `Could not open {file}`.
    /// - [`Error::InvalidMagic`]: `Invalid magic {magic!r} in file {file}`,
    ///   the magic as a Python `bytes` literal; for an MTP data block
    ///   `Unsupported block id in MtpData: {block_id}`.
    /// - [`Error::InvalidCheckSum`]: `Invalid checksum {md5 hex} in file
    ///   {file}`.
    /// - [`Error::BadEncryptedDataSize`] and [`Error::BadDecryptedDataSize`]:
    ///   the `Storage.DecryptLocal` messages with their sizes.
    /// - [`Error::BadDecryptKey`]: the `Storage.DecryptLocal` message, which
    ///   is also given where 1.5.0 named a key-data step instead.
    /// - [`Error::QDataStreamFailed`]: the context, else 1.5.0's default
    ///   `Could not stream data`.
    /// - [`Error::ReadMapDataFailed`], [`Error::ReadMapDataIncorrectPasscode`],
    ///   [`Error::AuthKeyNotFound`] and [`Error::MaxAccountLimit`]: the
    ///   `MapData.read`, `_findMainAuthKey` and `FromTelethon` messages.
    /// - [`Error::KeyDataInvalid`]: the `read_key_data`,
    ///   `create_passcode_key` and `__loadFromTData` message of its context.
    /// - [`Error::SaveFailed`]: `Could not save tdata, something went wrong`,
    ///   the one message 1.5.0's `SaveTData` raised.
    ///
    /// [`Error::WrongPasscode`] (never raised by 1.5.0), [`Error::BadConfigData`]
    /// (no context yet), [`Error::BadLength`] and [`Error::Io`] give their
    /// `Display` text.
    #[must_use]
    pub fn legacy_message(&self) -> String {
        match self {
            Self::FileNotFound { file } => format!("Could not open {file}"),
            Self::InvalidMagic {
                context: MagicContext::File { file, magic },
            } => format!("Invalid magic {} in file {file}", py_bytes_repr(magic)),
            Self::InvalidMagic {
                context: MagicContext::MtpDataBlock { block_id },
            } => format!("Unsupported block id in MtpData: {block_id}"),
            Self::InvalidCheckSum { file, computed } => {
                let mut hex = String::with_capacity(2 * computed.len());
                for &byte in computed {
                    push_hex(&mut hex, byte);
                }
                format!("Invalid checksum {hex} in file {file}")
            }
            Self::BadDecryptKey => {
                "Bad decrypt key, data not decrypted - incorrect password?".to_owned()
            }
            Self::BadEncryptedDataSize { size } => format!("Bad encrypted part size: {size}"),
            Self::BadDecryptedDataSize {
                encrypted_size,
                full_len,
                decrypted_size,
            } => format!(
                "Bad decrypted part size: {encrypted_size}, fullLen: {full_len}, \
                 decrypted size: {decrypted_size}"
            ),
            Self::QDataStreamFailed { context } => {
                context.unwrap_or("Could not stream data").to_owned()
            }
            Self::ReadMapDataFailed { context } => match context {
                MapReadFailure::Open => {
                    "Could not read map data, file not found or couldn't be opened".to_owned()
                }
                MapReadFailure::BadSalt { size } => {
                    format!("Bad salt in map file, size: {size}")
                }
                MapReadFailure::Decrypt => "Could not decrypt map data".to_owned(),
            },
            Self::ReadMapDataIncorrectPasscode => {
                "Could not decrypt pass-protected key from map file, maybe bad password..."
                    .to_owned()
            }
            Self::AuthKeyNotFound => "Could not find the main authKey".to_owned(),
            Self::MaxAccountLimit => {
                "You can't have more than 6 accounts in one TDesktop client".to_owned()
            }
            Self::KeyDataInvalid { context } => key_data_message(*context),
            Self::SaveFailed => "Could not save tdata, something went wrong".to_owned(),
            Self::WrongPasscode | Self::BadConfigData | Self::BadLength { .. } | Self::Io(_) => {
                self.to_string()
            }
        }
    }
}

/// The 1.5.0 message of an [`Error::KeyDataInvalid`].
fn key_data_message(context: KeyDataFailure) -> String {
    match context {
        KeyDataFailure::UnusableWrapParameters {
            kind,
            memory,
            time,
            parallelism,
        } => format!(
            "Unusable passcode wrap parameters: PasscodeKdf(kind={kind}, memory={memory}, \
             time={time}, parallel={parallelism})"
        ),
        KeyDataFailure::BadSalt { size } => format!("Bad salt in key data, size: {size}"),
        KeyDataFailure::BadTrailerMagic => "Bad key data trailer magic".to_owned(),
        KeyDataFailure::BadWrapCount { count } => format!("Bad key data wrap count: {count}"),
        KeyDataFailure::BadKdfFamily { kind } => format!("Bad key data KDF family: {kind}"),
        KeyDataFailure::BadWrapSaltSize { size } => {
            format!("Bad key data wrap salt size: {size}")
        }
        KeyDataFailure::DuplicateWrapGeneration { generation } => {
            format!("Duplicate key data wrap generation: {generation}")
        }
        KeyDataFailure::AccountsInfoDecrypt => "Could not decrypt the accounts info".to_owned(),
        KeyDataFailure::BadAccountsCount { count } => {
            format!("Bad accounts count {count}, the data might have been corrupted")
        }
    }
}

/// Python `repr(bytes)`: `b'…'`, or `b"…"` when the bytes hold a single
/// quote and no double quote; `\\`, the quote, `\t`, `\n` and `\r` are
/// escaped, other bytes outside printable ASCII are `\xNN`.
fn py_bytes_repr(bytes: &[u8]) -> String {
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut out = format!("b{quote}");
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if char::from(byte) == quote => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {
                out.push_str("\\x");
                push_hex(&mut out, byte);
            }
        }
    }
    out.push(quote);
    out
}

/// Appends `byte` as two lowercase hex digits.
fn push_hex(out: &mut String, byte: u8) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(DIGITS[usize::from(byte >> 4)]));
    out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
}

#[cfg(test)]
mod tests {
    use super::{Error, KeyDataFailure, MagicContext, MapReadFailure};
    use std::collections::HashSet;

    /// One value of every variant; the exhaustive match below fails to
    /// compile when a variant is added without extending this list.
    fn every_variant() -> Vec<Error> {
        let all = vec![
            Error::FileNotFound {
                file: "map".to_owned(),
            },
            Error::InvalidMagic {
                context: MagicContext::File {
                    file: "maps".to_owned(),
                    magic: b"ABCD".to_vec(),
                },
            },
            Error::InvalidCheckSum {
                file: "ck".to_owned(),
                computed: [0; 16],
            },
            Error::BadDecryptKey,
            Error::WrongPasscode,
            Error::BadEncryptedDataSize { size: 16 },
            Error::BadDecryptedDataSize {
                encrypted_size: 48,
                full_len: 32,
                decrypted_size: 32,
            },
            Error::BadConfigData,
            Error::QDataStreamFailed { context: None },
            Error::ReadMapDataFailed {
                context: MapReadFailure::Open,
            },
            Error::ReadMapDataIncorrectPasscode,
            Error::AuthKeyNotFound,
            Error::MaxAccountLimit,
            Error::SaveFailed,
            Error::KeyDataInvalid {
                context: KeyDataFailure::BadTrailerMagic,
            },
            Error::BadLength {
                what: "key",
                expected: 32,
                actual: 16,
            },
            Error::Io(std::io::Error::other("disk gone")),
        ];
        for error in &all {
            match error {
                Error::FileNotFound { .. }
                | Error::InvalidMagic { .. }
                | Error::InvalidCheckSum { .. }
                | Error::BadDecryptKey
                | Error::WrongPasscode
                | Error::BadEncryptedDataSize { .. }
                | Error::BadDecryptedDataSize { .. }
                | Error::BadConfigData
                | Error::QDataStreamFailed { .. }
                | Error::ReadMapDataFailed { .. }
                | Error::ReadMapDataIncorrectPasscode
                | Error::AuthKeyNotFound
                | Error::MaxAccountLimit
                | Error::SaveFailed
                | Error::KeyDataInvalid { .. }
                | Error::BadLength { .. }
                | Error::Io(_) => {}
            }
        }
        all
    }

    #[test]
    fn codes_are_unique() {
        let all = every_variant();
        let codes: HashSet<&str> = all.iter().map(Error::code).collect();
        assert_eq!(codes.len(), all.len(), "duplicate code in {codes:?}");
    }

    #[test]
    fn codes_are_non_empty_screaming_snake() {
        for error in every_variant() {
            let code = error.code();
            assert!(!code.is_empty(), "{error:?} has an empty code");
            assert!(
                code.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "{code} is not SCREAMING_SNAKE"
            );
        }
    }

    #[test]
    fn wrong_passcode_code_is_stable() {
        assert_eq!(Error::WrongPasscode.code(), "TDATA_WRONG_PASSCODE");
    }

    /// The codes and `Display` texts bindings dispatch on and show stay
    /// what they were before the variants carried context.
    #[test]
    fn codes_and_display_texts_are_unchanged() {
        let expected = [
            ("TFILE_NOT_FOUND", "tdata file not found"),
            ("TDATA_INVALID_MAGIC", "tdata file has an invalid magic"),
            (
                "TDATA_INVALID_CHECKSUM",
                "tdata file has an invalid checksum",
            ),
            ("TDATA_BAD_DECRYPT_KEY", "tdata decrypt key is bad"),
            ("TDATA_WRONG_PASSCODE", "tdata passcode is wrong"),
            (
                "TDATA_BAD_ENCRYPTED_DATA_SIZE",
                "tdata encrypted data has a bad size",
            ),
            (
                "TDATA_BAD_DECRYPTED_DATA_SIZE",
                "tdata decrypted data has a bad size",
            ),
            ("TDATA_BAD_CONFIG_DATA", "tdata config data is bad"),
            ("QDATASTREAM_FAILED", "QDataStream operation failed"),
            (
                "TDATA_READ_MAP_DATA_FAILED",
                "failed to read tdata map data",
            ),
            (
                "TDATA_READ_MAP_DATA_INCORRECT_PASSCODE",
                "tdata map data passcode is incorrect",
            ),
            ("TDATA_AUTH_KEY_NOT_FOUND", "tdata auth key not found"),
            ("MAX_ACCOUNT_LIMIT", "maximum number of accounts reached"),
            ("TDATA_SAVE_FAILED", "failed to save tdata"),
            ("TDATA_KEY_DATA_INVALID", "tdata key data is invalid"),
            ("BAD_LENGTH", "key has a bad length: expected 32, got 16"),
            ("IO", "I/O error: disk gone"),
        ];
        let all = every_variant();
        assert_eq!(all.len(), expected.len());
        for (error, (code, display)) in all.iter().zip(expected) {
            assert_eq!(error.code(), code);
            assert_eq!(error.to_string(), display);
        }
    }

    /// Variants without a 1.5.0 message of their own give their `Display`
    /// text.
    #[test]
    fn legacy_message_falls_back_to_display() {
        for error in [Error::WrongPasscode, Error::BadConfigData] {
            assert_eq!(error.legacy_message(), error.to_string());
        }
    }

    #[test]
    fn io_error_converts_and_displays() {
        let error: Error = std::io::Error::other("disk gone").into();
        assert_eq!(error.code(), "IO");
        assert_eq!(error.to_string(), "I/O error: disk gone");
    }

    #[test]
    fn bad_length_displays_its_fields() {
        let error = Error::BadLength {
            what: "iv",
            expected: 32,
            actual: 31,
        };
        assert_eq!(
            error.to_string(),
            "iv has a bad length: expected 32, got 31"
        );
    }
}
