//! The single error type of the core and its stable codes.

/// Result alias used by every fallible operation in the core.
pub type Result<T> = std::result::Result<T, Error>;

/// Every failure the core can report.
///
/// Variants map 1:1 onto the tdata exceptions of the Python package
/// (`src/exception.py`), plus [`Error::BadLength`] and [`Error::Io`]. Bindings
/// dispatch on [`Error::code`], which is stable across releases; the
/// `Display` text is for humans and may change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A required tdata file does not exist (`TFileNotFound`).
    #[error("tdata file not found")]
    FileNotFound,

    /// A tdata file does not start with the `TDF$` magic (`TDataInvalidMagic`).
    #[error("tdata file has an invalid magic")]
    InvalidMagic,

    /// A tdata file's MD5 checksum does not match its contents
    /// (`TDataInvalidCheckSum`).
    #[error("tdata file has an invalid checksum")]
    InvalidCheckSum,

    /// Decryption produced data that does not match its key (`TDataBadDecryptKey`).
    #[error("tdata decrypt key is bad")]
    BadDecryptKey,

    /// The local passcode does not unlock the tdata (`TDataWrongPasscode`).
    #[error("tdata passcode is wrong")]
    WrongPasscode,

    /// Encrypted data has a size that is not valid for AES-IGE
    /// (`TDataBadEncryptedDataSize`).
    #[error("tdata encrypted data has a bad size")]
    BadEncryptedDataSize,

    /// Decrypted data declares a size that does not fit the buffer
    /// (`TDataBadDecryptedDataSize`).
    #[error("tdata decrypted data has a bad size")]
    BadDecryptedDataSize,

    /// The config block of a tdata file cannot be parsed (`TDataBadConfigData`).
    #[error("tdata config data is bad")]
    BadConfigData,

    /// A `QDataStream` read or write failed (`QDataStreamFailed`).
    #[error("QDataStream operation failed")]
    QDataStreamFailed,

    /// The account map data cannot be read (`TDataReadMapDataFailed`).
    #[error("failed to read tdata map data")]
    ReadMapDataFailed,

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
    KeyDataInvalid,

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
            Self::FileNotFound => "TFILE_NOT_FOUND",
            Self::InvalidMagic => "TDATA_INVALID_MAGIC",
            Self::InvalidCheckSum => "TDATA_INVALID_CHECKSUM",
            Self::BadDecryptKey => "TDATA_BAD_DECRYPT_KEY",
            Self::WrongPasscode => "TDATA_WRONG_PASSCODE",
            Self::BadEncryptedDataSize => "TDATA_BAD_ENCRYPTED_DATA_SIZE",
            Self::BadDecryptedDataSize => "TDATA_BAD_DECRYPTED_DATA_SIZE",
            Self::BadConfigData => "TDATA_BAD_CONFIG_DATA",
            Self::QDataStreamFailed => "QDATASTREAM_FAILED",
            Self::ReadMapDataFailed => "TDATA_READ_MAP_DATA_FAILED",
            Self::ReadMapDataIncorrectPasscode => "TDATA_READ_MAP_DATA_INCORRECT_PASSCODE",
            Self::AuthKeyNotFound => "TDATA_AUTH_KEY_NOT_FOUND",
            Self::MaxAccountLimit => "MAX_ACCOUNT_LIMIT",
            Self::SaveFailed => "TDATA_SAVE_FAILED",
            Self::KeyDataInvalid => "TDATA_KEY_DATA_INVALID",
            Self::BadLength { .. } => "BAD_LENGTH",
            Self::Io(_) => "IO",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use std::collections::HashSet;

    /// One value of every variant; the exhaustive match below fails to
    /// compile when a variant is added without extending this list.
    fn every_variant() -> Vec<Error> {
        let all = vec![
            Error::FileNotFound,
            Error::InvalidMagic,
            Error::InvalidCheckSum,
            Error::BadDecryptKey,
            Error::WrongPasscode,
            Error::BadEncryptedDataSize,
            Error::BadDecryptedDataSize,
            Error::BadConfigData,
            Error::QDataStreamFailed,
            Error::ReadMapDataFailed,
            Error::ReadMapDataIncorrectPasscode,
            Error::AuthKeyNotFound,
            Error::MaxAccountLimit,
            Error::SaveFailed,
            Error::KeyDataInvalid,
            Error::BadLength {
                what: "key",
                expected: 32,
                actual: 16,
            },
            Error::Io(std::io::Error::other("disk gone")),
        ];
        for error in &all {
            match error {
                Error::FileNotFound
                | Error::InvalidMagic
                | Error::InvalidCheckSum
                | Error::BadDecryptKey
                | Error::WrongPasscode
                | Error::BadEncryptedDataSize
                | Error::BadDecryptedDataSize
                | Error::BadConfigData
                | Error::QDataStreamFailed
                | Error::ReadMapDataFailed
                | Error::ReadMapDataIncorrectPasscode
                | Error::AuthKeyNotFound
                | Error::MaxAccountLimit
                | Error::SaveFailed
                | Error::KeyDataInvalid
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
