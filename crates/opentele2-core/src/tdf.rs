//! The `TDF$` container that wraps every Telegram Desktop `tdata` file.
//!
//! Layout, as in 1.5.0 (`src/td/storage.py`):
//!
//! ```text
//! b"TDF$" | version: u32 LE | payload | md5(payload | len(payload): u32 LE | version: u32 LE | b"TDF$")
//! ```
//!
//! On disk a file named `name` is stored as `name` plus one of the suffixes
//! `s`, `1`, `0`. [`read`] tries them in that order and [`write`] always
//! writes the `s` variant.

use std::fs;
use std::path::Path;

use md5::{Digest, Md5};

use crate::{Error, Result};

/// The four bytes every `TDF$` file starts with.
pub const MAGIC: [u8; 4] = *b"TDF$";

/// File name suffixes [`read`] tries, in order.
pub const READ_SUFFIXES: [&str; 3] = ["s", "1", "0"];

/// File name suffix [`write`] uses.
pub const WRITE_SUFFIX: &str = "s";

const HEADER_LEN: usize = MAGIC.len() + 4;
const CHECKSUM_LEN: usize = 16;

/// A decoded `TDF$` file: the app version that wrote it and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdfFile {
    /// Telegram Desktop version number stored after the magic.
    pub version: u32,
    /// Bytes between the header and the checksum.
    pub payload: Vec<u8>,
}

/// MD5 over the payload and trailer fields, as Telegram Desktop computes it.
fn checksum(version: u32, payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    // tdesktop hashes the length as a 32-bit int; widen first so the low
    // four bytes are taken on every platform without a truncating cast.
    let len = (payload.len() as u64).to_le_bytes();
    let mut hasher = Md5::new();
    hasher.update(payload);
    hasher.update(&len[..4]);
    hasher.update(version.to_le_bytes());
    hasher.update(MAGIC);
    let mut digest = [0; CHECKSUM_LEN];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

impl TdfFile {
    /// Decodes the bytes of a whole `TDF$` file and checks its MD5.
    ///
    /// # Errors
    ///
    /// - [`Error::QDataStreamFailed`] when the input is too short to hold the
    ///   magic, the version, and the checksum.
    /// - [`Error::InvalidMagic`] when it does not start with `TDF$`.
    /// - [`Error::InvalidCheckSum`] when the stored MD5 does not match.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let magic = data.get(..MAGIC.len()).ok_or(Error::QDataStreamFailed)?;
        if magic != MAGIC {
            return Err(Error::InvalidMagic);
        }
        if data.len() < HEADER_LEN + CHECKSUM_LEN {
            return Err(Error::QDataStreamFailed);
        }
        let (header, rest) = data.split_at(HEADER_LEN);
        let (payload, stored) = rest.split_at(rest.len() - CHECKSUM_LEN);
        let mut version = [0; 4];
        version.copy_from_slice(&header[MAGIC.len()..]);
        let version = u32::from_le_bytes(version);
        if checksum(version, payload) != stored {
            return Err(Error::InvalidCheckSum);
        }
        Ok(Self {
            version,
            payload: payload.to_vec(),
        })
    }

    /// Encodes the file bytes: header, payload, and MD5 checksum.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len() + CHECKSUM_LEN);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&checksum(self.version, &self.payload));
        out
    }
}

/// Reads `name` from `dir`, trying the suffixes of [`READ_SUFFIXES`] in order.
///
/// A suffix whose file cannot be opened or fails to parse is skipped and the
/// next one is tried; the first that parses wins.
///
/// # Errors
///
/// When no suffix yields a valid file: the error of the last file that exists
/// but failed to parse ([`Error::InvalidMagic`], [`Error::InvalidCheckSum`],
/// or [`Error::QDataStreamFailed`]), else [`Error::FileNotFound`].
pub fn read(dir: impl AsRef<Path>, name: &str) -> Result<TdfFile> {
    let dir = dir.as_ref();
    let mut failure = None;
    for suffix in READ_SUFFIXES {
        // 1.5.0 treats any file it cannot open or read as absent.
        let Ok(data) = fs::read(dir.join(format!("{name}{suffix}"))) else {
            continue;
        };
        match TdfFile::parse(&data) {
            Ok(file) => return Ok(file),
            Err(error) => failure = Some(error),
        }
    }
    Err(failure.unwrap_or(Error::FileNotFound))
}

/// Writes `file` to `dir` as `name` plus [`WRITE_SUFFIX`], creating `dir`
/// when it does not exist.
///
/// # Errors
///
/// [`Error::Io`] when the directory cannot be created or the file written.
pub fn write(dir: impl AsRef<Path>, name: &str, file: &TdfFile) -> Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    fs::write(dir.join(format!("{name}{WRITE_SUFFIX}")), file.encode())?;
    Ok(())
}
