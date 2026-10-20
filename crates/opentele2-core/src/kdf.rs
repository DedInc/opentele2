//! Passcode key derivation: the PBKDF2 local keys and the Argon2id / scrypt
//! passcode wraps of the v2 `key_data` file.
//!
//! The read caps mirror `storage_file_utilities.cpp`, with stricter scrypt
//! caps: a crafted `key_data` must not make a read cost
//! unbounded memory or CPU. A parameter above a cap, a salt shorter than
//! [`PASSCODE_SALT_MIN_SIZE`], or an empty passcode is [`Error::BadLength`];
//! parameters inside the caps that the KDF still rejects are
//! [`Error::BadDecryptKey`], which Telegram Desktop treats as a wrong passcode.

use sha1::Sha1;
use sha2::{Digest, Sha512};

use crate::crypto::AuthKey;
use crate::{Error, Result};

/// PBKDF2-HMAC-SHA512 iterations of [`create_local_key`] for a passcode.
pub const PBKDF2_ITERATIONS: u32 = 100_000;
/// PBKDF2-HMAC-SHA512 iterations of [`create_local_key`] without a passcode.
pub const PBKDF2_ITERATIONS_EMPTY: u32 = 1;
/// PBKDF2-HMAC-SHA1 iterations of [`create_legacy_local_key`] for a passcode.
pub const LEGACY_PBKDF2_ITERATIONS: u32 = 4000;
/// PBKDF2-HMAC-SHA1 iterations of [`create_legacy_local_key`] without one.
pub const LEGACY_PBKDF2_ITERATIONS_EMPTY: u32 = 4;

/// Minimum salt length of a passcode wrap, in bytes.
pub const PASSCODE_SALT_MIN_SIZE: usize = 8;

/// Highest Argon2id memory cost accepted on read, in KiB (256 MiB).
pub const ARGON2_MAX_MEMORY_KIB: u32 = 262_144;
/// Highest Argon2id time cost accepted on read.
pub const ARGON2_MAX_TIME: u32 = 64;
/// Highest Argon2id lane count accepted on read.
pub const ARGON2_MAX_LANES: u32 = 16;

/// Highest scrypt `N` accepted on read.
pub const SCRYPT_MAX_N: u32 = 1 << 20;
/// Highest scrypt `r` accepted on read.
pub const SCRYPT_MAX_R: u32 = 32;
/// Highest scrypt `p` accepted on read.
pub const SCRYPT_MAX_P: u32 = 16;
/// Memory ceiling of one scrypt derivation, in bytes, counted as `OpenSSL`
/// does: `128 * r * p + 128 * r * (N + 2)`.
pub const SCRYPT_MAX_MEM: u64 = 192 * 1024 * 1024;

/// Derives the local key from `passcode` (`Storage::CreateLocalKey`):
/// PBKDF2-HMAC-SHA512 over `sha512(salt || passcode || salt)` with `salt`,
/// [`PBKDF2_ITERATIONS`] rounds (or [`PBKDF2_ITERATIONS_EMPTY`] for an empty
/// passcode), 256 bytes of output.
#[must_use]
pub fn create_local_key(passcode: &[u8], salt: &[u8]) -> AuthKey {
    let hash_key = Sha512::new()
        .chain_update(salt)
        .chain_update(passcode)
        .chain_update(salt)
        .finalize();
    let rounds = if passcode.is_empty() {
        PBKDF2_ITERATIONS_EMPTY
    } else {
        PBKDF2_ITERATIONS
    };
    let mut key = [0u8; AuthKey::SIZE];
    pbkdf2::pbkdf2_hmac::<Sha512>(&hash_key, salt, rounds, &mut key);
    AuthKey::new(key)
}

/// Derives a Telegram Desktop legacy local key (`Storage::CreateLegacyLocalKey`):
/// PBKDF2-HMAC-SHA1 over `passcode` with `salt`, [`LEGACY_PBKDF2_ITERATIONS`]
/// rounds (or [`LEGACY_PBKDF2_ITERATIONS_EMPTY`] for an empty passcode),
/// 256 bytes of output.
#[must_use]
pub fn create_legacy_local_key(passcode: &[u8], salt: &[u8]) -> AuthKey {
    let rounds = if passcode.is_empty() {
        LEGACY_PBKDF2_ITERATIONS_EMPTY
    } else {
        LEGACY_PBKDF2_ITERATIONS
    };
    let mut key = [0u8; AuthKey::SIZE];
    pbkdf2::pbkdf2_hmac::<Sha1>(passcode, salt, rounds, &mut key);
    AuthKey::new(key)
}

fn usize_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Rejects a value above its read cap.
fn cap(what: &'static str, value: u32, max: u32) -> Result<()> {
    if value > max {
        return Err(Error::BadLength {
            what,
            expected: usize_of(max),
            actual: usize_of(value),
        });
    }
    Ok(())
}

/// Rejects the passcode and salt shapes no passcode wrap may have.
fn check_wrap_inputs(passcode: &[u8], salt: &[u8]) -> Result<()> {
    if passcode.is_empty() {
        return Err(Error::BadLength {
            what: "passcode",
            expected: 1,
            actual: 0,
        });
    }
    if salt.len() < PASSCODE_SALT_MIN_SIZE {
        return Err(Error::BadLength {
            what: "passcode salt",
            expected: PASSCODE_SALT_MIN_SIZE,
            actual: salt.len(),
        });
    }
    Ok(())
}

/// Derives a passcode wrap key with Argon2id version 0x13, 256 bytes raw.
///
/// `memory_kib` is the memory cost in KiB, `time` the pass count, and `lanes`
/// the parallelism, which shapes the output (threads do not).
///
/// # Errors
/// - [`Error::BadLength`] for an empty passcode, a salt shorter than
///   [`PASSCODE_SALT_MIN_SIZE`], or a cost above [`ARGON2_MAX_MEMORY_KIB`],
///   [`ARGON2_MAX_TIME`], or [`ARGON2_MAX_LANES`].
/// - [`Error::BadDecryptKey`] when `time` or `lanes` is zero, `memory_kib` is
///   below `8 * lanes`, or the derivation itself fails.
pub fn argon2id(
    passcode: &[u8],
    salt: &[u8],
    memory_kib: u32,
    time: u32,
    lanes: u32,
) -> Result<[u8; AuthKey::SIZE]> {
    check_wrap_inputs(passcode, salt)?;
    cap("Argon2id memory_kib", memory_kib, ARGON2_MAX_MEMORY_KIB)?;
    cap("Argon2id time", time, ARGON2_MAX_TIME)?;
    cap("Argon2id lanes", lanes, ARGON2_MAX_LANES)?;
    // Lanes are capped at 16, so 8 * lanes cannot overflow.
    if time == 0 || lanes == 0 || memory_kib < 8 * lanes {
        return Err(Error::BadDecryptKey);
    }

    let params = argon2::Params::new(memory_kib, time, lanes, Some(AuthKey::SIZE))
        .map_err(|_| Error::BadDecryptKey)?;
    let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; AuthKey::SIZE];
    hasher
        .hash_password_into(passcode, salt, &mut out)
        .map_err(|_| Error::BadDecryptKey)?;
    Ok(out)
}

/// Derives a passcode wrap key with scrypt, 256 bytes; read-only, since
/// Telegram Desktop writes scrypt wraps only on builds without Argon2id.
///
/// # Errors
/// - [`Error::BadLength`] for an empty passcode, a salt shorter than
///   [`PASSCODE_SALT_MIN_SIZE`], or a cost above [`SCRYPT_MAX_N`],
///   [`SCRYPT_MAX_R`], or [`SCRYPT_MAX_P`].
/// - [`Error::BadDecryptKey`] when `n` is not a power of two of at least 2,
///   `r` or `p` is zero, the memory exceeds [`SCRYPT_MAX_MEM`], or the
///   derivation itself fails.
pub fn scrypt(passcode: &[u8], salt: &[u8], n: u32, r: u32, p: u32) -> Result<[u8; AuthKey::SIZE]> {
    check_wrap_inputs(passcode, salt)?;
    cap("scrypt N", n, SCRYPT_MAX_N)?;
    cap("scrypt r", r, SCRYPT_MAX_R)?;
    cap("scrypt p", p, SCRYPT_MAX_P)?;
    if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 {
        return Err(Error::BadDecryptKey);
    }
    let memory = 128 * u64::from(r) * u64::from(p) + 128 * u64::from(r) * (u64::from(n) + 2);
    if memory > SCRYPT_MAX_MEM {
        return Err(Error::BadDecryptKey);
    }

    let log_n = u8::try_from(n.trailing_zeros()).map_err(|_| Error::BadDecryptKey)?;
    let params = scrypt::Params::new(log_n, r, p).map_err(|_| Error::BadDecryptKey)?;
    let mut out = [0u8; AuthKey::SIZE];
    scrypt::scrypt(passcode, salt, &params, &mut out).map_err(|_| Error::BadDecryptKey)?;
    Ok(out)
}
