//! Telegram Desktop local crypto: auth keys, `prepareAES_oldmtp`, AES-256-IGE
//! and the `tdata` local encryption envelope, plus the primitives an `MTProto`
//! client needs: SHA-1, SHA-256, HMAC-SHA256, PBKDF2, AES-256-CTR, `pq`
//! factorisation and the operating system's random source.
//!
//! AES-IGE itself comes from `grammers-crypto`, which panics on a buffer that
//! is not a whole number of blocks; every wrapper here validates lengths first
//! and returns [`Error::BadLength`] instead.

use std::{fmt, io};

use ::sha1::{Digest as _, Sha1};
use aes::Aes256;
use ctr::cipher::{KeyIvInit as _, StreamCipher as _};
use hmac::{KeyInit as _, Mac as _};
use sha2::{Sha256, Sha512};

use crate::{Error, Result};

/// AES block size in bytes; IGE buffers must be a multiple of it.
pub const AES_BLOCK_SIZE: usize = 16;

/// Size of an AES-256 key and of an IGE initialisation vector, in bytes.
pub const AES_KEY_SIZE: usize = 32;

/// Size of the SHA1-derived message key that prefixes local encrypted data.
pub const MSG_KEY_SIZE: usize = 16;

/// Bytes of the little-endian `u32` length header inside local plaintext.
const LENGTH_HEADER_SIZE: usize = 4;

/// A 256-byte Telegram Desktop authorization or local key (`MTP::AuthKey`).
///
/// `Debug` prints only the key id, never the key material.
#[derive(Clone)]
pub struct AuthKey([u8; AuthKey::SIZE]);

impl AuthKey {
    /// Size of every auth key, in bytes (`AuthKey::kSize`).
    pub const SIZE: usize = 256;

    /// Wraps raw key bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Copies a key from a slice.
    ///
    /// # Errors
    /// [`Error::BadLength`] when `bytes` is not exactly [`AuthKey::SIZE`] long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let key = <[u8; Self::SIZE]>::try_from(bytes).map_err(|_| Error::BadLength {
            what: "auth key",
            expected: Self::SIZE,
            actual: bytes.len(),
        })?;
        Ok(Self(key))
    }

    /// The raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    /// The key id: little-endian `u64` of `sha1(key)[12..20]`.
    #[must_use]
    pub fn key_id(&self) -> u64 {
        let hash = Sha1::digest(self.0);
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash[12..20]);
        u64::from_le_bytes(id)
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthKey")
            .field("key_id", &format_args!("{:#018x}", self.key_id()))
            .finish_non_exhaustive()
    }
}

/// Derives the AES-256 key and IGE IV for `msg_key` (`prepareAES_oldmtp`).
///
/// `send` selects the key offset: 0 when sending, 8 when receiving. Local
/// storage always uses `send = false`.
#[must_use]
pub fn prepare_aes_oldmtp(
    auth_key: &AuthKey,
    msg_key: &[u8; MSG_KEY_SIZE],
    send: bool,
) -> ([u8; AES_KEY_SIZE], [u8; AES_KEY_SIZE]) {
    let x = if send { 0 } else { 8 };
    let key = auth_key.as_bytes();

    let sha1_a = Sha1::new()
        .chain_update(msg_key)
        .chain_update(&key[x..x + 32])
        .finalize();
    let sha1_b = Sha1::new()
        .chain_update(&key[x + 32..x + 48])
        .chain_update(msg_key)
        .chain_update(&key[x + 48..x + 64])
        .finalize();
    let sha1_c = Sha1::new()
        .chain_update(&key[x + 64..x + 96])
        .chain_update(msg_key)
        .finalize();
    let sha1_d = Sha1::new()
        .chain_update(msg_key)
        .chain_update(&key[x + 96..x + 128])
        .finalize();

    let mut aes_key = [0u8; AES_KEY_SIZE];
    aes_key[..8].copy_from_slice(&sha1_a[..8]);
    aes_key[8..20].copy_from_slice(&sha1_b[8..20]);
    aes_key[20..].copy_from_slice(&sha1_c[4..16]);

    let mut aes_iv = [0u8; AES_KEY_SIZE];
    aes_iv[..12].copy_from_slice(&sha1_a[8..20]);
    aes_iv[12..20].copy_from_slice(&sha1_b[..8]);
    aes_iv[20..24].copy_from_slice(&sha1_c[16..20]);
    aes_iv[24..].copy_from_slice(&sha1_d[..8]);

    (aes_key, aes_iv)
}

/// Validates an IGE call and returns the key and IV as arrays.
fn ige_params<'k>(
    buf: &[u8],
    key: &'k [u8],
    iv: &'k [u8],
) -> Result<(&'k [u8; AES_KEY_SIZE], &'k [u8; AES_KEY_SIZE])> {
    if !buf.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(Error::BadLength {
            what: "AES-IGE buffer",
            expected: buf.len().next_multiple_of(AES_BLOCK_SIZE),
            actual: buf.len(),
        });
    }
    let key = <&[u8; AES_KEY_SIZE]>::try_from(key).map_err(|_| Error::BadLength {
        what: "AES-IGE key",
        expected: AES_KEY_SIZE,
        actual: key.len(),
    })?;
    let iv = <&[u8; AES_KEY_SIZE]>::try_from(iv).map_err(|_| Error::BadLength {
        what: "AES-IGE iv",
        expected: AES_KEY_SIZE,
        actual: iv.len(),
    })?;
    Ok((key, iv))
}

/// Encrypts `buf` in place with AES-256-IGE.
///
/// # Errors
/// [`Error::BadLength`] when `buf` is not a multiple of 16 bytes or `key` or
/// `iv` is not 32 bytes; `buf` is left untouched.
pub fn aes_ige_encrypt(buf: &mut [u8], key: &[u8], iv: &[u8]) -> Result<()> {
    let (key, iv) = ige_params(buf, key, iv)?;
    grammers_crypto::aes::ige_encrypt(buf, key, iv);
    Ok(())
}

/// Decrypts `buf` in place with AES-256-IGE.
///
/// # Errors
/// [`Error::BadLength`] when `buf` is not a multiple of 16 bytes or `key` or
/// `iv` is not 32 bytes; `buf` is left untouched.
pub fn aes_ige_decrypt(buf: &mut [u8], key: &[u8], iv: &[u8]) -> Result<()> {
    let (key, iv) = ige_params(buf, key, iv)?;
    grammers_crypto::aes::ige_decrypt(buf, key, iv);
    Ok(())
}

/// Number of padding bytes [`encrypt_local`] requests for `data_len` bytes.
#[must_use]
pub const fn local_padding_len(data_len: usize) -> usize {
    let size = data_len + LENGTH_HEADER_SIZE;
    size.next_multiple_of(AES_BLOCK_SIZE) - size
}

/// Encrypts `data` for local storage (`Storage::PrepareEncrypted`).
///
/// The plaintext is the little-endian `u32` real length (`data.len() + 4`),
/// then `data`, then padding to a 16-byte boundary taken from
/// `padding_source(len)`. The output is `sha1(plaintext)[..16]` followed by
/// the plaintext under AES-256-IGE keyed by
/// `prepare_aes_oldmtp(local_key, msg_key, false)`.
///
/// # Errors
/// [`Error::BadLength`] when `data` is too long for a `u32` length header or
/// `padding_source` returns a buffer of the wrong length.
pub fn encrypt_local(
    data: &[u8],
    local_key: &AuthKey,
    padding_source: impl FnOnce(usize) -> Vec<u8>,
) -> Result<Vec<u8>> {
    let size = data.len() + LENGTH_HEADER_SIZE;
    let real_len = u32::try_from(size).map_err(|_| Error::BadLength {
        what: "local data",
        expected: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
        actual: size,
    })?;
    let padding_len = local_padding_len(data.len());
    let padding = padding_source(padding_len);
    if padding.len() != padding_len {
        return Err(Error::BadLength {
            what: "local padding",
            expected: padding_len,
            actual: padding.len(),
        });
    }

    let mut out = Vec::with_capacity(MSG_KEY_SIZE + size + padding_len);
    out.extend_from_slice(&[0u8; MSG_KEY_SIZE]);
    out.extend_from_slice(&real_len.to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&padding);

    let (head, body) = out.split_at_mut(MSG_KEY_SIZE);
    let mut msg_key = [0u8; MSG_KEY_SIZE];
    msg_key.copy_from_slice(&Sha1::digest(&*body)[..MSG_KEY_SIZE]);
    head.copy_from_slice(&msg_key);

    let (aes_key, aes_iv) = prepare_aes_oldmtp(local_key, &msg_key, false);
    aes_ige_encrypt(body, &aes_key, &aes_iv)?;
    Ok(out)
}

/// [`encrypt_local`] with padding from the operating system's CSPRNG, as
/// Telegram Desktop does.
///
/// # Errors
/// [`Error::Io`] when the system random source fails, otherwise as
/// [`encrypt_local`].
pub fn encrypt_local_random(data: &[u8], local_key: &AuthKey) -> Result<Vec<u8>> {
    let mut padding = vec![0u8; local_padding_len(data.len())];
    random_fill(&mut padding)?;
    encrypt_local(data, local_key, move |_| padding)
}

/// Decrypts local storage data written by [`encrypt_local`]
/// (`Storage::DecryptLocal`) and returns the `data` part, without the
/// length header or padding.
///
/// # Errors
/// - [`Error::BadEncryptedDataSize`] when `encrypted` is at most 16 bytes or
///   not a multiple of 16.
/// - [`Error::BadDecryptKey`] when the decrypted SHA1 does not match the
///   message key, which usually means a wrong passcode.
/// - [`Error::BadDecryptedDataSize`] when the length header does not fit.
pub fn decrypt_local(encrypted: &[u8], local_key: &AuthKey) -> Result<Vec<u8>> {
    let encrypted_size = encrypted.len();
    if encrypted_size <= AES_BLOCK_SIZE || !encrypted_size.is_multiple_of(AES_BLOCK_SIZE) {
        return Err(Error::BadEncryptedDataSize {
            size: encrypted_size,
        });
    }

    let mut msg_key = [0u8; MSG_KEY_SIZE];
    msg_key.copy_from_slice(&encrypted[..MSG_KEY_SIZE]);
    let mut decrypted = encrypted[MSG_KEY_SIZE..].to_vec();

    let (aes_key, aes_iv) = prepare_aes_oldmtp(local_key, &msg_key, false);
    aes_ige_decrypt(&mut decrypted, &aes_key, &aes_iv)?;
    if Sha1::digest(&decrypted)[..MSG_KEY_SIZE] != msg_key {
        return Err(Error::BadDecryptKey);
    }

    let full_len = encrypted_size - MSG_KEY_SIZE;
    let bad_size = Error::BadDecryptedDataSize {
        encrypted_size,
        full_len,
        decrypted_size: decrypted.len(),
    };
    let mut header = [0u8; LENGTH_HEADER_SIZE];
    header.copy_from_slice(&decrypted[..LENGTH_HEADER_SIZE]);
    let Ok(data_len) = usize::try_from(u32::from_le_bytes(header)) else {
        return Err(bad_size);
    };
    if data_len > decrypted.len()
        || data_len <= full_len - AES_BLOCK_SIZE
        || data_len < LENGTH_HEADER_SIZE
    {
        return Err(bad_size);
    }

    decrypted.truncate(data_len);
    decrypted.drain(..LENGTH_HEADER_SIZE);
    Ok(decrypted)
}

/// Size of an AES-CTR initial counter block, in bytes.
pub const AES_CTR_IV_SIZE: usize = 16;

/// Largest `pq` [`factorize_pq`] accepts, in bytes.
pub const PQ_MAX_SIZE: usize = 8;

/// HMAC block size of SHA-256, in bytes.
const SHA256_BLOCK_SIZE: usize = 64;

/// SHA-1 of `data` (FIPS 180-4).
#[must_use]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

/// SHA-256 of `data` (FIPS 180-4).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256 of `data` under `key` (RFC 2104); `key` may have any length.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // RFC 2104 hashes a key longer than the block and zero-pads the rest, so
    // the block-sized key gives the same MAC through the infallible `new`.
    let mut block = hmac::digest::Key::<hmac::Hmac<Sha256>>::default();
    if key.len() > SHA256_BLOCK_SIZE {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut mac = hmac::Hmac::<Sha256>::new(&block);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Hash function of the HMAC that [`pbkdf2()`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Digest {
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Digest {
    /// Parses `"sha1"`, `"sha256"` or `"sha512"`, ignoring ASCII case.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] for any other name.
    pub fn from_name(name: &str) -> Result<Self> {
        [
            ("sha1", Self::Sha1),
            ("sha256", Self::Sha256),
            ("sha512", Self::Sha512),
        ]
        .into_iter()
        .find_map(|(known, digest)| name.eq_ignore_ascii_case(known).then_some(digest))
        .ok_or_else(|| Error::InvalidInput {
            what: "PBKDF2 digest",
            reason: format!("unknown digest {name:?}"),
        })
    }
}

/// PBKDF2 (RFC 8018) with HMAC over `digest`, producing `key_len` bytes.
///
/// # Errors
/// [`Error::InvalidInput`] when `iterations` is 0, which RFC 8018 does not
/// define.
pub fn pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
    digest: Digest,
) -> Result<Vec<u8>> {
    if iterations == 0 {
        return Err(Error::InvalidInput {
            what: "PBKDF2 iterations",
            reason: "needs at least one iteration".to_owned(),
        });
    }
    let mut key = vec![0u8; key_len];
    match digest {
        Digest::Sha1 => ::pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, iterations, &mut key),
        Digest::Sha256 => ::pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key),
        Digest::Sha512 => ::pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut key),
    }
    Ok(key)
}

/// AES-256 in CTR mode with the 16-byte IV as a 128-bit big-endian counter,
/// as OpenSSL's `aes-256-ctr`.
///
/// The keystream continues across [`AesCtr::apply`] calls, so a buffer
/// processed in pieces gives the same bytes as in one call. Encryption and
/// decryption are the same operation. `Debug` never prints key material.
pub struct AesCtr(ctr::Ctr128BE<Aes256>);

impl AesCtr {
    /// Starts a keystream at counter `iv` under `key`.
    ///
    /// # Errors
    /// [`Error::BadLength`] when `key` is not 32 bytes or `iv` is not 16.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        let key = <[u8; AES_KEY_SIZE]>::try_from(key).map_err(|_| Error::BadLength {
            what: "AES-CTR key",
            expected: AES_KEY_SIZE,
            actual: key.len(),
        })?;
        let iv = <[u8; AES_CTR_IV_SIZE]>::try_from(iv).map_err(|_| Error::BadLength {
            what: "AES-CTR iv",
            expected: AES_CTR_IV_SIZE,
            actual: iv.len(),
        })?;
        Ok(Self(ctr::Ctr128BE::<Aes256>::new(&key.into(), &iv.into())))
    }

    /// XORs the next `buf.len()` keystream bytes into `buf`.
    pub fn apply(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}

impl fmt::Debug for AesCtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesCtr").finish_non_exhaustive()
    }
}

/// Splits the `MTProto` `pq` into its factors `p <= q`.
///
/// `pq` is big-endian, 1 to 8 bytes, leading zeros allowed. `p` and `q` are
/// returned as minimal big-endian encodings; they are equal only when `pq`
/// is a square. The factorisation is deterministic Miller-Rabin followed by
/// Pollard-Brent rho, and never panics.
///
/// # Errors
/// - [`Error::BadLength`] when `pq` is empty or longer than 8 bytes.
/// - [`Error::InvalidInput`] when `pq` is 0, 1, or a prime, so it is not a
///   product of two factors greater than 1.
pub fn factorize_pq(pq: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if pq.is_empty() || pq.len() > PQ_MAX_SIZE {
        return Err(Error::BadLength {
            what: "pq",
            expected: PQ_MAX_SIZE,
            actual: pq.len(),
        });
    }
    let mut be = [0u8; PQ_MAX_SIZE];
    be[PQ_MAX_SIZE - pq.len()..].copy_from_slice(pq);
    let n = u64::from_be_bytes(be);
    let factor = find_factor(n).ok_or_else(|| Error::InvalidInput {
        what: "pq",
        reason: format!("{n} is not a product of two factors greater than 1"),
    })?;
    let (p, q) = (factor.min(n / factor), factor.max(n / factor));
    Ok((minimal_be(p), minimal_be(q)))
}

/// `value` big-endian without leading zero bytes.
fn minimal_be(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    bytes[skip..].to_vec()
}

/// A factor `d` of `n` with `1 < d < n`, or `None` when `n` is below 4 or
/// prime.
fn find_factor(n: u64) -> Option<u64> {
    if n < 4 {
        return None;
    }
    if n.is_multiple_of(2) {
        return Some(2);
    }
    if is_prime(n) {
        return None;
    }
    // A composite `n` always yields to some `c`; the range only bounds the
    // search so the function stays total.
    (1..u64::MAX).find_map(|c| pollard_brent(n, c))
}

/// `a * b mod m` without overflow.
fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    let product = u128::from(a) * u128::from(b) % u128::from(m);
    // The remainder is below `m`, so it always fits.
    u64::try_from(product).unwrap_or_default()
}

/// `base^exp mod m`.
fn pow_mod(mut base: u64, mut exp: u64, m: u64) -> u64 {
    let mut result = 1 % m;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mul_mod(result, base, m);
        }
        base = mul_mod(base, base, m);
        exp >>= 1;
    }
    result
}

/// Deterministic Miller-Rabin for odd `n >= 5`: the first twelve primes as
/// bases decide every `u64`.
fn is_prime(n: u64) -> bool {
    const BASES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    let s = (n - 1).trailing_zeros();
    let d = (n - 1) >> s;
    BASES.iter().all(|&a| {
        if a % n == 0 {
            return true;
        }
        let mut x = pow_mod(a, d, n);
        if x == 1 || x == n - 1 {
            return true;
        }
        for _ in 1..s {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                return true;
            }
        }
        false
    })
}

/// Greatest common divisor.
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// One Pollard-Brent rho run over `x -> x^2 + c mod n`: a factor strictly
/// between 1 and `n`, or `None` when this `c` only finds `n` itself.
fn pollard_brent(n: u64, increment: u64) -> Option<u64> {
    const BATCH: u64 = 128;
    let step = |value: u64| {
        let sum = u128::from(mul_mod(value, value, n)) + u128::from(increment);
        u64::try_from(sum % u128::from(n)).unwrap_or_default()
    };
    let (mut anchor, mut walker, mut batch_start) = (2u64, 2u64, 2u64);
    let (mut divisor, mut product, mut span) = (1u64, 1u64, 1u64);
    while divisor == 1 {
        anchor = walker;
        for _ in 0..span {
            walker = step(walker);
        }
        let mut done = 0;
        while done < span && divisor == 1 {
            batch_start = walker;
            for _ in 0..BATCH.min(span - done) {
                walker = step(walker);
                product = mul_mod(product, anchor.abs_diff(walker), n);
            }
            divisor = gcd(product, n);
            done += BATCH;
        }
        span = span.saturating_mul(2);
    }
    if divisor == n {
        // The batch overshot: replay it one step at a time from its start.
        loop {
            batch_start = step(batch_start);
            divisor = gcd(anchor.abs_diff(batch_start), n);
            if divisor > 1 {
                break;
            }
        }
    }
    (divisor != n).then_some(divisor)
}

/// Fills `buf` from the operating system's CSPRNG.
///
/// # Errors
/// [`Error::Io`] when the system random source fails.
pub fn random_fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Io(io::Error::other(e)))
}
