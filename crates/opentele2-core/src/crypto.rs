//! Telegram Desktop local crypto: auth keys, `prepareAES_oldmtp`, AES-256-IGE
//! and the `tdata` local encryption envelope.
//!
//! AES-IGE itself comes from `grammers-crypto`, which panics on a buffer that
//! is not a whole number of blocks; every wrapper here validates lengths first
//! and returns [`Error::BadLength`] instead.

use std::fmt;

use sha1::{Digest, Sha1};

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
    getrandom::fill(&mut padding).map_err(|e| Error::Io(std::io::Error::other(e)))?;
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
