//! AES-256-IGE and AES-256-CTR, the hashes, the passcode KDFs and PBKDF2,
//! `pq` factorisation, gzip and the OS random source: every primitive of an
//! mtcute crypto provider.
//!
//! The per-packet primitives run synchronously, as mtcute calls them once
//! per packet; the KDFs and PBKDF2 take hundreds of milliseconds and run as
//! async tasks on the libuv pool.

use napi::Task;
use napi::bindgen_prelude::{AsyncTask, Buffer, Either, Env, Uint8Array};
use napi_derive::napi;

use opentele2_core::{compress, crypto, kdf};

use crate::convert::to_passcode;
use crate::error::{Result, check, core_error, rejection, thrown};

/// Runs AES-256-IGE over a copy of `data`.
fn ige(data: &[u8], key: &[u8], iv: &[u8], encrypt: bool) -> Result<Buffer> {
    let mut buf = data.to_vec();
    if encrypt {
        check(crypto::aes_ige_encrypt(&mut buf, key, iv))?;
    } else {
        check(crypto::aes_ige_decrypt(&mut buf, key, iv))?;
    }
    Ok(Buffer::from(buf))
}

/// Encrypts `data` with AES-256-IGE. `data` must be whole 16-byte blocks and
/// `key` and `iv` 32 bytes each; otherwise throws `OT_BAD_LENGTH`.
#[napi]
pub fn aes_ige_encrypt(env: Env, data: &[u8], key: &[u8], iv: &[u8]) -> napi::Result<Buffer> {
    thrown(env, ige(data, key, iv, true))
}

/// Decrypts `data` with AES-256-IGE; lengths as `aesIgeEncrypt`.
#[napi]
pub fn aes_ige_decrypt(env: Env, data: &[u8], key: &[u8], iv: &[u8]) -> napi::Result<Buffer> {
    thrown(env, ige(data, key, iv, false))
}

/// An AES-256-CTR keystream (OpenSSL `aes-256-ctr`: the 16-byte IV is a
/// 128-bit big-endian counter). The keystream continues across `process`
/// calls, so data processed in pieces gives the same bytes as in one call;
/// encryption and decryption are the same operation.
#[napi]
pub struct AesCtr(crypto::AesCtr);

#[napi]
impl AesCtr {
    /// Starts a keystream under the 32-byte `key` at the 16-byte counter
    /// `iv`; other lengths throw `OT_BAD_LENGTH`.
    #[napi(constructor)]
    pub fn new(env: Env, key: &[u8], iv: &[u8]) -> napi::Result<Self> {
        thrown(env, check(crypto::AesCtr::new(key, iv)).map(Self))
    }

    /// XORs the next `data.length` keystream bytes into a copy of `data`.
    #[napi]
    pub fn process(&mut self, data: &[u8]) -> Buffer {
        let mut buf = data.to_vec();
        self.0.apply(&mut buf);
        Buffer::from(buf)
    }
}

/// The 20-byte SHA-1 of `data`.
#[napi]
#[must_use]
pub fn sha1(data: &[u8]) -> Buffer {
    Buffer::from(crypto::sha1(data).to_vec())
}

/// The 32-byte SHA-256 of `data`.
#[napi]
#[must_use]
pub fn sha256(data: &[u8]) -> Buffer {
    Buffer::from(crypto::sha256(data).to_vec())
}

/// The 32-byte HMAC-SHA256 of `data` under `key`, which may have any
/// length. The key comes first, as in `createHmac(key).update(data)`.
#[napi]
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Buffer {
    Buffer::from(crypto::hmac_sha256(key, data).to_vec())
}

/// The factors `[p, q]` of the `MTProto` `pq`, `p <= q`, as minimal
/// big-endian bytes. `pq` is 1 to 8 big-endian bytes, otherwise throws
/// `OT_BAD_LENGTH`; 0, 1 or a prime throws `OT_INVALID_INPUT`.
#[napi]
pub fn factorize_pq(env: Env, pq: &[u8]) -> napi::Result<(Buffer, Buffer)> {
    thrown(
        env,
        check(crypto::factorize_pq(pq)).map(|(p, q)| (Buffer::from(p), Buffer::from(q))),
    )
}

/// A `Uint8Array` argument borrowed mutably for the length of one call.
///
/// napi-derive reads a written `&mut [u8]` parameter as a class reference;
/// through the alias it takes napi's `FromNapiValue for &mut [u8]`, which
/// views the array's own bytes (offset included) instead of copying them.
/// The `'static` is only what that impl yields: the slice never leaves the
/// call that receives it.
type BytesMut = &'static mut [u8];

/// Fills `buf` in place from the operating system's CSPRNG; a failing
/// source throws `OT_IO`.
#[napi(ts_args_type = "buf: Uint8Array")]
pub fn random_fill(env: Env, buf: BytesMut) -> napi::Result<()> {
    thrown(env, check(crypto::random_fill(buf)))
}

/// `size` bytes from the operating system's CSPRNG.
#[napi]
pub fn random_bytes(env: Env, size: u32) -> napi::Result<Buffer> {
    let mut buf = vec![0u8; size as usize];
    thrown(env, check(crypto::random_fill(&mut buf)))?;
    Ok(Buffer::from(buf))
}

/// `data` gzipped at the default level, or `null` when the output would be
/// longer than `maxSize` bytes; without `maxSize` there is no limit.
#[napi]
#[must_use]
pub fn gzip(data: &[u8], max_size: Option<u32>) -> Option<Buffer> {
    compress::gzip(data, max_size.map(|size| size as usize)).map(Buffer::from)
}

/// Decompresses one gzip member; data that is not a whole, intact gzip
/// stream throws `OT_IO`.
#[napi]
pub fn gunzip(env: Env, data: &[u8]) -> napi::Result<Buffer> {
    thrown(env, check(compress::gunzip(data)).map(Buffer::from))
}

/// Which passcode KDF a [`KdfTask`] runs.
enum Kdf {
    /// `Storage::CreateLocalKey`.
    Local,
    /// `Storage::CreateLegacyLocalKey`.
    Legacy,
    /// Argon2id version 0x13 with its costs.
    Argon2id {
        memory_kib: u32,
        time: u32,
        lanes: u32,
    },
    /// PBKDF2 over the HMAC of the digest named `digest`.
    Pbkdf2 {
        iterations: u32,
        key_len: usize,
        digest: String,
    },
}

/// One KDF call, run off the JavaScript thread.
pub struct KdfTask {
    kdf: Kdf,
    passcode: Vec<u8>,
    salt: Vec<u8>,
}

#[napi]
impl Task for KdfTask {
    type Output = opentele2_core::Result<Vec<u8>>;
    type JsValue = Buffer;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let (passcode, salt) = (&self.passcode, &self.salt);
        Ok(match &self.kdf {
            Kdf::Local => Ok(kdf::create_local_key(passcode, salt).as_bytes().to_vec()),
            Kdf::Legacy => Ok(kdf::create_legacy_local_key(passcode, salt)
                .as_bytes()
                .to_vec()),
            Kdf::Argon2id {
                memory_kib,
                time,
                lanes,
            } => kdf::argon2id(passcode, salt, *memory_kib, *time, *lanes).map(|key| key.to_vec()),
            Kdf::Pbkdf2 {
                iterations,
                key_len,
                digest,
            } => crypto::Digest::from_name(digest)
                .and_then(|digest| crypto::pbkdf2(passcode, salt, *iterations, *key_len, digest)),
        })
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<Buffer> {
        match output {
            Ok(key) => Ok(Buffer::from(key)),
            Err(error) => Err(rejection(env, core_error(&error))),
        }
    }
}

/// A [`KdfTask`] over copies of the arguments.
fn kdf_task(kdf: Kdf, passcode: Either<String, Uint8Array>, salt: &[u8]) -> AsyncTask<KdfTask> {
    AsyncTask::new(KdfTask {
        kdf,
        passcode: to_passcode(Some(passcode)),
        salt: salt.to_vec(),
    })
}

/// The 256-byte local key for `passcode` and `salt`
/// (`Storage::CreateLocalKey`); a string passcode is UTF-8 encoded.
#[napi]
pub fn create_local_key(passcode: Either<String, Uint8Array>, salt: &[u8]) -> AsyncTask<KdfTask> {
    kdf_task(Kdf::Local, passcode, salt)
}

/// The 256-byte pre-1.x local key for `passcode` and `salt`
/// (`Storage::CreateLegacyLocalKey`).
#[napi]
pub fn create_legacy_local_key(
    passcode: Either<String, Uint8Array>,
    salt: &[u8],
) -> AsyncTask<KdfTask> {
    kdf_task(Kdf::Legacy, passcode, salt)
}

/// A 256-byte Argon2id (version 0x13) passcode wrap key; `memoryKib` is the
/// memory cost in KiB, `time` the pass count and `lanes` the parallelism.
/// An empty passcode, a salt under 8 bytes or a cost above its cap rejects
/// with `OT_BAD_LENGTH`; a zero cost with `OT_TDATA_BAD_DECRYPT_KEY`.
#[napi(js_name = "argon2id")]
pub fn argon2id(
    passcode: Either<String, Uint8Array>,
    salt: &[u8],
    memory_kib: u32,
    time: u32,
    lanes: u32,
) -> AsyncTask<KdfTask> {
    let kdf = Kdf::Argon2id {
        memory_kib,
        time,
        lanes,
    };
    kdf_task(kdf, passcode, salt)
}

/// PBKDF2 (RFC 8018) of `password` and `salt`: `keyLen` bytes (default 64)
/// over the HMAC of `digest`, `"sha1"`, `"sha256"` or `"sha512"` (the
/// default), ignoring case. A string password is UTF-8 encoded. Zero
/// iterations or another digest rejects with `OT_INVALID_INPUT`.
#[napi]
pub fn pbkdf2(
    password: Either<String, Uint8Array>,
    salt: &[u8],
    iterations: u32,
    key_len: Option<u32>,
    digest: Option<String>,
) -> AsyncTask<KdfTask> {
    let kdf = Kdf::Pbkdf2 {
        iterations,
        key_len: key_len.map_or(64, |len| len as usize),
        digest: digest.unwrap_or_else(|| "sha512".to_owned()),
    };
    kdf_task(kdf, password, salt)
}
