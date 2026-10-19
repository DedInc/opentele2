//! AES-256-IGE and the passcode KDFs.
//!
//! IGE runs synchronously, as mtcute calls it once per packet; the KDFs
//! take hundreds of milliseconds and run as async tasks on the libuv pool.

use napi::Task;
use napi::bindgen_prelude::{AsyncTask, Buffer, Either, Env, Uint8Array};
use napi_derive::napi;

use opentele2_core::{crypto, kdf};

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
        Ok(match self.kdf {
            Kdf::Local => Ok(kdf::create_local_key(passcode, salt).as_bytes().to_vec()),
            Kdf::Legacy => Ok(kdf::create_legacy_local_key(passcode, salt)
                .as_bytes()
                .to_vec()),
            Kdf::Argon2id {
                memory_kib,
                time,
                lanes,
            } => kdf::argon2id(passcode, salt, memory_kib, time, lanes).map(|key| key.to_vec()),
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
