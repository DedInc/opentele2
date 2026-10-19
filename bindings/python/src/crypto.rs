//! Crypto and KDF functions, and the cryptg-compatible submodule.
//!
//! Every function copies its inputs and runs the work with the thread
//! detached from the interpreter.

use std::borrow::Cow;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use opentele2_core::{crypto, kdf};

use crate::convert::{fixed_bytes, to_auth_key, to_bytes, to_passcode};
use crate::error::{check, check_value};

/// The key id of a 256-byte auth key: the little-endian `u64` of
/// `sha1(key)[12:20]`.
#[pyfunction]
fn key_id(py: Python<'_>, auth_key: &Bound<'_, PyAny>) -> PyResult<u64> {
    let key = to_auth_key(py, auth_key)?;
    Ok(py.detach(move || key.key_id()))
}

/// The AES-256 key and IGE IV for `msg_key` (`prepareAES_oldmtp`); `send`
/// selects the key offset, `False` for local storage.
#[pyfunction]
#[pyo3(signature = (auth_key, msg_key, send = false))]
fn prepare_aes_oldmtp<'py>(
    py: Python<'py>,
    auth_key: &Bound<'py, PyAny>,
    msg_key: &Bound<'py, PyAny>,
    send: bool,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let key = to_auth_key(py, auth_key)?;
    let msg_key = fixed_bytes::<{ crypto::MSG_KEY_SIZE }>(py, msg_key, "msg key")?;
    let (aes_key, aes_iv) = py.detach(move || crypto::prepare_aes_oldmtp(&key, &msg_key, send));
    Ok((to_bytes(py, &aes_key), to_bytes(py, &aes_iv)))
}

/// Runs AES-256-IGE over a copy of `data`.
fn ige(
    py: Python<'_>,
    data: Cow<'_, [u8]>,
    key: Cow<'_, [u8]>,
    iv: Cow<'_, [u8]>,
    encrypt: bool,
) -> opentele2_core::Result<Vec<u8>> {
    let mut buf = data.into_owned();
    let key = key.into_owned();
    let iv = iv.into_owned();
    py.detach(move || {
        if encrypt {
            crypto::aes_ige_encrypt(&mut buf, &key, &iv)?;
        } else {
            crypto::aes_ige_decrypt(&mut buf, &key, &iv)?;
        }
        Ok(buf)
    })
}

/// Encrypts `data` with AES-256-IGE. `data` must be a multiple of 16 bytes,
/// `key` and `iv` 32 bytes each; otherwise `CoreError` `BAD_LENGTH`.
#[pyfunction]
fn aes_ige_encrypt<'py>(
    py: Python<'py>,
    data: Cow<'_, [u8]>,
    key: Cow<'_, [u8]>,
    iv: Cow<'_, [u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let out = check(py, ige(py, data, key, iv, true))?;
    Ok(to_bytes(py, &out))
}

/// Decrypts `data` with AES-256-IGE; lengths as [`aes_ige_encrypt`].
#[pyfunction]
fn aes_ige_decrypt<'py>(
    py: Python<'py>,
    data: Cow<'_, [u8]>,
    key: Cow<'_, [u8]>,
    iv: Cow<'_, [u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let out = check(py, ige(py, data, key, iv, false))?;
    Ok(to_bytes(py, &out))
}

/// Encrypts `data` for local storage (`Storage::PrepareEncrypted`) under a
/// 256-byte local key, with padding from the OS random source.
#[pyfunction]
fn encrypt_local<'py>(
    py: Python<'py>,
    data: Cow<'_, [u8]>,
    local_key: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let key = to_auth_key(py, local_key)?;
    let data = data.into_owned();
    let out = check(
        py,
        py.detach(move || crypto::encrypt_local_random(&data, &key)),
    )?;
    Ok(to_bytes(py, &out))
}

/// Decrypts local storage data (`Storage::DecryptLocal`) and returns the
/// payload without its length header and padding.
#[pyfunction]
fn decrypt_local<'py>(
    py: Python<'py>,
    encrypted: Cow<'_, [u8]>,
    local_key: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let key = to_auth_key(py, local_key)?;
    let encrypted = encrypted.into_owned();
    let out = check(
        py,
        py.detach(move || crypto::decrypt_local(&encrypted, &key)),
    )?;
    Ok(to_bytes(py, &out))
}

/// The local key for `passcode` and `salt` (`Storage::CreateLocalKey`),
/// 256 bytes.
#[pyfunction]
fn create_local_key<'py>(
    py: Python<'py>,
    passcode: &Bound<'py, PyAny>,
    salt: Cow<'_, [u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let passcode = to_passcode(Some(passcode))?;
    let salt = salt.into_owned();
    let key = py.detach(move || kdf::create_local_key(&passcode, &salt));
    Ok(to_bytes(py, key.as_bytes()))
}

/// The pre-1.x local key for `passcode` and `salt`
/// (`Storage::CreateLegacyLocalKey`), 256 bytes.
#[pyfunction]
fn create_legacy_local_key<'py>(
    py: Python<'py>,
    passcode: &Bound<'py, PyAny>,
    salt: Cow<'_, [u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let passcode = to_passcode(Some(passcode))?;
    let salt = salt.into_owned();
    let key = py.detach(move || kdf::create_legacy_local_key(&passcode, &salt));
    Ok(to_bytes(py, key.as_bytes()))
}

/// A 256-byte Argon2id (version 0x13) passcode wrap key; `memory_kib` is the
/// memory cost in KiB, `time` the pass count, `lanes` the parallelism.
#[pyfunction]
fn argon2id<'py>(
    py: Python<'py>,
    passcode: &Bound<'py, PyAny>,
    salt: Cow<'_, [u8]>,
    memory_kib: u32,
    time: u32,
    lanes: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let passcode = to_passcode(Some(passcode))?;
    let salt = salt.into_owned();
    let key = check(
        py,
        py.detach(move || kdf::argon2id(&passcode, &salt, memory_kib, time, lanes)),
    )?;
    Ok(to_bytes(py, &key))
}

/// cryptg 0.6.0 `encrypt_ige`: AES-256-IGE encryption; `ValueError` when
/// `data` is not whole 16-byte blocks or `key`/`iv` are not 32 bytes.
#[pyfunction]
#[pyo3(name = "encrypt_ige")]
fn cryptg_encrypt_ige<'py>(
    py: Python<'py>,
    data: Cow<'_, [u8]>,
    key: Cow<'_, [u8]>,
    iv: Cow<'_, [u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let out = check_value(ige(py, data, key, iv, true))?;
    Ok(to_bytes(py, &out))
}

/// cryptg 0.6.0 `decrypt_ige`: AES-256-IGE decryption; `ValueError` on bad
/// lengths as `encrypt_ige`.
#[pyfunction]
#[pyo3(name = "decrypt_ige")]
fn cryptg_decrypt_ige<'py>(
    py: Python<'py>,
    data: Cow<'_, [u8]>,
    key: Cow<'_, [u8]>,
    iv: Cow<'_, [u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let out = check_value(ige(py, data, key, iv, false))?;
    Ok(to_bytes(py, &out))
}

/// Adds the crypto functions to `module`.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(key_id, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_aes_oldmtp, module)?)?;
    module.add_function(wrap_pyfunction!(aes_ige_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes_ige_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_local, module)?)?;
    module.add_function(wrap_pyfunction!(decrypt_local, module)?)?;
    module.add_function(wrap_pyfunction!(create_local_key, module)?)?;
    module.add_function(wrap_pyfunction!(create_legacy_local_key, module)?)?;
    module.add_function(wrap_pyfunction!(argon2id, module)?)?;
    Ok(())
}

/// The `opentele2._native.cryptg` submodule, also registered in
/// `sys.modules` so `import opentele2._native.cryptg` works.
pub(crate) fn register_cryptg(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    let cryptg = PyModule::new(py, "opentele2._native.cryptg")?;
    cryptg.setattr(
        "__doc__",
        "AES-256-IGE with the cryptg 0.6.0 interface, for Telethon.",
    )?;
    cryptg.add_function(wrap_pyfunction!(cryptg_encrypt_ige, &cryptg)?)?;
    cryptg.add_function(wrap_pyfunction!(cryptg_decrypt_ige, &cryptg)?)?;
    module.add_submodule(&cryptg)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("opentele2._native.cryptg", &cryptg)?;
    Ok(())
}
