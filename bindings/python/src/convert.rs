//! Conversions of Python arguments into owned Rust values.

use std::borrow::Cow;

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyInt, PyString};

use opentele2_core::Error;
use opentele2_core::crypto::AuthKey;

use crate::error::check;

/// Copies a `bytes` or `bytearray` argument.
pub(crate) fn owned_bytes(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    Ok(value.extract::<Cow<'_, [u8]>>()?.into_owned())
}

/// A passcode: `bytes`/`bytearray` as given, `str` encoded as UTF-8, and a
/// missing passcode as empty.
pub(crate) fn to_passcode(value: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<u8>> {
    match value {
        None => Ok(Vec::new()),
        Some(value) if value.is_none() => Ok(Vec::new()),
        Some(value) => match value.cast::<PyString>() {
            Ok(text) => Ok(text.to_cow()?.as_bytes().to_vec()),
            Err(_) => owned_bytes(value),
        },
    }
}

/// A 256-byte auth key argument; a wrong length raises `CoreError`
/// `BAD_LENGTH`.
pub(crate) fn to_auth_key(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<AuthKey> {
    let bytes = value.extract::<Cow<'_, [u8]>>()?;
    check(py, AuthKey::from_slice(&bytes))
}

/// A fixed-size byte argument; a wrong length raises `CoreError`
/// `BAD_LENGTH` naming `what`.
pub(crate) fn fixed_bytes<const N: usize>(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    what: &'static str,
) -> PyResult<[u8; N]> {
    let bytes = value.extract::<Cow<'_, [u8]>>()?;
    let actual = bytes.len();
    check(
        py,
        <[u8; N]>::try_from(bytes.as_ref()).map_err(|_| Error::BadLength {
            what,
            expected: N,
            actual,
        }),
    )
}

/// A device seed: a `str` as given or an `int` as its decimal `str()`, as
/// 1.5.0 hashes it.
pub(crate) fn seed(value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_none()) else {
        return Ok(None);
    };
    if let Ok(text) = value.cast::<PyString>() {
        return Ok(Some(text.to_cow()?.into_owned()));
    }
    if value.is_instance_of::<PyInt>() {
        return Ok(Some(value.str()?.to_cow()?.into_owned()));
    }
    Err(PyTypeError::new_err(format!(
        "seed must be str or int, not {}",
        value.get_type().name()?
    )))
}

/// Copies `bytes` into a new Python `bytes` object.
pub(crate) fn to_bytes<'py>(py: Python<'py>, bytes: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, bytes)
}
