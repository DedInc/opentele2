//! Conversions of Python arguments into owned Rust values.

use std::borrow::Cow;
use std::path::PathBuf;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyInt, PyString};

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

/// A device seed: a `str` as given or an `int` as its decimal `str()`, the
/// text the device pick hashes.
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

/// The value of `key` in `dict`; a missing key raises `TypeError` naming
/// `what`, the dict's role.
pub(crate) fn required<'py, T>(dict: &Bound<'py, PyDict>, key: &str, what: &str) -> PyResult<T>
where
    T: FromPyObjectOwned<'py>,
{
    let value = dict
        .get_item(key)?
        .ok_or_else(|| PyTypeError::new_err(format!("{what} is missing {key:?}")))?;
    value.extract::<T>().map_err(Into::into)
}

/// The value of `key` in `dict`; `None` when the key is missing or `None`.
pub(crate) fn optional<'py, T>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Option<T>>
where
    T: FromPyObjectOwned<'py>,
{
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<T>().map_err(Into::into)?)),
        _ => Ok(None),
    }
}

/// The bytes of `key` in `dict`, `bytes` or `bytearray`; a missing key
/// raises `TypeError` naming `what`.
pub(crate) fn required_bytes(dict: &Bound<'_, PyDict>, key: &str, what: &str) -> PyResult<Vec<u8>> {
    let value = dict
        .get_item(key)?
        .ok_or_else(|| PyTypeError::new_err(format!("{what} is missing {key:?}")))?;
    owned_bytes(&value)
}

/// Every item of the iterable `items` as a dict; another item raises
/// `TypeError` naming `what`.
pub(crate) fn dicts<'py>(
    items: &Bound<'py, PyAny>,
    what: &str,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    items
        .try_iter()?
        .map(|item| {
            item?
                .cast_into::<PyDict>()
                .map_err(|_| PyTypeError::new_err(format!("every {what} must be a dict")))
        })
        .collect()
}

/// A path built from text, as text; every path built from a `str` is one.
pub(crate) fn path_text(path: PathBuf) -> PyResult<String> {
    path.into_os_string()
        .into_string()
        .map_err(|_| PyValueError::new_err("the path is not valid Unicode"))
}
