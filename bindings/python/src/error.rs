//! The single `CoreError` exception and the mapping of core errors onto it.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyType};

use opentele2_core::Error;

/// `CoreError` is a plain Python class: abi3 below 3.12 cannot subclass a
/// native exception from Rust, and a Python class keeps `code` and `message`
/// as ordinary attributes that survive pickling through `args`.
const CORE_ERROR_SOURCE: &std::ffi::CStr = cr#"
class CoreError(Exception):
    """An error raised by the opentele2 core.

    ``code`` is a stable SCREAMING_SNAKE identifier such as
    ``"TDATA_WRONG_PASSCODE"``; ``message`` is human-readable text that may
    change between releases.
    """

    def __init__(self, code, message):
        super().__init__(code, message)
        self.code = code
        self.message = message

    def __str__(self):
        return "%s: %s" % (self.code, self.message)
"#;

static CORE_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();

/// The `CoreError` class, created on first use.
pub(crate) fn core_error_type(py: Python<'_>) -> PyResult<&Bound<'_, PyType>> {
    CORE_ERROR
        .get_or_try_init(py, || {
            let namespace = PyDict::new(py);
            namespace.set_item("__name__", "opentele2_core")?;
            py.run(CORE_ERROR_SOURCE, Some(&namespace), None)?;
            let class = namespace
                .get_item("CoreError")?
                .ok_or_else(|| PyRuntimeError::new_err("CoreError was not defined"))?;
            Ok::<_, PyErr>(class.cast_into::<PyType>()?.unbind())
        })
        .map(|class| class.bind(py))
}

/// A `CoreError` instance for `error`, not raised.
pub(crate) fn core_error_value<'py>(py: Python<'py>, error: &Error) -> PyResult<Bound<'py, PyAny>> {
    core_error_type(py)?.call1((error.code(), error.to_string()))
}

/// `error` as a raisable `CoreError`.
pub(crate) fn core_error(py: Python<'_>, error: &Error) -> PyErr {
    match core_error_value(py, error) {
        Ok(value) => PyErr::from_value(value),
        Err(failure) => failure,
    }
}

/// Maps a core result onto a Python result raising `CoreError`.
pub(crate) fn check<T>(py: Python<'_>, result: opentele2_core::Result<T>) -> PyResult<T> {
    result.map_err(|error| core_error(py, &error))
}

/// Maps a core result onto a Python result raising `ValueError`, the
/// contract of cryptg.
pub(crate) fn check_value<T>(result: opentele2_core::Result<T>) -> PyResult<T> {
    result.map_err(|error| PyValueError::new_err(error.to_string()))
}
