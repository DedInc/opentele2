//! The mapping of core errors onto JavaScript `Error`s with a `code`.
//!
//! A core failure becomes an `Error` whose `code` is `"OT_"` followed by
//! [`opentele2_core::Error::code`], for example `"OT_TDATA_WRONG_PASSCODE"`,
//! and whose `message` is the core's human-readable text. An argument the
//! core never sees, such as an unknown client name, raises an `Error` with
//! Node's `"ERR_INVALID_ARG_VALUE"` code.

use napi::bindgen_prelude::{Env, JsError};

/// The `code` prefix of every core error.
const CODE_PREFIX: &str = "OT_";

/// The `code` of an argument the binding rejects before reaching the core.
const INVALID_ARG: &str = "ERR_INVALID_ARG_VALUE";

/// A JavaScript error whose `code` is the string status.
pub(crate) type CodedError = napi::Error<String>;

/// The result of every binding function; the error is thrown, or rejects the
/// promise, as an `Error` carrying its `code`.
pub(crate) type Result<T> = std::result::Result<T, CodedError>;

/// `error` as an `Error` with `code` `"OT_<CODE>"`.
pub(crate) fn core_error(error: &opentele2_core::Error) -> CodedError {
    CodedError::new(format!("{CODE_PREFIX}{}", error.code()), error.to_string())
}

/// An `Error` with `code` `"ERR_INVALID_ARG_VALUE"`.
pub(crate) fn invalid_arg(message: impl ToString) -> CodedError {
    CodedError::new(INVALID_ARG.to_owned(), message)
}

/// Maps a core result onto a binding result.
pub(crate) fn check<T>(result: opentele2_core::Result<T>) -> Result<T> {
    result.map_err(|error| core_error(&error))
}

/// `error` as the `napi::Error` an async task rejects with.
///
/// A task can only reject with a `Status`-coded error, whose `code` would
/// be the status name. The JavaScript `Error` is therefore built here, on
/// the main thread, and captured by reference, so the promise rejects with
/// that very object and its `"OT_"` code.
pub(crate) fn rejection(env: Env, error: CodedError) -> napi::Error {
    napi::Error::from(JsError::from(error).into_unknown(env))
}
