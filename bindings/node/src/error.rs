//! The mapping of core errors onto JavaScript `Error`s with a `code`.
//!
//! A core failure becomes an `Error` whose `code` is `"OT_"` followed by
//! [`opentele2_core::Error::code`], for example `"OT_TDATA_WRONG_PASSCODE"`,
//! whose `message` is the core's human-readable text, and whose
//! `legacyMessage` is the message of the matching Python exception
//! ([`opentele2_core::Error::legacy_message`]); an `"OT_"` error the core
//! has no such message for, such as an SRP refusal, repeats its `message`
//! there. An argument the core never sees, such as an unknown client name,
//! raises an `Error` with Node's `"ERR_INVALID_ARG_VALUE"` code and no
//! `legacyMessage`.
//!
//! `legacyMessage` is an own property of the JavaScript object, so it can
//! only be set once that object exists: every function that can fail with
//! an `"OT_"` error takes the [`Env`] and throws through [`thrown`], and
//! every task rejects through [`rejection`].

use napi::JsValue;
use napi::Status;
use napi::bindgen_prelude::{Env, JsError, JsObjectValue, Object};

/// The `code` prefix of every core error.
const CODE_PREFIX: &str = "OT_";

/// The `code` of an argument the binding rejects before reaching the core.
const INVALID_ARG: &str = "ERR_INVALID_ARG_VALUE";

/// The property holding the Python exception message of an `"OT_"` error.
const LEGACY_MESSAGE: &str = "legacyMessage";

/// A JavaScript error whose `code` is the string status.
pub(crate) type CodedError = napi::Error<String>;

/// The result of every binding function; the error is thrown, or rejects the
/// promise, as an `Error` carrying its `code`.
pub(crate) type Result<T> = std::result::Result<T, CodedError>;

/// `error` as an `Error` with `code` `"OT_<CODE>"`.
///
/// Its Python exception message travels as the `cause` until [`rejection`] builds the
/// JavaScript object, which carries it as `legacyMessage` instead.
pub(crate) fn core_error(error: &opentele2_core::Error) -> CodedError {
    let mut coded = CodedError::new(format!("{CODE_PREFIX}{}", error.code()), error.to_string());
    coded.set_cause(napi::Error::new(
        Status::GenericFailure,
        error.legacy_message(),
    ));
    coded
}

/// An `Error` with `code` `"ERR_INVALID_ARG_VALUE"`.
pub(crate) fn invalid_arg(message: impl ToString) -> CodedError {
    CodedError::new(INVALID_ARG.to_owned(), message)
}

/// Maps a core result onto a binding result.
pub(crate) fn check<T>(result: opentele2_core::Result<T>) -> Result<T> {
    result.map_err(|error| core_error(&error))
}

/// `error` as the JavaScript `Error` object a function throws or a task
/// rejects with, wrapped as the `napi::Error` that throws that very object.
///
/// A thrown or rejected `napi::Error` is otherwise rebuilt from its code and
/// message alone, and a task can only reject with a `Status`-coded error,
/// whose `code` would be the status name. The object is therefore built
/// here, on the main thread, with its `"OT_"` code and `legacyMessage`, and
/// captured by reference.
pub(crate) fn rejection(env: Env, mut error: CodedError) -> napi::Error {
    let legacy_message = match error.cause.take() {
        Some(cause) => Some(cause.reason.clone()),
        None if error.status.starts_with(CODE_PREFIX) => Some(error.reason.clone()),
        None => None,
    };
    let value = JsError::from(error).into_unknown(env);
    if let Some(legacy_message) = legacy_message {
        let mut object = Object::from_raw(env.raw(), value.raw());
        // Best effort, as napi's own `cause`: an environment that can no
        // longer write the property still gets the error itself.
        let _ = object.set_named_property(LEGACY_MESSAGE, legacy_message);
    }
    napi::Error::from(value)
}

/// Maps a binding result onto the result of a synchronous function, whose
/// error is thrown as [`rejection`] builds it.
pub(crate) fn thrown<T>(env: Env, result: Result<T>) -> napi::Result<T> {
    result.map_err(|error| rejection(env, error))
}
