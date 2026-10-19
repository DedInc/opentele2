//! Python bindings of opentele2-core, built as the abi3 extension module
//! `opentele2._native` of the `opentele2` package.
//!
//! Every function that does crypto, KDF, file IO, batch, SRP or network
//! work copies its inputs into owned Rust values and runs with the thread
//! detached from the interpreter. Core failures raise one
//! `opentele2._native.CoreError(code, message)`; the cryptg-compatible
//! submodule raises `ValueError` instead.

mod api;
mod auth;
mod convert;
mod crypto;
mod draws;
mod error;
mod fingerprint;
mod json;
mod session;
mod tdata;
mod versions;

use pyo3::prelude::*;

/// The Cargo version in PEP 440 form, as maturin writes it into the wheel
/// metadata: `2.0.0-alpha.1` becomes `2.0.0a1`.
fn pep440_version(cargo: &str) -> String {
    let Some((release, pre)) = cargo.split_once('-') else {
        return cargo.to_owned();
    };
    let (kind, number) = pre.split_once('.').unwrap_or((pre, "0"));
    let tag = match kind {
        "alpha" => "a",
        "beta" => "b",
        "rc" => "rc",
        _ => return cargo.to_owned(),
    };
    format!("{release}{tag}{number}")
}

/// Telegram Desktop tdata formats, crypto, string sessions and API
/// fingerprints from the Rust core of opentele2.
#[pymodule(name = "_native")]
fn native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", pep440_version(env!("CARGO_PKG_VERSION")))?;
    module.add("CoreError", error::core_error_type(module.py())?)?;
    crypto::register(module)?;
    crypto::register_cryptg(module)?;
    tdata::register(module)?;
    session::register(module)?;
    api::register(module)?;
    versions::register(module)?;
    fingerprint::register(module)?;
    auth::register(module)?;
    Ok(())
}
