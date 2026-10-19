//! Node.js bindings of opentele2-core, built with napi-rs as the addon of
//! the npm package `opentele2`.
//!
//! Every function copies its inputs into owned Rust values. Per-packet
//! AES-IGE, the string sessions and the pure fingerprint, session and
//! formatting helpers run synchronously; the KDFs, every tdata file
//! operation, legacy key migration, the SRP check and the version fetch are
//! async tasks returning promises. Core failures
//! are JavaScript `Error`s whose `code` is `"OT_"` plus the core's stable
//! error code.
//!
//! napi-derive registers the exports only outside `cfg(test)`, so a test
//! build of this crate would hold nothing but unreachable code; the modules
//! are compiled into the addon alone. Behaviour is tested from Node in
//! `bindings/node/__test__`.

#[cfg(not(test))]
mod api;
#[cfg(not(test))]
mod auth;
#[cfg(not(test))]
mod convert;
#[cfg(not(test))]
mod crypto;
#[cfg(not(test))]
mod draws;
#[cfg(not(test))]
mod error;
#[cfg(not(test))]
mod fingerprint;
#[cfg(not(test))]
mod session;
#[cfg(not(test))]
mod tdata;
#[cfg(not(test))]
mod versions;
