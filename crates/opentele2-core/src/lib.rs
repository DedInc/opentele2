//! Pure core of opentele2.
//!
//! This crate holds every Telegram Desktop `tdata` format and crypto rule
//! shared by the Python and Node bindings. Its contract:
//!
//! - **Pure**: the core transforms bytes and values it is given; it walks no
//!   filesystem beyond explicit paths passed by the caller.
//! - **No async**: every function is synchronous; there is no runtime
//!   dependency such as tokio.
//! - **No network**: the core opens no sockets and speaks no `MTProto`
//!   transport.
//! - **No FFI**: bindings live in separate crates; this crate exports a plain
//!   Rust API and forbids `unsafe` code.
//!
//! Every fallible operation returns [`Result`], whose error type [`Error`]
//! carries a stable [`Error::code`] that bindings map onto their own
//! exception types.
//!
//! The default feature `parallel` runs the [`batch`] entry points over
//! independent folders on a dedicated rayon pool; without it they run
//! sequentially with identical results.

pub mod api;
pub mod auth;
pub mod batch;
pub mod crypto;
pub mod devices;
mod error;
pub mod fingerprint;
pub mod kdf;
pub mod qt;
pub mod session;
pub mod tdata;
pub mod tdf;

pub use error::{Error, KeyDataFailure, MagicContext, MapReadFailure, Result};
