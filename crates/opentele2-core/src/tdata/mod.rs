//! Telegram Desktop `tdata` folder formats, built on the [`crate::tdf`]
//! container, the [`crate::qt`] stream encoding, and the [`crate::crypto`]
//! and [`crate::kdf`] primitives.
//!
//! - [`key_data`]: the `key_<dataName>` file that holds the local key and the
//!   list of accounts.

pub mod key_data;
