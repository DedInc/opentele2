//! Browser HTTP header and fingerprint generation from the Apify fingerprint
//! datapoints; a Rust port of [browserforge].
//!
//! The crate embeds the three Bayesian networks of
//! `apify_fingerprint_datapoints` 0.15.0 (see `data/SOURCE.md`) and samples
//! them exactly as browserforge's `bayesian_network.py` does, with two
//! deliberate differences: every random draw comes from the seedable
//! [`Rng`], and every set operation keeps first-seen order instead of
//! Python's hash order, so a seed reproduces its output on any platform.
//!
//! [browserforge]: https://github.com/daijro/browserforge

mod map;
pub mod network;
pub mod rng;
mod zip;

pub use map::{OrderedMap, Restrictions, Values};
pub use network::{BayesianNetwork, Node, fingerprint_network, header_network, input_network};
pub use rng::Rng;

/// The message browserforge raises for an unsatisfiable constraint closure.
const TOO_RESTRICTIVE: &str = "The current constraints are too restrictive. No possible values can be found for the given constraints.";

/// Errors of the crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The constraints leave some node without any possible value.
    #[error("{TOO_RESTRICTIVE}")]
    TooRestrictive,
    /// A constraint names a node the network does not have.
    #[error("unknown network node {0:?}")]
    UnknownNode(String),
    /// A network archive is not a readable zip file.
    #[error("malformed zip archive: {0}")]
    Zip(String),
    /// A network definition is not valid network JSON.
    #[error("malformed network definition: {0}")]
    Network(String),
    /// The operating system could not provide entropy.
    #[error("operating system entropy unavailable: {0}")]
    Entropy(#[source] getrandom::Error),
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;
