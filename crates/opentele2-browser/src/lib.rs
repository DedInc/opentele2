//! Browser HTTP header and fingerprint generation from the Apify fingerprint
//! datapoints, based on [browserforge].
//!
//! The crate embeds the three Bayesian networks of
//! `apify_fingerprint_datapoints` 0.15.0 (see `data/SOURCE.md`) and samples
//! them exactly as browserforge's `bayesian_network.py` does, with two
//! deliberate differences: every random draw comes from the seedable
//! [`Rng`], and every set operation keeps first-seen order instead of
//! Python's hash order, so a seed reproduces its output on any platform.
//!
//! [browserforge]: https://github.com/daijro/browserforge

pub mod fingerprint;
pub mod headers;
mod map;
pub mod network;
pub mod rng;
mod zip;

pub use fingerprint::{
    Fingerprint, FingerprintGenerator, FingerprintOptions, FingerprintOverrides,
    NavigatorFingerprint, Screen, ScreenFingerprint, VideoCard, generate_fingerprint,
    generate_headers,
};
pub use headers::{
    Browser, HeaderGenerator, HeaderOptions, HeaderOverrides, Headers, HttpVersion, browser_of,
    get_user_agent, pascalize,
};
pub use map::{OrderedMap, Restrictions, Values};
pub use network::{BayesianNetwork, Node, fingerprint_network, header_network, input_network};
pub use rng::Rng;

/// The message browserforge raises for an unsatisfiable constraint closure.
const TOO_RESTRICTIVE: &str = "The current constraints are too restrictive. No possible values can be found for the given constraints.";

/// The message browserforge raises when no headers fit the options.
const NO_HEADERS: &str = "No headers based on this input can be generated. Please relax or change some of the requirements you specified.";

/// The message browserforge raises when no fingerprint fits the headers.
const NO_FINGERPRINT: &str = "Cannot generate headers. User-Agent may be invalid, or screen constraints are too restrictive.";

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
    /// Header generator options that browserforge rejects, such as a browser
    /// whose minimum version exceeds its maximum or more than ten locales.
    #[error("invalid header options: {0}")]
    InvalidOptions(String),
    /// No input sample satisfies the options, even after the permitted
    /// relaxations.
    #[error("{NO_HEADERS}")]
    NoHeaders,
    /// The generated headers carry no `User-Agent`.
    #[error("Failed to find User-Agent in generated response")]
    MissingUserAgent,
    /// The fingerprint network has no sample for the generated `User-Agent`
    /// (and, when strict, the screen constraint).
    #[error("{NO_FINGERPRINT}")]
    NoFingerprint,
    /// The generated `User-Agent` names no known browser.
    #[error("Failed to find browser in User-Agent {0:?}")]
    UnknownBrowser(String),
    /// An embedded JSON data file is malformed.
    #[error("malformed embedded data: {0}")]
    Data(String),
    /// The operating system could not provide entropy.
    #[error("operating system entropy unavailable: {0}")]
    Entropy(#[source] getrandom::Error),
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;
