//! Browser HTTP header generation, based on browserforge's
//! `headers/generator.py` and `headers/utils.py` (browserforge 1.2.4).
//!
//! The input network draws a browser, operating system and device that fit
//! the [`HeaderOptions`]; the header network then draws the headers given
//! that draw. The result is filtered, ordered as the browser orders its
//! headers (`data/headers-order.json`) and, for HTTP/2, pascalized.
//!
//! The module fixes these browserforge defects, each documented where it
//! lives:
//!
//! 1. the Sec-Fetch headers carry real navigation values ([`SEC_FETCH`]);
//! 2. the operating system option is relaxed (browserforge's relaxation key
//!    `operatingSystems` never matched its `os` option);
//! 3. the HTTP/1 to HTTP/2 fallback cannot fail on its own arguments
//!    (browserforge passed `http_version` twice and raised `TypeError`);
//! 4. [`browser_of`] recognises Edge before Chrome, so Edge headers use the
//!    Edge order;
//! 5. with a `user_agent` override the header network is sampled with the
//!    `User-Agent` restricted to the given values, so the output carries one
//!    of them;
//! 6. at most [`MAX_LOCALES`] locales, so no `q` falls below 0.1;
//! 7. request-dependent headers are kept rather than dropped by the ordering.

use std::collections::HashMap;

use crate::network::{BayesianNetwork, header_network, input_network};
use crate::{Error, OrderedMap, Restrictions, Result, Rng, Values};

/// The browsers browserforge supports, in its default order.
pub const SUPPORTED_BROWSERS: [&str; 4] = ["chrome", "firefox", "safari", "edge"];
/// The operating systems browserforge supports.
pub const SUPPORTED_OPERATING_SYSTEMS: [&str; 5] = ["windows", "macos", "linux", "android", "ios"];
/// The devices browserforge supports.
pub const SUPPORTED_DEVICES: [&str; 2] = ["desktop", "mobile"];
/// The dataset token for an absent header.
pub const MISSING_VALUE: &str = "*MISSING_VALUE*";
/// The most locales an `Accept-Language` header takes.
///
/// Defect (6): browserforge documents this bound but never enforces it, so an
/// eleventh locale got `q=0.0` and later ones negative weights. Ten locales
/// give weights 1.0 down to 0.1.
pub const MAX_LOCALES: usize = 10;

/// The Sec-Fetch headers of a user-initiated top-level navigation, in HTTP/2
/// spelling.
///
/// Defect (1): browserforge assigned these values to the wrong names
/// (`Sec-Fetch-Mode: same-site`, `Sec-Fetch-Dest: navigate`,
/// `Sec-Fetch-Site: ?1`, `Sec-Fetch-User: document`), a combination no
/// browser sends.
pub const SEC_FETCH: [(&str, &str); 4] = [
    ("sec-fetch-site", "same-site"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"),
];

/// How many input samples a `user_agent`-restricted generation draws before
/// it counts as a failed attempt.
///
/// The `user_agent` closures constrain the browser, operating system and
/// device one at a time, so an input sample can combine them in a way no
/// listed User-Agent has (a Safari build on Windows, say); a fresh draw then
/// usually fits.
const UA_INPUT_DRAWS: usize = 16;

const BROWSER_HELPER_JSON: &str = include_str!("../data/browser-helper-file.json");
const HEADERS_ORDER_JSON: &str = include_str!("../data/headers-order.json");

/// Generated headers: name to value, in sending order.
pub type Headers = OrderedMap<String>;

/// The HTTP version of the generated request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HttpVersion {
    /// HTTP/1.1: Pascal-Case header names.
    One,
    /// HTTP/2: lower-case header names in the networks, pascalized on
    /// output.
    #[default]
    Two,
}

impl HttpVersion {
    /// The version as browserforge spells it: `"1"` or `"2"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::One => "1",
            Self::Two => "2",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "1" => Some(Self::One),
            "2" => Some(Self::Two),
            _ => None,
        }
    }
}

/// A browser the headers may come from, with optional bounds on its major
/// version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Browser {
    /// `chrome`, `firefox`, `safari` or `edge`.
    pub name: String,
    /// The lowest major version, inclusive.
    pub min_version: Option<u32>,
    /// The highest major version, inclusive.
    pub max_version: Option<u32>,
    /// The HTTP version the browser speaks.
    pub http_version: HttpVersion,
}

impl Browser {
    /// Any version of `name` over HTTP/2.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            min_version: None,
            max_version: None,
            http_version: HttpVersion::Two,
        }
    }

    fn matches(&self, candidate: &HttpBrowser) -> bool {
        self.name == candidate.name
            && self.min_version.is_none_or(|min| min <= candidate.major)
            && self.max_version.is_none_or(|max| max >= candidate.major)
            && self.http_version == candidate.http_version
    }
}

fn default_browsers(http_version: HttpVersion) -> Vec<Browser> {
    SUPPORTED_BROWSERS
        .iter()
        .map(|&name| Browser {
            http_version,
            ..Browser::new(name)
        })
        .collect()
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|&v| v.to_owned()).collect()
}

/// The options of a [`HeaderGenerator`], defaulting as browserforge does:
/// every supported browser, operating system and device, `en-US`, HTTP/2,
/// not strict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderOptions {
    /// The browsers to draw from; each carries its own HTTP version.
    pub browsers: Vec<Browser>,
    /// The operating systems to draw from.
    pub os: Vec<String>,
    /// The devices to draw from.
    pub devices: Vec<String>,
    /// The `Accept-Language` locales, most preferred first; at most
    /// [`MAX_LOCALES`].
    pub locales: Vec<String>,
    /// The requested HTTP version. HTTP/1 falls back to HTTP/2 when no
    /// HTTP/1 sample fits.
    pub http_version: HttpVersion,
    /// Fail instead of relaxing the options when no sample fits them.
    pub strict: bool,
}

impl Default for HeaderOptions {
    fn default() -> Self {
        Self {
            browsers: default_browsers(HttpVersion::Two),
            os: owned(&SUPPORTED_OPERATING_SYSTEMS),
            devices: owned(&SUPPORTED_DEVICES),
            locales: vec!["en-US".to_owned()],
            http_version: HttpVersion::Two,
            strict: false,
        }
    }
}

impl HeaderOptions {
    /// Sets the requested HTTP version and that of every browser, as
    /// browserforge's `http_version` argument does for browsers given by
    /// name.
    #[must_use]
    pub fn with_http_version(mut self, http_version: HttpVersion) -> Self {
        self.http_version = http_version;
        for browser in &mut self.browsers {
            browser.http_version = http_version;
        }
        self
    }

    /// Resets the first option that differs from its default, in
    /// browserforge's relaxation order: locales, devices, operating systems,
    /// browsers. `false` when every one is already at its default.
    ///
    /// Defect (2): browserforge's order named `operatingSystems`, a key its
    /// options never had, so the operating system was never relaxed.
    fn relax(&mut self) -> bool {
        let defaults = Self::default().with_http_version(self.http_version);
        if self.locales != defaults.locales {
            self.locales = defaults.locales;
        } else if self.devices != defaults.devices {
            self.devices = defaults.devices;
        } else if self.os != defaults.os {
            self.os = defaults.os;
        } else if self.browsers != defaults.browsers {
            self.browsers = defaults.browsers;
        } else {
            return false;
        }
        true
    }
}

/// Per-call additions to the [`HeaderOptions`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderOverrides {
    /// When non-empty, the generated `User-Agent` is one of these.
    pub user_agent: Vec<String>,
    /// Headers that depend on the request (`Referer`, `Cookie`, ...).
    ///
    /// Defect (7): browserforge merged these before ordering, so any name
    /// missing from the browser's order was silently dropped. Here a name
    /// that matches a generated header (ignoring ASCII case) replaces its
    /// value in place; any other is appended after the ordered headers.
    pub request_dependent_headers: Headers,
}

/// A `*BROWSER_HTTP` value: `name/a.b.c|http`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpBrowser {
    name: String,
    major: u32,
    complete: String,
    http_version: HttpVersion,
}

impl HttpBrowser {
    fn parse(value: &str) -> Result<Self> {
        let malformed = || Error::Data(format!("malformed browser entry {value:?}"));
        let (browser, http) = value.split_once('|').ok_or_else(malformed)?;
        let (name, version) = browser.split_once('/').ok_or_else(malformed)?;
        let mut parts = version.split('.');
        let major = parts
            .next()
            .and_then(|part| part.parse().ok())
            .ok_or_else(malformed)?;
        if parts.any(|part| part.parse::<u32>().is_err()) {
            return Err(malformed());
        }
        Ok(Self {
            name: name.to_owned(),
            major,
            complete: value.to_owned(),
            http_version: HttpVersion::parse(http).ok_or_else(malformed)?,
        })
    }

    /// browserforge's `_should_add_sec_fetch`; Safari never sends them.
    fn sends_sec_fetch(&self) -> bool {
        match self.name.as_str() {
            "chrome" => self.major >= 76,
            "firefox" => self.major >= 90,
            "edge" => self.major >= 79,
            _ => false,
        }
    }
}

/// The `possible_values` closures of the `User-Agent` override, per HTTP
/// version.
struct UaClosures {
    http1: Restrictions,
    http2: Restrictions,
}

impl UaClosures {
    fn contains(closure: &Restrictions, key: &str, value: &str) -> bool {
        closure
            .get(key)
            .is_some_and(|values| values.iter().any(|v| v == value))
    }

    /// browserforge's `filter_browser_http`.
    fn allows_browser_http(&self, value: &str) -> bool {
        let (browser, http) = value.split_once('|').unwrap_or((value, ""));
        let closure = if http == "1" {
            &self.http1
        } else {
            &self.http2
        };
        Self::contains(closure, "*BROWSER", browser)
    }

    /// browserforge's `filter_other_values`.
    fn allows(&self, key: &str, value: &str) -> bool {
        Self::contains(&self.http1, key, value) || Self::contains(&self.http2, key, value)
    }
}

/// Generates browser HTTP headers, as browserforge's `HeaderGenerator`.
#[derive(Debug, Clone)]
pub struct HeaderGenerator {
    options: HeaderOptions,
    unique_browsers: Vec<HttpBrowser>,
    headers_order: HashMap<String, Vec<String>>,
}

impl HeaderGenerator {
    /// Builds a generator for `options`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOptions`] for a browser whose minimum version exceeds
    /// its maximum or for more than [`MAX_LOCALES`] locales;
    /// [`Error::Data`] when the embedded browser list or header order is
    /// malformed (never for the shipped data).
    pub fn new(options: HeaderOptions) -> Result<Self> {
        for browser in &options.browsers {
            if let (Some(min), Some(max)) = (browser.min_version, browser.max_version)
                && min > max
            {
                return Err(Error::InvalidOptions(format!(
                    "Browser min version constraint ({min}) cannot exceed max version ({max})"
                )));
            }
        }
        if options.locales.len() > MAX_LOCALES {
            return Err(Error::InvalidOptions(format!(
                "at most {MAX_LOCALES} locales are allowed, got {}",
                options.locales.len()
            )));
        }
        let data_error = |e: serde_json::Error| Error::Data(e.to_string());
        let helper: Vec<String> = serde_json::from_str(BROWSER_HELPER_JSON).map_err(data_error)?;
        let unique_browsers = helper
            .iter()
            .filter(|entry| *entry != MISSING_VALUE)
            .map(|entry| HttpBrowser::parse(entry))
            .collect::<Result<_>>()?;
        let headers_order = serde_json::from_str(HEADERS_ORDER_JSON).map_err(data_error)?;
        Ok(Self {
            options,
            unique_browsers,
            headers_order,
        })
    }

    /// The options the generator was built with.
    #[must_use]
    pub fn options(&self) -> &HeaderOptions {
        &self.options
    }

    /// Generates one set of headers. The same `rng` state, options and
    /// overrides always give the same headers.
    ///
    /// When no input sample fits, HTTP/1 falls back to HTTP/2; then, unless
    /// the options are strict, the first non-default option among locales,
    /// devices, operating systems and browsers is reset and the draw
    /// retried.
    ///
    /// Defect (3): browserforge's fallback passed `http_version` twice and
    /// raised `TypeError` whenever `generate` had been given one; here it
    /// only switches every browser to HTTP/2.
    ///
    /// # Errors
    ///
    /// [`Error::NoHeaders`] when nothing fits and nothing is left to relax
    /// (or the options are strict); [`Error::MissingUserAgent`] or
    /// [`Error::UnknownBrowser`] when the drawn headers cannot be ordered;
    /// the network errors of [`input_network`] and [`header_network`].
    pub fn generate(&self, rng: &mut Rng, overrides: &HeaderOverrides) -> Result<Headers> {
        let input_net = input_network()?;
        let header_net = header_network()?;
        let closures = if overrides.user_agent.is_empty() {
            None
        } else {
            let restrict = |node: &str| -> Result<Restrictions> {
                let mut restriction = Restrictions::new();
                restriction.insert(node, overrides.user_agent.clone());
                header_net.possible_values(&restriction)
            };
            Some(UaClosures {
                http1: restrict("User-Agent")?,
                http2: restrict("user-agent")?,
            })
        };
        let draws = if closures.is_some() {
            UA_INPUT_DRAWS
        } else {
            1
        };

        let mut state = self.options.clone();
        loop {
            let constraints = self.constraints(&state, closures.as_ref());
            for _ in 0..draws {
                let Some(input) = input_net.consistent_sample(rng, &constraints) else {
                    break;
                };
                if let Some(mut headers) =
                    self.headers_for(rng, header_net, &input, &state.locales, overrides)?
                {
                    add_request_dependent(&mut headers, &overrides.request_dependent_headers);
                    return Ok(headers);
                }
            }
            if state.http_version == HttpVersion::One {
                state = state.with_http_version(HttpVersion::Two);
            } else if state.strict || !state.relax() {
                return Err(Error::NoHeaders);
            }
        }
    }

    /// browserforge's `_get_possible_attribute_values` followed by
    /// `_prepare_constraints`.
    fn constraints(&self, state: &HeaderOptions, closures: Option<&UaClosures>) -> Restrictions {
        let mut browser_http: Vec<String> = state
            .browsers
            .iter()
            .flat_map(|browser| {
                self.unique_browsers
                    .iter()
                    .filter(|candidate| browser.matches(candidate))
                    .map(|candidate| candidate.complete.clone())
            })
            .collect();
        let mut os = state.os.clone();
        let mut devices = state.devices.clone();
        if let Some(closures) = closures {
            browser_http.retain(|value| closures.allows_browser_http(value));
            os.retain(|value| closures.allows("*OPERATING_SYSTEM", value));
            devices.retain(|value| closures.allows("*DEVICE", value));
        }
        let mut constraints = Restrictions::new();
        constraints.insert("*BROWSER_HTTP", browser_http);
        constraints.insert("*OPERATING_SYSTEM", os);
        constraints.insert("*DEVICE", devices);
        constraints
    }

    /// The headers for one input sample; `None` when the header network has
    /// no sample with one of the override User-Agents.
    fn headers_for(
        &self,
        rng: &mut Rng,
        header_net: &BayesianNetwork,
        input: &Values,
        locales: &[String],
        overrides: &HeaderOverrides,
    ) -> Result<Option<Headers>> {
        let browser_http = input
            .get("*BROWSER_HTTP")
            .ok_or_else(|| Error::Data("input sample without *BROWSER_HTTP".to_owned()))?;
        let browser = HttpBrowser::parse(browser_http)?;
        let http2 = browser.http_version == HttpVersion::Two;

        // Defect (5): browserforge sampled the header network freely after
        // the input network, so the output User-Agent ignored the override.
        let mut restrictions = Restrictions::new();
        if !overrides.user_agent.is_empty() {
            let node = if http2 { "user-agent" } else { "User-Agent" };
            restrictions.insert(node, overrides.user_agent.clone());
        }
        let Some(mut sample) = header_net.restricted_sample(rng, input, &restrictions) else {
            return Ok(None);
        };

        let accept_language = if http2 {
            "accept-language"
        } else {
            "Accept-Language"
        };
        sample.insert(accept_language, accept_language_header(locales));
        if browser.sends_sec_fetch() {
            for (name, value) in SEC_FETCH {
                let name = if http2 {
                    name.to_owned()
                } else {
                    pascalize(name)
                };
                sample.insert(name, value.to_owned());
            }
        }
        let kept: Headers = sample
            .into_iter()
            .filter(|(name, value)| {
                !(name.starts_with('*')
                    || value == MISSING_VALUE
                    || (name.eq_ignore_ascii_case("connection") && value == "close"))
            })
            .collect();
        let ordered = self.order(kept)?;
        Ok(Some(if http2 {
            ordered
                .into_iter()
                .map(|(name, value)| (pascalize(&name), value))
                .collect()
        } else {
            ordered
        }))
    }

    /// browserforge's `order_headers`: the headers named in the order of the
    /// User-Agent's browser, in that order; the rest are dropped. Headers of
    /// a browser without an order stay as they are.
    fn order(&self, headers: Headers) -> Result<Headers> {
        let user_agent = get_user_agent(&headers).ok_or(Error::MissingUserAgent)?;
        let browser =
            browser_of(user_agent).ok_or_else(|| Error::UnknownBrowser(user_agent.to_owned()))?;
        let Some(order) = self.headers_order.get(browser) else {
            return Ok(headers);
        };
        Ok(order
            .iter()
            .filter_map(|name| {
                headers
                    .get(name)
                    .map(|value| (name.as_str(), value.clone()))
            })
            .collect())
    }
}

/// `l1;q=1.0, l2;q=0.9, ...`, browserforge's `_get_accept_language_header`.
fn accept_language_header(locales: &[String]) -> String {
    locales
        .iter()
        .enumerate()
        .map(|(index, locale)| {
            // Weights in tenths, never below 0.1 (defect (6)).
            let tenths = 10_usize.saturating_sub(index).max(1);
            format!("{locale};q={}.{}", tenths / 10, tenths % 10)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Defect (7): see [`HeaderOverrides::request_dependent_headers`].
fn add_request_dependent(headers: &mut Headers, extra: &Headers) {
    for (name, value) in extra {
        let existing = headers
            .keys()
            .find(|key| key.eq_ignore_ascii_case(name))
            .map(str::to_owned);
        headers.insert(existing.unwrap_or_else(|| name.to_owned()), value.clone());
    }
}

/// The `User-Agent` (or HTTP/2 `user-agent`) of `headers`, browserforge's
/// `get_user_agent`; an empty value counts as absent.
#[must_use]
pub fn get_user_agent(headers: &Headers) -> Option<&str> {
    ["User-Agent", "user-agent"]
        .into_iter()
        .filter_map(|name| headers.get(name))
        .map(String::as_str)
        .find(|value| !value.is_empty())
}

/// The browser a User-Agent belongs to: `firefox`, `edge`, `chrome` or
/// `safari`; browserforge's `get_browser`.
///
/// Defect (4): Edge User-Agents also contain `Chrome` and `Safari`, and
/// browserforge tested `Chrome` first, so it never returned `edge`. Edge's
/// tokens are checked before Chrome's here.
#[must_use]
pub fn browser_of(user_agent: &str) -> Option<&'static str> {
    let has = |aliases: &[&str]| aliases.iter().any(|alias| user_agent.contains(alias));
    if has(&["Firefox", "FxiOS"]) {
        Some("firefox")
    } else if has(&["Edge", "EdgA", "EdgiOS", "Edg"]) {
        Some("edge")
    } else if has(&["Chrome", "CriOS"]) {
        Some("chrome")
    } else if has(&["Safari"]) {
        Some("safari")
    } else {
        None
    }
}

/// The HTTP/1 spelling of an HTTP/2 header name, browserforge's
/// `pascalize`: pseudo-headers (`:path`) and `sec-ch-ua*` stay as they are,
/// `dnt`, `rtt` and `ect` are upper-cased, anything else is title-cased as
/// Python's `str.title` does.
#[must_use]
pub fn pascalize(name: &str) -> String {
    if name.starts_with(':') || name.starts_with("sec-ch-ua") {
        return name.to_owned();
    }
    if matches!(name, "dnt" | "rtt" | "ect") {
        return name.to_ascii_uppercase();
    }
    let mut pascal = String::with_capacity(name.len());
    let mut after_letter = false;
    for c in name.chars() {
        if after_letter {
            pascal.extend(c.to_lowercase());
        } else {
            pascal.extend(c.to_uppercase());
        }
        after_letter = c.is_alphabetic();
    }
    pascal
}
