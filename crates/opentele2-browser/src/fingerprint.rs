//! Browser fingerprint generation, a port of browserforge's
//! `fingerprints/generator.py` (browserforge 1.2.4).
//!
//! A [`HeaderGenerator`] draws the headers first; the fingerprint network is
//! then sampled with its `userAgent` fixed to the drawn `User-Agent`, so the
//! fingerprint and the headers describe the same browser. A [`Screen`]
//! constraint restricts the network's `screen` node and, through the
//! network's `possible_values` closure, the User-Agents the headers may use.
//!
//! The port fixes these browserforge defects, each documented where it
//! lives:
//!
//! 1. `navigator.languages` are trimmed (browserforge kept the space after
//!    each comma of `Accept-Language`: `["en-US", " en;q=0.9"]` became
//!    `["en-US", " en"]`);
//! 2. the fingerprint retry is bounded: one retry without the screen filter,
//!    then [`Error::NoFingerprint`] (browserforge looped forever when the
//!    User-Agent alone had no consistent sample);
//! 3. with a screen constraint the `User-Agent` is guaranteed to come from
//!    the screen-compatible list (browserforge's header generator ignored
//!    its `user_agent` argument when sampling the header network).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::network::{BayesianNetwork, fingerprint_network};
use crate::{
    Error, HeaderGenerator, HeaderOptions, HeaderOverrides, Headers, OrderedMap, Restrictions,
    Result, Rng, get_user_agent,
};

/// The dataset prefix of a JSON-encoded value.
pub const STRINGIFIED: &str = "*STRINGIFIED*";

/// The dataset token for an absent attribute.
const MISSING_VALUE: &str = crate::headers::MISSING_VALUE;

/// The largest screen dimension browserforge assumes for an unset maximum.
const DEFAULT_MAX_DIMENSION: u32 = 100_000;

/// Bounds on the screen dimensions of a generated fingerprint, in CSS
/// pixels, each inclusive; `None` leaves that side open.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Screen {
    /// The smallest screen width.
    pub min_width: Option<u32>,
    /// The largest screen width.
    pub max_width: Option<u32>,
    /// The smallest screen height.
    pub min_height: Option<u32>,
    /// The largest screen height.
    pub max_height: Option<u32>,
}

impl Screen {
    /// Checks that no minimum exceeds its maximum, as browserforge's
    /// `Screen.__post_init__`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOptions`] when a minimum exceeds its maximum.
    pub fn validate(&self) -> Result<()> {
        let inverted =
            |min: Option<u32>, max: Option<u32>| min.zip(max).is_some_and(|(a, b)| a > b);
        if inverted(self.min_width, self.max_width) || inverted(self.min_height, self.max_height) {
            return Err(Error::InvalidOptions(
                "Invalid screen constraints: min values cannot be greater than max values"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// `true` when any bound is set.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.min_width.is_some()
            || self.max_width.is_some()
            || self.min_height.is_some()
            || self.max_height.is_some()
    }

    /// browserforge's `_is_screen_within_constraints` for one `screen` value
    /// of the fingerprint network (`*STRINGIFIED*{...}`). A value that does
    /// not parse, or lacks a numeric `width` or `height`, is outside.
    ///
    /// browserforge read an explicit maximum of `0` as unset (`max or 1e5`);
    /// here `Some(0)` bounds the dimension at zero.
    #[must_use]
    pub fn admits(&self, screen_value: &str) -> bool {
        let Some(json) = screen_value.strip_prefix(STRINGIFIED) else {
            return false;
        };
        let Ok(screen) = serde_json::from_str::<Value>(json) else {
            return false;
        };
        let within = |key: &str, min: Option<u32>, max: Option<u32>| {
            screen.get(key).and_then(Value::as_f64).is_some_and(|size| {
                size >= f64::from(min.unwrap_or(0))
                    && size <= f64::from(max.unwrap_or(DEFAULT_MAX_DIMENSION))
            })
        };
        within("width", self.min_width, self.max_width)
            && within("height", self.min_height, self.max_height)
    }
}

/// The options of a [`FingerprintGenerator`], defaulting as browserforge
/// does: no screen constraint, not strict, no WebRTC mocking, not slim, the
/// default [`HeaderOptions`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FingerprintOptions {
    /// The screen constraint.
    pub screen: Option<Screen>,
    /// Fail instead of dropping the screen constraint when it cannot be met.
    pub strict: bool,
    /// Whether an injector should mock WebRTC; carried to the output.
    pub mock_webrtc: bool,
    /// Whether an injector should skip performance-heavy evasions; carried
    /// to the output.
    pub slim: bool,
    /// The options of the underlying [`HeaderGenerator`].
    pub header: HeaderOptions,
}

/// Per-call replacements for the [`FingerprintOptions`], browserforge's
/// `generate` keyword arguments; `None` keeps the generator's option.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FingerprintOverrides {
    /// Replaces the generator's screen constraint.
    pub screen: Option<Screen>,
    /// Replaces the generator's strictness.
    pub strict: Option<bool>,
    /// Replaces the generator's WebRTC mocking flag.
    pub mock_webrtc: Option<bool>,
    /// Replaces the generator's slim flag.
    pub slim: Option<bool>,
    /// Passed to [`HeaderGenerator::generate`]. With a screen constraint a
    /// non-empty `user_agent` list is narrowed to the screen-compatible
    /// User-Agents.
    pub header: HeaderOverrides,
}

/// The `window.screen` and window-geometry attributes of a fingerprint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenFingerprint {
    /// `screen.availTop`.
    pub avail_top: i64,
    /// `screen.availLeft`.
    pub avail_left: i64,
    /// `window.pageXOffset`.
    pub page_x_offset: i64,
    /// `window.pageYOffset`.
    pub page_y_offset: i64,
    /// `window.screenX`.
    pub screen_x: i64,
    /// Whether the display reports HDR (`dynamic-range: high`).
    #[serde(rename = "hasHDR")]
    pub has_hdr: bool,
    /// `screen.width`.
    pub width: i64,
    /// `screen.height`.
    pub height: i64,
    /// `screen.availWidth`.
    pub avail_width: i64,
    /// `screen.availHeight`.
    pub avail_height: i64,
    /// `document.documentElement.clientWidth`.
    pub client_width: i64,
    /// `document.documentElement.clientHeight`.
    pub client_height: i64,
    /// `window.innerWidth`.
    pub inner_width: i64,
    /// `window.innerHeight`.
    pub inner_height: i64,
    /// `window.outerWidth`.
    pub outer_width: i64,
    /// `window.outerHeight`.
    pub outer_height: i64,
    /// `screen.colorDepth`.
    pub color_depth: i64,
    /// `screen.pixelDepth`.
    pub pixel_depth: i64,
    /// `window.devicePixelRatio`.
    pub device_pixel_ratio: f64,
}

/// The `window.navigator` attributes of a fingerprint. Attributes whose
/// dataset values vary in type (or may be absent, `null`) are JSON values.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigatorFingerprint {
    /// `navigator.userAgent`, equal to the headers' `User-Agent`.
    pub user_agent: String,
    /// `navigator.userAgentData` (brands, platform, high-entropy values), or
    /// `null`.
    pub user_agent_data: Value,
    /// `navigator.doNotTrack`: `"1"` or `null`.
    pub do_not_track: Value,
    /// `navigator.appCodeName`.
    pub app_code_name: String,
    /// `navigator.appName`.
    pub app_name: String,
    /// `navigator.appVersion`.
    pub app_version: String,
    /// `navigator.oscpu` (Firefox only), or `null`.
    pub oscpu: Value,
    /// `navigator.webdriver`.
    pub webdriver: Value,
    /// `navigator.language`, the first of [`Self::languages`].
    pub language: String,
    /// `navigator.languages`, the `Accept-Language` locales in order.
    pub languages: Vec<String>,
    /// `navigator.platform`.
    pub platform: String,
    /// `navigator.deviceMemory` in GiB, or `null`.
    pub device_memory: Value,
    /// `navigator.hardwareConcurrency`.
    pub hardware_concurrency: i64,
    /// `navigator.product`.
    pub product: String,
    /// `navigator.productSub`.
    pub product_sub: String,
    /// `navigator.vendor`, or `null`.
    pub vendor: Value,
    /// `navigator.vendorSub`, or `null`.
    pub vendor_sub: Value,
    /// `navigator.maxTouchPoints`, 0 when the sample has none.
    pub max_touch_points: i64,
    /// Browser-specific extras (`vendorFlavors`, `globalPrivacyControl`, ...).
    pub extra_properties: Value,
}

/// The WebGL renderer and vendor of a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoCard {
    /// The unmasked WebGL renderer.
    pub renderer: String,
    /// The unmasked WebGL vendor.
    pub vendor: String,
}

/// A generated browser fingerprint with its matching headers, serialised
/// with browserforge's field names ([`Fingerprint::to_json`]).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fingerprint {
    /// The screen attributes.
    pub screen: ScreenFingerprint,
    /// The navigator attributes.
    pub navigator: NavigatorFingerprint,
    /// The headers the fingerprint was drawn for, in sending order.
    #[serde(serialize_with = "serialize_headers")]
    pub headers: Headers,
    /// `canPlayType` answers per video format.
    pub video_codecs: Value,
    /// `canPlayType` answers per audio format.
    pub audio_codecs: Value,
    /// `navigator.plugins` and `navigator.mimeTypes`.
    pub plugins_data: Value,
    /// The Battery Status API state, or `null`.
    pub battery: Value,
    /// The WebGL renderer and vendor, or `None`.
    pub video_card: Option<VideoCard>,
    /// The media devices by kind.
    pub multimedia_devices: Value,
    /// The installed fonts.
    pub fonts: Value,
    /// Whether an injector should mock WebRTC.
    #[serde(rename = "mockWebRTC")]
    pub mock_webrtc: bool,
    /// Whether an injector should skip performance-heavy evasions.
    pub slim: bool,
}

impl Fingerprint {
    /// The fingerprint as compact JSON, browserforge's `Fingerprint.dumps`.
    ///
    /// # Errors
    ///
    /// [`Error::Data`] if serialisation fails (never for a generated
    /// fingerprint).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| Error::Data(e.to_string()))
    }
}

fn serialize_headers<S: Serializer>(
    headers: &Headers,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.collect_map(headers.iter())
}

/// Generates browser fingerprints with matching headers, as browserforge's
/// `FingerprintGenerator`.
#[derive(Debug, Clone)]
pub struct FingerprintGenerator {
    options: FingerprintOptions,
    header_generator: HeaderGenerator,
}

impl FingerprintGenerator {
    /// Builds a generator for `options`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOptions`] for an inverted screen constraint or header
    /// options [`HeaderGenerator::new`] rejects; [`Error::Data`] for
    /// malformed embedded data (never for the shipped data).
    pub fn new(options: FingerprintOptions) -> Result<Self> {
        if let Some(screen) = &options.screen {
            screen.validate()?;
        }
        let header_generator = HeaderGenerator::new(options.header.clone())?;
        Ok(Self {
            options,
            header_generator,
        })
    }

    /// The options the generator was built with.
    #[must_use]
    pub fn options(&self) -> &FingerprintOptions {
        &self.options
    }

    /// Generates one fingerprint and its headers. The same `rng` state,
    /// options and overrides always give the same fingerprint.
    ///
    /// With a screen constraint that no screen meets, a strict generator
    /// fails with [`Error::NoFingerprint`] (browserforge raised its
    /// constraint-closure error there); a non-strict one drops the
    /// constraint.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOptions`] for an inverted override screen;
    /// [`Error::NoFingerprint`] when the fingerprint network has no sample
    /// for the drawn `User-Agent` (with the screen constraint when strict,
    /// otherwise even without it); the errors of
    /// [`HeaderGenerator::generate`] and [`fingerprint_network`].
    pub fn generate(&self, rng: &mut Rng, overrides: &FingerprintOverrides) -> Result<Fingerprint> {
        let screen = overrides
            .screen
            .or(self.options.screen)
            .filter(Screen::is_set);
        if let Some(screen) = &screen {
            screen.validate()?;
        }
        let strict = overrides.strict.unwrap_or(self.options.strict);
        let net = fingerprint_network()?;

        let mut header_overrides = overrides.header.clone();
        let screen_values = match screen {
            Some(screen) => {
                let constrained = screen_constraint(net, &screen, &header_overrides.user_agent)?;
                match constrained {
                    Some((values, user_agents)) => {
                        // Defect (3): the screen-compatible list reaches the
                        // header network itself, so the drawn User-Agent is
                        // one of them.
                        header_overrides.user_agent = user_agents;
                        Some(values)
                    }
                    None if strict => return Err(Error::NoFingerprint),
                    None => None,
                }
            }
            None => None,
        };

        // Every User-Agent of the shipped header network is a `userAgent`
        // value of the fingerprint network, so the sample below exists for
        // it; another dataset would end in `NoFingerprint`, not a loop.
        let headers = self.header_generator.generate(rng, &header_overrides)?;
        let user_agent = get_user_agent(&headers)
            .map(str::to_owned)
            .ok_or(Error::MissingUserAgent)?;

        let mut restrictions = Restrictions::new();
        if let Some(values) = screen_values {
            restrictions.insert("screen", values);
        }
        restrictions.insert("userAgent", vec![user_agent]);
        // Defect (2): at most one relaxation, then an error.
        let mut sample = net.consistent_sample(rng, &restrictions);
        if sample.is_none() && !strict && restrictions.remove("screen").is_some() {
            sample = net.consistent_sample(rng, &restrictions);
        }
        let sample = sample.ok_or(Error::NoFingerprint)?;

        let mut attributes: OrderedMap<Value> = OrderedMap::new();
        for (name, value) in sample {
            attributes.insert(name, unpack(&value)?);
        }
        Ok(Fingerprint {
            screen: typed(&mut attributes, "screen")?,
            navigator: navigator(&mut attributes, &headers)?,
            video_codecs: take(&mut attributes, "videoCodecs"),
            audio_codecs: take(&mut attributes, "audioCodecs"),
            plugins_data: take(&mut attributes, "pluginsData"),
            battery: take(&mut attributes, "battery"),
            video_card: video_card(take(&mut attributes, "videoCard"))?,
            multimedia_devices: take(&mut attributes, "multimediaDevices"),
            fonts: take(&mut attributes, "fonts"),
            mock_webrtc: overrides.mock_webrtc.unwrap_or(self.options.mock_webrtc),
            slim: overrides.slim.unwrap_or(self.options.slim),
            headers,
        })
    }
}

/// browserforge's `partial_csp`: the `screen` values within `screen` and the
/// User-Agents compatible with them (narrowed to `user_agents` when that is
/// non-empty); `None` when nothing fits.
fn screen_constraint(
    net: &BayesianNetwork,
    screen: &Screen,
    user_agents: &[String],
) -> Result<Option<(Vec<String>, Vec<String>)>> {
    let values: Vec<String> = node_values(net, "screen")?
        .into_iter()
        .filter(|value| screen.admits(value))
        .collect();
    let mut restriction = Restrictions::new();
    restriction.insert("screen", values.clone());
    let closure = match net.possible_values(&restriction) {
        Ok(closure) => closure,
        Err(Error::TooRestrictive) => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut compatible = closure.get("userAgent").cloned().unwrap_or_default();
    if !user_agents.is_empty() {
        compatible.retain(|ua| user_agents.contains(ua));
    }
    Ok((!compatible.is_empty()).then_some((values, compatible)))
}

fn node_values(net: &BayesianNetwork, name: &str) -> Result<Vec<String>> {
    let node = net
        .node(name)
        .ok_or_else(|| Error::UnknownNode(name.to_owned()))?;
    Ok(node.possible_values().map(str::to_owned).collect())
}

/// `*MISSING_VALUE*` to `null`, `*STRINGIFIED*<json>` to the JSON, anything
/// else to a string.
fn unpack(value: &str) -> Result<Value> {
    if value == MISSING_VALUE {
        return Ok(Value::Null);
    }
    match value.strip_prefix(STRINGIFIED) {
        Some(json) => serde_json::from_str(json)
            .map_err(|e| Error::Data(format!("malformed stringified value {json:?}: {e}"))),
        None => Ok(Value::String(value.to_owned())),
    }
}

fn take(attributes: &mut OrderedMap<Value>, name: &str) -> Value {
    attributes.remove(name).unwrap_or(Value::Null)
}

fn typed<T: DeserializeOwned>(attributes: &mut OrderedMap<Value>, name: &str) -> Result<T> {
    serde_json::from_value(take(attributes, name))
        .map_err(|e| Error::Data(format!("fingerprint attribute {name}: {e}")))
}

/// browserforge's `VideoCard(**videoCard) if videoCard else None`.
fn video_card(value: Value) -> Result<Option<VideoCard>> {
    let empty = match &value {
        Value::Null => true,
        Value::Object(map) => map.is_empty(),
        _ => false,
    };
    if empty {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .map_err(|e| Error::Data(format!("fingerprint attribute videoCard: {e}")))
}

/// The locales of the `Accept-Language` header, `q` weights dropped.
///
/// Defect (1): each locale is trimmed; browserforge split on `,` alone and
/// kept the leading space of every locale after the first.
fn languages(headers: &Headers) -> Vec<String> {
    let accept_language = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("accept-language"))
        .map_or("", |(_, value)| value.as_str());
    accept_language
        .split(',')
        .map(|locale| {
            locale
                .split_once(';')
                .map_or(locale, |(tag, _)| tag)
                .trim()
                .to_owned()
        })
        .collect()
}

fn navigator(
    attributes: &mut OrderedMap<Value>,
    headers: &Headers,
) -> Result<NavigatorFingerprint> {
    let languages = languages(headers);
    let max_touch_points = match take(attributes, "maxTouchPoints") {
        Value::Null => 0,
        value => serde_json::from_value(value)
            .map_err(|e| Error::Data(format!("fingerprint attribute maxTouchPoints: {e}")))?,
    };
    Ok(NavigatorFingerprint {
        user_agent: typed(attributes, "userAgent")?,
        user_agent_data: take(attributes, "userAgentData"),
        do_not_track: take(attributes, "doNotTrack"),
        app_code_name: typed(attributes, "appCodeName")?,
        app_name: typed(attributes, "appName")?,
        app_version: typed(attributes, "appVersion")?,
        oscpu: take(attributes, "oscpu"),
        webdriver: take(attributes, "webdriver"),
        language: languages.first().cloned().unwrap_or_default(),
        languages,
        platform: typed(attributes, "platform")?,
        device_memory: take(attributes, "deviceMemory"),
        hardware_concurrency: typed(attributes, "hardwareConcurrency")?,
        product: typed(attributes, "product")?,
        product_sub: typed(attributes, "productSub")?,
        vendor: take(attributes, "vendor"),
        vendor_sub: take(attributes, "vendorSub"),
        max_touch_points,
        extra_properties: take(attributes, "extraProperties"),
    })
}

fn rng_for(seed: Option<&str>) -> Result<Rng> {
    seed.map_or_else(Rng::from_entropy, |seed| Ok(Rng::from_seed(seed)))
}

/// One fingerprint for `options`, drawn from [`Rng::from_seed`] of `seed`,
/// or from operating system entropy when `seed` is `None`.
///
/// # Errors
///
/// The errors of [`FingerprintGenerator::new`] and
/// [`FingerprintGenerator::generate`]; [`Error::Entropy`] without a seed
/// when the system has no entropy.
pub fn generate_fingerprint(
    seed: Option<&str>,
    options: &FingerprintOptions,
) -> Result<Fingerprint> {
    let mut rng = rng_for(seed)?;
    FingerprintGenerator::new(options.clone())?.generate(&mut rng, &FingerprintOverrides::default())
}

/// One set of headers for `options`, drawn from [`Rng::from_seed`] of
/// `seed`, or from operating system entropy when `seed` is `None`.
///
/// # Errors
///
/// The errors of [`HeaderGenerator::new`] and [`HeaderGenerator::generate`];
/// [`Error::Entropy`] without a seed when the system has no entropy.
pub fn generate_headers(seed: Option<&str>, options: &HeaderOptions) -> Result<Headers> {
    let mut rng = rng_for(seed)?;
    HeaderGenerator::new(options.clone())?.generate(&mut rng, &HeaderOverrides::default())
}
