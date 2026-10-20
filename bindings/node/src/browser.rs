//! Browser HTTP header and fingerprint generation from opentele2-browser, a
//! Rust port of browserforge, as async tasks.
//!
//! The options mirror the crate's `HeaderOptions`, `HeaderOverrides`,
//! `FingerprintOptions` and `Screen` in camelCase, with browserforge's
//! semantics (`opentele2.browser` of the Python binding takes the same
//! options in `snake_case`). Generation runs off the JavaScript thread: the
//! first call unpacks and parses the embedded Bayesian networks, which takes
//! a noticeable moment; later calls reuse them.
//!
//! Every failure rejects the promise. An option the binding or browserforge
//! rejects (an HTTP version other than 1 or 2, a fractional or negative
//! version or screen bound, a minimum above its maximum, more than ten
//! locales, a non-string header value, a bad seed) rejects with
//! `ERR_INVALID_ARG_VALUE`; options nothing in the dataset satisfies (only
//! reachable when `strict`, or with a `userAgent` the dataset lacks) reject
//! with `OT_INVALID_INPUT`, and an operating system without entropy for an
//! unseeded call with `OT_IO`. A wrongly typed option throws napi's own type
//! error before the task starts.

use napi::ScopedTask;
use napi::bindgen_prelude::{AsyncTask, Either, Env, Object};
use napi_derive::napi;
use serde_json::{Map, Value};

use opentele2_browser::{
    Browser, Error as BrowserError, Fingerprint, FingerprintGenerator, FingerprintOptions,
    FingerprintOverrides, HeaderGenerator, HeaderOptions, HeaderOverrides, Headers, HttpVersion,
    NavigatorFingerprint, Rng, Screen, ScreenFingerprint, VideoCard,
};

use crate::convert::{Seed, to_seed};
use crate::error::{CodedError, Result, core_error, invalid_arg, rejection};

/// The TypeScript type of an HTTP version option.
const HTTP_VERSION_TS: &str = "1 | 2 | '1' | '2'";

/// One value or an array of them, as browserforge's `tuplify` accepts.
type OneOrMany<T> = Either<T, Vec<T>>;

/// An HTTP version given as a `number` or a string.
type HttpVersionArg = Either<f64, String>;

/// A browser the headers may come from, with optional bounds on its major
/// version.
#[napi(object, object_to_js = false)]
pub struct BrowserSpec {
    /// `'chrome'`, `'firefox'`, `'safari'` or `'edge'`.
    pub name: String,
    /// The lowest major version, inclusive.
    pub min_version: Option<f64>,
    /// The highest major version, inclusive.
    pub max_version: Option<f64>,
    /// The HTTP version the browser speaks; the options' `httpVersion` by
    /// default.
    #[napi(ts_type = "1 | 2 | '1' | '2'")]
    pub http_version: Option<HttpVersionArg>,
}

/// Options of `generateHeaders`, browserforge's `HeaderGenerator` arguments;
/// every field is optional and defaults as browserforge does.
#[napi(object, object_to_js = false)]
pub struct BrowserHeaderOptions {
    /// The browsers to draw from, by name or as a `BrowserSpec`; all four by
    /// default.
    #[napi(ts_type = "string | BrowserSpec | Array<string | BrowserSpec>")]
    pub browsers: Option<OneOrMany<Either<String, BrowserSpec>>>,
    /// The operating systems to draw from: `'windows'`, `'macos'`,
    /// `'linux'`, `'android'`, `'ios'`; all by default.
    #[napi(ts_type = "string | Array<string>")]
    pub os: Option<OneOrMany<String>>,
    /// The devices to draw from: `'desktop'`, `'mobile'`; both by default.
    #[napi(ts_type = "string | Array<string>")]
    pub devices: Option<OneOrMany<String>>,
    /// The `Accept-Language` locales, most preferred first, at most ten;
    /// `'en-US'` by default.
    #[napi(ts_type = "string | Array<string>")]
    pub locales: Option<OneOrMany<String>>,
    /// The HTTP version, also that of every browser given by name; `2` by
    /// default. HTTP/1 falls back to HTTP/2 when no HTTP/1 sample fits.
    #[napi(ts_type = "1 | 2 | '1' | '2'")]
    pub http_version: Option<HttpVersionArg>,
    /// Fail instead of relaxing the options when nothing fits them; `false`
    /// by default.
    pub strict: Option<bool>,
    /// When given, the generated `User-Agent` is one of these.
    #[napi(ts_type = "string | Array<string>")]
    pub user_agent: Option<OneOrMany<String>>,
    /// Headers that depend on the request (`Referer`, `Cookie`, ...): one
    /// matching a generated header (ignoring case) replaces its value in
    /// place, any other is appended after the generated headers.
    #[napi(ts_type = "Record<string, string>")]
    pub request_dependent_headers: Option<Map<String, Value>>,
}

/// Bounds on the screen of a generated fingerprint, in CSS pixels, each
/// inclusive and optional.
#[napi(object, object_to_js = false)]
pub struct ScreenConstraint {
    /// The smallest screen width.
    pub min_width: Option<f64>,
    /// The largest screen width.
    pub max_width: Option<f64>,
    /// The smallest screen height.
    pub min_height: Option<f64>,
    /// The largest screen height.
    pub max_height: Option<f64>,
}

/// Options of `generateFingerprint`, browserforge's `FingerprintGenerator`
/// arguments; every field is optional.
#[napi(object, object_to_js = false)]
pub struct BrowserFingerprintOptions {
    /// The screen constraint; none by default.
    pub screen: Option<ScreenConstraint>,
    /// Fail instead of dropping the screen constraint when no fingerprint
    /// meets it; `false` by default.
    pub strict: Option<bool>,
    /// Carried to the output as `mockWebRTC`; `false` by default.
    pub mock_web_rtc: Option<bool>,
    /// Carried to the output as `slim`; `false` by default.
    pub slim: Option<bool>,
    /// The options of the headers the fingerprint is drawn for, as
    /// `generateHeaders` takes them.
    pub header: Option<BrowserHeaderOptions>,
}

/// The `window.screen` and window-geometry attributes of a fingerprint.
#[napi(object, object_from_js = false)]
pub struct FingerprintScreen {
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
    /// Whether the display reports HDR.
    #[napi(js_name = "hasHDR")]
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

impl From<ScreenFingerprint> for FingerprintScreen {
    fn from(screen: ScreenFingerprint) -> Self {
        Self {
            avail_top: screen.avail_top,
            avail_left: screen.avail_left,
            page_x_offset: screen.page_x_offset,
            page_y_offset: screen.page_y_offset,
            screen_x: screen.screen_x,
            has_hdr: screen.has_hdr,
            width: screen.width,
            height: screen.height,
            avail_width: screen.avail_width,
            avail_height: screen.avail_height,
            client_width: screen.client_width,
            client_height: screen.client_height,
            inner_width: screen.inner_width,
            inner_height: screen.inner_height,
            outer_width: screen.outer_width,
            outer_height: screen.outer_height,
            color_depth: screen.color_depth,
            pixel_depth: screen.pixel_depth,
            device_pixel_ratio: screen.device_pixel_ratio,
        }
    }
}

/// The `window.navigator` attributes of a fingerprint.
#[napi(object, object_from_js = false)]
pub struct FingerprintNavigator {
    /// `navigator.userAgent`, equal to the headers' `User-Agent`.
    pub user_agent: String,
    /// `navigator.userAgentData`, or `null`.
    #[napi(ts_type = "Record<string, unknown> | null")]
    pub user_agent_data: Value,
    /// `navigator.doNotTrack`.
    #[napi(ts_type = "string | null")]
    pub do_not_track: Value,
    /// `navigator.appCodeName`.
    pub app_code_name: String,
    /// `navigator.appName`.
    pub app_name: String,
    /// `navigator.appVersion`.
    pub app_version: String,
    /// `navigator.oscpu` (Firefox only), or `null`.
    #[napi(ts_type = "string | null")]
    pub oscpu: Value,
    /// `navigator.webdriver`.
    #[napi(ts_type = "unknown")]
    pub webdriver: Value,
    /// `navigator.language`, the first of `languages`.
    pub language: String,
    /// `navigator.languages`, the `Accept-Language` locales in order.
    pub languages: Vec<String>,
    /// `navigator.platform`.
    pub platform: String,
    /// `navigator.deviceMemory` in GiB, or `null`.
    #[napi(ts_type = "number | null")]
    pub device_memory: Value,
    /// `navigator.hardwareConcurrency`.
    pub hardware_concurrency: i64,
    /// `navigator.product`.
    pub product: String,
    /// `navigator.productSub`.
    pub product_sub: String,
    /// `navigator.vendor`, or `null`.
    #[napi(ts_type = "string | null")]
    pub vendor: Value,
    /// `navigator.vendorSub`, or `null`.
    #[napi(ts_type = "string | null")]
    pub vendor_sub: Value,
    /// `navigator.maxTouchPoints`.
    pub max_touch_points: i64,
    /// Browser-specific extras (`vendorFlavors`, `globalPrivacyControl`,
    /// ...).
    #[napi(ts_type = "Record<string, unknown>")]
    pub extra_properties: Value,
}

impl From<NavigatorFingerprint> for FingerprintNavigator {
    fn from(navigator: NavigatorFingerprint) -> Self {
        Self {
            user_agent: navigator.user_agent,
            user_agent_data: navigator.user_agent_data,
            do_not_track: navigator.do_not_track,
            app_code_name: navigator.app_code_name,
            app_name: navigator.app_name,
            app_version: navigator.app_version,
            oscpu: navigator.oscpu,
            webdriver: navigator.webdriver,
            language: navigator.language,
            languages: navigator.languages,
            platform: navigator.platform,
            device_memory: navigator.device_memory,
            hardware_concurrency: navigator.hardware_concurrency,
            product: navigator.product,
            product_sub: navigator.product_sub,
            vendor: navigator.vendor,
            vendor_sub: navigator.vendor_sub,
            max_touch_points: navigator.max_touch_points,
            extra_properties: navigator.extra_properties,
        }
    }
}

/// The unmasked WebGL renderer and vendor of a fingerprint.
#[napi(object, object_from_js = false)]
pub struct FingerprintVideoCard {
    /// The unmasked WebGL renderer.
    pub renderer: String,
    /// The unmasked WebGL vendor.
    pub vendor: String,
}

impl From<VideoCard> for FingerprintVideoCard {
    fn from(card: VideoCard) -> Self {
        Self {
            renderer: card.renderer,
            vendor: card.vendor,
        }
    }
}

/// A browser fingerprint with its matching headers, keyed and ordered as
/// browserforge's `Fingerprint` dumps it.
#[napi(object, object_from_js = false, use_nullable = true)]
pub struct BrowserFingerprint {
    /// The screen attributes.
    pub screen: FingerprintScreen,
    /// The navigator attributes.
    pub navigator: FingerprintNavigator,
    /// The headers the fingerprint was drawn for, in sending order.
    #[napi(ts_type = "Record<string, string>")]
    pub headers: Map<String, Value>,
    /// `canPlayType` answers per video format.
    #[napi(ts_type = "Record<string, string>")]
    pub video_codecs: Value,
    /// `canPlayType` answers per audio format.
    #[napi(ts_type = "Record<string, string>")]
    pub audio_codecs: Value,
    /// `navigator.plugins` and `navigator.mimeTypes`.
    #[napi(ts_type = "Record<string, unknown>")]
    pub plugins_data: Value,
    /// The Battery Status API state, or `null`.
    #[napi(ts_type = "Record<string, unknown> | null")]
    pub battery: Value,
    /// The WebGL renderer and vendor, or `null`.
    pub video_card: Option<FingerprintVideoCard>,
    /// The media devices by kind.
    #[napi(ts_type = "Record<string, unknown>")]
    pub multimedia_devices: Value,
    /// The installed fonts.
    #[napi(ts_type = "Array<string>")]
    pub fonts: Value,
    /// Whether an injector should mock WebRTC.
    #[napi(js_name = "mockWebRTC")]
    pub mock_webrtc: bool,
    /// Whether an injector should skip performance-heavy evasions.
    pub slim: bool,
}

/// `headers` as a JSON object, in sending order.
fn headers_map(headers: Headers) -> Map<String, Value> {
    headers
        .into_iter()
        .map(|(name, value)| (name, Value::String(value)))
        .collect()
}

impl From<Fingerprint> for BrowserFingerprint {
    fn from(fingerprint: Fingerprint) -> Self {
        Self {
            screen: fingerprint.screen.into(),
            navigator: fingerprint.navigator.into(),
            headers: headers_map(fingerprint.headers),
            video_codecs: fingerprint.video_codecs,
            audio_codecs: fingerprint.audio_codecs,
            plugins_data: fingerprint.plugins_data,
            battery: fingerprint.battery,
            video_card: fingerprint.video_card.map(FingerprintVideoCard::from),
            multimedia_devices: fingerprint.multimedia_devices,
            fonts: fingerprint.fonts,
            mock_webrtc: fingerprint.mock_webrtc,
            slim: fingerprint.slim,
        }
    }
}

/// `value` as a list, one value or the array as given.
fn many<T>(value: OneOrMany<T>) -> Vec<T> {
    match value {
        Either::A(one) => vec![one],
        Either::B(all) => all,
    }
}

/// An HTTP version option; anything but `1`, `2`, `'1'` or `'2'` is
/// `ERR_INVALID_ARG_VALUE`.
fn http_version(value: &HttpVersionArg) -> Result<HttpVersion> {
    // A `number` prints as its shortest text: `1` and `2` exactly, any
    // other value (`1.5`, `-0`, `NaN`) as something else.
    let text = match value {
        Either::A(number) => number.to_string(),
        Either::B(text) => text.clone(),
    };
    let version = match text.as_str() {
        "1" => Some(HttpVersion::One),
        "2" => Some(HttpVersion::Two),
        _ => None,
    };
    version.ok_or_else(|| invalid_arg(format!("httpVersion must be one of {HTTP_VERSION_TS}")))
}

/// A bound given as a `number`; anything but an integer in `0..2**32` is
/// `ERR_INVALID_ARG_VALUE` naming `name`.
fn to_bound(value: Option<f64>, name: &str) -> Result<Option<u32>> {
    let Some(number) = value else {
        return Ok(None);
    };
    let invalid = || invalid_arg(format!("{name} must be an integer in 0..2**32"));
    if !number.is_finite() || number.fract() != 0.0 || number < 0.0 {
        return Err(invalid());
    }
    if number == 0.0 {
        // `-0` is the integer 0, not the text "-0".
        return Ok(Some(0));
    }
    // An integral f64 prints its exact digits with no fraction; above
    // u32::MAX the parse fails.
    format!("{number:.0}")
        .parse()
        .map(Some)
        .map_err(|_| invalid())
}

/// The browsers of a `browsers` option; a name speaks `default`.
fn to_browsers(
    value: OneOrMany<Either<String, BrowserSpec>>,
    default: HttpVersion,
) -> Result<Vec<Browser>> {
    many(value)
        .into_iter()
        .map(|browser| match browser {
            Either::A(name) => Ok(Browser {
                http_version: default,
                ..Browser::new(name)
            }),
            Either::B(spec) => Ok(Browser {
                min_version: to_bound(spec.min_version, "minVersion")?,
                max_version: to_bound(spec.max_version, "maxVersion")?,
                http_version: spec
                    .http_version
                    .as_ref()
                    .map(http_version)
                    .transpose()?
                    .unwrap_or(default),
                name: spec.name,
            }),
        })
        .collect()
}

/// The generator options and per-call overrides of `options`, defaulting as
/// browserforge's `HeaderGenerator`.
fn header_request(
    options: Option<BrowserHeaderOptions>,
) -> Result<(HeaderOptions, HeaderOverrides)> {
    let mut core = HeaderOptions::default();
    let mut overrides = HeaderOverrides::default();
    let Some(options) = options else {
        return Ok((core, overrides));
    };
    if let Some(value) = &options.http_version {
        core = core.with_http_version(http_version(value)?);
    }
    if let Some(value) = options.browsers {
        core.browsers = to_browsers(value, core.http_version)?;
    }
    if let Some(value) = options.os {
        core.os = many(value);
    }
    if let Some(value) = options.devices {
        core.devices = many(value);
    }
    if let Some(value) = options.locales {
        core.locales = many(value);
    }
    if let Some(strict) = options.strict {
        core.strict = strict;
    }
    if let Some(value) = options.user_agent {
        overrides.user_agent = many(value);
    }
    if let Some(headers) = options.request_dependent_headers {
        overrides.request_dependent_headers = headers
            .into_iter()
            .map(|(name, value)| match value {
                Value::String(text) => Ok((name, text)),
                _ => Err(invalid_arg(format!(
                    "requestDependentHeaders[{name:?}] must be a string"
                ))),
            })
            .collect::<Result<Headers>>()?;
    }
    Ok((core, overrides))
}

/// The screen constraint of `screen`.
fn to_screen(screen: &ScreenConstraint) -> Result<Screen> {
    Ok(Screen {
        min_width: to_bound(screen.min_width, "screen.minWidth")?,
        max_width: to_bound(screen.max_width, "screen.maxWidth")?,
        min_height: to_bound(screen.min_height, "screen.minHeight")?,
        max_height: to_bound(screen.max_height, "screen.maxHeight")?,
    })
}

/// The generator options and per-call overrides of `options`, defaulting as
/// browserforge's `FingerprintGenerator`.
fn fingerprint_request(
    options: Option<BrowserFingerprintOptions>,
) -> Result<(FingerprintOptions, FingerprintOverrides)> {
    let options = options.unwrap_or(BrowserFingerprintOptions {
        screen: None,
        strict: None,
        mock_web_rtc: None,
        slim: None,
        header: None,
    });
    let (header, header_overrides) = header_request(options.header)?;
    let core = FingerprintOptions {
        screen: options.screen.as_ref().map(to_screen).transpose()?,
        strict: options.strict.unwrap_or(false),
        mock_webrtc: options.mock_web_rtc.unwrap_or(false),
        slim: options.slim.unwrap_or(false),
        header,
    };
    let overrides = FingerprintOverrides {
        header: header_overrides,
        ..FingerprintOverrides::default()
    };
    Ok((core, overrides))
}

/// A crate error as the promise rejects with it: rejected options are
/// `ERR_INVALID_ARG_VALUE`, missing entropy `OT_IO`, and every other failure
/// (nothing in the dataset fits) `OT_INVALID_INPUT`.
fn generation_error(error: &BrowserError) -> CodedError {
    match error {
        BrowserError::InvalidOptions(_) => invalid_arg(error),
        BrowserError::Entropy(_) => core_error(&opentele2_core::Error::Io(std::io::Error::other(
            error.to_string(),
        ))),
        _ => core_error(&opentele2_core::Error::InvalidInput {
            what: "browser options",
            reason: error.to_string(),
        }),
    }
}

/// A generator seeded from the text of `seed`, or from the operating
/// system's entropy without one.
fn rng(seed: Option<&str>) -> std::result::Result<Rng, BrowserError> {
    seed.map_or_else(Rng::from_entropy, |seed| Ok(Rng::from_seed(seed)))
}

/// One draw: the options, the overrides and the seed text, or the argument
/// error that rejects the call.
type Request<O, V> = Result<(O, V, Option<String>)>;

/// Builds the request of a call from its converted options and seed.
fn request<O, V>(options: Result<(O, V)>, seed: Option<Seed>) -> Request<O, V> {
    let (options, overrides) = options?;
    Ok((options, overrides, to_seed(seed)?))
}

/// `generateHeaders` off the JavaScript thread.
pub struct HeadersTask {
    request: Option<Request<HeaderOptions, HeaderOverrides>>,
}

#[napi]
impl<'task> ScopedTask<'task> for HeadersTask {
    type Output = Result<Headers>;
    type JsValue = Object<'task>;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let Some(request) = self.request.take() else {
            return Err(napi::Error::from_reason("the task already ran"));
        };
        Ok(request.and_then(|(options, overrides, seed)| {
            rng(seed.as_deref())
                .and_then(|mut rng| HeaderGenerator::new(options)?.generate(&mut rng, &overrides))
                .map_err(|error| generation_error(&error))
        }))
    }

    fn resolve(&mut self, env: &'task Env, output: Self::Output) -> napi::Result<Object<'task>> {
        let headers = output.map_err(|error| rejection(*env, error))?;
        let mut object = Object::new(env)?;
        for (name, value) in headers {
            object.set(name, value)?;
        }
        Ok(object)
    }
}

/// `generateFingerprint` off the JavaScript thread.
pub struct FingerprintTask {
    request: Option<Request<FingerprintOptions, FingerprintOverrides>>,
}

#[napi]
impl napi::Task for FingerprintTask {
    type Output = Result<Fingerprint>;
    type JsValue = BrowserFingerprint;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let Some(request) = self.request.take() else {
            return Err(napi::Error::from_reason("the task already ran"));
        };
        Ok(request.and_then(|(options, overrides, seed)| {
            rng(seed.as_deref())
                .and_then(|mut rng| {
                    FingerprintGenerator::new(options)?.generate(&mut rng, &overrides)
                })
                .map_err(|error| generation_error(&error))
        }))
    }

    fn resolve(&mut self, env: Env, output: Self::Output) -> napi::Result<BrowserFingerprint> {
        output
            .map(BrowserFingerprint::from)
            .map_err(|error| rejection(env, error))
    }
}

/// One set of browser HTTP headers, name to value in sending order, as
/// browserforge's `HeaderGenerator(...).generate()`. A `seed` (a string, or
/// an integer `number` or `bigint` as its decimal text, as Python's `str()`
/// of an `int`) makes the draw reproducible, the same as
/// `opentele2.browser.HeaderGenerator(...).generate(seed=...)` of the
/// Python binding with those options and that seed; without one it comes
/// from the operating system's entropy.
///
/// Runs as an async task: the first call parses the embedded networks.
/// Invalid options reject with `ERR_INVALID_ARG_VALUE`; options nothing
/// satisfies (`strict`) with `OT_INVALID_INPUT`.
#[napi(
    ts_args_type = "options?: BrowserHeaderOptions | undefined | null, seed?: string | number | bigint | undefined | null",
    ts_return_type = "Promise<Record<string, string>>"
)]
pub fn generate_headers(
    options: Option<BrowserHeaderOptions>,
    seed: Option<Seed>,
) -> AsyncTask<HeadersTask> {
    AsyncTask::new(HeadersTask {
        request: Some(request(header_request(options), seed)),
    })
}

/// One browser fingerprint with its matching headers, as browserforge's
/// `FingerprintGenerator(...).generate()`, keyed as browserforge's
/// `Fingerprint` (`screen`, `navigator`, `headers`, `videoCodecs`,
/// `audioCodecs`, `pluginsData`, `battery`, `videoCard`,
/// `multimediaDevices`, `fonts`, `mockWebRTC`, `slim`). `seed` as for
/// `generateHeaders`.
///
/// Runs as an async task: the first call parses the embedded networks.
/// Invalid options reject with `ERR_INVALID_ARG_VALUE`; options nothing
/// satisfies (`strict`, or a `screen` no sample has with `strict`) with
/// `OT_INVALID_INPUT`.
#[napi(
    ts_args_type = "options?: BrowserFingerprintOptions | undefined | null, seed?: string | number | bigint | undefined | null"
)]
pub fn generate_fingerprint(
    options: Option<BrowserFingerprintOptions>,
    seed: Option<Seed>,
) -> AsyncTask<FingerprintTask> {
    AsyncTask::new(FingerprintTask {
        request: Some(request(fingerprint_request(options), seed)),
    })
}
