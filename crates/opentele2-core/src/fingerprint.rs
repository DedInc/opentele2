//! The pure `initConnection` fingerprint helpers.
//!
//! - [`tz_offset`] is `tdesktop_tz_offset`, the `tz_offset` Telegram Desktop
//!   puts into `initConnection` `params`. The caller passes the local UTC
//!   offset, so results do not depend on the machine's clock or zone.
//! - [`validate_init_params`] is `validate_init_connection_params`, and
//!   [`check_versions`] is its strict version check. Versions come from a
//!   [`Versions`] the caller passes, such as the Python binding's global
//!   `PLATFORM_VERSIONS`.
//!   [`validate_raw_init_params`] takes the arguments as the caller gave
//!   them ([`RawInitParams`], `None` and an `api_id` of any type included)
//!   and words each message as the Python binding shows it.
//! - [`layer_mismatch_warning`] is the `get_recommended_layer` warning.
//! - [`StrictMode`] and [`FingerprintConfig`] are the Python types of the
//!   same names.
//! - [`msg_id_offset`] is `generate_msg_id_offset` with randomness from the
//!   caller, and [`is_valid_msg_id`] takes the current unix time instead of
//!   reading the clock.
//!
//! Every finding is an [`Issue`] with its message and a [`Severity`] that
//! says what `FingerprintConfig.validate_params` does with it under the
//! [`StrictMode`] in force:
//!
//! | Python behaviour | Mode | Severity |
//! |---|---|---|
//! | returned in the list, never warned or raised | [`StrictMode::Off`] | [`Severity::Note`] |
//! | `warnings.warn(msg)` | [`StrictMode::Warn`] | [`Severity::Warning`] |
//! | `raise ValueError(msg)` | [`StrictMode::Strict`] | [`Severity::Error`] |
//!
//! [`issues_message`] builds the `msg` that is warned or raised with.
//!
//! `TransportRecommendation` needs Telethon connection classes and stays in
//! the Python binding.

use std::cmp::Ordering;
use std::fmt;

use crate::Result;
use crate::api::{ApiProfile, LAYER, Versions};

/// The `tz_offset` Telegram Desktop sends in `initConnection` `params` for a
/// local UTC offset of `utc_offset_seconds` (`tdesktop_tz_offset`,
/// mirroring `SessionPrivate::prepareInitParams`).
///
/// The offset is wrapped by whole days into -12 h..+14 h: an offset below
/// -12 h gains days until it is at least -12 h, and one above +14 h loses
/// days until it is at most +14 h. It is then rounded to a multiple of 900
/// seconds with halves away from zero (`std::round`).
///
/// An offset read from a Python `datetime` is under 24 h either way; any
/// `i32` is accepted here and wrapped the same way.
#[must_use]
pub fn tz_offset(utc_offset_seconds: i32) -> f64 {
    const DAY: i32 = 24 * 3600;
    const LOW: i32 = -12 * 3600;
    const HIGH: i32 = 14 * 3600;
    let mut sliced = utc_offset_seconds;
    // Closed forms of tdesktop's `while` loops, safe at the `i32` extremes:
    // `sliced + 43200` and `50400 - sliced` cannot overflow in their branch.
    if sliced < LOW {
        sliced = LOW + (sliced - LOW).rem_euclid(DAY);
    }
    if sliced > HIGH {
        sliced = HIGH - (HIGH - sliced).rem_euclid(DAY);
    }
    // `|sliced| <= 50400`, so the integer form of `int(|s| / 900 + 0.5)`
    // is exact and cannot overflow.
    let rounded = (sliced.abs() + 450) / 900 * 900;
    f64::from(if sliced < 0 { -rounded } else { rounded })
}

/// How fingerprint consistency issues are handled (`StrictMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StrictMode {
    /// `OFF`: no extra checks; findings are neither warned nor raised.
    Off,
    /// `WARN`: findings are warned about but do not block.
    Warn,
    /// `STRICT`: the strict checks run too, and any finding is an error.
    Strict,
}

impl StrictMode {
    /// Every mode, in declaration order.
    pub const ALL: [Self; 3] = [Self::Off, Self::Warn, Self::Strict];

    /// The enum value: `off`, `warn` or `strict`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Strict => "strict",
        }
    }

    /// The mode whose enum value is `value`, as `StrictMode(value)`;
    /// `None` for any other string, including other cases.
    #[must_use]
    pub fn from_value(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == value)
    }

    /// The severity a finding gets under this mode.
    #[must_use]
    pub fn severity(self) -> Severity {
        match self {
            Self::Off => Severity::Note,
            Self::Warn => Severity::Warning,
            Self::Strict => Severity::Error,
        }
    }
}

/// What the Python binding does with a finding; see the module
/// documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Returned in the list only.
    Note,
    /// Emitted as a Python warning.
    Warning,
    /// Raised as a `ValueError`.
    Error,
}

impl Severity {
    /// Every severity, from the mildest.
    pub const ALL: [Self; 3] = [Self::Note, Self::Warning, Self::Error];

    /// The name the bindings give the severity: `note`, `warning` or
    /// `error`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// The severity whose [`Severity::name`] is exactly `name`; `None` for
    /// any other text, including other cases.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|severity| severity.name() == name)
    }
}

/// The check that produced an [`Issue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueKind {
    /// `lang_pack` is not one of the official values.
    UnknownLangPack,
    /// `lang_code` has fewer than two characters.
    ShortLangCode,
    /// An Android or iOS `system_lang_code` has no region (no `-`).
    MissingRegion,
    /// `device_model` is empty.
    EmptyDeviceModel,
    /// `system_version` is empty.
    EmptySystemVersion,
    /// `app_version` is empty.
    EmptyAppVersion,
    /// Strict: `api_id` is not the official one for `lang_pack`.
    ApiIdMismatch,
    /// Strict: `app_version` does not start with the latest known major.
    AppVersionMajor,
    /// Strict: an Android SDK level is outside `android_sdk_range`.
    AndroidSdkRange,
}

impl IssueKind {
    /// Every kind, in the order [`validate_init_params`] checks them.
    pub const ALL: [Self; 9] = [
        Self::UnknownLangPack,
        Self::ShortLangCode,
        Self::MissingRegion,
        Self::EmptyDeviceModel,
        Self::EmptySystemVersion,
        Self::EmptyAppVersion,
        Self::ApiIdMismatch,
        Self::AppVersionMajor,
        Self::AndroidSdkRange,
    ];

    /// The name the bindings give the kind: the variant's name, for example
    /// `UnknownLangPack`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::UnknownLangPack => "UnknownLangPack",
            Self::ShortLangCode => "ShortLangCode",
            Self::MissingRegion => "MissingRegion",
            Self::EmptyDeviceModel => "EmptyDeviceModel",
            Self::EmptySystemVersion => "EmptySystemVersion",
            Self::EmptyAppVersion => "EmptyAppVersion",
            Self::ApiIdMismatch => "ApiIdMismatch",
            Self::AppVersionMajor => "AppVersionMajor",
            Self::AndroidSdkRange => "AndroidSdkRange",
        }
    }

    /// The kind whose [`IssueKind::name`] is exactly `name`; `None` for any
    /// other text, including other cases.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }
}

/// One finding, with the message reported for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Issue {
    /// The check that failed.
    pub kind: IssueKind,
    /// What the Python binding does with the finding.
    pub severity: Severity,
    /// The message, character for character as the bindings show it.
    pub message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The message `FingerprintConfig.validate_params` warns or raises
/// with: a header line, then one `  - ` line per issue.
#[must_use]
pub fn issues_message(issues: &[Issue]) -> String {
    let mut message = String::from("initConnection fingerprint issues:");
    for issue in issues {
        message.push_str("\n  - ");
        message.push_str(&issue.message);
    }
    message
}

/// The official `lang_pack` values, sorted as messages list them.
const VALID_LANG_PACKS: [&str; 5] = ["", "android", "ios", "macos", "tdesktop"];

/// The official `api_id` of each `lang_pack` that has one.
fn official_api_id(lang_pack: &str) -> Option<i32> {
    match lang_pack {
        "tdesktop" => Some(2040),
        "android" => Some(6),
        "ios" => Some(10840),
        "macos" => Some(2834),
        _ => None,
    }
}

/// The findings of `validate_init_connection_params` for `profile`,
/// in its order, with `strict` on exactly when `mode` is
/// [`StrictMode::Strict`]. Each finding has `mode`'s [`Severity`].
///
/// Always checked: `lang_pack` is official, `lang_code` has at least two
/// characters, an Android or iOS `system_lang_code` has a region, and the
/// device model, system version and app version are not empty. Strict mode
/// adds the official `api_id` of the `lang_pack` and [`check_versions`]
/// against `versions`. `api_hash` is not checked.
///
/// This is [`validate_raw_init_params`] of
/// [`RawInitParams::from_profile`].
#[must_use]
pub fn validate_init_params(
    profile: &ApiProfile,
    versions: &Versions,
    mode: StrictMode,
) -> Vec<Issue> {
    validate_raw_init_params(&RawInitParams::from_profile(profile), versions, mode)
}

/// An `api_id` as a caller of `validate_init_connection_params` gave it,
/// before any conversion: it is compared with the official id of the
/// `lang_pack` by Python `!=` and shown with Python `str()`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum RawApiId<'a> {
    /// An integer: equal to an official id of the same value, shown in
    /// decimal.
    Int(i64),
    /// A float: equal to an official id it holds exactly (`2040.0 ==
    /// 2040`), shown as Python `repr` (`2040.0`, `1e+16`, `nan`).
    Float(f64),
    /// A bool: equal to the id 1 or 0, shown as `True` or `False`.
    Bool(bool),
    /// Text, such as `"2040"`: equal to no official id, shown as given. An
    /// integer outside `i64` is passed as its decimal text, which shows and
    /// compares as Python does.
    Text(&'a str),
    /// Python `None`: equal to no official id, shown as `None`.
    #[default]
    Missing,
}

impl RawApiId<'_> {
    /// Whether the value equals the official id `id` (Python `==` between
    /// the value and an `int`).
    #[must_use]
    pub fn equals_id(&self, id: i32) -> bool {
        match *self {
            Self::Int(value) => value == i64::from(id),
            // Python compares exactly too: -0.0 equals 0, NaN equals nothing.
            Self::Float(value) => {
                matches!(value.partial_cmp(&f64::from(id)), Some(Ordering::Equal))
            }
            Self::Bool(value) => i32::from(value) == id,
            Self::Text(_) | Self::Missing => false,
        }
    }
}

impl fmt::Display for RawApiId<'_> {
    /// Python `str()` of the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Int(value) => write!(f, "{value}"),
            Self::Float(value) => f.write_str(&py_float_repr(value)),
            Self::Bool(true) => f.write_str("True"),
            Self::Bool(false) => f.write_str("False"),
            Self::Text(text) => f.write_str(text),
            Self::Missing => f.write_str("None"),
        }
    }
}

/// Python `repr` of a float: the shortest text that reads back as `value`,
/// in fixed notation with at least one decimal for decimal exponents
/// -4..=15, otherwise as `d.ddde±XX`.
fn py_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if value.is_infinite() {
        return format!("{sign}inf");
    }
    // Rust's `{:e}` is the shortest round-trip form too: `2.04e3`, `5e-324`.
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    if !(-4..16).contains(&exponent) {
        let (first, rest) = digits.split_at(1);
        let fraction = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        return format!(
            "{sign}{first}{fraction}e{exponent_sign}{:02}",
            exponent.unsigned_abs()
        );
    }
    // `exponent` is in -4..16 here, so the casts are exact.
    let point = usize::try_from(exponent + 1).unwrap_or(0);
    if exponent < 0 {
        let zeros = "0".repeat(usize::try_from(-exponent - 1).unwrap_or(0));
        return format!("{sign}0.{zeros}{digits}");
    }
    if digits.len() <= point {
        let zeros = "0".repeat(point - digits.len());
        format!("{sign}{digits}{zeros}.0")
    } else {
        let (whole, fraction) = digits.split_at(point);
        format!("{sign}{whole}.{fraction}")
    }
}

/// The arguments of `validate_init_connection_params` as the caller
/// gave them, `None` standing for Python `None`.
///
/// A `None` text is tested as empty and shown as `None` where a message
/// formats it: `lang_code 'None'`, and a `lang_pack` of `None` is the
/// unknown pack `'None'`. A missing `system_lang_code` of an Android or iOS
/// pack, and a missing `app_version` or `system_version` in strict mode,
/// are tested and shown as empty text.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct RawInitParams<'a> {
    /// `api_id`.
    pub api_id: RawApiId<'a>,
    /// `device_model`.
    pub device_model: Option<&'a str>,
    /// `system_version`.
    pub system_version: Option<&'a str>,
    /// `app_version`.
    pub app_version: Option<&'a str>,
    /// `system_lang_code`.
    pub system_lang_code: Option<&'a str>,
    /// `lang_pack`.
    pub lang_pack: Option<&'a str>,
    /// `lang_code`.
    pub lang_code: Option<&'a str>,
}

impl<'a> RawInitParams<'a> {
    /// The fields of `profile`, every one present; `api_hash` is not
    /// checked.
    #[must_use]
    pub fn from_profile(profile: &'a ApiProfile) -> Self {
        Self {
            api_id: RawApiId::Int(i64::from(profile.api_id)),
            device_model: Some(&profile.device_model),
            system_version: Some(&profile.system_version),
            app_version: Some(&profile.app_version),
            system_lang_code: Some(&profile.system_lang_code),
            lang_pack: Some(&profile.lang_pack),
            lang_code: Some(&profile.lang_code),
        }
    }
}

/// [`validate_init_params`] of the values a caller gave
/// `validate_init_connection_params`, with every message in the form the
/// Python binding shows: `None` values and an `api_id` of any type are shown
/// as Python `str()` shows them (see [`RawInitParams`] and [`RawApiId`]).
#[must_use]
pub fn validate_raw_init_params(
    params: &RawInitParams<'_>,
    versions: &Versions,
    mode: StrictMode,
) -> Vec<Issue> {
    let severity = mode.severity();
    let mut issues = Vec::new();
    let mut push = |kind, message| {
        issues.push(Issue {
            kind,
            severity,
            message,
        });
    };
    // A `None` pack is looked up as its `str()`.
    let lang_pack = params.lang_pack.unwrap_or("None");
    let lang_code = params.lang_code.unwrap_or("");
    let system_lang_code = params.system_lang_code.unwrap_or("");
    let system_version = params.system_version.unwrap_or("");
    let app_version = params.app_version.unwrap_or("");

    if !VALID_LANG_PACKS.contains(&lang_pack) {
        push(
            IssueKind::UnknownLangPack,
            format!(
                "lang_pack '{lang_pack}' is not a known official value. \
                 Expected one of: ['', 'android', 'ios', 'macos', 'tdesktop']"
            ),
        );
    }
    // Python's `len` counts code points.
    if lang_code.chars().count() < 2 {
        push(
            IssueKind::ShortLangCode,
            format!(
                "lang_code '{}' looks invalid (too short)",
                params.lang_code.unwrap_or("None")
            ),
        );
    }
    if matches!(lang_pack, "android" | "ios") && !system_lang_code.contains('-') {
        push(
            IssueKind::MissingRegion,
            format!(
                "system_lang_code '{system_lang_code}' should include a region code \
                 (e.g. 'en-US') for {lang_pack} clients"
            ),
        );
    }
    if params.device_model.unwrap_or("").is_empty() {
        push(
            IssueKind::EmptyDeviceModel,
            "device_model is empty".to_owned(),
        );
    }
    if system_version.is_empty() {
        push(
            IssueKind::EmptySystemVersion,
            "system_version is empty".to_owned(),
        );
    }
    if app_version.is_empty() {
        push(
            IssueKind::EmptyAppVersion,
            "app_version is empty".to_owned(),
        );
    }

    if mode == StrictMode::Strict {
        if let Some(expected) = official_api_id(lang_pack)
            && !params.api_id.equals_id(expected)
        {
            push(
                IssueKind::ApiIdMismatch,
                format!(
                    "api_id {} does not match lang_pack '{lang_pack}' (expected {expected})",
                    params.api_id
                ),
            );
        }
        version_issues(
            lang_pack,
            app_version,
            system_version,
            versions,
            severity,
            &mut issues,
        );
    }
    issues
}

/// The strict version findings for `profile` against `versions`, each with
/// [`Severity::Error`]: the check runs only in strict mode, where findings
/// are raised.
///
/// - For `android`, `ios`, `tdesktop` and `macos`: `app_version` must start
///   with the major (the text before the first `.`) of the latest known app
///   version. It is a prefix test, so `130.0` passes for a known `13.0.3`.
/// - For `android`: a system version containing `SDK` has every `SDK `
///   removed and the rest read as a Python `int()`; any other system version
///   must match `^\d+(?:\.\d+)?\s*\((\d+)\)$` (Python `re`, Unicode digits
///   and spaces) and the group is read. The level must lie in
///   `android_sdk_range`. Text that does not read as an integer, including
///   over 4300 digits (`sys.get_int_max_str_digits()` default), is skipped.
#[must_use]
pub fn check_versions(profile: &ApiProfile, versions: &Versions) -> Vec<Issue> {
    let mut issues = Vec::new();
    version_issues(
        &profile.lang_pack,
        &profile.app_version,
        &profile.system_version,
        versions,
        Severity::Error,
        &mut issues,
    );
    issues
}

fn version_issues(
    lang_pack: &str,
    app_version: &str,
    system_version: &str,
    versions: &Versions,
    severity: Severity,
    issues: &mut Vec<Issue>,
) {
    let known = match lang_pack {
        "android" => Some((&versions.android_app_version, "Android")),
        "ios" => Some((&versions.ios_app_version, "iOS")),
        "tdesktop" => Some((&versions.desktop_app_version, "Desktop")),
        "macos" => Some((&versions.macos_app_version, "macOS")),
        _ => None,
    };
    if let Some((known, label)) = known {
        let major = known
            .split_once('.')
            .map_or(known.as_str(), |(major, _)| major);
        if !app_version.starts_with(major) {
            issues.push(Issue {
                kind: IssueKind::AppVersionMajor,
                severity,
                message: format!(
                    "{label} app_version '{app_version}' major does not match latest known '{known}'"
                ),
            });
        }
    }

    if lang_pack == "android" {
        let sdk = if system_version.contains("SDK") {
            PyInt::parse(&system_version.replace("SDK ", ""))
        } else {
            sdk_in_parentheses(system_version).and_then(PyInt::parse)
        };
        if let Some(sdk) = sdk {
            let (lo, hi) = versions.android_sdk_range;
            if !sdk.within(lo, hi) {
                issues.push(Issue {
                    kind: IssueKind::AndroidSdkRange,
                    severity,
                    message: format!(
                        "Android SDK {sdk} is outside the expected range [{lo}, {hi}]"
                    ),
                });
            }
        }
    }
}

/// The group of `^\d+(?:\.\d+)?\s*\((\d+)\)$` in Python `re.match`.
///
/// The classes are disjoint, so a left-to-right scan finds the only match.
/// `$` also matches before one final `\n`.
fn sdk_in_parentheses(text: &str) -> Option<&str> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    let rest = skip_decimals(text)?;
    let rest = match rest.strip_prefix('.') {
        Some(fraction) => skip_decimals(fraction)?,
        None => rest,
    };
    let group = rest
        .trim_start_matches(is_python_space)
        .strip_prefix('(')?
        .strip_suffix(')')?;
    (!group.is_empty() && group.chars().all(|c| decimal_value(c).is_some())).then_some(group)
}

/// `text` after its leading `\d+`; `None` when it has no leading digit.
fn skip_decimals(text: &str) -> Option<&str> {
    let rest = text.trim_start_matches(|c| decimal_value(c).is_some());
    (rest.len() < text.len()).then_some(rest)
}

/// The first code point of every run of ten Unicode decimal digits
/// (`unicodedata.decimal(c) == 0`), from Python 3.12's Unicode 15.0.0. These
/// are the characters Python's `int()` and `re` `\d` read as digits.
const DECIMAL_ZEROS: [u32; 68] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16A60, 0x16AC0,
    0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E950,
    0x1FBF0,
];

/// The decimal value of `c` as Python's `unicodedata.decimal` gives it.
fn decimal_value(c: char) -> Option<u8> {
    let code = u32::from(c);
    let run = DECIMAL_ZEROS.partition_point(|&zero| zero <= code);
    let zero = DECIMAL_ZEROS.get(run.checked_sub(1)?)?;
    u8::try_from(code - zero).ok().filter(|digit| *digit < 10)
}

/// Python's `str.isspace`, which `re` `\s` also uses.
fn is_python_space(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\u{1c}'..='\u{1f}'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// The spaces Python's `int()` strips: ASCII spaces of C `isspace`, plus
/// every non-ASCII `str.isspace` character. `\x1c`..`\x1f` are not stripped,
/// because `int()` keeps ASCII characters as they are.
fn is_int_space(c: char) -> bool {
    if c.is_ascii() {
        matches!(c, '\t'..='\r' | ' ')
    } else {
        is_python_space(c)
    }
}

/// Python's default `sys.get_int_max_str_digits()`.
const MAX_STR_DIGITS: usize = 4300;

/// An integer read as Python's `int(text)` reads a `str`, kept as its
/// decimal form so that any length compares and prints as Python's does.
struct PyInt {
    negative: bool,
    /// ASCII digits without leading zeros; `0` for zero.
    digits: String,
}

impl PyInt {
    /// `int(text)`, or `None` where it raises `ValueError`: surrounding
    /// spaces, an optional sign, then Unicode decimal digits with single
    /// underscores between them, at most [`MAX_STR_DIGITS`] digits.
    fn parse(text: &str) -> Option<Self> {
        let text = text.trim_matches(is_int_space);
        let (negative, body) = match text.strip_prefix('-') {
            Some(body) => (true, body),
            None => (false, text.strip_prefix('+').unwrap_or(text)),
        };
        let mut digits = String::new();
        let mut count = 0usize;
        // True at the start, so a leading underscore or an empty body fails.
        let mut after_underscore = true;
        for c in body.chars() {
            if c == '_' {
                if after_underscore {
                    return None;
                }
                after_underscore = true;
                continue;
            }
            let digit = decimal_value(c)?;
            count += 1;
            after_underscore = false;
            if !(digits.is_empty() && digit == 0) {
                digits.push(char::from(b'0' + digit));
            }
        }
        if after_underscore || count > MAX_STR_DIGITS {
            return None;
        }
        let negative = negative && !digits.is_empty();
        if digits.is_empty() {
            digits.push('0');
        }
        Some(Self { negative, digits })
    }

    /// `lo <= self <= hi`.
    fn within(&self, lo: u32, hi: u32) -> bool {
        if self.negative || self.digits.len() > 10 {
            return false;
        }
        self.digits
            .parse::<u64>()
            .is_ok_and(|value| u64::from(lo) <= value && value <= u64::from(hi))
    }
}

impl fmt::Display for PyInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        f.write_str(&self.digits)
    }
}

/// The fingerprint options of `FingerprintConfig`, with its defaults
/// from [`FingerprintConfig::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FingerprintConfig {
    /// How consistency issues are handled; default [`StrictMode::Warn`].
    pub strict_mode: StrictMode,
    /// Whether [`FingerprintConfig::validate`] checks anything; default on.
    pub auto_validate: bool,
    /// Preferred transport: `full`, `intermediate`, `abridged` or
    /// `obfuscated` (the default, which official clients use).
    pub preferred_transport: String,
    /// Whether to warn when the library layer differs from the advertised
    /// one; default on.
    pub warn_on_layer_mismatch: bool,
    /// The layer used in `invokeWithLayer` instead of the default; none by
    /// default.
    pub layer_override: Option<i32>,
    /// Whether msg ids get a small random offset; default on.
    pub randomize_msg_id_offset: bool,
    /// The msg id offset (`_msg_id_offset`), drawn by
    /// [`msg_id_offset`] on construction.
    pub msg_id_offset: u16,
}

impl FingerprintConfig {
    /// The defaults, drawing [`FingerprintConfig::msg_id_offset`] from
    /// `rng` as [`msg_id_offset`] does.
    #[must_use]
    pub fn new(rng: &mut dyn FnMut(&mut [u8])) -> Self {
        Self {
            strict_mode: StrictMode::Warn,
            auto_validate: true,
            preferred_transport: "obfuscated".to_owned(),
            warn_on_layer_mismatch: true,
            layer_override: None,
            randomize_msg_id_offset: true,
            msg_id_offset: msg_id_offset(rng),
        }
    }

    /// [`FingerprintConfig::new`] with randomness from the operating system.
    ///
    /// # Errors
    ///
    /// [`Error::Io`](crate::Error::Io) when the operating system has no randomness to give.
    pub fn from_os_rng() -> Result<Self> {
        let mut bytes = [0u8; 2];
        crate::crypto::random_fill(&mut bytes)?;
        // `new` draws exactly these two bytes.
        Ok(Self::new(&mut |buf| buf.copy_from_slice(&bytes)))
    }

    /// The layer to invoke with: [`FingerprintConfig::layer_override`] when
    /// set, otherwise [`LAYER`].
    ///
    /// Without an override the Python `get_effective_layer` returns the
    /// layer of the installed Telethon ([`FingerprintConfig::effective_layer_for`]). That is a property of the `MTProto`
    /// library, which the core does not have; the core answers with the
    /// layer it advertises, and bindings pass their library's layer as the
    /// override.
    #[must_use]
    pub fn effective_layer(&self) -> i32 {
        self.layer_override.unwrap_or(LAYER)
    }

    /// `get_effective_layer` for an `MTProto` library built for
    /// `library_layer`: the layer to invoke with, and the warning
    /// `get_recommended_layer` emits on the way.
    ///
    /// With [`FingerprintConfig::layer_override`] set, that layer and no
    /// warning. Otherwise `library_layer` and [`layer_mismatch_warning`] of
    /// it, whatever [`FingerprintConfig::warn_on_layer_mismatch`] says.
    #[must_use]
    pub fn effective_layer_for(&self, library_layer: i32) -> (i32, Option<String>) {
        match self.layer_override {
            Some(layer) => (layer, None),
            None => (library_layer, layer_mismatch_warning(library_layer)),
        }
    }

    /// The issues `validate_params` warns about or raises for
    /// `profile` (render them with [`issues_message`]).
    ///
    /// Empty when [`FingerprintConfig::auto_validate`] is off, and under
    /// [`StrictMode::Off`], where nothing is surfaced. Otherwise
    /// [`validate_init_params`] under the configured mode: warnings under
    /// [`StrictMode::Warn`], errors under [`StrictMode::Strict`].
    #[must_use]
    pub fn validate(&self, profile: &ApiProfile, versions: &Versions) -> Vec<Issue> {
        self.validate_raw(&RawInitParams::from_profile(profile), versions)
    }

    /// [`FingerprintConfig::validate`] of the values the caller gave
    /// `validate_params`, through [`validate_raw_init_params`], so the
    /// messages are in their final display form.
    #[must_use]
    pub fn validate_raw(&self, params: &RawInitParams<'_>, versions: &Versions) -> Vec<Issue> {
        if !self.auto_validate || self.strict_mode == StrictMode::Off {
            return Vec::new();
        }
        validate_raw_init_params(params, versions, self.strict_mode)
    }
}

/// The warning `get_recommended_layer` emits when the `MTProto`
/// library's layer `library_layer` is more than
/// [`crate::auth::LAYER_TOLERANCE`] layers from [`LAYER`]; `None` within
/// it. The warning names the library after Telethon.
#[must_use]
pub fn layer_mismatch_warning(library_layer: i32) -> Option<String> {
    let diff = library_layer.abs_diff(LAYER);
    (diff > crate::auth::LAYER_TOLERANCE).then(|| {
        format!(
            "Telethon TL layer ({library_layer}) differs from advertised layer \
             ({LAYER}, base={LAYER}) by {diff} layers. This may cause initConnection \
             fingerprint inconsistencies. Consider updating Telethon or opentele2."
        )
    })
}

/// The options a binding's `fingerprint_config` takes: each field that is
/// set replaces the [`FingerprintConfig::new`] default of the same name.
///
/// Bindings read their text and integer arguments into these types first,
/// with [`StrictMode::from_value`] and [`to_offset`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct FingerprintConfigOptions {
    /// Replaces [`FingerprintConfig::strict_mode`].
    pub strict_mode: Option<StrictMode>,
    /// Replaces [`FingerprintConfig::auto_validate`].
    pub auto_validate: Option<bool>,
    /// Replaces [`FingerprintConfig::preferred_transport`].
    pub preferred_transport: Option<String>,
    /// Replaces [`FingerprintConfig::warn_on_layer_mismatch`].
    pub warn_on_layer_mismatch: Option<bool>,
    /// Sets [`FingerprintConfig::layer_override`]; unset keeps no override.
    pub layer_override: Option<i32>,
    /// Replaces [`FingerprintConfig::randomize_msg_id_offset`].
    pub randomize_msg_id_offset: Option<bool>,
    /// Replaces the drawn [`FingerprintConfig::msg_id_offset`]; when set,
    /// nothing is drawn.
    pub msg_id_offset: Option<u16>,
}

impl FingerprintConfig {
    /// The defaults with every option that is set in `options`
    /// replacing its default. Without
    /// [`FingerprintConfigOptions::msg_id_offset`] the offset is drawn from
    /// `rng` as [`FingerprintConfig::new`] draws it; with it, `rng` is not
    /// called.
    #[must_use]
    pub fn with_options(options: FingerprintConfigOptions, rng: &mut dyn FnMut(&mut [u8])) -> Self {
        let mut config = match options.msg_id_offset {
            Some(offset) => {
                let bytes = offset.to_le_bytes();
                Self::new(&mut |buf| buf.copy_from_slice(&bytes))
            }
            None => Self::new(rng),
        };
        config.apply(options);
        config
    }

    /// [`FingerprintConfig::with_options`] drawing a missing offset from the
    /// operating system, as the bindings' `fingerprint_config` does.
    ///
    /// # Errors
    ///
    /// [`Error::Io`](crate::Error::Io) when no offset is given and the operating system has
    /// no randomness to give.
    pub fn from_options(options: FingerprintConfigOptions) -> Result<Self> {
        let mut config = match options.msg_id_offset {
            Some(offset) => {
                let bytes = offset.to_le_bytes();
                Self::new(&mut |buf| buf.copy_from_slice(&bytes))
            }
            None => Self::from_os_rng()?,
        };
        config.apply(options);
        Ok(config)
    }

    /// Replaces every field `options` sets except the offset, which the
    /// constructors take.
    fn apply(&mut self, options: FingerprintConfigOptions) {
        if let Some(mode) = options.strict_mode {
            self.strict_mode = mode;
        }
        if let Some(auto) = options.auto_validate {
            self.auto_validate = auto;
        }
        if let Some(transport) = options.preferred_transport {
            self.preferred_transport = transport;
        }
        if let Some(warn) = options.warn_on_layer_mismatch {
            self.warn_on_layer_mismatch = warn;
        }
        if options.layer_override.is_some() {
            self.layer_override = options.layer_override;
        }
        if let Some(randomize) = options.randomize_msg_id_offset {
            self.randomize_msg_id_offset = randomize;
        }
    }
}

/// A msg id offset given as an integer: `Some` within `0..=0xFFFF`, `None`
/// outside it, where the bindings raise
/// `msg_id_offset must be in 0..=0xFFFF`.
#[must_use]
pub fn to_offset(value: i64) -> Option<u16> {
    u16::try_from(value).ok()
}

/// A random msg id offset in `0..=0xFFFF` from the operating system's
/// CSPRNG: [`msg_id_offset`] over two bytes of OS randomness, as the
/// bindings' `msg_id_offset` draws it.
///
/// # Errors
///
/// [`Error::Io`](crate::Error::Io) when the operating system has no randomness to give.
pub fn msg_id_offset_for_os() -> Result<u16> {
    let mut bytes = [0u8; 2];
    crate::crypto::random_fill(&mut bytes)?;
    // `msg_id_offset` draws exactly these two bytes.
    Ok(msg_id_offset(&mut |buf| buf.copy_from_slice(&bytes)))
}

/// A random msg id offset in `0..=0xFFFF`, the range of
/// `generate_msg_id_offset` (`random.randint(0, 0xFFFF)`), from two bytes
/// of `rng` read little-endian.
#[must_use]
pub fn msg_id_offset(rng: &mut dyn FnMut(&mut [u8])) -> u16 {
    let mut bytes = [0u8; 2];
    rng(&mut bytes);
    u16::from_le_bytes(bytes)
}

/// Whether `msg_id` is plausible at unix time `now_unix` (`is_valid_msg_id`,
/// whose Python form reads `int(time.time())`).
///
/// It must be positive and odd when `from_client`, even otherwise, and its
/// upper 32 bits must be within 300 seconds of `now_unix`, exclusive.
#[must_use]
pub fn is_valid_msg_id(msg_id: i64, from_client: bool, now_unix: i64) -> bool {
    if msg_id <= 0 {
        return false;
    }
    if (msg_id % 2 == 1) != from_client {
        return false;
    }
    (msg_id >> 32).abs_diff(now_unix) < 300
}
