//! The pure `initConnection` fingerprint helpers of opentele2 1.5.0
//! (`src/fingerprint.py`).
//!
//! - [`tz_offset`] is `tdesktop_tz_offset`, the `tz_offset` Telegram Desktop
//!   puts into `initConnection` `params`. The caller passes the local UTC
//!   offset, so results do not depend on the machine's clock or zone.
//! - [`validate_init_params`] is `validate_init_connection_params`, and
//!   [`check_versions`] is its strict version check
//!   `_check_version_consistency`. Versions come from a [`Versions`] the
//!   caller passes, where 1.5.0 reads its global `PLATFORM_VERSIONS`.
//! - [`StrictMode`] and [`FingerprintConfig`] are the 1.5.0 types of the same
//!   names.
//! - [`msg_id_offset`] is `generate_msg_id_offset` with randomness from the
//!   caller, and [`is_valid_msg_id`] takes the current unix time where 1.5.0
//!   reads `time.time()`.
//!
//! 1.5.0 returns findings as strings and leaves warning or raising to
//! `FingerprintConfig.validate_params`. Here every finding is an [`Issue`]
//! with the 1.5.0 message and a [`Severity`] that says what 1.5.0 does with
//! it under the [`StrictMode`] in force:
//!
//! | 1.5.0 behaviour | Mode | Severity |
//! |---|---|---|
//! | returned in the list, never warned or raised | [`StrictMode::Off`] | [`Severity::Note`] |
//! | `warnings.warn(msg)` | [`StrictMode::Warn`] | [`Severity::Warning`] |
//! | `raise ValueError(msg)` | [`StrictMode::Strict`] | [`Severity::Error`] |
//!
//! [`issues_message`] builds the `msg` 1.5.0 warns or raises with.
//!
//! `TransportRecommendation` needs Telethon connection classes and stays in
//! the Python binding.

use std::fmt;

use crate::api::{ApiProfile, LAYER, Versions};
use crate::{Error, Result};

/// The `tz_offset` Telegram Desktop sends in `initConnection` `params` for a
/// local UTC offset of `utc_offset_seconds` (1.5.0 `tdesktop_tz_offset`,
/// mirroring `SessionPrivate::prepareInitParams`).
///
/// The offset is wrapped by whole days into -12 h..+14 h: an offset below
/// -12 h gains days until it is at least -12 h, and one above +14 h loses
/// days until it is at most +14 h. It is then rounded to a multiple of 900
/// seconds with halves away from zero (`std::round`).
///
/// 1.5.0 reads the offset from a `datetime`, which bounds it to under 24 h
/// either way; any `i32` is accepted here and wrapped the same way.
#[must_use]
pub fn tz_offset(utc_offset_seconds: i32) -> f64 {
    const DAY: i32 = 24 * 3600;
    const LOW: i32 = -12 * 3600;
    const HIGH: i32 = 14 * 3600;
    let mut sliced = utc_offset_seconds;
    // Closed forms of the 1.5.0 `while` loops, safe at the `i32` extremes:
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

/// How 1.5.0 handles fingerprint consistency issues (`StrictMode`).
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
    /// Every mode, in 1.5.0's declaration order.
    pub const ALL: [Self; 3] = [Self::Off, Self::Warn, Self::Strict];

    /// The 1.5.0 enum value: `off`, `warn` or `strict`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Strict => "strict",
        }
    }

    /// The mode whose 1.5.0 enum value is `value`, as `StrictMode(value)`;
    /// `None` for any other string, including other cases.
    #[must_use]
    pub fn from_value(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == value)
    }

    /// The severity 1.5.0 gives a finding under this mode.
    #[must_use]
    pub fn severity(self) -> Severity {
        match self {
            Self::Off => Severity::Note,
            Self::Warn => Severity::Warning,
            Self::Strict => Severity::Error,
        }
    }
}

/// What 1.5.0 does with a finding; see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Returned in the list only.
    Note,
    /// Emitted as a Python warning.
    Warning,
    /// Raised as a `ValueError`.
    Error,
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

/// One finding, with the message 1.5.0 reports for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Issue {
    /// The check that failed.
    pub kind: IssueKind,
    /// What 1.5.0 does with the finding.
    pub severity: Severity,
    /// The 1.5.0 message, character for character.
    pub message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The message 1.5.0 `FingerprintConfig.validate_params` warns or raises
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

/// 1.5.0 `_VALID_LANG_PACKS`, as its `sorted()` list renders in messages.
const VALID_LANG_PACKS: [&str; 5] = ["", "android", "ios", "macos", "tdesktop"];

/// 1.5.0 `_LANG_PACK_API_ID_MAP`.
fn official_api_id(lang_pack: &str) -> Option<i32> {
    match lang_pack {
        "tdesktop" => Some(2040),
        "android" => Some(6),
        "ios" => Some(10840),
        "macos" => Some(2834),
        _ => None,
    }
}

/// The findings of 1.5.0 `validate_init_connection_params` for `profile`,
/// in its order, with `strict` on exactly when `mode` is
/// [`StrictMode::Strict`]. Each finding has `mode`'s [`Severity`].
///
/// Always checked: `lang_pack` is official, `lang_code` has at least two
/// characters, an Android or iOS `system_lang_code` has a region, and the
/// device model, system version and app version are not empty. Strict mode
/// adds the official `api_id` of the `lang_pack` and [`check_versions`]
/// against `versions`. `api_hash` is not checked.
#[must_use]
pub fn validate_init_params(
    profile: &ApiProfile,
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
    let lang_pack = profile.lang_pack.as_str();

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
    if profile.lang_code.chars().count() < 2 {
        push(
            IssueKind::ShortLangCode,
            format!(
                "lang_code '{}' looks invalid (too short)",
                profile.lang_code
            ),
        );
    }
    if matches!(lang_pack, "android" | "ios") && !profile.system_lang_code.contains('-') {
        push(
            IssueKind::MissingRegion,
            format!(
                "system_lang_code '{}' should include a region code (e.g. 'en-US') \
                 for {lang_pack} clients",
                profile.system_lang_code
            ),
        );
    }
    if profile.device_model.is_empty() {
        push(
            IssueKind::EmptyDeviceModel,
            "device_model is empty".to_owned(),
        );
    }
    if profile.system_version.is_empty() {
        push(
            IssueKind::EmptySystemVersion,
            "system_version is empty".to_owned(),
        );
    }
    if profile.app_version.is_empty() {
        push(
            IssueKind::EmptyAppVersion,
            "app_version is empty".to_owned(),
        );
    }

    if mode == StrictMode::Strict {
        if let Some(expected) = official_api_id(lang_pack)
            && profile.api_id != expected
        {
            push(
                IssueKind::ApiIdMismatch,
                format!(
                    "api_id {} does not match lang_pack '{lang_pack}' (expected {expected})",
                    profile.api_id
                ),
            );
        }
        version_issues(profile, versions, severity, &mut issues);
    }
    issues
}

/// The findings of 1.5.0 `_check_version_consistency` for `profile`
/// against `versions`, each with [`Severity::Error`]: 1.5.0 runs this check
/// only in strict mode, where findings are raised.
///
/// - For `android`, `ios`, `tdesktop` and `macos`: `app_version` must start
///   with the major (the text before the first `.`) of the latest known app
///   version. It is a prefix test, as in 1.5.0, so `130.0` passes for a
///   known `13.0.3`.
/// - For `android`: a system version containing `SDK` has every `SDK `
///   removed and the rest read as a Python `int()`; any other system version
///   must match `^\d+(?:\.\d+)?\s*\((\d+)\)$` (Python `re`, Unicode digits
///   and spaces) and the group is read. The level must lie in
///   `android_sdk_range`. Text that does not read as an integer, including
///   over 4300 digits (`sys.get_int_max_str_digits()` default), is skipped.
#[must_use]
pub fn check_versions(profile: &ApiProfile, versions: &Versions) -> Vec<Issue> {
    let mut issues = Vec::new();
    version_issues(profile, versions, Severity::Error, &mut issues);
    issues
}

fn version_issues(
    profile: &ApiProfile,
    versions: &Versions,
    severity: Severity,
    issues: &mut Vec<Issue>,
) {
    let lang_pack = profile.lang_pack.as_str();
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
        if !profile.app_version.starts_with(major) {
            issues.push(Issue {
                kind: IssueKind::AppVersionMajor,
                severity,
                message: format!(
                    "{label} app_version '{}' major does not match latest known '{known}'",
                    profile.app_version
                ),
            });
        }
    }

    if lang_pack == "android" {
        let system_version = profile.system_version.as_str();
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

/// The fingerprint options of 1.5.0 `FingerprintConfig`, with its defaults
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
    /// The msg id offset (1.5.0 `_msg_id_offset`), drawn by
    /// [`msg_id_offset`] on construction.
    pub msg_id_offset: u16,
}

impl FingerprintConfig {
    /// The 1.5.0 defaults, drawing [`FingerprintConfig::msg_id_offset`] from
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
    /// [`Error::Io`] when the operating system has no randomness to give.
    pub fn from_os_rng() -> Result<Self> {
        let mut bytes = [0u8; 2];
        getrandom::fill(&mut bytes).map_err(|e| Error::Io(std::io::Error::other(e)))?;
        // `new` draws exactly these two bytes.
        Ok(Self::new(&mut |buf| buf.copy_from_slice(&bytes)))
    }

    /// The layer to invoke with (1.5.0 `get_effective_layer`):
    /// [`FingerprintConfig::layer_override`] when set, otherwise
    /// [`LAYER`].
    ///
    /// Without an override 1.5.0 returns the layer of the installed Telethon
    /// (`get_recommended_layer`). That is a property of the `MTProto`
    /// library, which the core does not have; the core answers with the
    /// layer it advertises, and bindings pass their library's layer as the
    /// override.
    #[must_use]
    pub fn effective_layer(&self) -> i32 {
        self.layer_override.unwrap_or(LAYER)
    }

    /// The issues 1.5.0 `validate_params` warns about or raises for
    /// `profile` (render them with [`issues_message`]).
    ///
    /// Empty when [`FingerprintConfig::auto_validate`] is off, and under
    /// [`StrictMode::Off`], where 1.5.0 surfaces nothing. Otherwise
    /// [`validate_init_params`] under the configured mode: warnings under
    /// [`StrictMode::Warn`], errors under [`StrictMode::Strict`].
    #[must_use]
    pub fn validate(&self, profile: &ApiProfile, versions: &Versions) -> Vec<Issue> {
        if !self.auto_validate || self.strict_mode == StrictMode::Off {
            return Vec::new();
        }
        validate_init_params(profile, versions, self.strict_mode)
    }
}

/// A random msg id offset in `0..=0xFFFF`, as 1.5.0
/// `generate_msg_id_offset` (`random.randint(0, 0xFFFF)`), from two bytes
/// of `rng` read little-endian.
#[must_use]
pub fn msg_id_offset(rng: &mut dyn FnMut(&mut [u8])) -> u16 {
    let mut bytes = [0u8; 2];
    rng(&mut bytes);
    u16::from_le_bytes(bytes)
}

/// Whether `msg_id` is plausible at unix time `now_unix` (1.5.0
/// `is_valid_msg_id`, which reads `int(time.time())`).
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
