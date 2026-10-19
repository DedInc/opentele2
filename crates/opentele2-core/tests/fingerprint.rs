//! Tests for `fingerprint`. Every expected value was printed by the 1.5.0
//! Python functions of `src/fingerprint.py` (Python 3.12.8, imported as
//! `src` with `OPENTELE_NO_FETCH=1`, so `PLATFORM_VERSIONS` holds the
//! offline defaults of `Versions::offline`):
//!
//! - `tdesktop_tz_offset` on `datetime(2026, 10, 18, 12, 0,
//!   tzinfo=timezone(timedelta(seconds=s)))`, and on instants converted to
//!   `zoneinfo` zones for the DST cases;
//! - `validate_init_connection_params` with `strict=False` and `strict=True`;
//! - `FingerprintConfig.validate_params` per mode, catching the warning or
//!   the `ValueError`;
//! - `is_valid_msg_id` with `time.time` patched to `1760000000.9`.

use opentele2_core::api::{ApiProfile, LAYER, Versions};
use opentele2_core::fingerprint::{
    self, FingerprintConfig, Issue, IssueKind, Severity, StrictMode, check_versions,
    is_valid_msg_id, issues_message, msg_id_offset, tz_offset, validate_init_params,
};

// ---------------------------------------------------------------- tz_offset

#[test]
fn tz_offset_matches_1_5_0_for_fixed_offsets() {
    // (utc offset in seconds, 1.5.0 tdesktop_tz_offset)
    let cases: [(i32, f64); 22] = [
        (18000, 18000.0),
        (19800, 19800.0),
        (20700, 20700.0),
        (-12600, -12600.0),
        (50400, 50400.0),
        (-43200, -43200.0),
        (0, 0.0),
        // std::round sends halves away from zero.
        (450, 900.0),
        (-450, -900.0),
        (420, 0.0),
        (449, 0.0),
        (-449, 0.0),
        (451, 900.0),
        (1350, 1800.0),
        (-1350, -1800.0),
        // Above +14 h loses a day; below -12 h gains one.
        (50401, -36000.0),
        (54000, -32400.0),
        (86399, 0.0),
        (-43201, 43200.0),
        (-86399, 0.0),
        (-50400, 36000.0),
        (45900, 45900.0),
    ];
    for (offset, expected) in cases {
        assert_eq!(
            tz_offset(offset).to_bits(),
            expected.to_bits(),
            "offset {offset}"
        );
    }
}

#[test]
fn tz_offset_matches_1_5_0_for_every_second_of_a_day_either_way() {
    // 1.5.0: sum(int(tdesktop_tz_offset(at(s))) // 900 * (s + 86400)
    //            for s in range(-86399, 86400))
    let mut total = 0i64;
    let mut quarter = -56i32;
    for offset in -86_399..86_400 {
        let value = tz_offset(offset);
        // Every result is a multiple of 900 in -43200..=50400; find which.
        while f64::from(quarter * 900) < value {
            quarter += 1;
        }
        while f64::from(quarter * 900) > value {
            quarter -= 1;
        }
        assert_eq!(f64::from(quarter * 900).to_bits(), value.to_bits());
        total += i64::from(quarter) * i64::from(offset + 86_400);
    }
    assert_eq!(total, 32_358_124_800);
}

#[test]
fn tz_offset_follows_dst_and_odd_zones() {
    // (zone, UTC instant, zoneinfo utcoffset, 1.5.0 result)
    let cases: [(&str, &str, i32, f64); 13] = [
        ("Europe/Berlin", "2026-01-15", 3600, 3600.0),
        ("Europe/Berlin", "2026-07-15", 7200, 7200.0),
        ("America/St_Johns", "2026-01-15", -12600, -12600.0),
        ("America/St_Johns", "2026-07-15", -9000, -9000.0),
        ("Australia/Lord_Howe", "2026-01-15", 39600, 39600.0),
        ("Australia/Lord_Howe", "2026-07-15", 37800, 37800.0),
        ("Pacific/Chatham", "2026-01-15", 49500, 49500.0),
        ("Pacific/Chatham", "2026-07-15", 45900, 45900.0),
        ("Asia/Kathmandu", "2026-07-15", 20700, 20700.0),
        ("Pacific/Kiritimati", "2026-07-15", 50400, 50400.0),
        ("Pacific/Marquesas", "2026-07-15", -34200, -34200.0),
        // Liberian mean time, -0:44:30: not a quarter hour.
        ("Africa/Monrovia", "1971-07-15", -2670, -2700.0),
        ("Europe/Amsterdam", "1937-07-15", 3600, 3600.0),
    ];
    for (zone, date, offset, expected) in cases {
        assert_eq!(
            tz_offset(offset).to_bits(),
            expected.to_bits(),
            "{zone} {date}"
        );
    }
}

#[test]
fn tz_offset_wraps_any_i32_by_whole_days() {
    // Beyond a datetime's range; the 1.5.0 loops wrap by whole days, so the
    // result equals that of the congruent offset inside one day.
    for offset in [
        i32::MIN,
        i32::MIN + 1,
        -1_000_000,
        1_000_000,
        i32::MAX - 1,
        i32::MAX,
    ] {
        let within_day = offset % 86_400;
        assert_eq!(
            tz_offset(offset).to_bits(),
            tz_offset(within_day).to_bits(),
            "{offset}"
        );
    }
}

// ----------------------------------------------------- validate_init_params

const PACKS: &str = "Expected one of: ['', 'android', 'ios', 'macos', 'tdesktop']";
const ANDROID_MAJOR: &str =
    "Android app_version '12.3.0' major does not match latest known '13.0.3'";

fn profile(
    api_id: i32,
    device_model: &str,
    system_version: &str,
    app_version: &str,
    system_lang_code: &str,
    lang_pack: &str,
    lang_code: &str,
) -> ApiProfile {
    ApiProfile {
        api_id,
        api_hash: String::new(),
        device_model: device_model.to_owned(),
        system_version: system_version.to_owned(),
        app_version: app_version.to_owned(),
        lang_code: lang_code.to_owned(),
        system_lang_code: system_lang_code.to_owned(),
        lang_pack: lang_pack.to_owned(),
    }
}

/// The Android base case of 1.5.0 `tests/test_fingerprints.py`.
fn android() -> ApiProfile {
    profile(
        6,
        "Samsung SM-S928B",
        "SDK 35",
        "12.3.0",
        "en-US",
        "android",
        "en",
    )
}

fn messages(issues: &[Issue]) -> Vec<&str> {
    issues.iter().map(|issue| issue.message.as_str()).collect()
}

fn check(label: &str, profile: &ApiProfile, loose: &[&str], strict: &[&str]) {
    let versions = Versions::offline();
    for mode in [StrictMode::Off, StrictMode::Warn] {
        let issues = validate_init_params(profile, &versions, mode);
        assert_eq!(messages(&issues), loose, "{label} {mode:?}");
        assert!(issues.iter().all(|i| i.severity == mode.severity()));
    }
    let issues = validate_init_params(profile, &versions, StrictMode::Strict);
    assert_eq!(messages(&issues), strict, "{label} strict");
    assert!(issues.iter().all(|i| i.severity == Severity::Error));
}

fn unknown(pack: &str) -> String {
    format!("lang_pack '{pack}' is not a known official value. {PACKS}")
}

#[test]
fn validate_matches_1_5_0_for_its_own_test_cases() {
    check("android_ok", &android(), &[], &[ANDROID_MAJOR]);
    check(
        "desktop_ok",
        &profile(
            2040,
            "Desktop",
            "Windows 11",
            "5.12.3 x64",
            "en-US",
            "tdesktop",
            "en",
        ),
        &[],
        &["Desktop app_version '5.12.3 x64' major does not match latest known '7.3.1'"],
    );
    check(
        "web_ok",
        &profile(
            2496,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Windows",
            "5.0.0 Z",
            "en-US",
            "",
            "en",
        ),
        &[],
        &[],
    );
    check(
        "empty_device",
        &ApiProfile {
            device_model: String::new(),
            ..android()
        },
        &["device_model is empty"],
        &["device_model is empty", ANDROID_MAJOR],
    );
    let all_empty = [
        unknown("invalid"),
        "lang_code '' looks invalid (too short)".to_owned(),
        "device_model is empty".to_owned(),
        "system_version is empty".to_owned(),
        "app_version is empty".to_owned(),
    ];
    let all_empty: Vec<&str> = all_empty.iter().map(String::as_str).collect();
    check(
        "all_empty",
        &profile(6, "", "", "", "", "invalid", ""),
        &all_empty,
        &all_empty,
    );
}

#[test]
fn validate_matches_1_5_0_for_language_fields() {
    let bad_pack = unknown("invalid_pack");
    check(
        "bad_pack",
        &ApiProfile {
            lang_pack: "invalid_pack".to_owned(),
            ..android()
        },
        &[&bad_pack],
        &[&bad_pack],
    );
    let short = "lang_code 'x' looks invalid (too short)";
    check(
        "short_lang",
        &ApiProfile {
            lang_code: "x".to_owned(),
            ..android()
        },
        &[short],
        &[short, ANDROID_MAJOR],
    );
    // Python's len counts code points, not UTF-8 bytes.
    let one_char = "lang_code '\u{e9}' looks invalid (too short)";
    check(
        "one_char_lang",
        &ApiProfile {
            lang_code: "\u{e9}".to_owned(),
            ..android()
        },
        &[one_char],
        &[one_char, ANDROID_MAJOR],
    );
    check(
        "two_char_lang",
        &ApiProfile {
            lang_code: "\u{e9}\u{e9}".to_owned(),
            ..android()
        },
        &[],
        &[ANDROID_MAJOR],
    );
    check(
        "api_mismatch",
        &ApiProfile {
            api_id: 99999,
            ..android()
        },
        &[],
        &[
            "api_id 99999 does not match lang_pack 'android' (expected 6)",
            ANDROID_MAJOR,
        ],
    );
}

#[test]
fn validate_matches_1_5_0_for_regions() {
    let region =
        "system_lang_code 'en' should include a region code (e.g. 'en-US') for android clients";
    check(
        "no_region_android",
        &ApiProfile {
            system_lang_code: "en".to_owned(),
            ..android()
        },
        &[region],
        &[region, ANDROID_MAJOR],
    );
    let region =
        "system_lang_code 'en' should include a region code (e.g. 'en-US') for ios clients";
    check(
        "no_region_ios",
        &profile(
            10840,
            "Samsung SM-S928B",
            "27.0.1",
            "13.0",
            "en",
            "ios",
            "en",
        ),
        &[region],
        &[region],
    );
    check(
        "no_region_desktop",
        &profile(
            2040,
            "Desktop",
            "Windows 11",
            "7.3.1 x64",
            "en",
            "tdesktop",
            "en",
        ),
        &[],
        &[],
    );
}

#[test]
fn validate_matches_1_5_0_for_each_platform_in_strict_mode() {
    check(
        "macos_ok",
        &profile(
            2834,
            "MacBook Air",
            "macOS 27.0.1",
            "13.0",
            "en-US",
            "macos",
            "en",
        ),
        &[],
        &[],
    );
    check(
        "macos_old",
        &profile(
            2834,
            "MacBook Air",
            "macOS 27.0.1",
            "12.9",
            "en-US",
            "macos",
            "en",
        ),
        &[],
        &["macOS app_version '12.9' major does not match latest known '13.0'"],
    );
    check(
        "ios_wrong_id",
        &profile(
            6,
            "Samsung SM-S928B",
            "27.0.1",
            "13.0",
            "en-US",
            "ios",
            "en",
        ),
        &[],
        &["api_id 6 does not match lang_pack 'ios' (expected 10840)"],
    );
    check(
        "desktop_old",
        &profile(
            2040,
            "Desktop",
            "Windows 11",
            "6.9 x64",
            "en-US",
            "tdesktop",
            "en",
        ),
        &[],
        &["Desktop app_version '6.9 x64' major does not match latest known '7.3.1'"],
    );
    // 1.5.0 tests a prefix, so "130.0" passes against "13".
    check(
        "startswith_quirk",
        &ApiProfile {
            app_version: "130.0".to_owned(),
            ..android()
        },
        &[],
        &[],
    );
    let weba = unknown("weba");
    check(
        "unknown_pack",
        &ApiProfile {
            api_id: 1,
            lang_pack: "weba".to_owned(),
            ..android()
        },
        &[&weba],
        &[&weba],
    );
    check(
        "android_current",
        &ApiProfile {
            app_version: "13.0.3".to_owned(),
            system_version: "SDK 37".to_owned(),
            ..android()
        },
        &[],
        &[],
    );
}

#[test]
fn issues_carry_their_kind() {
    let issues = validate_init_params(
        &profile(1, "", "", "", "en", "ios", "x"),
        &Versions::offline(),
        StrictMode::Strict,
    );
    let kinds: Vec<IssueKind> = issues.iter().map(|issue| issue.kind).collect();
    assert_eq!(
        kinds,
        [
            IssueKind::ShortLangCode,
            IssueKind::MissingRegion,
            IssueKind::EmptyDeviceModel,
            IssueKind::EmptySystemVersion,
            IssueKind::EmptyAppVersion,
            IssueKind::ApiIdMismatch,
            IssueKind::AppVersionMajor,
        ]
    );
    assert_eq!(
        issues[0].to_string(),
        "lang_code 'x' looks invalid (too short)"
    );
}

// ----------------------------------------------------------- check_versions

fn sdk_issue(level: &str) -> String {
    format!("Android SDK {level} is outside the expected range [29, 37]")
}

#[test]
fn check_versions_reads_android_sdk_levels_as_1_5_0_does() {
    let big = "9".repeat(30);
    let cases: Vec<(String, Option<String>)> = vec![
        ("SDK 29".into(), None),
        ("SDK 37".into(), None),
        ("SDK 28".into(), Some("28".into())),
        ("SDK 38".into(), Some("38".into())),
        // No "SDK " to remove: int("SDK35") raises, nothing is reported.
        ("SDK35".into(), None),
        ("SDK  40".into(), Some("40".into())),
        ("SDK -5".into(), Some("-5".into())),
        ("SDK +40".into(), Some("40".into())),
        ("SDK 3_8".into(), Some("38".into())),
        ("SDK 3__8".into(), None),
        ("SDK 0040".into(), Some("40".into())),
        ("SDK \u{663}\u{668}".into(), Some("38".into())),
        ("SDK 40 ".into(), Some("40".into())),
        ("SDK \u{3000}40".into(), Some("40".into())),
        // int() strips no ASCII \x1c, though str.isspace() is true for it.
        ("SDK \u{1c}40".into(), None),
        ("Android SDK 40".into(), None),
        ("SDK SDK 40".into(), Some("40".into())),
        ("SDK -0".into(), Some("0".into())),
        (format!("SDK {big}"), Some(big.clone())),
        // int() refuses more than 4300 digits; underscores do not count.
        (format!("SDK {}", "9".repeat(4301)), None),
        (format!("SDK 1{}", "_0".repeat(4300)), None),
        (
            format!("SDK 1{}", "_0".repeat(4299)),
            Some(format!("1{}", "0".repeat(4299))),
        ),
        (format!("SDK 0{}", "0".repeat(4300)), None),
        ("14 (34)".into(), None),
        ("14 (40)".into(), Some("40".into())),
        ("15.0 (28)".into(), Some("28".into())),
        ("15.0(40)".into(), Some("40".into())),
        ("15. (40)".into(), None),
        ("15.0.1 (40)".into(), None),
        // `$` matches before one final newline.
        ("14 (40)\n".into(), Some("40".into())),
        ("14 (40)\n\n".into(), None),
        // re's \s does include \x1c.
        ("14\u{1c}(40)".into(), Some("40".into())),
        ("14 (\u{664}\u{660})".into(), Some("40".into())),
        ("14 (0040)".into(), Some("40".into())),
        ("Android 14 (40)".into(), None),
        ("14 (40) ".into(), None),
        ("(40)".into(), None),
        ("14 ()".into(), None),
        ("\u{661}\u{664} (40)".into(), Some("40".into())),
        (format!("14 (4{})", "0".repeat(4300)), None),
        (
            format!("14 (4{})", "0".repeat(4299)),
            Some(format!("4{}", "0".repeat(4299))),
        ),
        ("14 (-40)".into(), None),
        ("14\u{2003}\t(40)".into(), Some("40".into())),
        ("14 (40)\r".into(), None),
        ("sdk 40".into(), None),
        ("14 (\u{ff14}\u{ff10})".into(), Some("40".into())),
    ];
    let versions = Versions::offline();
    for (system_version, level) in cases {
        let android = ApiProfile {
            app_version: "13.0.3".to_owned(),
            system_version: system_version.clone(),
            ..android()
        };
        let expected: Vec<String> = level.iter().map(|level| sdk_issue(level)).collect();
        let issues = check_versions(&android, &versions);
        assert_eq!(messages(&issues), expected, "{system_version:?}");
        assert!(
            issues
                .iter()
                .all(|i| i.kind == IssueKind::AndroidSdkRange && i.severity == Severity::Error)
        );
        let strict = validate_init_params(&android, &versions, StrictMode::Strict);
        assert_eq!(messages(&strict), expected, "{system_version:?} strict");
    }
}

#[test]
fn check_versions_follows_the_versions_passed() {
    let versions = Versions {
        android_app_version: "12.9".to_owned(),
        android_sdk_range: (21, 40),
        ..Versions::offline()
    };
    let android = ApiProfile {
        system_version: "SDK 40".to_owned(),
        ..android()
    };
    assert_eq!(messages(&check_versions(&android, &versions)), [""; 0]);
    let issues = check_versions(
        &ApiProfile {
            system_version: "SDK 41".to_owned(),
            ..android
        },
        &versions,
    );
    assert_eq!(
        messages(&issues),
        ["Android SDK 41 is outside the expected range [21, 40]"]
    );
}

// ------------------------------------------------- StrictMode and the config

#[test]
fn strict_mode_has_the_1_5_0_values() {
    let values: Vec<&str> = StrictMode::ALL.iter().map(|mode| mode.as_str()).collect();
    assert_eq!(values, ["off", "warn", "strict"]);
    for mode in StrictMode::ALL {
        assert_eq!(StrictMode::from_value(mode.as_str()), Some(mode));
    }
    assert_eq!(StrictMode::from_value("WARN"), None);
    assert_eq!(StrictMode::Off.severity(), Severity::Note);
    assert_eq!(StrictMode::Warn.severity(), Severity::Warning);
    assert_eq!(StrictMode::Strict.severity(), Severity::Error);
}

#[test]
fn config_defaults_match_1_5_0() {
    let config = FingerprintConfig::new(&mut |buf| buf.copy_from_slice(&[0x34, 0x12]));
    assert_eq!(
        config,
        FingerprintConfig {
            strict_mode: StrictMode::Warn,
            auto_validate: true,
            preferred_transport: "obfuscated".to_owned(),
            warn_on_layer_mismatch: true,
            layer_override: None,
            randomize_msg_id_offset: true,
            msg_id_offset: 0x1234,
        }
    );
    assert_eq!(config.effective_layer(), LAYER);
    let config = FingerprintConfig {
        layer_override: Some(201),
        ..config
    };
    assert_eq!(config.effective_layer(), 201);
    FingerprintConfig::from_os_rng().expect("os randomness");
}

#[test]
fn config_validate_warns_and_raises_as_1_5_0() {
    let versions = Versions::offline();
    let android = ApiProfile {
        api_id: 1,
        device_model: String::new(),
        ..android()
    };
    let config = |strict_mode, auto_validate| FingerprintConfig {
        strict_mode,
        auto_validate,
        ..FingerprintConfig::new(&mut |buf| buf.fill(0))
    };
    // OFF: nothing surfaces; auto_validate off: nothing is checked.
    for (mode, auto) in [
        (StrictMode::Off, true),
        (StrictMode::Off, false),
        (StrictMode::Warn, false),
        (StrictMode::Strict, false),
    ] {
        let issues = config(mode, auto).validate(&android, &versions);
        assert_eq!(messages(&issues), [""; 0], "{mode:?} {auto}");
    }
    // WARN: warnings.warn(msg).
    let warned = config(StrictMode::Warn, true).validate(&android, &versions);
    assert!(warned.iter().all(|i| i.severity == Severity::Warning));
    assert_eq!(
        issues_message(&warned),
        "initConnection fingerprint issues:\n  - device_model is empty"
    );
    // STRICT: raise ValueError(msg).
    let raised = config(StrictMode::Strict, true).validate(&android, &versions);
    assert!(raised.iter().all(|i| i.severity == Severity::Error));
    assert_eq!(
        issues_message(&raised),
        "initConnection fingerprint issues:\n  - device_model is empty\n  - api_id 1 does not \
         match lang_pack 'android' (expected 6)\n  - Android app_version '12.3.0' major does \
         not match latest known '13.0.3'"
    );
}

// ------------------------------------------------------------------- msg_id

#[test]
fn msg_id_offset_spans_0_to_0xffff() {
    assert_eq!(msg_id_offset(&mut |buf| buf.fill(0)), 0);
    assert_eq!(msg_id_offset(&mut |buf| buf.fill(0xFF)), 0xFFFF);
    assert_eq!(
        msg_id_offset(&mut |buf| buf.copy_from_slice(&[0x01, 0x80])),
        0x8001
    );
    let mut drawn = 0;
    let _ = fingerprint::msg_id_offset(&mut |buf| drawn += buf.len());
    assert_eq!(drawn, 2);
}

#[test]
fn is_valid_msg_id_matches_1_5_0() {
    const NOW: i64 = 1_760_000_000;
    // (msg_id, from_client, 1.5.0 result at time.time() == NOW + 0.9)
    let cases: [(i64, bool, bool); 17] = [
        (7_559_142_440_960_000_001, true, true),
        (7_559_142_440_960_000_001, false, false),
        (7_559_142_440_960_000_000, true, false),
        (7_559_142_440_960_000_000, false, true),
        // NOW + 299 and NOW + 300 in the upper bits.
        (7_559_143_725_155_221_505, true, true),
        (7_559_143_729_450_188_801, true, false),
        // NOW - 299 and NOW - 300.
        (7_559_141_156_764_778_497, true, true),
        (7_559_141_152_469_811_201, true, false),
        // Lower 32 bits all set at NOW + 299 and NOW - 300.
        (7_559_143_729_450_188_799, true, true),
        (7_559_141_156_764_778_495, true, false),
        (0, true, false),
        (0, false, false),
        (-1, true, false),
        (-2, false, false),
        (1, true, false),
        (i64::MAX, true, false),
        (7_559_142_440_960_000_004, false, true),
    ];
    for (msg_id, from_client, expected) in cases {
        assert_eq!(
            is_valid_msg_id(msg_id, from_client, NOW),
            expected,
            "{msg_id} {from_client}"
        );
    }
}

#[test]
fn is_valid_msg_id_survives_extreme_clocks() {
    let msg_id = (1_760_000_000i64 << 32) | 1;
    assert!(!is_valid_msg_id(msg_id, true, i64::MIN));
    assert!(!is_valid_msg_id(msg_id, true, i64::MAX));
    assert!(is_valid_msg_id(i64::MAX, true, i64::MAX >> 32));
    assert!(!is_valid_msg_id(i64::MAX, false, i64::MAX >> 32));
}
