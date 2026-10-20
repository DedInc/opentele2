//! Tests for the name tables the bindings share. Every expected string is
//! the one the Python (`bindings/python/src`) and Node (`bindings/node/src`)
//! bindings show; both show the same strings, except that Node prefixes SRP
//! codes with `OT_`.

use opentele2_core::api::Client;
use opentele2_core::auth::SrpError;
use opentele2_core::devices::{Platform, WebClient};
use opentele2_core::fingerprint::{
    self, FingerprintConfig, FingerprintConfigOptions, IssueKind, Severity, StrictMode, to_offset,
};

// ------------------------------------------------------------------- clients

/// Python and Node `CLIENT_NAMES`, in their order.
const CLIENT_NAMES: [(&str, Client); 8] = [
    ("TelegramDesktop", Client::Desktop),
    ("TelegramAndroid", Client::Android),
    ("TelegramAndroidX", Client::AndroidX),
    ("TelegramIOS", Client::Ios),
    ("TelegramMacOS", Client::MacOS),
    ("TelegramWeb_A", Client::WebA),
    ("TelegramWeb_K", Client::WebK),
    ("Webogram", Client::Webogram),
];

#[test]
fn client_names_match_the_bindings() {
    for (name, client) in CLIENT_NAMES {
        assert_eq!(client.name(), name);
        assert_eq!(Client::from_name(name), Some(client), "{name}");
    }
    let names: Vec<&str> = Client::ALL.into_iter().map(Client::name).collect();
    let expected: Vec<&str> = CLIENT_NAMES.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, expected);
}

#[test]
fn client_from_name_is_exact() {
    for name in [
        "",
        "telegramdesktop",
        "TELEGRAMDESKTOP",
        " TelegramDesktop",
        "TelegramDesktop ",
        "TelegramWeb_Z",
        "Desktop",
        "webogram",
    ] {
        assert_eq!(Client::from_name(name), None, "{name:?}");
    }
}

// ----------------------------------------------------------------- platforms

/// Python and Node `PLATFORM_NAMES`, in their order.
const PLATFORM_NAMES: [(&str, Platform); 7] = [
    ("windows", Platform::Windows),
    ("linux", Platform::Linux),
    ("macos", Platform::MacOS { swift: false }),
    ("android", Platform::Android),
    ("ios", Platform::Ios),
    (
        "web_a",
        Platform::Web {
            client: WebClient::A,
        },
    ),
    (
        "web_k",
        Platform::Web {
            client: WebClient::K,
        },
    ),
];

#[test]
fn platform_names_match_the_bindings() {
    for (name, platform) in PLATFORM_NAMES {
        assert_eq!(platform.name(), name);
        assert_eq!(Platform::from_name(name), Some(platform), "{name}");
    }
    let named: Vec<Platform> = PLATFORM_NAMES.iter().map(|(_, p)| *p).collect();
    assert_eq!(Platform::NAMED.to_vec(), named);
}

#[test]
fn the_swift_mac_shares_the_macos_name() {
    let swift = Platform::MacOS { swift: true };
    assert_eq!(swift.name(), "macos");
    assert_eq!(
        Platform::from_name("macos"),
        Some(Platform::MacOS { swift: false })
    );
}

#[test]
fn platform_from_name_is_exact() {
    for name in [
        "", "Windows", "MACOS", "web", "web_z", "webA", " ios", "mac",
    ] {
        assert_eq!(Platform::from_name(name), None, "{name:?}");
    }
}

// --------------------------------------------------------------- issue kinds

/// Python and Node `KINDS`, in their order.
const KINDS: [(&str, IssueKind); 9] = [
    ("UnknownLangPack", IssueKind::UnknownLangPack),
    ("ShortLangCode", IssueKind::ShortLangCode),
    ("MissingRegion", IssueKind::MissingRegion),
    ("EmptyDeviceModel", IssueKind::EmptyDeviceModel),
    ("EmptySystemVersion", IssueKind::EmptySystemVersion),
    ("EmptyAppVersion", IssueKind::EmptyAppVersion),
    ("ApiIdMismatch", IssueKind::ApiIdMismatch),
    ("AppVersionMajor", IssueKind::AppVersionMajor),
    ("AndroidSdkRange", IssueKind::AndroidSdkRange),
];

#[test]
fn issue_kind_names_match_the_bindings() {
    for (name, kind) in KINDS {
        assert_eq!(kind.name(), name);
        assert_eq!(IssueKind::from_name(name), Some(kind), "{name}");
        // The name is the variant's, as both bindings documented.
        assert_eq!(format!("{kind:?}"), name);
    }
    let all: Vec<IssueKind> = KINDS.iter().map(|(_, kind)| *kind).collect();
    assert_eq!(IssueKind::ALL.to_vec(), all);
}

#[test]
fn issue_kind_from_name_is_exact() {
    for name in [
        "",
        "unknownLangPack",
        "UNKNOWNLANGPACK",
        "unknown_lang_pack",
    ] {
        assert_eq!(IssueKind::from_name(name), None, "{name:?}");
    }
}

// ---------------------------------------------------------------- severities

/// Python and Node `SEVERITIES`, in their order.
const SEVERITIES: [(&str, Severity); 3] = [
    ("note", Severity::Note),
    ("warning", Severity::Warning),
    ("error", Severity::Error),
];

#[test]
fn severity_names_match_the_bindings() {
    for (name, severity) in SEVERITIES {
        assert_eq!(severity.name(), name);
        assert_eq!(Severity::from_name(name), Some(severity), "{name}");
    }
    let all: Vec<Severity> = SEVERITIES.iter().map(|(_, s)| *s).collect();
    assert_eq!(Severity::ALL.to_vec(), all);
    // Each mode's severity carries a name.
    let by_mode: Vec<&str> = StrictMode::ALL
        .into_iter()
        .map(|mode| mode.severity().name())
        .collect();
    assert_eq!(by_mode, ["note", "warning", "error"]);
}

#[test]
fn severity_from_name_is_exact() {
    for name in ["", "Note", "WARNING", "warn", "err", "errors"] {
        assert_eq!(Severity::from_name(name), None, "{name:?}");
    }
}

// ----------------------------------------------------------------- SRP codes

#[test]
fn srp_codes_match_the_bindings() {
    // Python `srp_code`; Node `srp_error` is `OT_` followed by the same.
    let cases = [
        (SrpError::BadPrimeOrGenerator, "SRP_BAD_PRIME_OR_GENERATOR"),
        (SrpError::BadB, "SRP_BAD_B"),
        (SrpError::NoGoodRandom, "SRP_NO_GOOD_RANDOM"),
        (SrpError::RandomUnavailable, "SRP_RANDOM_UNAVAILABLE"),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
    }
}

// ------------------------------------------------------------ msg id offsets

#[test]
fn to_offset_accepts_exactly_the_u16_range() {
    assert_eq!(to_offset(0), Some(0));
    assert_eq!(to_offset(1), Some(1));
    assert_eq!(to_offset(0x1234), Some(0x1234));
    assert_eq!(to_offset(0xFFFF), Some(0xFFFF));
    for value in [-1, 0x1_0000, i64::MIN, i64::MAX, i64::from(u32::MAX)] {
        assert_eq!(to_offset(value), None, "{value}");
    }
}

#[test]
fn msg_id_offset_for_os_draws_from_the_os() {
    // Two 16-bit draws; 64 equal ones in a row would mean a constant.
    let first = fingerprint::msg_id_offset_for_os().expect("OS randomness");
    let varied = (0..64).any(|_| fingerprint::msg_id_offset_for_os().expect("OS") != first);
    assert!(varied);
}

// ------------------------------------------------------------- config merge

/// An rng that must not be called.
fn no_rng(_: &mut [u8]) {
    panic!("the offset was given, so nothing is drawn");
}

#[test]
fn no_options_keep_the_defaults_and_draw_the_offset() {
    let config = FingerprintConfig::with_options(FingerprintConfigOptions::default(), &mut |buf| {
        buf.copy_from_slice(&[0x34, 0x12]);
    });
    let expected = FingerprintConfig::new(&mut |buf| buf.copy_from_slice(&[0x34, 0x12]));
    assert_eq!(config, expected);
    assert_eq!(config.msg_id_offset, 0x1234);
    assert_eq!(config.strict_mode, StrictMode::Warn);
    assert!(config.auto_validate);
    assert_eq!(config.preferred_transport, "obfuscated");
    assert!(config.warn_on_layer_mismatch);
    assert_eq!(config.layer_override, None);
    assert!(config.randomize_msg_id_offset);
}

#[test]
fn every_option_replaces_its_default() {
    let options = FingerprintConfigOptions {
        strict_mode: Some(StrictMode::Strict),
        auto_validate: Some(false),
        preferred_transport: Some("abridged".to_owned()),
        warn_on_layer_mismatch: Some(false),
        layer_override: Some(201),
        randomize_msg_id_offset: Some(false),
        msg_id_offset: Some(0xBEEF),
    };
    let config = FingerprintConfig::with_options(options.clone(), &mut no_rng);
    assert_eq!(
        config,
        FingerprintConfig {
            strict_mode: StrictMode::Strict,
            auto_validate: false,
            preferred_transport: "abridged".to_owned(),
            warn_on_layer_mismatch: false,
            layer_override: Some(201),
            randomize_msg_id_offset: false,
            msg_id_offset: 0xBEEF,
        }
    );
    // A given offset draws nothing from the OS either.
    assert_eq!(
        FingerprintConfig::from_options(options).expect("no draw"),
        config
    );
}

#[test]
fn one_option_changes_one_field() {
    let base = FingerprintConfig::with_options(
        FingerprintConfigOptions {
            msg_id_offset: Some(7),
            ..FingerprintConfigOptions::default()
        },
        &mut no_rng,
    );
    let off = FingerprintConfig::with_options(
        FingerprintConfigOptions {
            strict_mode: Some(StrictMode::Off),
            msg_id_offset: Some(7),
            ..FingerprintConfigOptions::default()
        },
        &mut no_rng,
    );
    assert_eq!(
        off,
        FingerprintConfig {
            strict_mode: StrictMode::Off,
            ..base.clone()
        }
    );
    let layered = FingerprintConfig::with_options(
        FingerprintConfigOptions {
            layer_override: Some(0),
            msg_id_offset: Some(7),
            ..FingerprintConfigOptions::default()
        },
        &mut no_rng,
    );
    assert_eq!(
        layered,
        FingerprintConfig {
            layer_override: Some(0),
            ..base
        }
    );
}

#[test]
fn from_options_draws_a_missing_offset_from_the_os() {
    let options = FingerprintConfigOptions {
        preferred_transport: Some("full".to_owned()),
        ..FingerprintConfigOptions::default()
    };
    let config = FingerprintConfig::from_options(options).expect("OS randomness");
    assert_eq!(config.preferred_transport, "full");
    assert_eq!(config.strict_mode, StrictMode::Warn);
    assert_eq!(config.layer_override, None);
}
