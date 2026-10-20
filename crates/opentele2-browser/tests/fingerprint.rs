//! The fingerprint generator on the embedded Apify networks.

use opentele2_browser::headers::MISSING_VALUE;
use opentele2_browser::{
    Error, Fingerprint, FingerprintGenerator, FingerprintOptions, FingerprintOverrides,
    HeaderGenerator, HeaderOptions, HeaderOverrides, Rng, Screen, fingerprint_network,
    generate_fingerprint, generate_headers, get_user_agent, header_network,
};
use serde_json::Value;

const SCREEN_KEYS: [&str; 19] = [
    "availTop",
    "availLeft",
    "pageXOffset",
    "pageYOffset",
    "screenX",
    "hasHDR",
    "width",
    "height",
    "availWidth",
    "availHeight",
    "clientWidth",
    "clientHeight",
    "innerWidth",
    "innerHeight",
    "outerWidth",
    "outerHeight",
    "colorDepth",
    "pixelDepth",
    "devicePixelRatio",
];

const TOP_LEVEL_KEYS: [&str; 12] = [
    "screen",
    "navigator",
    "headers",
    "videoCodecs",
    "audioCodecs",
    "pluginsData",
    "battery",
    "videoCard",
    "multimediaDevices",
    "fonts",
    "mockWebRTC",
    "slim",
];

const NO_FINGERPRINT: &str = "Cannot generate headers. User-Agent may be invalid, or screen constraints are too restrictive.";

fn generator(options: FingerprintOptions) -> FingerprintGenerator {
    FingerprintGenerator::new(options).unwrap()
}

fn generate(generator: &FingerprintGenerator, seed: &str) -> Fingerprint {
    generator
        .generate(&mut Rng::from_seed(seed), &FingerprintOverrides::default())
        .unwrap()
}

fn json(fingerprint: &Fingerprint) -> Value {
    serde_json::from_str(&fingerprint.to_json().unwrap()).unwrap()
}

fn with_screen(screen: Screen, strict: bool) -> FingerprintOptions {
    FingerprintOptions {
        screen: Some(screen),
        strict,
        ..FingerprintOptions::default()
    }
}

#[test]
fn fingerprints_match_their_headers() {
    let generator = generator(FingerprintOptions::default());
    for i in 0..100 {
        let fingerprint = generate(&generator, &format!("fingerprint-{i}"));
        let header_ua = get_user_agent(&fingerprint.headers).expect("a User-Agent");
        assert_eq!(fingerprint.navigator.user_agent, header_ua, "seed {i}");
        let value = json(&fingerprint);
        let screen = value["screen"].as_object().unwrap();
        assert_eq!(screen.len(), SCREEN_KEYS.len(), "seed {i}");
        for key in SCREEN_KEYS {
            assert!(screen.contains_key(key), "seed {i} lacks screen.{key}");
        }
        let navigator = &fingerprint.navigator;
        assert_eq!(navigator.languages[0], navigator.language, "seed {i}");
        assert!(
            navigator.languages.iter().all(|l| l.trim() == l),
            "seed {i}"
        );
    }
}

/// Every User-Agent the header network can draw is a `userAgent` value of
/// the fingerprint network, so a fingerprint always exists for the headers
/// (browserforge looped forever when it did not).
#[test]
fn header_user_agents_are_known_to_the_fingerprint_network() {
    let known: Vec<&str> = fingerprint_network()
        .unwrap()
        .node("userAgent")
        .unwrap()
        .possible_values()
        .collect();
    let header_net = header_network().unwrap();
    for name in ["user-agent", "User-Agent"] {
        for ua in header_net.node(name).unwrap().possible_values() {
            assert!(ua == MISSING_VALUE || known.contains(&ua), "{name}: {ua}");
        }
    }
    let headers = HeaderGenerator::new(HeaderOptions::default()).unwrap();
    let absent = (0..100)
        .filter(|i| {
            let drawn = headers
                .generate(
                    &mut Rng::from_seed(&format!("fingerprint-{i}")),
                    &HeaderOverrides::default(),
                )
                .unwrap();
            !known.contains(&get_user_agent(&drawn).unwrap())
        })
        .count();
    assert_eq!(absent, 0);
}

#[test]
fn languages_are_trimmed_locales() {
    let options = FingerprintOptions {
        header: HeaderOptions {
            locales: vec!["en-US".to_owned(), "en".to_owned(), "de-DE".to_owned()],
            ..HeaderOptions::default()
        },
        ..FingerprintOptions::default()
    };
    let generator = generator(options);
    for i in 0..10 {
        let navigator = generate(&generator, &format!("locales-{i}")).navigator;
        assert_eq!(navigator.languages, ["en-US", "en", "de-DE"], "seed {i}");
        assert_eq!(navigator.language, "en-US", "seed {i}");
    }
}

#[test]
fn min_width_is_honoured() {
    let generator = generator(with_screen(
        Screen {
            min_width: Some(1920),
            ..Screen::default()
        },
        false,
    ));
    for i in 0..50 {
        let fingerprint = generate(&generator, &format!("wide-{i}"));
        assert!(fingerprint.screen.width >= 1920, "seed {i}");
        let header_ua = get_user_agent(&fingerprint.headers).unwrap();
        assert_eq!(fingerprint.navigator.user_agent, header_ua, "seed {i}");
    }
}

#[test]
fn screen_admits_by_width_and_height() {
    let screen = Screen {
        min_width: Some(1920),
        max_height: Some(1080),
        ..Screen::default()
    };
    assert!(screen.admits(r#"*STRINGIFIED*{"width":1920,"height":1080}"#));
    assert!(!screen.admits(r#"*STRINGIFIED*{"width":1919,"height":1080}"#));
    assert!(!screen.admits(r#"*STRINGIFIED*{"width":2560,"height":1440}"#));
    assert!(!screen.admits(r#"*STRINGIFIED*{"height":1080}"#));
    assert!(!screen.admits("*STRINGIFIED*{not json"));
    assert!(!screen.admits(r#"{"width":1920,"height":1080}"#));
}

#[test]
fn impossible_strict_screen_fails() {
    let impossible = Screen {
        min_width: Some(99_999),
        ..Screen::default()
    };
    let generator = generator(with_screen(impossible, true));
    let error = generator
        .generate(
            &mut Rng::from_seed("strict"),
            &FingerprintOverrides::default(),
        )
        .unwrap_err();
    assert_eq!(error, Error::NoFingerprint);
    assert_eq!(error.to_string(), NO_FINGERPRINT);
}

#[test]
fn impossible_lenient_screen_still_generates() {
    let impossible = Screen {
        min_width: Some(99_999),
        ..Screen::default()
    };
    let generator = generator(with_screen(impossible, false));
    let fingerprint = generate(&generator, "lenient");
    let header_ua = get_user_agent(&fingerprint.headers).unwrap();
    assert_eq!(fingerprint.navigator.user_agent, header_ua);
    assert!(fingerprint.screen.width < 99_999);
}

#[test]
fn inverted_screen_is_rejected() {
    let inverted = Screen {
        min_height: Some(800),
        max_height: Some(600),
        ..Screen::default()
    };
    assert!(matches!(
        FingerprintGenerator::new(with_screen(inverted, false)),
        Err(Error::InvalidOptions(_))
    ));
    let generator = generator(FingerprintOptions::default());
    let overrides = FingerprintOverrides {
        screen: Some(inverted),
        ..FingerprintOverrides::default()
    };
    assert!(matches!(
        generator.generate(&mut Rng::from_seed("inverted"), &overrides),
        Err(Error::InvalidOptions(_))
    ));
}

#[test]
fn same_seed_same_json() {
    let generator = generator(FingerprintOptions::default());
    for seed in ["a", "b", "c"] {
        let first = generate(&generator, seed).to_json().unwrap();
        let second = generate(&generator, seed).to_json().unwrap();
        assert_eq!(first, second, "seed {seed}");
    }
    let options = FingerprintOptions::default();
    assert_eq!(
        generate_fingerprint(Some("x"), &options).unwrap(),
        generate_fingerprint(Some("x"), &options).unwrap()
    );
    assert_eq!(
        generate_headers(Some("x"), &HeaderOptions::default()).unwrap(),
        generate_headers(Some("x"), &HeaderOptions::default()).unwrap()
    );
    assert!(generate_fingerprint(None, &options).is_ok());
    assert!(generate_headers(None, &HeaderOptions::default()).is_ok());
}

#[test]
fn json_has_browserforge_keys() {
    let options = FingerprintOptions {
        mock_webrtc: true,
        ..FingerprintOptions::default()
    };
    let fingerprint = generate(&generator(options), "keys");
    let value = json(&fingerprint);
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, TOP_LEVEL_KEYS);
    assert_eq!(value["mockWebRTC"], Value::Bool(true));
    assert_eq!(value["slim"], Value::Bool(false));
    let navigator = value["navigator"].as_object().unwrap();
    for key in [
        "userAgent",
        "userAgentData",
        "doNotTrack",
        "appCodeName",
        "appName",
        "appVersion",
        "oscpu",
        "webdriver",
        "language",
        "languages",
        "platform",
        "deviceMemory",
        "hardwareConcurrency",
        "product",
        "productSub",
        "vendor",
        "vendorSub",
        "maxTouchPoints",
        "extraProperties",
    ] {
        assert!(navigator.contains_key(key), "navigator.{key}");
    }
    let headers = value["headers"].as_object().unwrap();
    assert_eq!(
        headers.keys().collect::<Vec<_>>(),
        fingerprint.headers.keys().collect::<Vec<_>>()
    );
}

#[test]
fn stringified_and_missing_values_are_unpacked() {
    let generator = generator(FingerprintOptions::default());
    for i in 0..20 {
        let value = json(&generate(&generator, &format!("unpack-{i}")));
        let text = value.to_string();
        assert!(!text.contains("*STRINGIFIED*"), "seed {i}");
        assert!(!text.contains("*MISSING_VALUE*"), "seed {i}");
        assert!(value["fonts"].is_array(), "seed {i}");
        assert!(value["videoCodecs"].is_object(), "seed {i}");
        assert!(value["navigator"]["webdriver"].is_boolean(), "seed {i}");
    }
}
