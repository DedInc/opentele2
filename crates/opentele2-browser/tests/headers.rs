//! The header generator on the embedded Apify networks.

use std::collections::HashMap;

use opentele2_browser::headers::{MAX_LOCALES, SEC_FETCH};
use opentele2_browser::{
    Browser, Error, HeaderGenerator, HeaderOptions, HeaderOverrides, Headers, HttpVersion,
    Restrictions, Rng, Values, browser_of, get_user_agent, header_network, pascalize,
};

const CHROME_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";
const EDGE_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0";
const SAFARI_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15";

fn generator(options: HeaderOptions) -> HeaderGenerator {
    HeaderGenerator::new(options).unwrap()
}

fn generate(generator: &HeaderGenerator, seed: &str) -> Headers {
    generator
        .generate(&mut Rng::from_seed(seed), &HeaderOverrides::default())
        .unwrap()
}

fn user_agent(headers: &Headers) -> &str {
    get_user_agent(headers).expect("a User-Agent")
}

fn header<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str)
}

fn orders() -> HashMap<String, Vec<String>> {
    serde_json::from_str(include_str!("../data/headers-order.json")).unwrap()
}

/// `true` when every header is in `order` and they come in its order, the
/// names matched either as they are (HTTP/1) or lower-cased against the
/// HTTP/2 tail of the list (pascalized HTTP/2 output).
fn follows(headers: &Headers, order: &[String]) -> bool {
    let increasing = |position: &dyn Fn(&str) -> Option<usize>| {
        let positions: Option<Vec<usize>> = headers.keys().map(position).collect();
        positions.is_some_and(|p| p.windows(2).all(|w| w[0] < w[1]))
    };
    increasing(&|name| order.iter().position(|o| o == name))
        || increasing(&|name| {
            let lower = name.to_ascii_lowercase();
            order.iter().rposition(|o| *o == lower)
        })
}

fn chrome_major(user_agent: &str) -> u32 {
    // Chrome on iOS says `CriOS/`, everywhere else `Chrome/`.
    let start = ["Chrome/", "CriOS/"]
        .iter()
        .find_map(|token| user_agent.find(token).map(|i| i + token.len()))
        .expect("a Chrome token");
    let tail = &user_agent[start..];
    tail.split('.').next().unwrap().parse().unwrap()
}

#[test]
fn default_options_give_a_user_agent_in_browser_order() {
    let generator = generator(HeaderOptions::default());
    let orders = orders();
    for seed in 0..200 {
        let headers = generate(&generator, &seed.to_string());
        let browser = browser_of(user_agent(&headers)).expect("a known browser");
        assert!(
            follows(&headers, &orders[browser]),
            "seed {seed}: {browser} order broken: {headers:?}"
        );
        assert!(
            headers
                .iter()
                .all(|(k, v)| !k.starts_with('*') && v != "*MISSING_VALUE*"),
            "seed {seed}: {headers:?}"
        );
        assert_eq!(header(&headers, "Accept-Language"), Some("en-US;q=1.0"));
    }
}

#[test]
fn chrome_only_gives_chrome_inside_the_version_bounds() {
    let generator = generator(HeaderOptions {
        browsers: vec![Browser {
            min_version: Some(130),
            max_version: Some(146),
            ..Browser::new("chrome")
        }],
        ..HeaderOptions::default()
    });
    for seed in 0..40 {
        let headers = generate(&generator, &format!("chrome {seed}"));
        let ua = user_agent(&headers);
        assert_eq!(browser_of(ua), Some("chrome"), "{ua}");
        assert!((130..=146).contains(&chrome_major(ua)), "{ua}");
    }
}

#[test]
fn firefox_http1_falls_back_to_http2() {
    let generator = generator(
        HeaderOptions {
            browsers: vec![Browser::new("firefox")],
            strict: true,
            ..HeaderOptions::default()
        }
        .with_http_version(HttpVersion::One),
    );
    for seed in 0..10 {
        let headers = generate(&generator, &format!("firefox {seed}"));
        assert_eq!(browser_of(user_agent(&headers)), Some("firefox"));
        // The HTTP/2 sample comes out pascalized.
        assert!(headers.contains_key("User-Agent"));
        assert!(headers.contains_key("Accept-Language"));
    }
}

#[test]
fn strict_impossible_options_fail_with_the_message() {
    let generator = generator(HeaderOptions {
        browsers: vec![Browser::new("safari")],
        os: vec!["windows".to_owned()],
        devices: vec!["desktop".to_owned()],
        strict: true,
        ..HeaderOptions::default()
    });
    let error = generator
        .generate(&mut Rng::from_seed("strict"), &HeaderOverrides::default())
        .unwrap_err();
    assert_eq!(error, Error::NoHeaders);
    assert_eq!(
        error.to_string(),
        "No headers based on this input can be generated. Please relax or change some of the requirements you specified."
    );
}

#[test]
fn relaxation_drops_locales_first_and_keeps_the_browser() {
    let locales = vec!["de-DE".to_owned(), "fr-FR".to_owned()];
    let impossible = generator(HeaderOptions {
        browsers: vec![Browser::new("safari")],
        os: vec!["windows".to_owned()],
        devices: vec!["desktop".to_owned()],
        locales: locales.clone(),
        ..HeaderOptions::default()
    });
    for seed in 0..10 {
        let headers = generate(&impossible, &format!("relax {seed}"));
        assert_eq!(browser_of(user_agent(&headers)), Some("safari"));
        assert_eq!(header(&headers, "Accept-Language"), Some("en-US;q=1.0"));
    }
    let possible = generator(HeaderOptions {
        locales,
        ..HeaderOptions::default()
    });
    let headers = generate(&possible, "kept");
    assert_eq!(
        header(&headers, "Accept-Language"),
        Some("de-DE;q=1.0, fr-FR;q=0.9")
    );
}

#[test]
fn sec_fetch_values_are_real_for_chrome_and_absent_for_safari() {
    let chrome = generator(HeaderOptions {
        browsers: vec![Browser::new("chrome")],
        ..HeaderOptions::default()
    });
    for seed in 0..10 {
        let headers = generate(&chrome, &format!("sec {seed}"));
        for (name, value) in SEC_FETCH {
            assert_eq!(header(&headers, &pascalize(name)), Some(value), "{name}");
        }
        assert_eq!(header(&headers, "Sec-Fetch-Site"), Some("same-site"));
        assert_eq!(header(&headers, "Sec-Fetch-Mode"), Some("navigate"));
        assert_eq!(header(&headers, "Sec-Fetch-User"), Some("?1"));
        assert_eq!(header(&headers, "Sec-Fetch-Dest"), Some("document"));
    }
    let safari = generator(HeaderOptions {
        browsers: vec![Browser::new("safari")],
        ..HeaderOptions::default()
    });
    for seed in 0..10 {
        let headers = generate(&safari, &format!("sec {seed}"));
        assert!(
            headers
                .keys()
                .all(|k| !k.to_ascii_lowercase().starts_with("sec-fetch")),
            "{headers:?}"
        );
    }
}

#[test]
fn edge_user_agents_use_the_edge_order() {
    assert_eq!(browser_of(EDGE_WINDOWS), Some("edge"));
    assert_eq!(
        browser_of(
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36 EdgA/147.0.0.0"
        ),
        Some("edge")
    );
    assert_eq!(
        browser_of(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/147.0.0.0 Mobile/15E148 Safari/605.1.15"
        ),
        Some("edge")
    );
    assert_eq!(browser_of(CHROME_WINDOWS), Some("chrome"));
    assert_eq!(browser_of(SAFARI_MAC), Some("safari"));
    assert_eq!(browser_of("curl/8.0"), None);

    let edge = generator(HeaderOptions {
        browsers: vec![Browser::new("edge")],
        ..HeaderOptions::default()
    });
    let orders = orders();
    for seed in 0..10 {
        let headers = generate(&edge, &format!("edge {seed}"));
        assert_eq!(browser_of(user_agent(&headers)), Some("edge"));
        assert!(follows(&headers, &orders["edge"]), "{headers:?}");
    }
}

#[test]
fn user_agent_override_is_honoured() {
    let generator = generator(HeaderOptions::default());
    let one = HeaderOverrides {
        user_agent: vec![CHROME_WINDOWS.to_owned()],
        ..HeaderOverrides::default()
    };
    let two = HeaderOverrides {
        user_agent: vec![CHROME_WINDOWS.to_owned(), SAFARI_MAC.to_owned()],
        ..HeaderOverrides::default()
    };
    for seed in 0..20 {
        let headers = generator
            .generate(&mut Rng::from_seed(&format!("ua {seed}")), &one)
            .unwrap();
        assert_eq!(user_agent(&headers), CHROME_WINDOWS);
        let headers = generator
            .generate(&mut Rng::from_seed(&format!("ua {seed}")), &two)
            .unwrap();
        assert!([CHROME_WINDOWS, SAFARI_MAC].contains(&user_agent(&headers)));
    }
}

#[test]
fn request_dependent_headers_are_kept() {
    let generator = generator(HeaderOptions::default());
    let mut extra = Headers::new();
    extra.insert("accept-language", "uk-UA;q=1.0".to_owned());
    extra.insert("X-Request-Id", "42".to_owned());
    let overrides = HeaderOverrides {
        request_dependent_headers: extra,
        ..HeaderOverrides::default()
    };
    let headers = generator
        .generate(&mut Rng::from_seed("extra"), &overrides)
        .unwrap();
    let plain = generate(&generator, "extra");
    assert_eq!(header(&headers, "Accept-Language"), Some("uk-UA;q=1.0"));
    assert!(!headers.contains_key("accept-language"));
    assert_eq!(headers.keys().last(), Some("X-Request-Id"));
    assert_eq!(headers.len(), plain.len() + 1);
}

#[test]
fn same_seed_same_headers_different_seeds_differ() {
    let generator = generator(HeaderOptions::default());
    let first = generate(&generator, "Мухамед");
    assert_eq!(first, generate(&generator, "Мухамед"));
    let all: Vec<Headers> = (0..20)
        .map(|seed| generate(&generator, &format!("spread {seed}")))
        .collect();
    assert!(all.iter().any(|headers| *headers != all[0]));
}

#[test]
fn invalid_options_are_rejected() {
    let inverted = HeaderGenerator::new(HeaderOptions {
        browsers: vec![Browser {
            min_version: Some(120),
            max_version: Some(110),
            ..Browser::new("chrome")
        }],
        ..HeaderOptions::default()
    });
    assert!(matches!(inverted, Err(Error::InvalidOptions(_))));

    let locales = |n: usize| (0..n).map(|i| format!("l{i}")).collect::<Vec<_>>();
    let too_many = HeaderGenerator::new(HeaderOptions {
        locales: locales(MAX_LOCALES + 1),
        ..HeaderOptions::default()
    });
    assert!(matches!(too_many, Err(Error::InvalidOptions(_))));

    let ten = generator(HeaderOptions {
        locales: locales(MAX_LOCALES),
        ..HeaderOptions::default()
    });
    let headers = generate(&ten, "ten");
    let value = header(&headers, "Accept-Language").unwrap();
    assert!(value.starts_with("l0;q=1.0, l1;q=0.9"), "{value}");
    assert!(value.ends_with("l9;q=0.1"), "{value}");
}

#[test]
fn pascalize_matches_browserforge() {
    assert_eq!(pascalize(":method"), ":method");
    assert_eq!(pascalize("sec-ch-ua-mobile"), "sec-ch-ua-mobile");
    assert_eq!(pascalize("dnt"), "DNT");
    assert_eq!(pascalize("rtt"), "RTT");
    assert_eq!(pascalize("te"), "Te");
    assert_eq!(pascalize("sec-fetch-site"), "Sec-Fetch-Site");
    assert_eq!(pascalize("accept-language"), "Accept-Language");
    assert_eq!(pascalize("x-a1b"), "X-A1B");
}

#[test]
fn restricted_sample_without_restrictions_is_sample() {
    let net = header_network().unwrap();
    let fixed: Values = [("*HTTP_VERSION", "_2.0_".to_owned())]
        .into_iter()
        .collect();
    for seed in 0..20 {
        let seed = seed.to_string();
        let free = net.sample(&mut Rng::from_seed(&seed), &fixed);
        let restricted = net
            .restricted_sample(&mut Rng::from_seed(&seed), &fixed, &Restrictions::new())
            .unwrap();
        assert_eq!(free, restricted);
    }
    let only: Restrictions = [("user-agent", vec![SAFARI_MAC.to_owned()])]
        .into_iter()
        .collect();
    let sample = net
        .restricted_sample(&mut Rng::from_seed("only"), &fixed, &only)
        .unwrap();
    assert_eq!(
        sample.get("user-agent").map(String::as_str),
        Some(SAFARI_MAC)
    );
    let unknown: Restrictions = [("user-agent", vec!["nobody".to_owned()])]
        .into_iter()
        .collect();
    assert!(
        net.restricted_sample(&mut Rng::from_seed("none"), &fixed, &unknown)
            .is_none()
    );
}
