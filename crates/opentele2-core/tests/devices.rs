//! Tests for `devices`: every case of `tests/vectors/devices.json` (1.5.0
//! `Generate` per entry point), seed hashes computed by 1.5.0's
//! `_strtohashid` and catalog sizes equal to 1.5.0's expanded list lengths.
//! The web catalog
//! has no 1.5.0 vectors (1.5.0 drew it from browserforge), so its tests check
//! determinism, reachability, the cited weights and the user agent formats.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use opentele2_core::Result;
use opentele2_core::devices::{self, Platform, WebClient};
use serde_json::Value;

const WEB_A: Platform = Platform::Web {
    client: WebClient::A,
};
const WEB_K: Platform = Platform::Web {
    client: WebClient::K,
};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_vectors() -> Value {
    let path = crate_dir().join("tests/vectors/devices.json");
    let text = fs::read_to_string(path).expect("read devices.json");
    serde_json::from_str(&text).expect("parse devices.json")
}

/// The seed 1.5.0 hashes: strings as given, integers as their decimal `str()`.
fn seed_of(case: &Value) -> String {
    match (&case["seed_kind"], &case["seed"]) {
        (Value::String(kind), Value::String(seed)) if kind == "str" => seed.clone(),
        (Value::String(kind), Value::Number(seed)) if kind == "int" => seed.to_string(),
        other => panic!("unexpected seed {other:?}"),
    }
}

/// The platform 1.5.0 `src/api.py` uses for an entry point and system.
fn platform_of(entry_point: &str, system: &Value, seed: &str) -> Result<Platform> {
    Ok(match (entry_point, system.as_str()) {
        ("TelegramDesktop", None) => devices::desktop_system(Some(seed))?,
        ("TelegramDesktop", Some("windows")) => Platform::Windows,
        ("TelegramDesktop", Some("macos")) => Platform::MacOS { swift: false },
        ("TelegramDesktop", Some("linux")) => Platform::Linux,
        // `_GENERATE_MAP`: Telegram X uses the Android catalog.
        ("TelegramAndroid" | "TelegramAndroidX", None) => Platform::Android,
        ("TelegramIOS", None) => Platform::Ios,
        ("TelegramMacOS", None) => Platform::MacOS { swift: true },
        other => panic!("unexpected entry point {other:?}"),
    })
}

#[test]
fn every_vector_case_matches_1_5_0() -> Result<()> {
    let vectors = read_vectors();
    let cases = vectors["cases"].as_array().expect("cases array");
    assert_eq!(cases.len(), 2800);
    let mut mismatches = Vec::new();
    for case in cases {
        let seed = seed_of(case);
        let entry_point = case["entry_point"].as_str().expect("entry_point");
        let platform = platform_of(entry_point, &case["system"], &seed)?;
        let device = devices::pick(platform, Some(&seed))?;
        let expected_model = case["device_model"].as_str().expect("device_model");
        let expected_version = case["system_version"].as_str().expect("system_version");
        if device.model != expected_model || device.system_version != expected_version {
            mismatches.push(format!(
                "{entry_point} {:?} {seed:?}: got {:?} / {:?}, want {expected_model:?} / {expected_version:?}",
                case["system"], device.model, device.system_version
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} cases differ:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
    Ok(())
}

#[test]
fn seed_hash_matches_python() {
    // int(hashlib.sha1(seed.encode()).hexdigest(), 16) % 10**12 in CPython.
    let expected = [
        ("", 403_882_391_305),
        ("user1@example.org", 266_454_831_697),
        ("ключ-2", 906_553_413_814),
        ("☃ snow 🔑 3", 677_289_622_030),
        ("0", 496_841_564_428),
        ("-1", 60_831_328_281),
        ("18446744073709551615", 172_076_701_297),
        ("-9223372036854775808", 132_465_474_143),
    ];
    for (seed, hash) in expected {
        assert_eq!(devices::seed_hash(seed), hash, "seed {seed:?}");
    }
}

#[test]
fn catalog_weights_equal_expanded_list_lengths() -> Result<()> {
    // len(cls.deviceList) after cls.__gen__() in 1.5.0.
    let expected = [
        (Platform::Windows, 3050),
        (Platform::Linux, 21045),
        (Platform::MacOS { swift: false }, 19680),
        (Platform::MacOS { swift: true }, 19680),
        (Platform::Android, 31148),
        (Platform::Ios, 18115),
    ];
    for (platform, total) in expected {
        let catalog = devices::catalog(platform)?;
        assert_eq!(catalog.total_weight(), total, "{platform:?}");
        assert!(!catalog.is_empty());
        assert_eq!(catalog.entries().len(), catalog.len());
        let sum: u64 = catalog.entries().map(|entry| entry.weight).sum();
        assert_eq!(sum, total, "{platform:?}");
        assert!(catalog.entries().all(|entry| entry.weight > 0));
    }
    Ok(())
}

#[test]
fn first_and_last_slots_match_expanded_list_ends() -> Result<()> {
    // deviceList[0] and deviceList[-1] in 1.5.0.
    let expected = [
        (
            Platform::Windows,
            ("Desktop", "Windows 11 x64"),
            ("PRIME X870-P", "Windows 10 x64"),
        ),
        (
            Platform::Linux,
            ("Desktop", "Linux ubuntu GNOME Wayland glibc 2.39"),
            ("PRIME X870-P", "Linux GNOME Xwayland glibc 2.43"),
        ),
        (
            Platform::MacOS { swift: true },
            ("MacBook Pro M1", "27.0.1"),
            ("MacBook Pro M5 Pro", "26.3"),
        ),
        (
            Platform::Android,
            ("asusASUS_AI2201_A", "SDK 31"),
            ("XiaomiNote 9S", "SDK 31"),
        ),
        (
            Platform::Ios,
            ("iPhone XS", "18.7.10"),
            ("iPhone Air", "26.0"),
        ),
    ];
    for (platform, first, last) in expected {
        let catalog = devices::catalog(platform)?;
        let entries: Vec<_> = catalog.entries().collect();
        let head = entries.first().expect("non-empty catalog");
        let tail = entries.last().expect("non-empty catalog");
        assert_eq!((head.model, head.system_version), first, "{platform:?}");
        assert_eq!((tail.model, tail.system_version), last, "{platform:?}");
    }
    Ok(())
}

#[test]
fn unseeded_pick_comes_from_the_catalog() -> Result<()> {
    for platform in [
        Platform::Windows,
        Platform::Linux,
        Platform::MacOS { swift: true },
        Platform::Android,
        Platform::Ios,
        WEB_A,
        WEB_K,
    ] {
        let device = devices::pick(platform, None)?;
        let catalog = devices::catalog(platform)?;
        assert!(
            catalog
                .entries()
                .any(|e| e.model == device.model && e.system_version == device.system_version),
            "{platform:?} picked {device:?}"
        );
    }
    let device = devices::pick(Platform::MacOS { swift: false }, None)?;
    assert!(device.system_version.starts_with("macOS "), "{device:?}");
    assert!(matches!(
        devices::desktop_system(None)?,
        Platform::Windows | Platform::Linux | Platform::MacOS { swift: false }
    ));
    Ok(())
}

fn web_json_text() -> String {
    fs::read_to_string(crate_dir().join("data/devices/web.json")).expect("read web.json")
}

/// The slot of 1.5.0's expanded list that `hash` lands on.
fn expected_web_pick(platform: Platform, seed: &str) -> Result<(String, String)> {
    let catalog = devices::catalog(platform)?;
    let mut index = devices::seed_hash(seed) % catalog.total_weight();
    for entry in catalog.entries() {
        if index < entry.weight {
            return Ok((entry.model.to_owned(), entry.system_version.to_owned()));
        }
        index -= entry.weight;
    }
    panic!("hash beyond the catalog's total weight");
}

#[test]
fn web_pick_is_deterministic_per_seed() -> Result<()> {
    for seed in ["", "user1@example.org", "ключ-2", "☃ snow 🔑 3", "0", "-1"] {
        let a = devices::pick(WEB_A, Some(seed))?;
        let k = devices::pick(WEB_K, Some(seed))?;
        for _ in 0..3 {
            assert_eq!(devices::pick(WEB_A, Some(seed))?, a, "{seed:?}");
            assert_eq!(devices::pick(WEB_K, Some(seed))?, k, "{seed:?}");
        }
        // One browser catalog: both clients see the same user agent.
        assert_eq!(a.model, k.model, "{seed:?}");
        assert_eq!(
            (a.model.clone(), a.system_version.clone()),
            expected_web_pick(WEB_A, seed)?
        );
        assert_eq!(
            (k.model.clone(), k.system_version.clone()),
            expected_web_pick(WEB_K, seed)?
        );
    }
    Ok(())
}

#[test]
fn every_web_entry_is_reachable() -> Result<()> {
    for platform in [WEB_A, WEB_K] {
        let catalog = devices::catalog(platform)?;
        let mut seen = HashSet::new();
        for i in 0..200_000 {
            let device = devices::pick(platform, Some(&format!("web-{i}")))?;
            seen.insert((device.model, device.system_version));
            if seen.len() == catalog.len() {
                break;
            }
        }
        let all: HashSet<_> = catalog
            .entries()
            .map(|e| (e.model.to_owned(), e.system_version.to_owned()))
            .collect();
        assert_eq!(
            all.len(),
            catalog.len(),
            "{platform:?} has duplicate entries"
        );
        assert_eq!(seen, all, "{platform:?}");
    }
    Ok(())
}

#[test]
fn web_weights_follow_the_cited_shares() -> Result<()> {
    let file: Value = serde_json::from_str(&web_json_text()).expect("parse web.json");
    assert_eq!(file["schema"], 1);
    let sources = file["sources"].as_array().expect("sources array");
    assert_ne!(sources.len(), 0);
    for source in sources {
        let url = source["url"].as_str().expect("source url");
        assert!(url.starts_with("https://"), "{url}");
        assert_eq!(source["accessed"], "2026-10-19", "{url}");
    }
    let platforms = file["platforms"].as_array().expect("platforms array");
    let share_of = |os: &str| -> u64 {
        platforms
            .iter()
            .find(|p| p["os"] == os)
            .and_then(|p| p["share_bp"].as_u64())
            .expect("OS share")
    };
    // round(browser share * OS share / sum of the browser's OS shares).
    let mut expected = Vec::new();
    for browser in file["browsers"].as_array().expect("browsers array") {
        let share = browser["share_bp"].as_u64().expect("browser share");
        let version = browser["version"].as_str().expect("version");
        let agents = browser["user_agents"].as_array().expect("user_agents");
        let total: u64 = agents
            .iter()
            .map(|a| share_of(a["os"].as_str().expect("os")))
            .sum();
        for agent in agents {
            let os_share = share_of(agent["os"].as_str().expect("os"));
            let template = agent["template"].as_str().expect("template");
            let weight = (share * os_share * 2 + total) / (total * 2);
            expected.push((template.replace("{version}", version), weight));
        }
    }
    for platform in [WEB_A, WEB_K] {
        let got: Vec<_> = devices::catalog(platform)?
            .entries()
            .map(|e| (e.model.to_owned(), e.weight))
            .collect();
        assert_eq!(got, expected, "{platform:?}");
    }
    // Chrome 5088+1118+303, Edge 1200+264, Firefox 478+105+28, Safari 806.
    assert_eq!(devices::catalog(WEB_A)?.total_weight(), 9390);
    assert_eq!(devices::catalog(WEB_A)?.len(), 9);
    Ok(())
}

fn is_dotted_number(text: &str) -> bool {
    !text.is_empty()
        && text
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

/// The browser and OS of a catalog user agent, asserting the exact format
/// each browser sends today, including Chromium's UA reduction.
fn classify(ua: &str) -> (&'static str, &'static str) {
    let rest = ua
        .strip_prefix("Mozilla/5.0 (")
        .unwrap_or_else(|| panic!("{ua}: no Mozilla/5.0 prefix"));
    let (system, tail) = rest
        .split_once(')')
        .unwrap_or_else(|| panic!("{ua}: no platform token"));
    if let Some((system, rv)) = system.split_once("; rv:") {
        let os = match system {
            "Windows NT 10.0; Win64; x64" => "windows",
            "Macintosh; Intel Mac OS X 10.15" => "macos",
            "X11; Linux x86_64" => "linux",
            other => panic!("{ua}: unexpected Firefox platform {other:?}"),
        };
        assert!(is_dotted_number(rv) && rv.contains('.'), "{ua}");
        assert_eq!(tail, format!(" Gecko/20100101 Firefox/{rv}"), "{ua}");
        return ("firefox", os);
    }
    let os = match system {
        "Windows NT 10.0; Win64; x64" => "windows",
        "Macintosh; Intel Mac OS X 10_15_7" => "macos",
        "X11; Linux x86_64" => "linux",
        other => panic!("{ua}: platform {other:?} is not a frozen one"),
    };
    if let Some(version) = tail
        .strip_prefix(" AppleWebKit/605.1.15 (KHTML, like Gecko) Version/")
        .and_then(|t| t.strip_suffix(" Safari/605.1.15"))
    {
        assert_eq!(os, "macos", "{ua}");
        assert!(is_dotted_number(version), "{ua}");
        return ("safari", os);
    }
    let chromium = tail
        .strip_prefix(" AppleWebKit/537.36 (KHTML, like Gecko) Chrome/")
        .unwrap_or_else(|| panic!("{ua}: unknown browser"));
    let (major, after) = chromium
        .split_once(".0.0.0 Safari/537.36")
        .unwrap_or_else(|| panic!("{ua}: Chrome version is not reduced to major.0.0.0"));
    assert!(is_dotted_number(major) && !major.contains('.'), "{ua}");
    if after.is_empty() {
        ("chrome", os)
    } else {
        assert_eq!(after, format!(" Edg/{major}.0.0.0"), "{ua}");
        ("edge", os)
    }
}

#[test]
fn web_user_agents_have_each_browsers_format() -> Result<()> {
    let a: Vec<_> = devices::catalog(WEB_A)?.entries().collect();
    let k: Vec<_> = devices::catalog(WEB_K)?.entries().collect();
    assert_eq!(a.len(), k.len());
    let mut browsers = HashSet::new();
    for (a, k) in a.iter().zip(&k) {
        assert_eq!(a.model, k.model);
        assert_eq!(a.weight, k.weight);
        let (browser, os) = classify(a.model);
        browsers.insert((browser, os));
        let (web_a, web_k) = match os {
            "windows" => ("Windows", "Win32"),
            "macos" => ("macOS", "MacIntel"),
            _ => ("Linux", "Linux x86_64"),
        };
        assert_eq!(a.system_version, web_a, "{}", a.model);
        assert_eq!(k.system_version, web_k, "{}", k.model);
    }
    let expected: HashSet<_> = [
        ("chrome", "windows"),
        ("chrome", "macos"),
        ("chrome", "linux"),
        ("edge", "windows"),
        ("edge", "macos"),
        ("firefox", "windows"),
        ("firefox", "macos"),
        ("firefox", "linux"),
        ("safari", "macos"),
    ]
    .into_iter()
    .collect();
    assert_eq!(browsers, expected);
    Ok(())
}

#[test]
fn web_catalog_parses_the_embedded_text() -> Result<()> {
    let text = web_json_text();
    for (client, platform) in [(WebClient::A, WEB_A), (WebClient::K, WEB_K)] {
        let parsed: Vec<_> = devices::web_catalog(&text, client)?
            .entries()
            .map(|e| (e.model.to_owned(), e.system_version.to_owned(), e.weight))
            .collect();
        let embedded: Vec<_> = devices::catalog(platform)?
            .entries()
            .map(|e| (e.model.to_owned(), e.system_version.to_owned(), e.weight))
            .collect();
        assert_eq!(parsed, embedded, "{client:?}");
    }
    Ok(())
}

#[test]
fn web_catalog_rejects_an_unknown_schema() {
    let text = web_json_text();
    assert!(text.contains("\"schema\": 1,"));
    for schema in ["0", "2", "100"] {
        let changed = text.replacen("\"schema\": 1,", &format!("\"schema\": {schema},"), 1);
        for client in [WebClient::A, WebClient::K] {
            let error = devices::web_catalog(&changed, client).expect_err("unknown schema");
            assert_eq!(error.code(), "IO");
            assert!(
                error
                    .to_string()
                    .contains(&format!("unknown schema {schema}")),
                "{error}"
            );
        }
    }
    let missing = text.replacen("\"schema\": 1,", "", 1);
    assert!(devices::web_catalog(&missing, WebClient::A).is_err());
}

#[test]
fn web_catalog_rejects_uncited_or_broken_entries() {
    let text = web_json_text();
    let cases = [
        ("\"url\": \"https://", "\"url\": \"http://"),
        ("\"os\": \"linux\",", "\"os\": \"bsd\","),
        ("Version/{version} Safari", "Version/27.0 Safari"),
    ];
    for (from, to) in cases {
        assert!(text.contains(from), "{from}");
        let changed = text.replacen(from, to, 1);
        let error = devices::web_catalog(&changed, WebClient::K).expect_err(to);
        assert_eq!(error.code(), "IO", "{to}");
    }
}

/// SHA-1 hex of `lines`, each followed by `\n`.
fn lines_digest<'a>(lines: impl Iterator<Item = String> + 'a) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// The owned entries list 1.5.0 `cls.deviceList` pair by pair: the
/// expected digests are of `itertools.groupby` runs of `(model, version)`
/// over the expanded list, one `model\tversion\tcount` line per run,
/// captured by running 1.5.0 after `cls.__gen__()`.
#[test]
fn catalog_entries_list_the_1_5_0_device_lists() -> Result<()> {
    let expected = [
        (
            Platform::Windows,
            232,
            "ad3775a3cc0e8a0a305aac31af80c3f5be39fb89",
        ),
        (
            Platform::Linux,
            3944,
            "d5f46c6619554458fa5b51b4f3a131086f1fbd86",
        ),
        (
            Platform::MacOS { swift: false },
            1349,
            "ba1531aa74ba005ed87bd4e69fce7a8bf746a368",
        ),
        (
            Platform::MacOS { swift: true },
            1349,
            "ba1531aa74ba005ed87bd4e69fce7a8bf746a368",
        ),
        (
            Platform::Android,
            6850,
            "3e20af265f8b392de686676d135c80cfa1fe0570",
        ),
        (
            Platform::Ios,
            1166,
            "77c5f221cd8683c02ba0f0a451c427029cab7740",
        ),
    ];
    for (platform, runs, digest) in expected {
        let entries = devices::catalog_entries(platform)?;
        let mut merged: Vec<(String, String, u64)> = Vec::new();
        for entry in entries {
            match merged.last_mut() {
                Some((model, version, weight))
                    if *model == entry.model && *version == entry.system_version =>
                {
                    *weight += entry.weight;
                }
                _ => merged.push((entry.model, entry.system_version, entry.weight)),
            }
        }
        assert_eq!(merged.len(), runs, "{platform:?}");
        let lines = merged
            .iter()
            .map(|(model, version, weight)| format!("{model}\t{version}\t{weight}"));
        assert_eq!(lines_digest(lines), digest, "{platform:?}");
    }
    Ok(())
}

/// `device_models` and `system_versions` of 1.5.0's `WindowsDevice`,
/// `LinuxDevice`, `macOSDevice` and `IOSDevice` after `__gen__()`, as the
/// SHA-1 of their lines, captured by running 1.5.0.
#[test]
fn catalog_lists_match_1_5_0_models_and_versions() -> Result<()> {
    let expected = [
        (
            Platform::Windows,
            (116, "5c52da02e390eac9e3753d929c3360cfabbc705a"),
            (2, "e6bb592d547ca159c19720732b2b5cbfd6adb4ba"),
        ),
        (
            Platform::Linux,
            (116, "5c52da02e390eac9e3753d929c3360cfabbc705a"),
            (34, "f248aeedf61275d7a4b90fcc3ec72d873d5eaac7"),
        ),
        (
            Platform::MacOS { swift: false },
            (36, "f4da4ee944ec827dbef2c3a4d60c58d318355fe3"),
            (42, "da876c68c841a5aaa2e37e32e847122642a3c28f"),
        ),
        (
            Platform::Ios,
            (33, "4e9dfe139b2110fdaa14f269b0d8a723793885be"),
            (46, "2c94f86b38782cc48e1d171fe82134039ed3efbd"),
        ),
    ];
    for (platform, (model_count, models), (version_count, versions)) in expected {
        let catalog = devices::catalog(platform)?;
        assert_eq!(catalog.device_models().len(), model_count, "{platform:?}");
        assert_eq!(
            lines_digest(catalog.device_models().iter().cloned()),
            models,
            "{platform:?}"
        );
        assert_eq!(
            catalog.system_versions().len(),
            version_count,
            "{platform:?}"
        );
        assert_eq!(
            lines_digest(catalog.system_versions().iter().cloned()),
            versions,
            "{platform:?}"
        );
    }
    let android = devices::catalog(Platform::Android)?;
    let sdks: Vec<String> = (29..=37).map(|sdk| format!("SDK {sdk}")).collect();
    assert_eq!(android.system_versions(), sdks.as_slice());
    Ok(())
}

#[test]
fn web_catalog_entries_are_listed_for_both_clients() -> Result<()> {
    for platform in [WEB_A, WEB_K] {
        let catalog = devices::catalog(platform)?;
        let entries = devices::catalog_entries(platform)?;
        assert_eq!(entries.len(), catalog.len());
        for (owned, borrowed) in entries.iter().zip(catalog.entries()) {
            assert_eq!(owned.model, borrowed.model);
            assert_eq!(owned.system_version, borrowed.system_version);
            assert_eq!(owned.weight, borrowed.weight);
        }
        let models: HashSet<&str> = catalog.device_models().iter().map(String::as_str).collect();
        assert!(
            entries
                .iter()
                .all(|entry| models.contains(entry.model.as_str()))
        );
    }
    let a = devices::catalog_entries(WEB_A)?;
    let k = devices::catalog_entries(WEB_K)?;
    let pairs = |entries: &[devices::CatalogEntry]| {
        entries
            .iter()
            .map(|entry| (entry.model.clone(), entry.weight))
            .collect::<Vec<_>>()
    };
    assert_eq!(pairs(&a), pairs(&k));
    Ok(())
}

/// 1.5.0 `WebBrowserDevice.BROWSER_WEIGHTS`, captured by running it:
/// `{'chrome': 19, 'edge': 2, 'firefox': 1}`.
#[test]
fn web_browser_weights_are_1_5_0s() {
    assert_eq!(
        devices::WEB_BROWSER_WEIGHTS,
        [("chrome", 19), ("edge", 2), ("firefox", 1)]
    );
}
