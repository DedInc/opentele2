//! Tests for `devices`: every case of `tests/vectors/devices.json` (1.5.0
//! `Generate` per entry point), seed hashes computed by 1.5.0's
//! `_strtohashid` and catalog sizes equal to 1.5.0's expanded list lengths.
//! The web pool has no 1.5.0 vectors (1.5.0 drew it at random from
//! browserforge), so its tests check 1.5.0's sizes, weights, platform
//! strings and version windows, determinism per seed and versions, and
//! reachability.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use opentele2_core::Result;
use opentele2_core::api::Versions;
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

/// Versions whose Chrome major (155) is ahead of the browserforge dataset's
/// newest (149) and whose Firefox major (150) is inside it.
fn lagging_versions() -> Versions {
    let mut versions = Versions::offline();
    versions.set_chrome_version("155.0.0.0");
    "150.0".clone_into(&mut versions.firefox_version);
    versions
}

/// Every major that follows `prefix` in `ua`.
fn majors_after(ua: &str, prefix: &str) -> Vec<u32> {
    ua.match_indices(prefix)
        .filter_map(|(at, _)| {
            let tail = &ua[at + prefix.len()..];
            let end = tail
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(tail.len());
            tail[..end].parse().ok()
        })
        .collect()
}

/// The browser of a pool user agent: Edge before Chrome, as browserforge.
fn browser(ua: &str) -> &'static str {
    match opentele2_browser::browser_of(ua) {
        Some(name @ ("chrome" | "edge" | "firefox")) => name,
        other => panic!("{ua}: unexpected browser {other:?}"),
    }
}

#[test]
fn web_pool_has_1_5_0s_sizes_and_weights() -> Result<()> {
    let versions = lagging_versions();
    for client in [WebClient::A, WebClient::K] {
        let catalog = devices::web_catalog_for(client, &versions)?;
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for entry in catalog.entries() {
            let name = browser(entry.model);
            let weight = devices::WEB_BROWSER_WEIGHTS
                .iter()
                .find(|(browser, _)| *browser == name)
                .map(|&(_, weight)| weight);
            assert_eq!(Some(entry.weight), weight, "{}", entry.model);
            *counts.entry(name).or_default() += 1;
        }
        let chrome = counts.get("chrome").copied().unwrap_or(0);
        let edge = counts.get("edge").copied().unwrap_or(0);
        let firefox = counts.get("firefox").copied().unwrap_or(0);
        assert!((1..=60).contains(&chrome), "{chrome} Chrome user agents");
        assert!((1..=30).contains(&edge), "{edge} Edge user agents");
        assert!((1..=20).contains(&firefox), "{firefox} Firefox user agents");
        assert_eq!(catalog.total_weight(), 19 * chrome + 2 * edge + firefox);
        let distinct: HashSet<_> = catalog.entries().map(|entry| entry.model).collect();
        assert_eq!(
            distinct.len(),
            catalog.len(),
            "{client:?} repeats a user agent"
        );
        assert_eq!(catalog.device_models().len(), catalog.len());
    }
    Ok(())
}

#[test]
fn web_pool_systems_come_from_the_user_agent() -> Result<()> {
    let versions = lagging_versions();
    let a = devices::web_catalog_for(WebClient::A, &versions)?;
    let k = devices::web_catalog_for(WebClient::K, &versions)?;
    assert_eq!(a.len(), k.len());
    let web_a = ["Windows", "macOS", "Linux", "ChromeOS"];
    let web_k = ["Win32", "MacIntel", "Linux x86_64", "Linux aarch64"];
    for (a, k) in a.entries().zip(k.entries()) {
        assert_eq!((a.model, a.weight), (k.model, k.weight));
        assert!(web_a.contains(&a.system_version), "{a:?}");
        assert!(web_k.contains(&k.system_version), "{k:?}");
        let lower = a.model.to_lowercase();
        if lower.contains("windows") {
            assert_eq!((a.system_version, k.system_version), ("Windows", "Win32"));
        } else if lower.contains("macintosh") {
            assert_eq!((a.system_version, k.system_version), ("macOS", "MacIntel"));
        }
    }
    assert!(
        a.system_versions()
            .iter()
            .all(|v| web_a.contains(&v.as_str()))
    );
    assert!(
        k.system_versions()
            .iter()
            .all(|v| web_k.contains(&v.as_str()))
    );
    Ok(())
}

/// The low end of the pool's Chrome window, `chrome - randint(2, 4)`: the
/// first draw of the pool generator, seeded as `devices::web_pool` seeds it.
fn chrome_min(chrome: u32, firefox: u32) -> u32 {
    let mut rng = opentele2_browser::Rng::from_seed(&format!(
        "opentele2/devices/web-pool/v1/chrome/{chrome}/firefox/{firefox}"
    ));
    let spread = 2 + u32::try_from(rng.next_u64() % 3).expect("below 3");
    chrome - spread
}

/// The majors of each browser in the Web A pool for `versions`, checking
/// that every user agent carries one major per prefix.
fn pool_majors(versions: &Versions) -> Result<HashMap<&'static str, Vec<u32>>> {
    let catalog = devices::web_catalog_for(WebClient::A, versions)?;
    let mut majors: HashMap<&str, Vec<u32>> = HashMap::new();
    for entry in catalog.entries() {
        let ua = entry.model;
        let chrome = majors_after(ua, "Chrome/");
        let name = browser(ua);
        let major = match name {
            "chrome" => chrome.clone(),
            "edge" => {
                let edge = majors_after(ua, "Edg/");
                assert_eq!(chrome, edge, "{ua}");
                edge
            }
            _ => {
                let firefox = majors_after(ua, "Firefox/");
                assert_eq!(majors_after(ua, "rv:"), firefox, "{ua}");
                firefox
            }
        };
        assert_eq!(major.len(), 1, "{ua}");
        majors.entry(name).or_default().extend(major);
    }
    Ok(majors)
}

fn distinct(majors: &[u32]) -> usize {
    majors.iter().collect::<HashSet<_>>().len()
}

#[test]
fn web_pool_majors_follow_the_live_versions() -> Result<()> {
    // Dataset newest: Chrome 149, Edge 148, Firefox 151. Chrome 155 lags by
    // six majors: the window slides down until its top is 149, keeps its
    // width, and the drawn majors are shifted back up into [chrome_min, 155].
    let low = chrome_min(155, 150);
    let majors = pool_majors(&lagging_versions())?;
    let chrome = majors.get("chrome").expect("Chrome user agents");
    assert!(distinct(chrome) >= 3, "Chrome majors {chrome:?}");
    assert!(chrome.iter().all(|m| (low..=155).contains(m)), "{chrome:?}");
    assert!(
        chrome.iter().all(|&m| m > 149),
        "{chrome:?} was not shifted"
    );
    let edge = majors.get("edge").expect("Edge user agents");
    assert!(edge.iter().all(|m| (low - 2..=155).contains(m)), "{edge:?}");
    assert!(edge.iter().all(|&m| m > 148), "{edge:?} was not shifted");
    // Firefox 150 is inside the dataset: [147, 150], unshifted.
    let firefox = majors.get("firefox").expect("Firefox user agents");
    assert!(
        firefox.iter().all(|m| (147..=150).contains(m)),
        "{firefox:?}"
    );
    Ok(())
}

#[test]
fn web_pool_is_unshifted_when_chrome_is_the_dataset_newest() -> Result<()> {
    // Chrome 149 is the dataset's newest: offset 0 (the `devices` unit test
    // `dataset_lag_is_the_distance_to_the_newest_major` checks the offset),
    // so the window [chrome_min, 149] is drawn as is. Its top is rare on
    // desktop in the dataset, so only the bounds are checked.
    let mut versions = lagging_versions();
    versions.set_chrome_version("149.0.0.0");
    let low = chrome_min(149, 150);
    let majors = pool_majors(&versions)?;
    let chrome = majors.get("chrome").expect("Chrome user agents");
    assert!(chrome.iter().all(|m| (low..=149).contains(m)), "{chrome:?}");
    Ok(())
}

#[test]
fn web_pool_is_a_pure_function_of_the_versions() -> Result<()> {
    let versions = lagging_versions();
    let entries = |client, versions: &Versions| -> Result<Vec<devices::CatalogEntry>> {
        Ok(devices::web_catalog_for(client, versions)?.to_entries())
    };
    for (client, platform) in [(WebClient::A, WEB_A), (WebClient::K, WEB_K)] {
        let pool = entries(client, &versions)?;
        assert_eq!(entries(client, &versions)?, pool, "{client:?}");
        // The offline versions are Chrome 155 and Firefox 150: the same pool.
        assert_eq!(devices::catalog(platform)?.to_entries(), pool, "{client:?}");
        // Unrelated fields do not change the pool.
        let mut other = versions.clone();
        other.web_a_version = "99.0 A".to_owned();
        other.set_chrome_version("155.0.7000.1");
        assert_eq!(entries(client, &other)?, pool, "{client:?}");
        // A new Chrome major draws a new pool.
        let mut newer = versions.clone();
        newer.set_chrome_version("156.0.0.0");
        assert_ne!(entries(client, &newer)?, pool, "{client:?}");
        let mut older = versions.clone();
        older.set_chrome_version("154.0.0.0");
        assert_ne!(entries(client, &older)?, pool, "{client:?}");
    }
    Ok(())
}

#[test]
fn web_pool_rejects_a_version_without_a_major() {
    for (chrome, firefox) in [("x.0.0.0", "150.0"), ("155.0.0.0", ""), ("", "150.0")] {
        let mut versions = Versions::offline();
        versions.chrome_version = chrome.to_owned();
        versions.firefox_version = firefox.to_owned();
        let error =
            devices::web_catalog_for(WebClient::A, &versions).expect_err("no numeric major");
        assert_eq!(error.code(), "IO", "{chrome:?} {firefox:?}");
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
