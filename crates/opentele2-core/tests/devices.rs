//! Tests for `devices`: every case of `tests/vectors/devices.json` (1.5.0
//! `Generate` per entry point), seed hashes computed by 1.5.0's
//! `_strtohashid`, catalog sizes equal to 1.5.0's expanded list lengths, and
//! the embedded catalogs against the Python package's copies.

use std::fs;
use std::path::{Path, PathBuf};

use opentele2_core::Result;
use opentele2_core::devices::{self, Platform};
use serde_json::Value;

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

#[test]
fn embedded_catalogs_equal_python_package_copies() {
    let python_dir = crate_dir().join("../../src/devices");
    let core_dir = crate_dir().join("data/devices");
    for name in ["android.json", "desktop.json", "ios.json", "mac.json"] {
        let core = fs::read(core_dir.join(name)).expect("read core catalog");
        let python = Path::new(&python_dir).join(name);
        // src/devices/ goes away once the Python package reads the core.
        if python.exists() {
            let python = fs::read(&python).expect("read Python catalog");
            assert!(core == python, "{name} differs from src/devices/{name}");
        }
    }
}
