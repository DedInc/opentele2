//! Tests for `api`: every case of `tests/vectors/devices.json` (1.5.0
//! `Generate` per entry point) on all five recorded fields, and every default
//! profile against the class values of 1.5.0 `src/api.py` after
//! `_sync_api_versions` with the offline `PlatformVersions` of
//! `src/fingerprint.py`.

use std::fs;
use std::path::PathBuf;

use opentele2_core::Result;
use opentele2_core::api::{self, ApiProfile, Client, Versions};
use serde_json::Value;

const WEB_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";

fn read_vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/devices.json");
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

fn client_of(entry_point: &str) -> Client {
    match entry_point {
        "TelegramDesktop" => Client::Desktop,
        "TelegramAndroid" => Client::Android,
        "TelegramAndroidX" => Client::AndroidX,
        "TelegramIOS" => Client::Ios,
        "TelegramMacOS" => Client::MacOS,
        other => panic!("unexpected entry point {other:?}"),
    }
}

fn text<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn expected(
    api_id: i32,
    api_hash: &str,
    device_model: &str,
    system_version: &str,
    app_version: &str,
    lang_pack: &str,
) -> ApiProfile {
    ApiProfile {
        api_id,
        api_hash: api_hash.to_owned(),
        device_model: device_model.to_owned(),
        system_version: system_version.to_owned(),
        app_version: app_version.to_owned(),
        lang_code: "en".to_owned(),
        system_lang_code: "en-US".to_owned(),
        lang_pack: lang_pack.to_owned(),
    }
}

#[test]
fn every_vector_case_matches_1_5_0() -> Result<()> {
    let versions = Versions::offline();
    let vectors = read_vectors();
    let cases = vectors["cases"].as_array().expect("cases array");
    assert_eq!(cases.len(), 2800);
    let mut mismatches = Vec::new();
    for case in cases {
        let seed = seed_of(case);
        let entry_point = text(case, "entry_point");
        let client = client_of(entry_point);
        let generated = match case["system"].as_str() {
            None => api::generate(client, Some(&seed), &versions)?,
            Some(system) => api::generate_desktop(Some(system), Some(&seed), &versions)?,
        };
        let got = [
            generated.app_version.as_str(),
            generated.lang_pack.as_str(),
            generated.system_lang_code.as_str(),
            generated.device_model.as_str(),
            generated.system_version.as_str(),
        ];
        let want = [
            text(case, "app_version"),
            text(case, "lang_pack"),
            text(case, "system_lang_code"),
            text(case, "device_model"),
            text(case, "system_version"),
        ];
        if got != want {
            mismatches.push(format!(
                "{entry_point} {:?} {seed:?}: got {got:?}, want {want:?}",
                case["system"]
            ));
        }
        // Generate keeps the class's credentials and language code.
        let default = api::profile(client, &versions);
        assert_eq!(generated.api_id, default.api_id);
        assert_eq!(generated.api_hash, default.api_hash);
        assert_eq!(generated.lang_code, default.lang_code);
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
fn offline_versions_equal_platform_versions_defaults() {
    let versions = Versions::offline();
    assert_eq!(versions.android_app_version, "13.0.3");
    assert_eq!(versions.android_app_version_code, 7183);
    assert_eq!(versions.ios_app_version, "13.0");
    assert_eq!(versions.ios_build_number, 35303);
    assert_eq!(versions.ios_system_version, "27.0.1");
    assert_eq!(versions.macos_system_version, "27.0.1");
    // APP_VERSION_STR of src/utils.py: format_app_version(7003001).
    assert_eq!(versions.desktop_app_version, "7.3.1");
    assert_eq!(versions.desktop_app_version_suffix, "x64");
    assert_eq!(versions.macos_app_version, "13.0");
    assert_eq!(versions.macos_build_number, 283_305);
    assert_eq!(versions.android_x_app_version, "0.29.1.1817");
    assert_eq!(versions.web_a_version, "12.0.47 A");
    assert_eq!(versions.web_k_version, "2.2 K");
}

#[test]
fn default_profiles_match_1_5_0() {
    let versions = Versions::offline();
    let web_hash = "8da85b0d5bfe62527e5b244c209159c3";
    let cases = [
        (
            Client::Desktop,
            expected(
                2040,
                "b18441a1ff607e10a989891a5462e627",
                "Desktop",
                "Windows 11 x64",
                "7.3.1 x64",
                "tdesktop",
            ),
        ),
        (
            Client::Android,
            expected(
                6,
                "eb06d4abfb49dc3eeb1aeb98ae0f581e",
                "samsungSM-S938B",
                "SDK 36",
                "13.0.3 (7183)",
                "android",
            ),
        ),
        (
            Client::AndroidX,
            expected(
                21724,
                "3e0cb5efcd52300aec5994fdfc5bdc16",
                "samsungSM-S938B",
                "SDK 36",
                "0.29.1.1817",
                "android",
            ),
        ),
        (
            Client::Ios,
            expected(
                10840,
                "33c45224029d59cb3ad0c16134215aeb",
                "iPhone 17 Pro",
                "27.0.1",
                "13.0 (35303) ",
                "ios",
            ),
        ),
        (
            Client::MacOS,
            expected(
                2834,
                "68875f756c9b437a8b916ca3de215815",
                "MacBook Air M4",
                "27.0.1",
                "13.0 (283305) ",
                "macos",
            ),
        ),
        (
            Client::WebA,
            expected(2496, web_hash, WEB_USER_AGENT, "Windows", "12.0.47 A", ""),
        ),
        (
            Client::WebK,
            expected(2496, web_hash, WEB_USER_AGENT, "Win32", "2.2 K", "macos"),
        ),
        (
            Client::Webogram,
            expected(2496, web_hash, WEB_USER_AGENT, "Win32", "0.7.0", ""),
        ),
    ];
    assert_eq!(cases.len(), Client::ALL.len());
    for ((client, want), listed) in cases.iter().zip(Client::ALL) {
        assert_eq!(*client, listed);
        assert_eq!(api::profile(*client, &versions), *want, "{client:?}");
    }
}

#[test]
fn profiles_follow_the_given_versions() {
    let versions = Versions {
        android_app_version: "14.1".to_owned(),
        android_app_version_code: 9001,
        ios_app_version: "14.2".to_owned(),
        ios_build_number: 40000,
        ios_system_version: "28.1".to_owned(),
        macos_system_version: "28.2".to_owned(),
        desktop_app_version: "8.0".to_owned(),
        desktop_app_version_suffix: String::new(),
        macos_app_version: "14.3".to_owned(),
        macos_build_number: 300_000,
        android_x_app_version: "0.30".to_owned(),
        web_a_version: "13.0 A".to_owned(),
        web_k_version: "3.0 K".to_owned(),
    };
    let app_version = |client| api::profile(client, &versions).app_version;
    // An empty suffix leaves the desktop version bare.
    assert_eq!(app_version(Client::Desktop), "8.0");
    assert_eq!(app_version(Client::Android), "14.1 (9001)");
    assert_eq!(app_version(Client::AndroidX), "0.30");
    assert_eq!(app_version(Client::Ios), "14.2 (40000) ");
    assert_eq!(app_version(Client::MacOS), "14.3 (300000) ");
    assert_eq!(app_version(Client::WebA), "13.0 A");
    assert_eq!(app_version(Client::WebK), "3.0 K");
    assert_eq!(app_version(Client::Webogram), "0.7.0");
    assert_eq!(api::profile(Client::Ios, &versions).system_version, "28.1");
    assert_eq!(
        api::profile(Client::MacOS, &versions).system_version,
        "28.2"
    );
}

#[test]
fn desktop_app_version_follows_the_generated_platform() -> Result<()> {
    let mut versions = Versions::offline();
    versions.desktop_app_version = "8.0".to_owned();
    versions.desktop_app_version_suffix = "ignored".to_owned();
    let app_version = |system| -> Result<String> {
        Ok(api::generate_desktop(Some(system), Some("seed"), &versions)?.app_version)
    };
    assert_eq!(app_version("windows")?, "8.0 x64");
    assert_eq!(app_version("macos")?, "8.0 arm64");
    assert_eq!(app_version("linux")?, "8.0");
    Ok(())
}

#[test]
fn lone_unknown_system_is_the_seed() -> Result<()> {
    let versions = Versions::offline();
    for seed in ["", "user1@example.org", "ключ-2", "Windows", "0"] {
        let as_seed = api::generate_desktop(None, Some(seed), &versions)?;
        assert_eq!(
            api::generate_desktop(Some(seed), None, &versions)?,
            as_seed,
            "{seed:?}"
        );
        assert_eq!(
            api::generate(Client::Desktop, Some(seed), &versions)?,
            as_seed
        );
    }
    Ok(())
}

#[test]
fn unknown_system_with_a_seed_is_chosen_by_hash() -> Result<()> {
    let versions = Versions::offline();
    // Platform names are matched case-sensitively, as in 1.5.0.
    for system in ["Windows", "MACOS", "bsd", ""] {
        for seed in ["", "user1@example.org", "ключ-2"] {
            assert_eq!(
                api::generate_desktop(Some(system), Some(seed), &versions)?,
                api::generate_desktop(None, Some(seed), &versions)?,
                "{system:?} {seed:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn web_clients_are_not_generated() {
    let versions = Versions::offline();
    for client in Client::ALL {
        let result = api::generate(client, Some("seed"), &versions);
        assert_eq!(result.is_err(), client.is_web(), "{client:?}");
        if let Err(error) = result {
            assert_eq!(error.code(), "IO");
        }
    }
}

#[test]
fn unseeded_generate_keeps_the_profile_fields() -> Result<()> {
    let versions = Versions::offline();
    for client in Client::ALL.into_iter().filter(|client| !client.is_web()) {
        let generated = api::generate(client, None, &versions)?;
        let default = api::profile(client, &versions);
        assert_eq!(generated.api_id, default.api_id);
        assert_eq!(generated.api_hash, default.api_hash);
        assert_eq!(generated.lang_pack, default.lang_pack);
        assert_ne!(generated.device_model, "");
        assert_ne!(generated.system_version, "");
    }
    Ok(())
}
