//! Tests for `VersionsPatch`: `apply` writes every fetched field but the
//! desktop version and leaves unset fields alone, and `merge` keeps the
//! fields a later answer leaves unset; `FIELDS`, `to_map` and `from_map` cover every field.

use opentele2_core::api::Versions;
use opentele2_versions::VersionsPatch;
use serde_json::{Map, Value, json};

fn full_patch() -> VersionsPatch {
    VersionsPatch {
        desktop_app_version: Some("9.9.9".to_owned()),
        android_app_version: Some("14.1.2".to_owned()),
        android_app_version_code: Some(7300),
        android_x_app_version: Some("0.30.0.1900".to_owned()),
        ios_app_version: Some("14.1".to_owned()),
        ios_build_number: Some(36000),
        macos_app_version: Some("14.2".to_owned()),
        macos_build_number: Some(290_001),
        web_k_version: Some("2.3 K".to_owned()),
        web_a_version: Some("12.1.0 A".to_owned()),
        chrome_version: Some("160.0.0.0".to_owned()),
        firefox_version: Some("155.0".to_owned()),
    }
}

#[test]
fn apply_maps_every_fetched_field_but_the_desktop_version() {
    let mut versions = Versions::offline();
    full_patch().apply(&mut versions);

    let expected = Versions {
        android_app_version: "14.1.2".to_owned(),
        android_app_version_code: 7300,
        android_x_app_version: "0.30.0.1900".to_owned(),
        ios_app_version: "14.1".to_owned(),
        ios_build_number: 36000,
        macos_app_version: "14.2".to_owned(),
        macos_build_number: 290_001,
        web_k_version: "2.3 K".to_owned(),
        web_a_version: "12.1.0 A".to_owned(),
        chrome_version: "160.0.0.0".to_owned(),
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36"
            .to_owned(),
        firefox_version: "155.0".to_owned(),
        ..Versions::offline()
    };
    assert_eq!(versions, expected);
    // Bound to the tdata version written by the core, never fetched.
    assert_eq!(versions.desktop_app_version, "7.3.1");
}

#[test]
fn offline_browser_versions_and_set_chrome_version() {
    let mut versions = Versions::offline();
    assert_eq!(versions.chrome_version, "155.0.0.0");
    assert_eq!(versions.firefox_version, "150.0");
    assert!(versions.user_agent.contains(" Chrome/155.0.0.0 "));

    versions.set_chrome_version("161.0.0.0");
    assert_eq!(versions.chrome_version, "161.0.0.0");
    assert_eq!(
        versions.user_agent,
        Versions::offline()
            .user_agent
            .replace("155.0.0.0", "161.0.0.0")
    );
}

#[test]
fn fields_lists_every_field_in_declaration_order() {
    assert_eq!(
        VersionsPatch::FIELDS,
        [
            "desktop_app_version",
            "android_app_version",
            "android_app_version_code",
            "android_x_app_version",
            "ios_app_version",
            "ios_build_number",
            "macos_app_version",
            "macos_build_number",
            "web_k_version",
            "web_a_version",
            "chrome_version",
            "firefox_version",
        ]
    );
    let keys: Vec<String> = full_patch().to_map().keys().cloned().collect();
    let mut fields: Vec<String> = VersionsPatch::FIELDS
        .iter()
        .map(|&f| f.to_owned())
        .collect();
    fields.sort();
    let mut sorted_keys = keys;
    sorted_keys.sort();
    assert_eq!(sorted_keys, fields);
}

#[test]
fn map_round_trips_and_holds_only_set_fields() {
    let full = full_patch();
    let map = full.to_map();
    assert_eq!(map.get("android_app_version_code"), Some(&json!(7300)));
    assert_eq!(map.get("chrome_version"), Some(&json!("160.0.0.0")));
    assert_eq!(VersionsPatch::from_map(&map), Ok(full));

    let partial = VersionsPatch {
        firefox_version: Some("155.0".to_owned()),
        ios_build_number: Some(36000),
        ..VersionsPatch::default()
    };
    let map = partial.to_map();
    assert_eq!(
        Value::Object(map.clone()),
        json!({"ios_build_number": 36000, "firefox_version": "155.0"})
    );
    assert_eq!(VersionsPatch::from_map(&map), Ok(partial));

    assert!(VersionsPatch::default().to_map().is_empty());
    assert_eq!(
        VersionsPatch::from_map(&Map::new()),
        Ok(VersionsPatch::default())
    );
}

#[test]
fn from_map_treats_null_as_unset() {
    let map = object(json!({"web_k_version": null, "macos_build_number": 1}));
    assert_eq!(
        VersionsPatch::from_map(&map),
        Ok(VersionsPatch {
            macos_build_number: Some(1),
            ..VersionsPatch::default()
        })
    );
}

#[test]
fn from_map_rejects_unknown_keys_and_wrong_types_naming_the_key() {
    let error = |value: Value| VersionsPatch::from_map(&object(value)).unwrap_err();

    assert!(error(json!({"user_agent": "x"})).contains("`user_agent`"));
    for (key, value) in [
        ("chrome_version", json!(155)),
        ("android_app_version", json!(["13.0"])),
        ("ios_build_number", json!("36000")),
        ("ios_build_number", json!(-1)),
        ("ios_build_number", json!(1.5)),
        ("macos_build_number", json!(u64::from(u32::MAX) + 1)),
    ] {
        let message = error(json!({ key: value }));
        assert!(message.contains(&format!("`{key}`")), "{message}");
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

#[test]
fn apply_leaves_unset_fields_alone() {
    let mut versions = Versions::offline();
    VersionsPatch::default().apply(&mut versions);
    assert_eq!(versions, Versions::offline());

    VersionsPatch {
        ios_app_version: Some("14.1".to_owned()),
        ..VersionsPatch::default()
    }
    .apply(&mut versions);
    assert_eq!(
        versions,
        Versions {
            ios_app_version: "14.1".to_owned(),
            ..Versions::offline()
        }
    );
}

#[test]
fn merge_overwrites_only_set_fields() {
    let mut patch = VersionsPatch {
        android_app_version: Some("13.0.3".to_owned()),
        android_app_version_code: Some(7183),
        ..VersionsPatch::default()
    };
    patch.merge(VersionsPatch {
        android_app_version: Some("13.0.4".to_owned()),
        web_a_version: Some("12.0.47 A".to_owned()),
        ..VersionsPatch::default()
    });

    assert_eq!(
        patch,
        VersionsPatch {
            android_app_version: Some("13.0.4".to_owned()),
            android_app_version_code: Some(7183),
            web_a_version: Some("12.0.47 A".to_owned()),
            ..VersionsPatch::default()
        }
    );
    assert!(!patch.is_empty());
    assert!(VersionsPatch::default().is_empty());
}
