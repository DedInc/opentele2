//! Tests for `VersionsPatch`: `apply` follows 1.5.0 `_apply_fetched_versions`
//! (src/fingerprint.py:122-147) and `merge` keeps the fields a later answer
//! leaves unset.

use opentele2_core::api::Versions;
use opentele2_versions::VersionsPatch;

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
        ..Versions::offline()
    };
    assert_eq!(versions, expected);
    // Bound to the tdata version written by the core, never fetched.
    assert_eq!(versions.desktop_app_version, "7.3.1");
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
