//! Live test of `fetch_all` against the real sources; needs the network, so
//! it only runs with `cargo test -p opentele2-versions -- --ignored`.

use opentele2_core::api::Versions;
use opentele2_versions::{DEFAULT_TIMEOUT, fetch_all};

#[test]
#[ignore = "needs the network"]
fn fetch_all_returns_current_versions() {
    let patch = fetch_all(DEFAULT_TIMEOUT);
    println!("{patch:#?}");

    assert!(!patch.is_empty(), "no source answered");
    let texts = [
        &patch.desktop_app_version,
        &patch.android_app_version,
        &patch.android_x_app_version,
        &patch.ios_app_version,
        &patch.macos_app_version,
        &patch.web_k_version,
        &patch.web_a_version,
        &patch.chrome_version,
        &patch.firefox_version,
    ];
    for text in texts.into_iter().flatten() {
        assert_ne!(text, "");
    }
    if let Some(web_k) = &patch.web_k_version {
        assert!(web_k.ends_with(" K"), "{web_k}");
    }
    if let Some(web_a) = &patch.web_a_version {
        assert!(web_a.ends_with(" A"), "{web_a}");
    }

    let mut versions = Versions::offline();
    patch.apply(&mut versions);
    assert_eq!(
        versions.desktop_app_version,
        Versions::offline().desktop_app_version
    );
}
