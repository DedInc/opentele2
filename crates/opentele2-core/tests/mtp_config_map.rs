//! Tests for the map conversions of `tdata::mtp_config`: the Python
//! binding's key names and value shapes, round trips of the default configs,
//! a vector tdata config and a custom one, and the `from_map` errors.
//!
//! Key material is never printed: the vector tdata is only read for its MTP
//! config, which holds no account key.

use std::path::Path;

use opentele2_core::Error;
use opentele2_core::tdata::TData;
use opentele2_core::tdata::mtp_config::{
    ConfigFields, DcOptions, Endpoint, Environment, FLAG_IPV6, FLAG_SECRET, MtpConfig, RsaPublicKey,
};
use serde_json::{Map, Value, json};

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("expected an object, got {other}"),
    }
}

fn keys(map: &Map<String, Value>) -> Vec<&str> {
    map.keys().map(String::as_str).collect()
}

/// The `what` and reason of an `InvalidInput` error.
fn invalid_input<T: std::fmt::Debug>(result: opentele2_core::Result<T>) -> (&'static str, String) {
    match result {
        Err(Error::InvalidInput { what, reason }) => (what, reason),
        other => panic!("expected an InvalidInput error, got {other:?}"),
    }
}

/// A config with secrets, CDN keys and non-default fields.
fn custom_config() -> MtpConfig {
    let mut config = MtpConfig::new(Environment::Test);
    config
        .dc_options
        .add(2, FLAG_SECRET, "203.0.113.3", 8443, &[1, 2, 3, 255]);
    config.dc_options.add(7, FLAG_IPV6, "2001:db8::7", 443, &[]);
    config.dc_options.cdn_public_keys.push(RsaPublicKey {
        dc_id: 203,
        n: vec![0, 1, 2, 254],
        e: vec![1, 0, 1],
    });
    config.fields.revoke_private_inbox = true;
    config.fields.chat_size_max = -5;
    config.fields.reaction_default_custom = u64::MAX;
    "gifs".clone_into(&mut config.fields.gif_search_username);
    config
}

#[test]
fn environment_names() {
    for (environment, name) in [
        (Environment::Production, "production"),
        (Environment::Test, "test"),
    ] {
        assert_eq!(environment.name(), name);
        assert_eq!(Environment::from_name(name), Some(environment));
    }
    for name in ["Production", "TEST", "", "prod"] {
        assert_eq!(Environment::from_name(name), None, "{name:?}");
    }
}

#[test]
fn map_has_the_python_shape() {
    let config = custom_config();
    let map = config.to_map();
    assert_eq!(keys(&map), MtpConfig::MAP_KEYS);
    assert_eq!(map["environment"], "test");
    let fields = map["fields"].as_object().expect("fields object");
    assert_eq!(keys(fields), ConfigFields::MAP_KEYS);
    assert_eq!(ConfigFields::MAP_KEYS.len(), 35);
    assert_eq!(fields["chat_size_max"], -5);
    assert_eq!(fields["revoke_private_inbox"], true);
    assert_eq!(fields["internal_links_domain"], "https://t.me/");
    assert_eq!(fields["reaction_default_custom"], u64::MAX);

    let dcs = map["dcs"].as_array().expect("dcs list");
    let dc_ids: Vec<&Value> = dcs.iter().map(|dc| &dc["dc_id"]).collect();
    assert_eq!(dc_ids, [1, 2, 3, 7]);
    let dc2 = object(dcs[1].clone());
    assert_eq!(keys(&dc2), ["dc_id", "endpoints"]);
    let secret_endpoint = dc2["endpoints"]
        .as_array()
        .expect("endpoints")
        .last()
        .expect("endpoint");
    assert_eq!(
        *secret_endpoint,
        json!({"id": 2, "flags": FLAG_SECRET, "ip": "203.0.113.3", "port": 8443,
               "secret": [1, 2, 3, 255]})
    );
    assert_eq!(
        keys(secret_endpoint.as_object().expect("endpoint")),
        Endpoint::MAP_KEYS
    );
    assert_eq!(
        map["cdn_public_keys"],
        json!([{"dc_id": 203, "n": [0, 1, 2, 254], "e": [1, 0, 1]}])
    );

    let endpoints = config.endpoints(2).expect("DC 2").to_map();
    assert_eq!(
        keys(&endpoints),
        ["ipv4", "ipv6", "selected_ipv4", "selected_ipv6"]
    );
    assert_eq!(
        keys(endpoints["ipv4"].as_object().expect("ipv4")),
        ["tcp", "http"]
    );
    // The secret endpoint is TCP only.
    assert_eq!(endpoints["ipv4"]["tcp"].as_array().map(Vec::len), Some(2));
    assert_eq!(endpoints["ipv4"]["http"].as_array().map(Vec::len), Some(1));
    assert_eq!(endpoints["selected_ipv4"]["ip"], "149.154.167.40");
    let dc7 = config.endpoints(7).expect("DC 7").to_map();
    assert_eq!(dc7["selected_ipv4"], Value::Null);
    assert_eq!(dc7["selected_ipv6"]["ip"], "2001:db8::7");
}

#[test]
fn default_configs_round_trip() {
    for environment in [Environment::Production, Environment::Test] {
        let config = MtpConfig::new(environment);
        let map = config.to_map();
        assert_eq!(MtpConfig::from_map(&map).expect("from_map"), config);
        assert_eq!(
            ConfigFields::from_map(&config.fields.to_map()).expect("fields"),
            config.fields
        );
        assert_eq!(
            DcOptions::from_map(&config.dc_options.to_map()).expect("dc options"),
            config.dc_options
        );
    }
}

#[test]
fn custom_config_round_trips_to_the_same_bytes() {
    let config = custom_config();
    let back = MtpConfig::from_map(&config.to_map()).expect("from_map");
    assert_eq!(back, config);
    assert_eq!(
        back.serialize().expect("serialize back"),
        config.serialize().expect("serialize")
    );
    // A JSON text round trip keeps every shape, u64::MAX included.
    let text = serde_json::to_string(&config.to_map()).expect("to text");
    let parsed: Map<String, Value> = serde_json::from_str(&text).expect("from text");
    assert_eq!(MtpConfig::from_map(&parsed).expect("from text map"), config);
    for endpoint in config.dc_options.dc(2).expect("DC 2") {
        assert_eq!(
            Endpoint::from_map(&endpoint.to_map()).expect("endpoint"),
            *endpoint
        );
    }
    let key = &config.dc_options.cdn_public_keys[0];
    assert_eq!(RsaPublicKey::from_map(&key.to_map()).expect("key"), *key);
}

#[test]
fn vector_tdata_config_round_trips() {
    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/tdata_plain/performance_off");
    let tdata = TData::load(&dir, b"", Some("data")).expect("load tdata");
    assert!(!tdata.accounts.is_empty(), "vector has accounts");
    for account in &tdata.accounts {
        assert!(account.config.is_some(), "vector stores a config");
        let config = account.mtp_config();
        let back = MtpConfig::from_map(&config.to_map()).expect("from_map");
        assert!(back == config, "account {} config differs", account.index);
        assert!(
            back.serialize().ok() == account.config,
            "account {} config bytes differ",
            account.index
        );
    }
}

#[test]
fn unknown_keys_are_rejected_naming_the_key() {
    let config = custom_config();
    let mut map = config.to_map();
    map.insert("dc_options".to_owned(), json!([]));
    let (what, reason) = invalid_input(MtpConfig::from_map(&map));
    assert_eq!(what, "config");
    assert!(reason.contains("`dc_options`"), "{reason}");

    let mut map = config.to_map();
    map["fields"]
        .as_object_mut()
        .expect("fields")
        .insert("chatSizeMax".to_owned(), json!(1));
    let (what, reason) = invalid_input(MtpConfig::from_map(&map));
    assert_eq!(what, "fields");
    assert!(
        reason.contains("`chatSizeMax`") && reason.contains("at fields"),
        "{reason}"
    );

    let mut map = config.to_map();
    map["dcs"][1]["endpoints"][0]
        .as_object_mut()
        .expect("endpoint")
        .insert("ipv6".to_owned(), json!(false));
    let (what, reason) = invalid_input(MtpConfig::from_map(&map));
    assert_eq!(what, "endpoints");
    assert!(
        reason.contains("`ipv6`") && reason.contains("dcs[1].endpoints[0]"),
        "{reason}"
    );

    let mut map = config.to_map();
    map["dcs"][0]
        .as_object_mut()
        .expect("dc")
        .insert("dcId".to_owned(), json!(1));
    assert_eq!(invalid_input(MtpConfig::from_map(&map)).0, "dcs");

    let mut key = config.dc_options.cdn_public_keys[0].to_map();
    key.insert("modulus".to_owned(), json!([]));
    assert_eq!(
        invalid_input(RsaPublicKey::from_map(&key)).0,
        "cdn_public_key"
    );
}

/// One damage done to a config map.
type MapEdit = fn(&mut Map<String, Value>);

#[test]
fn wrong_types_and_missing_keys_name_the_key() {
    let config = custom_config();
    let cases: [(&str, MapEdit, &str); 14] = [
        (
            "environment",
            |m| m["environment"] = json!("Test"),
            "environment",
        ),
        (
            "environment type",
            |m| m["environment"] = json!(1),
            "environment",
        ),
        ("dcs", |m| m["dcs"] = json!({}), "dcs"),
        ("fields", |m| m["fields"] = json!([]), "fields"),
        (
            "i32 range",
            |m| m["fields"]["chat_size_max"] = json!(1_u64 << 31),
            "chat_size_max",
        ),
        (
            "i32 float",
            |m| m["fields"]["rating_decay"] = json!(1.5),
            "rating_decay",
        ),
        (
            "bool",
            |m| m["fields"]["blocked_mode"] = json!(0),
            "blocked_mode",
        ),
        (
            "string",
            |m| m["fields"]["txt_domain_string"] = Value::Null,
            "txt_domain_string",
        ),
        (
            "u64",
            |m| m["fields"]["reaction_default_custom"] = json!(-1),
            "reaction_default_custom",
        ),
        (
            "byte",
            |m| m["dcs"][1]["endpoints"][1]["secret"] = json!([256]),
            "secret",
        ),
        ("bytes", |m| m["cdn_public_keys"][0]["n"] = json!("00"), "n"),
        (
            "endpoint",
            |m| m["dcs"][0]["endpoints"][0] = json!(1),
            "endpoints",
        ),
        (
            "missing field",
            |m| {
                m["fields"]
                    .as_object_mut()
                    .expect("fields")
                    .remove("rating_decay");
            },
            "rating_decay",
        ),
        (
            "missing",
            |m| {
                m.remove("cdn_public_keys");
            },
            "cdn_public_keys",
        ),
    ];
    for (case, edit, key) in cases {
        let mut map = config.to_map();
        edit(&mut map);
        let (what, reason) = invalid_input(MtpConfig::from_map(&map));
        assert_eq!(what, key, "{case}: {reason}");
    }
    let mut map = config.to_map();
    map["dcs"][1]["endpoints"][1]["port"] = json!("443");
    let (what, reason) = invalid_input(MtpConfig::from_map(&map));
    assert_eq!(what, "port");
    assert!(reason.contains("dcs[1].endpoints[1]"), "{reason}");
}

#[test]
fn dc_invariants_are_checked() {
    let config = custom_config();
    let mut map = config.to_map();
    map["dcs"][1]["endpoints"][0]["id"] = json!(3);
    assert_eq!(invalid_input(MtpConfig::from_map(&map)).0, "id");

    let mut map = config.to_map();
    let first = map["dcs"][1]["endpoints"][0].clone();
    map["dcs"][1]["endpoints"]
        .as_array_mut()
        .expect("endpoints")
        .push(first);
    assert_eq!(invalid_input(MtpConfig::from_map(&map)).0, "endpoints");

    let mut map = config.to_map();
    let first = map["dcs"][0].clone();
    map["dcs"].as_array_mut().expect("dcs").push(first);
    assert_eq!(invalid_input(MtpConfig::from_map(&map)).0, "dc_id");
}
