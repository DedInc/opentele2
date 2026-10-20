//! The embedded Apify networks.

use std::time::Instant;

use opentele2_browser::network::{FINGERPRINT_NETWORK_ZIP, HEADER_NETWORK_ZIP, INPUT_NETWORK_ZIP};
use opentele2_browser::{
    BayesianNetwork, Restrictions, Rng, Values, fingerprint_network, header_network, input_network,
};

fn names(network: &BayesianNetwork) -> Vec<&str> {
    network.nodes().map(|n| n.name()).collect()
}

#[test]
fn input_network_nodes() {
    let net = input_network().unwrap();
    assert_eq!(
        names(net),
        [
            "*DEVICE",
            "*OPERATING_SYSTEM",
            "*BROWSER_HTTP",
            "*HTTP_VERSION",
            "*BROWSER"
        ]
    );
}

#[test]
fn header_network_nodes() {
    let net = header_network().unwrap();
    assert_eq!(net.len(), 19);
    assert_eq!(
        names(net)[..4],
        ["*BROWSER", "*OPERATING_SYSTEM", "*DEVICE", "*HTTP_VERSION"]
    );
}

#[test]
fn fingerprint_network_nodes() {
    let net = fingerprint_network().unwrap();
    assert_eq!(net.len(), 25);
    assert_eq!(names(net)[0], "userAgent");
    assert!(net.node("userAgent").unwrap().possible_values().len() > 100);
}

#[test]
fn networks_are_parsed_once() {
    assert!(std::ptr::eq(
        input_network().unwrap(),
        input_network().unwrap()
    ));
}

#[test]
fn same_seed_same_sample_on_every_network() {
    for net in [input_network(), header_network(), fingerprint_network()] {
        let net = net.unwrap();
        let first = net.sample(&mut Rng::from_seed("Мухамед"), &Values::new());
        let second = net.sample(&mut Rng::from_seed("Мухамед"), &Values::new());
        assert_eq!(first, second);
        assert!(first.contains_key(names(net)[0]));
    }
    let net = input_network().unwrap();
    let sample = net.sample(&mut Rng::from_seed("input"), &Values::new());
    assert_eq!(sample.keys().collect::<Vec<_>>(), names(net));
}

#[test]
fn consistent_sample_honours_restrictions() {
    let net = input_network().unwrap();
    let mobile: Restrictions = [("*DEVICE", vec!["mobile".to_owned()])]
        .into_iter()
        .collect();
    for seed in 0..20 {
        let seed = seed.to_string();
        let a = net
            .consistent_sample(&mut Rng::from_seed(&seed), &mobile)
            .unwrap();
        let b = net
            .consistent_sample(&mut Rng::from_seed(&seed), &mobile)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.get("*DEVICE").unwrap(), "mobile");
        assert!(["ios", "android"].contains(&a.get("*OPERATING_SYSTEM").unwrap().as_str()));
    }
    let closure = net
        .possible_values(
            &[("*OPERATING_SYSTEM", vec!["ios".to_owned()])]
                .into_iter()
                .collect(),
        )
        .unwrap();
    assert_eq!(closure.get("*DEVICE").unwrap(), &["mobile"]);
}

/// Prints the parse time of each embedded network; run with `--nocapture`.
#[test]
fn report_parse_time() {
    for (name, archive) in [
        ("input", INPUT_NETWORK_ZIP),
        ("header", HEADER_NETWORK_ZIP),
        ("fingerprint", FINGERPRINT_NETWORK_ZIP),
    ] {
        let start = Instant::now();
        let net = BayesianNetwork::from_zip(archive).unwrap();
        let elapsed = start.elapsed();
        println!("parse {name}: {} nodes in {elapsed:?}", net.len());
    }
}
