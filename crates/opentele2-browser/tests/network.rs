//! The sampler on small hand-written networks.

use opentele2_browser::{BayesianNetwork, Error, Restrictions, Rng, Values};

/// A -> B -> C. B is a function of A; C is a function of B, with a `skip`
/// branch for any other B. `b1` is an integer probability on purpose.
const CHAIN: &str = r#"{"nodes":[
  {"name":"A","possibleValues":["a1","a2"],
   "conditionalProbabilities":{"a1":0.7,"a2":0.3}},
  {"name":"B","parentNames":["A"],"possibleValues":["b1","b2"],
   "conditionalProbabilities":{"deeper":{"a1":{"b1":1},"a2":{"b2":1.0}}}},
  {"name":"C","parentNames":["B"],"possibleValues":["c1","c2","c3"],
   "conditionalProbabilities":{"deeper":{"b1":{"c1":1.0},"b2":{"c2":1.0}},
                               "skip":{"c1":0.5,"c3":0.5}}}
]}"#;

/// D has an empty distribution under `a1` and none at all for other values.
const HOLES: &str = r#"{"nodes":[
  {"name":"A","possibleValues":["a1","a2"],
   "conditionalProbabilities":{"a1":0.5,"a2":0.5}},
  {"name":"D","parentNames":["A"],"possibleValues":["d1"],
   "conditionalProbabilities":{"deeper":{"a1":{},"a2":{"d1":1.0}}}}
]}"#;

fn chain() -> BayesianNetwork {
    BayesianNetwork::from_json(CHAIN.as_bytes()).unwrap()
}

fn values(pairs: &[(&str, &str)]) -> Values {
    pairs.iter().map(|&(k, v)| (k, v.to_owned())).collect()
}

fn restrictions(pairs: &[(&str, &[&str])]) -> Restrictions {
    pairs
        .iter()
        .map(|&(k, vs)| (k, vs.iter().map(|&v| v.to_owned()).collect()))
        .collect()
}

#[test]
fn parses_nodes_in_order_with_defaults() {
    let net = chain();
    let names: Vec<&str> = net.nodes().map(|n| n.name()).collect();
    assert_eq!(names, ["A", "B", "C"]);
    let a = net.node("A").unwrap();
    assert_eq!(a.parent_names().count(), 0);
    assert_eq!(a.possible_values().collect::<Vec<_>>(), ["a1", "a2"]);
    let c = net.node("C").unwrap();
    assert_eq!(c.probabilities(&values(&[("B", "b1")])), [("c1", 1.0)]);
    assert_eq!(
        c.probabilities(&values(&[("B", "other")])),
        [("c1", 0.5), ("c3", 0.5)]
    );
    assert!(net.node("Z").is_none());
}

#[test]
fn sample_distribution_matches_the_cpt() {
    let net = chain();
    let mut rng = Rng::from_seed("distribution");
    let runs = 20_000;
    let mut a1 = 0;
    let mut c1_under_skip = 0;
    for _ in 0..runs {
        let s = net.sample(&mut rng, &Values::new());
        let (a, b, c) = (
            s.get("A").unwrap(),
            s.get("B").unwrap(),
            s.get("C").unwrap(),
        );
        if a == "a1" {
            a1 += 1;
            assert_eq!((b.as_str(), c.as_str()), ("b1", "c1"));
        } else {
            assert_eq!((b.as_str(), c.as_str()), ("b2", "c2"));
        }
        let skipped = net.sample(&mut rng, &values(&[("B", "elsewhere")]));
        if skipped.get("C").unwrap() == "c1" {
            c1_under_skip += 1;
        }
    }
    let share = f64::from(a1) / f64::from(runs);
    assert!((0.68..0.72).contains(&share), "a1 share {share}");
    let share = f64::from(c1_under_skip) / f64::from(runs);
    assert!((0.48..0.52).contains(&share), "c1 share {share}");
}

#[test]
fn fixed_values_are_kept_and_come_first() {
    let net = chain();
    for seed in 0..50 {
        let mut rng = Rng::from_seed(&seed.to_string());
        let s = net.sample(&mut rng, &values(&[("A", "a2")]));
        assert_eq!(s, values(&[("A", "a2"), ("B", "b2"), ("C", "c2")]));
        let s = net.sample(&mut rng, &values(&[("B", "foreign"), ("extra", "x")]));
        let keys: Vec<&str> = s.keys().collect();
        assert_eq!(keys, ["B", "extra", "A", "C"]);
        assert_eq!(s.get("B").unwrap(), "foreign");
        assert!(["c1", "c3"].contains(&s.get("C").unwrap().as_str()));
    }
}

#[test]
fn same_seed_same_sample() {
    let net = chain();
    let first = net.sample(&mut Rng::from_seed("repeat"), &Values::new());
    let second = net.sample(&mut Rng::from_seed("repeat"), &Values::new());
    assert_eq!(first, second);
}

#[test]
fn consistent_sample_backtracks_past_a_dead_branch() {
    let net = chain();
    // A draws a1 first 70% of the time; that branch can only reach c1, so the
    // search has to ban b1, then a1, and settle on a2.
    let only_c2 = restrictions(&[("C", &["c2"])]);
    let mut dead_first = 0;
    for seed in 0..50 {
        let seed = seed.to_string();
        if net
            .sample(&mut Rng::from_seed(&seed), &Values::new())
            .get("A")
            .unwrap()
            == "a1"
        {
            dead_first += 1;
        }
        let s = net
            .consistent_sample(&mut Rng::from_seed(&seed), &only_c2)
            .unwrap();
        assert_eq!(s, values(&[("A", "a2"), ("B", "b2"), ("C", "c2")]));
    }
    assert!(dead_first > 0);
}

#[test]
fn consistent_sample_none_when_impossible() {
    let net = chain();
    let mut rng = Rng::from_seed("impossible");
    assert!(
        net.consistent_sample(&mut rng, &restrictions(&[("C", &["c3"])]))
            .is_none()
    );
    assert!(
        net.consistent_sample(&mut rng, &restrictions(&[("A", &["a1"]), ("C", &["c2"])]))
            .is_none()
    );
    assert!(
        net.consistent_sample(&mut rng, &restrictions(&[("A", &["unknown"])]))
            .is_none()
    );
    assert!(
        net.consistent_sample(&mut rng, &restrictions(&[("A", &[])]))
            .is_none()
    );
}

#[test]
fn possible_values_closure() {
    let net = chain();
    let got = net
        .possible_values(&restrictions(&[("C", &["c2"])]))
        .unwrap();
    assert_eq!(got, restrictions(&[("B", &["b2"]), ("C", &["c2"])]));

    // Parent values come out in CPT order, not constraint order.
    let got = net
        .possible_values(&restrictions(&[("C", &["c2", "c1"])]))
        .unwrap();
    assert_eq!(
        got,
        restrictions(&[("B", &["b1", "b2"]), ("C", &["c2", "c1"])])
    );

    let got = net
        .possible_values(&restrictions(&[("B", &["b2"]), ("C", &["c2", "c1"])]))
        .unwrap();
    assert_eq!(
        got,
        restrictions(&[("A", &["a2"]), ("B", &["b2"]), ("C", &["c2", "c1"])])
    );

    // A root node induces nothing on others.
    let got = net
        .possible_values(&restrictions(&[("A", &["a2", "a1"])]))
        .unwrap();
    assert_eq!(got, restrictions(&[("A", &["a2", "a1"])]));
}

#[test]
fn possible_values_too_restrictive() {
    let net = chain();
    let message = "The current constraints are too restrictive. No possible values can be found for the given constraints.";
    let err = net
        .possible_values(&restrictions(&[("B", &["b1"]), ("C", &["c2"])]))
        .unwrap_err();
    assert_eq!(err, Error::TooRestrictive);
    assert_eq!(err.to_string(), message);
    assert_eq!(
        net.possible_values(&restrictions(&[("A", &[])]))
            .unwrap_err(),
        Error::TooRestrictive
    );
    assert_eq!(
        net.possible_values(&restrictions(&[("Z", &["z"])]))
            .unwrap_err(),
        Error::UnknownNode("Z".to_owned())
    );
}

#[test]
fn empty_distribution_yields_no_value() {
    let net = BayesianNetwork::from_json(HOLES.as_bytes()).unwrap();
    let mut rng = Rng::from_seed("holes");
    let d = net.node("D").unwrap();
    assert!(d.sample(&mut rng, &values(&[("A", "a1")])).is_none());
    assert!(d.sample(&mut rng, &values(&[("A", "a9")])).is_none());
    assert_eq!(d.sample(&mut rng, &values(&[("A", "a2")])), Some("d1"));
    let s = net.sample(&mut rng, &values(&[("A", "a1")]));
    assert_eq!(s, values(&[("A", "a1")]));
    for seed in 0..20 {
        let s = net
            .consistent_sample(&mut Rng::from_seed(&seed.to_string()), &Restrictions::new())
            .unwrap();
        assert_eq!(s, values(&[("A", "a2"), ("D", "d1")]));
    }
}

#[test]
fn malformed_input_is_an_error() {
    assert!(matches!(
        BayesianNetwork::from_json(b"{}"),
        Err(Error::Network(_))
    ));
    assert!(matches!(
        BayesianNetwork::from_json(br#"{"nodes":[{"name":"A"}]}"#),
        Err(Error::Network(_))
    ));
    assert!(matches!(
        BayesianNetwork::from_zip(b"not a zip"),
        Err(Error::Zip(_))
    ));
}
