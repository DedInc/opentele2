//! Golden outputs of the xoshiro256** generator and its seeding.

use opentele2_browser::Rng;

/// 2^-53.
const UNIT: f64 = 1.0 / 9_007_199_254_740_992.0;

#[test]
fn xoshiro256starstar_reference_vector() {
    // The first outputs of the reference xoshiro256** for the state 1, 2, 3, 4.
    let expected: [u64; 10] = [
        11_520,
        0,
        1_509_978_240,
        1_215_971_899_390_074_240,
        1_216_172_134_540_287_360,
        607_988_272_756_665_600,
        16_172_922_978_634_559_625,
        8_476_171_486_693_032_832,
        10_595_114_339_597_558_777,
        2_904_607_092_377_533_576,
    ];
    let mut rng = Rng::from_state([1, 2, 3, 4]);
    let actual: Vec<u64> = (0..expected.len()).map(|_| rng.next_u64()).collect();
    assert_eq!(actual, expected);
}

#[test]
fn next_f64_takes_the_top_53_bits() {
    let mut rng = Rng::from_state([1, 2, 3, 4]);
    assert_eq!(rng.next_f64().to_bits(), (5.0 * UNIT).to_bits());
    assert_eq!(rng.next_f64().to_bits(), 0.0f64.to_bits());
    assert_eq!(rng.next_f64().to_bits(), (737_294.0 * UNIT).to_bits());
    assert_eq!(
        rng.next_f64().to_bits(),
        (593_736_278_999_059.0 * UNIT).to_bits()
    );
}

#[test]
fn seed_is_the_little_endian_sha256_of_the_utf8_seed() {
    // SHA-256("opentele2") = 8cddc43ada5d1c99 aeafbf25e19fcddc
    //                        e607c7ac0c08c534 207dee83e2def3a9
    let state = [
        0x991c_5dda_3ac4_dd8c,
        0xdccd_9fe1_25bf_afae,
        0x34c5_080c_acc7_07e6,
        0xa9f3_dee2_83ee_7d20,
    ];
    assert_eq!(Rng::from_seed("opentele2"), Rng::from_state(state));
}

#[test]
fn seeded_golden_first_outputs() {
    let mut rng = Rng::from_seed("opentele2");
    let actual: Vec<u64> = (0..4).map(|_| rng.next_f64().to_bits()).collect();
    // Pinned: a change here changes every seeded sample of the crate.
    let expected: Vec<u64> = vec![
        4_589_886_318_428_352_712,
        4_599_566_622_838_232_686,
        4_602_893_542_710_158_307,
        4_602_886_777_091_189_794,
    ];
    assert_eq!(actual, expected);
}

#[test]
fn same_seed_same_stream() {
    let mut a = Rng::from_seed("Мухамед");
    let mut b = Rng::from_seed("Мухамед");
    for _ in 0..1000 {
        let x = a.next_f64();
        assert!((0.0..1.0).contains(&x));
        assert_eq!(x.to_bits(), b.next_f64().to_bits());
    }
    assert_ne!(Rng::from_seed("a"), Rng::from_seed("b"));
}

#[test]
fn entropy_seeding_works() {
    let mut rng = Rng::from_entropy().unwrap();
    assert!((0.0..1.0).contains(&rng.next_f64()));
}
