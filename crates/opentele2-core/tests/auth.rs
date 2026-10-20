//! Tests for `opentele2_core::auth` against Telethon 1.45.0 and opentele2
//! 1.5.0.
//!
//! Every expected value was produced by running the reference code with
//! `python -c`: Telethon `QRLogin.url` for the QR URLs, Telethon
//! `password.compute_check` with `os.urandom` patched to serve the recorded
//! exponents for the SRP checks, 1.5.0 `TelegramClient.PrintSessions` on a
//! fake `account.Authorizations` for the tables, and 1.5.0
//! `ConsistencyChecker.run_all` on a fake client for the report texts. The
//! passwords are fixtures; no password or proof is printed on failure.

use opentele2_core::api::{self, ApiProfile, Client, LAYER, Versions};
use opentele2_core::auth::{
    self, CURRENT_SESSION_MISSING, Check, CheckResult, ConsistencyExpectations, FlowFailure,
    LANG_PACK_EMPTY, LAYER_TOLERANCE, NO_APP_UPDATE, OFFICIAL_API_IDS, SESSION_COLUMNS, SessionRow,
    SrpCheck, SrpError, SrpParams, TERMS_OF_SERVICE_OK,
};

/// `p` of the fixtures, Telegram's 2FA prime.
const P: &str = concat!(
    "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f",
    "48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37",
    "20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64",
    "2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4",
    "a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754",
    "fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4",
    "e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f",
    "0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b",
);

/// One recorded `account.Password` with its `compute_check` result.
struct SrpFixture {
    srp_id: i64,
    g: i32,
    salt1: &'static str,
    salt2: &'static str,
    srp_b: &'static str,
    password: &'static str,
    /// The `os.urandom(256)` results in order; Telethon used all of them.
    draws: &'static [&'static str],
    a: &'static str,
    m1: &'static str,
}

const SRP_ONE: SrpFixture = SrpFixture {
    srp_id: 2_479_236_611_711_966_277,
    g: 3,
    salt1: "713a69e9a27390a0968da87fbf1a8510a4c5da97ed6f64447cbc4135821f3eeeabd5317c3ca6d03e",
    salt2: "6c2fffb7af6a052438d3305e2f42f538",
    srp_b: concat!(
        "aabfadc340a660e89e0f964c749c62a91d955fa812f58ea17083c3b6b2ddd8e9",
        "04a40c3c3300a5cd6216ceea87982328fff1b08959e9587dfb2b2956954b948a",
        "fb689767e50254d9c732524af2f6e3e25c1db60f99672311669f1b4c50fe8ee0",
        "f8202dd71faee5864581146e4bdd933b8e043b1f3a84c5c8acae2d31215346a1",
        "eee0d52dd684ac451af249703afe79ab55bbf9e111ec157619205a8d900ae35a",
        "5508670b1da74bde487e58464481343d9b40f26bfac6c43b785e7e0853251b6c",
        "1de9315c25cfc22f474c6803f6eb7879f7198c7e0eed715c236da7a5de2a347b",
        "4ffc471c0f8982bf908e72ea264bced63a635bc3e148b61f0dd248443c06b39d",
    ),
    password: "hunter2-fixture",
    draws: &[concat!(
        "5e62ea01ba87e020b0b69300dbef2f1c0b8bd99ad78b1a54c8f29f462be3beda",
        "8e96b717b5e98c7f0c9c1be816e57afa06f372a2678876dbaee2ad3f5b37d829",
        "a49bbda90e92eb7bb5ca56defcf971319b8b87c7f1613886bfc067baef17920f",
        "6318981f3626ecbda3ad3194506e9fecd1fbdaa6eced7b2af8b2878c5a40e3f4",
        "ef7368d3fb76a170f5303830f4a07d621adf717a26c5a4fb68a308065a3ba5f6",
        "03b3cac89049642698fbf5ef7bf9455d69bfaae9ab57b7746573f33c54971f6a",
        "0988bbc32fcf75edb64dd438d7807007f598cc96c5ae3d2afe62f1ed109758a9",
        "8a37469dcb7f18505bd39d152b9273e48a69b70734b8fbc0dc90d07804483988",
    )],
    a: concat!(
        "4379fcb7331c3afd731a3fb183c43f54c0342caff67efb16d31c19d1a79a80d8",
        "731829fc977c46e2742fae5213d19ecbb1197444e5495e2c4cdb724f61a13475",
        "4132bdbfe7c4e65578d88a7ec20e915826315c74fdccd4fe4afc6722fe113351",
        "6ad599e9cefcfa2b85dbeaa9d279da272fd375715aa1967028d4f000cb9d5a10",
        "a26d4f4041c2f883ab4e025e729fcfa6130f7ea9548968f124ecb237504fde6c",
        "f34916851ee527d90c7ec540db946095b3cc5447bdacf319509b40dd83577471",
        "e33095fc69059d60a38d2daea78e1693d91bb59cd85d8bae42df1482ddd721d8",
        "7c763342f745343ff01f71a1b922b9a4687fff8c0e62567c75fcb918d9a30e79",
    ),
    m1: "f362f25a068ba4dd638905fda4d4e6b541f5dbbebfe7eedfcef23f96ec3eb0e3",
};

/// The first draw is `a = 1`, whose `A = 5` Telethon rejects and redraws.
const SRP_TWO: SrpFixture = SrpFixture {
    srp_id: 4_363_604_755_476_580_611,
    g: 5,
    salt1: "3ced22e9780b49d06180dee243d98f4127df5b5156974a9a0882b42403a53eddb77127d6e8b3dcb3",
    salt2: "8179e37406414367517fdb8145907c60",
    srp_b: concat!(
        "969f3c63ba009ca87e88de13714892ecd959eb8bb11302a8f264e545c0ab54f0",
        "632eadde6ad5966d2448e1cde0224d2fd3c5bab9ab5a662b6a26721e5fa52877",
        "2a3fe2a2ed19ffd1c41a1ea4f26f58e1bf6d5c6082915ca0cefdd01022c50cb4",
        "a80f92d28e05b26fb87c1757218dde35d2c180739497df9277ff5c6710829a9c",
        "e13c7742b37e74d9edcf9cbe971f1f37ab6d14fc51cea92b7ac54dab2fa97da4",
        "9e97cd2361024383569c617871087813d31fa4b273fb5d5e54ac8c584304ab82",
        "a81dad71ebdf3d74227cc9f778cfee212604c9b12ee3c183d16f37fa36ad6017",
        "b132e9b09d26b28f17fa5193e3afae73a88a511f9bad86e3e7aeb67c3c9472cc",
    ),
    password: "пароль-fixture",
    draws: &[
        concat!(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        concat!(
            "a64dcceb1a998d1a1c78f98d8f372ca4649d349f0d58fe487a450b3f308f0c6f",
            "f1dc4c8b85f7c69a42f3379106faa777c643de12ed93123c92c5a6917c5dcbdc",
            "4c5f7adfa2db439957eb16136d2fb35c872046021cb24d32b50362497c03b2fa",
            "7749bb9bfb335d14e9aa0e21ab38ac0fc6f62832555a3984dcef9f692415af2e",
            "e333bf43081178f80793a308460b5495699ac12c36ab6e0a819ba8ff69726deb",
            "c35ae6238b5bfe5b6fe61339312f89e7ce08c26baf9cd6c396f6ddd5657f18d6",
            "e14ca683ad4e81d797930d876c2dbdb75ca26d994974c9158bd01823e3a5846c",
            "e6882fd8907315b379cb1d674cf41611dd55baa4a9a975ff10a60881bcc87b0a",
        ),
    ],
    a: concat!(
        "53bf5c503f621219caf5d35d1ded97cb807d4a7037ddc0660f8fa32d582b0546",
        "2843fe09b40922ec724e33e522123990c22cbe773b4550f05a9cefd39808dddb",
        "d940c91e2e24196a5aaf38584df9377b587d922068c053d853caa00028218ad7",
        "c0d1db714abb763953ed6e6f621117ac63df534ac353390213bdc507a6fbc4a7",
        "da1de02d5ef52dd97e9b33f0e94a60782010374f51418a1c719cc4a1296b0a82",
        "14a9f6c26690176368c7bff6740fba3c2796b08616cddddc480e9bd432c15bc2",
        "1434ac1d9c55384afbf018c2008a8ffa5db40b061383c6f8cae28057a68e2d9b",
        "813ce2564376feb78572e4b0cb1669fa2e2f8f8ff2b7b7a9798dfeaa77faaefb",
    ),
    m1: "e3f599856deb285836c4e97b75226e43ca861635d48b72ef0ceed578f2845e49",
};

fn bytes(hex_text: &str) -> Vec<u8> {
    hex::decode(hex_text).expect("fixture hex")
}

/// Runs `srp_check` for `fixture`, serving its draws in order, and returns
/// the check with the number of draws made.
fn run_srp(fixture: &SrpFixture, p: &[u8], srp_b: &[u8]) -> (Result<SrpCheck, SrpError>, usize) {
    let salt1 = bytes(fixture.salt1);
    let salt2 = bytes(fixture.salt2);
    let params = SrpParams {
        srp_id: fixture.srp_id,
        g: fixture.g,
        p,
        salt1: &salt1,
        salt2: &salt2,
        srp_b,
    };
    let draws: Vec<Vec<u8>> = fixture.draws.iter().map(|d| bytes(d)).collect();
    let mut next = 0;
    let check = auth::srp_check(&params, fixture.password, &mut |buf| {
        let draw = draws.get(next).expect("an unrecorded draw");
        assert_eq!(buf.len(), draw.len(), "draw size");
        buf.copy_from_slice(draw);
        next += 1;
    });
    (check, next)
}

fn assert_srp_matches_telethon(fixture: &SrpFixture) {
    let (check, draws) = run_srp(fixture, &bytes(P), &bytes(fixture.srp_b));
    let check = check.expect("srp check");
    assert_eq!(draws, fixture.draws.len(), "draws made");
    assert_eq!(check.srp_id, fixture.srp_id);
    assert!(
        check.a.as_slice() == bytes(fixture.a),
        "A differs from Telethon"
    );
    assert!(
        check.m1.as_slice() == bytes(fixture.m1),
        "M1 differs from Telethon"
    );
}

#[test]
fn qr_login_url_matches_telethon() {
    let cases: [(&str, &str); 7] = [
        ("", "tg://login?token="),
        ("00", "tg://login?token=AA"),
        ("fb", "tg://login?token=-w"),
        ("fbff", "tg://login?token=-_8"),
        ("fbffbf", "tg://login?token=-_-_"),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "tg://login?token=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        ),
        (
            "6c6f67696e2d746f6b656efeff",
            "tg://login?token=bG9naW4tdG9rZW7-_w",
        ),
    ];
    for (token, url) in cases {
        assert_eq!(auth::qr_login_url(&bytes(token)), url, "token {token}");
        assert!(url.starts_with(auth::QR_LOGIN_URL_PREFIX));
    }
}

#[test]
fn srp_check_matches_telethon_compute_check() {
    assert_srp_matches_telethon(&SRP_ONE);
}

#[test]
fn srp_check_redraws_a_bad_exponent_like_telethon() {
    assert_srp_matches_telethon(&SRP_TWO);
}

#[test]
fn srp_check_refuses_what_telethon_refuses() {
    let p = bytes(P);
    let b = bytes(SRP_ONE.srp_b);
    let bad_g = SrpFixture { g: 9, ..SRP_ONE };
    assert_eq!(
        run_srp(&bad_g, &p, &b),
        (Err(SrpError::BadPrimeOrGenerator), 0)
    );
    assert_eq!(
        run_srp(&SRP_ONE, &p[1..], &b),
        (Err(SrpError::BadPrimeOrGenerator), 0)
    );

    assert_eq!(run_srp(&SRP_ONE, &p, &[]), (Err(SrpError::BadB), 0));
    assert_eq!(run_srp(&SRP_ONE, &p, &[0; 256]), (Err(SrpError::BadB), 0));
    assert_eq!(run_srp(&SRP_ONE, &p, &p), (Err(SrpError::BadB), 0));
    let mut over_p = p.clone();
    over_p[255] = over_p[255].wrapping_add(1);
    assert_eq!(run_srp(&SRP_ONE, &p, &over_p), (Err(SrpError::BadB), 0));
    let mut long_b = vec![0];
    long_b.extend_from_slice(&b);
    assert_eq!(run_srp(&SRP_ONE, &p, &long_b), (Err(SrpError::BadB), 0));

    assert_eq!(
        SrpError::BadPrimeOrGenerator.to_string(),
        "bad p/g in password"
    );
    assert_eq!(SrpError::BadB.to_string(), "bad b in check");
}

#[test]
fn srp_check_debug_hides_the_proof() {
    let (check, _) = run_srp(&SRP_ONE, &bytes(P), &bytes(SRP_ONE.srp_b));
    let check = check.expect("srp check");
    let text = format!("{check:?}");
    assert!(text.contains(&SRP_ONE.srp_id.to_string()));
    assert!(!text.contains("m1"), "M1 field in Debug");
    assert!(!text.contains("a:"), "A field in Debug");
}

#[test]
fn srp_check_random_makes_a_valid_check() {
    let salt1 = bytes(SRP_ONE.salt1);
    let salt2 = bytes(SRP_ONE.salt2);
    let p = bytes(P);
    let b = bytes(SRP_ONE.srp_b);
    let params = SrpParams {
        srp_id: SRP_ONE.srp_id,
        g: SRP_ONE.g,
        p: &p,
        salt1: &salt1,
        salt2: &salt2,
        srp_b: &b,
    };
    let first = auth::srp_check_random(&params, SRP_ONE.password).expect("srp check");
    let second = auth::srp_check_random(&params, SRP_ONE.password).expect("srp check");
    assert_eq!(first.srp_id, SRP_ONE.srp_id);
    assert!(first.a != second.a, "fresh exponents give a fresh A");
}

/// The `telethon.py` `_compute_check` rule: both fields or id 0 and an
/// empty `B`, which the check refuses as a bad `B`.
#[test]
fn srp_inputs_follow_the_python_rule() {
    let b = bytes(SRP_ONE.srp_b);
    assert_eq!(
        auth::srp_inputs(Some(SRP_ONE.srp_id), Some(&b)),
        (SRP_ONE.srp_id, b.clone())
    );
    assert_eq!(auth::srp_inputs(Some(7), Some(&[])), (7, Vec::new()));
    assert_eq!(auth::srp_inputs(None, Some(&b)), (0, Vec::new()));
    assert_eq!(
        auth::srp_inputs(Some(SRP_ONE.srp_id), None),
        (0, Vec::new())
    );
    assert_eq!(auth::srp_inputs(None, None), (0, Vec::new()));

    let (srp_id, srp_b) = auth::srp_inputs(None, Some(&b));
    let fixture = SrpFixture { srp_id, ..SRP_ONE };
    assert_eq!(
        run_srp(&fixture, &bytes(P), &srp_b),
        (Err(SrpError::BadB), 0)
    );
}

/// The `SrpError` codes and classes of `CORE_ERROR_TYPES`, without its
/// dead `SRP_FAILED` entry.
#[test]
fn srp_error_codes_and_classes_are_the_python_table() {
    let expected = [
        (SrpError::BadPrimeOrGenerator, "SRP_BAD_PRIME_OR_GENERATOR"),
        (SrpError::BadB, "SRP_BAD_B"),
        (SrpError::NoGoodRandom, "SRP_NO_GOOD_RANDOM"),
        (SrpError::RandomUnavailable, "SRP_RANDOM_UNAVAILABLE"),
    ];
    for (error, code) in expected {
        assert_eq!(error.code(), code);
        assert_ne!(error.code(), "SRP_FAILED");
        assert_eq!(error.legacy_class(), "ValueError", "{error:?}");
    }
}

#[test]
fn flow_rpc_error_names_are_telegrams() {
    assert_eq!(auth::RPC_PASSWORD_HASH_INVALID, "PASSWORD_HASH_INVALID");
    assert_eq!(auth::RPC_SESSION_PASSWORD_NEEDED, "SESSION_PASSWORD_NEEDED");
    assert_eq!(
        auth::RPC_FRESH_RESET_AUTHORISATION_FORBIDDEN,
        "FRESH_RESET_AUTHORISATION_FORBIDDEN"
    );
    assert_eq!(auth::RPC_HASH_INVALID, "HASH_INVALID");
    assert_eq!(
        auth::RPC_AUTH_TOKEN_ALREADY_ACCEPTED,
        "AUTH_TOKEN_ALREADY_ACCEPTED"
    );
    assert_eq!(auth::RPC_AUTH_TOKEN_EXPIRED, "AUTH_TOKEN_EXPIRED");
    assert_eq!(auth::RPC_AUTH_TOKEN_INVALID, "AUTH_TOKEN_INVALID");
}

#[test]
fn flow_texts_are_the_bindings() {
    assert_eq!(
        auth::USER_ID_UNRESOLVED,
        "Could not resolve the account's user id"
    );
    assert_eq!(
        auth::SIGN_UP_REQUIRED,
        "the server asked to sign up instead of logging in"
    );
}

/// The codes the Node flows give with `OT_` and the classes the Python
/// flows raise (`telethon.py`, `account.py`) and mtcute names its errors.
#[test]
fn flow_failure_codes_and_classes_are_pinned() {
    let expected = [
        (
            FlowFailure::NoPasswordProvided,
            "NO_PASSWORD_PROVIDED",
            "NoPasswordProvided",
        ),
        (
            FlowFailure::PasswordIncorrect,
            "PASSWORD_INCORRECT",
            "PasswordIncorrect",
        ),
        (
            FlowFailure::AuthTokenAlreadyAccepted,
            "AUTH_TOKEN_ALREADY_ACCEPTED",
            "AuthTokenAlreadyAcceptedError",
        ),
        (
            FlowFailure::AuthTokenExpired,
            "AUTH_TOKEN_EXPIRED",
            "AuthTokenExpiredError",
        ),
        (
            FlowFailure::AuthTokenInvalid,
            "AUTH_TOKEN_INVALID",
            "AuthTokenInvalidError",
        ),
        (
            FlowFailure::QrLoginTimeout,
            "QR_LOGIN_TIMEOUT",
            "TimeoutError",
        ),
        (
            FlowFailure::FreshResetForbidden,
            "FRESH_RESET_FORBIDDEN",
            "FreshResetAuthorisationForbiddenError",
        ),
        (FlowFailure::HashInvalid, "HASH_INVALID", "HashInvalidError"),
        (
            FlowFailure::UnsupportedPasswordAlgorithm,
            "UNSUPPORTED_PASSWORD_ALGORITHM",
            "ValueError",
        ),
        (
            FlowFailure::SignUpRequired,
            "SIGN_UP_REQUIRED",
            "SignUpRequired",
        ),
        (
            FlowFailure::UserIdUnresolved,
            "USER_ID_UNRESOLVED",
            "TelethonUnauthorized",
        ),
        (
            FlowFailure::SessionsUnavailable,
            "SESSIONS_UNAVAILABLE",
            "OpenTeleException",
        ),
    ];
    assert_eq!(FlowFailure::ALL.len(), expected.len());
    for (failure, (listed, code, class)) in FlowFailure::ALL.into_iter().zip(expected) {
        assert_eq!(failure, listed);
        assert_eq!(failure.code(), code);
        assert_eq!(failure.legacy_class(), class);
    }
}

/// A session row; `text` is device, platform, system, app name and version.
fn row(current: bool, official_app: bool, api_id: i32, text: [&str; 5]) -> SessionRow {
    let [
        device_model,
        platform,
        system_version,
        app_name,
        app_version,
    ] = text.map(str::to_owned);
    SessionRow {
        current,
        device_model,
        platform,
        system_version,
        api_id,
        app_name,
        app_version,
        official_app,
    }
}

#[test]
fn sessions_table_matches_print_sessions() {
    // The fourth session has `current` and `official_app` unset (None).
    let rows = [
        row(
            true,
            true,
            2040,
            [
                "Desktop",
                "Windows",
                "Windows 11 x64",
                "Telegram Desktop",
                "6.1.3 x64",
            ],
        ),
        row(
            false,
            true,
            6,
            [
                "samsungSM-S938B",
                "android",
                "SDK 36",
                "Telegram Android",
                "12.0.1 (61234)",
            ],
        ),
        row(
            false,
            false,
            123_456,
            ["Pixel 8 Прo", "", "Linux", "My bot thing", "0.1"],
        ),
        row(
            false,
            false,
            10840,
            [
                "iPhone 17 Pro",
                "iOS",
                "26.0",
                "Telegram iOS",
                "12.1 (32000) ",
            ],
        ),
    ];
    let expected = concat!(
        "|---------+-----------------+----------+----------------+--------+---------------------------------+--------------|\n",
        "|         |     Device      | Platform |     System     | API_ID |            App name             | Official App |\n",
        "|---------+-----------------+----------+----------------+--------+---------------------------------+--------------|\n",
        "| Current |     Desktop     | Windows  | Windows 11 x64 |  2040  |   Telegram Desktop 6.1.3 x64    |      ✔       |\n",
        "|---------+-----------------+----------+----------------+--------+---------------------------------+--------------|\n",
        "|    1    | samsungSM-S938B | android  |     SDK 36     |   6    | Telegram Android 12.0.1 (61234) |      ✔       |\n",
        "|    2    |   Pixel 8 Прo   |          |     Linux      | 123456 |        My bot thing 0.1         |      ✖       |\n",
        "|    3    |  iPhone 17 Pro  |   iOS    |      26.0      | 10840  |   Telegram iOS 12.1 (32000)     |      ✖       |\n",
        "|---------+-----------------+----------+----------------+--------+---------------------------------+--------------|",
    );
    assert_eq!(auth::format_sessions(&rows), expected);
}

#[test]
fn sessions_table_splits_after_the_first_row_wherever_current_is() {
    let one = [row(false, false, 1, ["x", "y", "z", "a", "b"])];
    assert_eq!(
        auth::format_sessions(&one),
        concat!(
            "|---+--------+----------+--------+--------+----------+--------------|\n",
            "|   | Device | Platform | System | API_ID | App name | Official App |\n",
            "|---+--------+----------+--------+--------+----------+--------------|\n",
            "| 0 |   x    |    y     |   z    |   1    |   a b    |      ✖       |\n",
            "|---+--------+----------+--------+--------+----------+--------------|",
        )
    );

    let two = [
        row(
            false,
            true,
            2496,
            ["Web", "web", "Win32", "Telegram Web", "2.2 K"],
        ),
        row(
            true,
            true,
            2040,
            ["Desktop", "Windows", "10", "Telegram Desktop", "6.1"],
        ),
    ];
    assert_eq!(
        auth::format_sessions(&two),
        concat!(
            "|---------+---------+----------+--------+--------+----------------------+--------------|\n",
            "|         | Device  | Platform | System | API_ID |       App name       | Official App |\n",
            "|---------+---------+----------+--------+--------+----------------------+--------------|\n",
            "|    0    |   Web   |   web    | Win32  |  2496  |  Telegram Web 2.2 K  |      ✔       |\n",
            "|---------+---------+----------+--------+--------+----------------------+--------------|\n",
            "| Current | Desktop | Windows  |   10   |  2040  | Telegram Desktop 6.1 |      ✔       |\n",
            "|---------+---------+----------+--------+--------+----------------------+--------------|",
        )
    );
}

#[test]
fn sessions_table_without_rows_is_the_header() {
    let table = auth::format_sessions(&[]);
    assert_eq!(table.lines().count(), 4);
    assert_eq!(
        table.lines().nth(1),
        Some("|   | Device | Platform | System | API_ID | App name | Official App |")
    );
    assert_eq!(SESSION_COLUMNS[0], " ");
}

/// 1.5.0 `PrettyTable(table, addSplit)` (`src/utils.py`) on each table,
/// captured by running it with `python -c`.
#[test]
fn format_table_matches_1_5_0_pretty_table() {
    assert_eq!(
        auth::format_table(&["a", "bb"], &[["1", "x"], ["long value", ""]], &[]),
        "|------------+----|\n|     a      | bb |\n|------------+----|\n\
         |     1      | x  |\n| long value |    |\n|------------+----|"
    );
    assert_eq!(
        auth::format_table(
            &["Name", "#"],
            &[["ok", "✔"], ["Ünïcødé", "12"], ["", "3"]],
            &[0, 2]
        ),
        "|---------+----|\n|  Name   | #  |\n|---------+----|\n|---------+----|\n\
         |   ok    | ✔  |\n| Ünïcødé | 12 |\n|---------+----|\n|         | 3  |\n\
         |---------+----|"
    );
    assert_eq!(
        auth::format_table(&["Header longer"], &[["x"]], &[1, 5]),
        "|---------------|\n| Header longer |\n|---------------|\n|       x       |\n\
         |---------------|"
    );
    let owned = vec![
        vec!["even".to_owned(), "odd".to_owned()],
        vec!["ab".to_owned(), "abc".to_owned()],
    ];
    assert_eq!(
        auth::format_table(&["x".to_owned(), "y".to_owned()], &owned, &[1, 1]),
        "|------+-----|\n|  x   |  y  |\n|------+-----|\n| even | odd |\n\
         |------+-----|\n|  ab  | abc |\n|------+-----|"
    );
}

#[test]
fn format_table_pads_short_rows_and_drops_extra_cells() {
    let rows: [&[&str]; 2] = [&["only"], &["a", "b", "ignored"]];
    assert_eq!(
        auth::format_table(&["h1", "h2"], &rows, &[]),
        "|------+----|\n|  h1  | h2 |\n|------+----|\n| only |    |\n\
         |  a   | b  |\n|------+----|"
    );
}

#[test]
fn session_admin_messages_are_1_5_0s() {
    assert_eq!(
        auth::FRESH_RESET_FORBIDDEN,
        "You can't logout other sessions if less than 24 hours have passed since you logged on the current session."
    );
    assert_eq!(auth::HASH_INVALID, "The provided hash is invalid.");
    assert_eq!(
        auth::SESSIONS_UNAVAILABLE,
        "Could not fetch the account's sessions"
    );
    assert_eq!(
        auth::NO_PASSWORD_PROVIDED,
        "Two-step verification is enabled for this account.\nYou need to provide the `password` to argument"
    );
}

#[test]
fn official_api_ids_are_the_profiles_ids() {
    let versions = Versions::offline();
    let mut ids = Vec::new();
    for client in Client::ALL {
        let id = api::profile(client, &versions).api_id;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    assert_eq!(ids, OFFICIAL_API_IDS);
    for id in OFFICIAL_API_IDS {
        assert!(auth::is_official_api_id(id));
    }
    assert!(!auth::is_official_api_id(123_456));
    assert!(!auth::is_official_api_id(0));
}

#[test]
fn consistency_expectations_follow_the_profile() {
    let versions = Versions::offline();
    let desktop = ConsistencyExpectations::for_client(Client::Desktop, &versions);
    assert_eq!(desktop.api_id, 2040);
    assert!(desktop.official_api_id);
    assert_eq!(desktop.lang_pack, "tdesktop");
    assert!(!desktop.lang_pack_skipped());
    assert_eq!(desktop.advertised_layer, LAYER);
    assert_eq!(desktop.layer_tolerance, LAYER_TOLERANCE);
    assert_eq!(LAYER_TOLERANCE, 15);
    assert!(desktop.app_version_current());
    assert_eq!(
        desktop.app_version,
        api::profile(Client::Desktop, &versions).app_version
    );

    // 1.5.0 `_check_version_consistency` on the offline profiles flags
    // Telegram X (Android pack, own versions) and Web K (macOS pack).
    let expected = [
        (Client::Android, "android", true),
        (Client::AndroidX, "android", false),
        (Client::Ios, "ios", true),
        (Client::MacOS, "macos", true),
        (Client::WebA, "", true),
        (Client::WebK, "macos", false),
        (Client::Webogram, "", true),
    ];
    for (client, pack, current) in expected {
        let expectations = ConsistencyExpectations::for_client(client, &versions);
        assert_eq!(expectations.lang_pack, pack, "{client:?}");
        assert_eq!(expectations.lang_pack_skipped(), pack.is_empty());
        assert!(expectations.official_api_id, "{client:?}");
        assert_eq!(expectations.app_version_current(), current, "{client:?}");
    }
    assert_eq!(
        ConsistencyExpectations::for_client(Client::WebK, &versions).version_issues[0].message,
        "macOS app_version '2.2 K' major does not match latest known '13.0'"
    );

    let custom = ApiProfile {
        api_id: 123_456,
        app_version: "1.0".to_owned(),
        ..api::profile(Client::Android, &versions)
    };
    let expectations = ConsistencyExpectations::new(&custom, &versions);
    assert!(!expectations.official_api_id);
    assert!(!expectations.app_version_current());
    assert_eq!(
        expectations.version_issues[0].message,
        format!(
            "Android app_version '1.0' major does not match latest known '{}'",
            versions.android_app_version
        )
    );
}

#[test]
fn layer_match_tolerates_fifteen_layers() {
    let expectations = ConsistencyExpectations::for_client(Client::Desktop, &Versions::offline());
    for (layer, passes) in [
        (229, true),
        (230, true),
        (215, true),
        (245, true),
        (214, false),
        (246, false),
    ] {
        assert_eq!(expectations.layer_matches(layer), passes, "layer {layer}");
    }
    assert_eq!(
        expectations.layer_result(229),
        CheckResult {
            name: "layer_match".to_owned(),
            passed: true,
            detail: "Telethon layer=229, advertised schema layer=230, diff=1".to_owned(),
        }
    );
    assert_eq!(
        expectations.layer_result(250).detail,
        "Telethon layer=250, advertised schema layer=230, diff=20"
    );
    assert!(!expectations.layer_result(250).passed);
}

fn result(check: Check, passed: bool, detail: String) -> CheckResult {
    CheckResult {
        name: check.name().to_owned(),
        passed,
        detail,
    }
}

#[test]
fn consistency_report_texts_match_1_5_0() {
    let names: Vec<&str> = Check::ALL.iter().map(|check| check.name()).collect();
    assert_eq!(
        names,
        [
            "get_config",
            "nearest_dc",
            "current_session",
            "layer_match",
            "lang_pack",
            "app_update",
            "terms_of_service"
        ]
    );
    let expectations = ConsistencyExpectations::for_client(Client::Desktop, &Versions::offline());
    let session = row(
        true,
        true,
        2040,
        [
            "Desktop",
            "Windows",
            "Windows 11 x64",
            "Telegram Desktop",
            "6.1.3 x64",
        ],
    );
    let unofficial = SessionRow {
        official_app: false,
        ..session.clone()
    };

    let all_ok = [
        result(Check::GetConfig, true, auth::get_config_detail(Some(2))),
        result(Check::NearestDc, true, auth::nearest_dc_detail("NL", 2, 4)),
        result(
            Check::CurrentSession,
            session.official_app,
            auth::current_session_detail(&session),
        ),
        expectations.layer_result(229),
        result(
            Check::LangPack,
            true,
            auth::lang_pack_detail(&expectations.lang_pack, 3),
        ),
        result(Check::AppUpdate, true, NO_APP_UPDATE.to_owned()),
        result(Check::TermsOfService, true, TERMS_OF_SERVICE_OK.to_owned()),
    ];
    assert_eq!(
        auth::consistency_summary(&all_ok),
        "Consistency: 7/7 checks passed\n  [OK] get_config: Config OK (DC 2)\n  [OK] nearest_dc: country='NL', this_dc=2, nearest_dc=4\n  [OK] current_session: api_id=2040, official=True, device='Desktop', app='Telegram Desktop 6.1.3 x64'\n  [OK] layer_match: Telethon layer=229, advertised schema layer=230, diff=1\n  [OK] lang_pack: lang_pack 'tdesktop' valid (3 languages)\n  [OK] app_update: No update available (app_version accepted)\n  [OK] terms_of_service: ToS check OK"
    );

    let web = [
        result(Check::GetConfig, true, auth::get_config_detail(Some(2))),
        result(Check::NearestDc, true, auth::nearest_dc_detail("NL", 2, 4)),
        result(
            Check::CurrentSession,
            unofficial.official_app,
            auth::current_session_detail(&unofficial),
        ),
        expectations.layer_result(229),
        result(Check::LangPack, true, LANG_PACK_EMPTY.to_owned()),
        result(
            Check::AppUpdate,
            true,
            auth::app_update_detail(Some("6.2.0")),
        ),
        result(Check::TermsOfService, true, TERMS_OF_SERVICE_OK.to_owned()),
    ];
    assert_eq!(
        auth::consistency_summary(&web),
        "Consistency: 6/7 checks passed\n  [OK] get_config: Config OK (DC 2)\n  [OK] nearest_dc: country='NL', this_dc=2, nearest_dc=4\n  [FAIL] current_session: api_id=2040, official=False, device='Desktop', app='Telegram Desktop 6.1.3 x64'\n  [OK] layer_match: Telethon layer=229, advertised schema layer=230, diff=1\n  [OK] lang_pack: lang_pack is empty (web client mode)\n  [OK] app_update: Update available: v6.2.0 (but request succeeded)\n  [OK] terms_of_service: ToS check OK"
    );
}

#[test]
fn failing_consistency_report_texts_match_1_5_0() {
    let expectations = ConsistencyExpectations::for_client(Client::Desktop, &Versions::offline());
    let failing = [
        result(
            Check::GetConfig,
            false,
            auth::get_config_error("boom GetConfigRequest"),
        ),
        result(
            Check::NearestDc,
            false,
            auth::nearest_dc_error("boom GetNearestDcRequest"),
        ),
        result(
            Check::CurrentSession,
            false,
            CURRENT_SESSION_MISSING.to_owned(),
        ),
        expectations.layer_result(229),
        result(
            Check::LangPack,
            false,
            auth::lang_pack_error("android", "LANG_PACK_INVALID"),
        ),
        result(
            Check::AppUpdate,
            false,
            auth::app_update_error("boom GetAppUpdateRequest"),
        ),
        result(
            Check::TermsOfService,
            false,
            auth::check_error("boom GetTermsOfServiceUpdateRequest"),
        ),
    ];
    assert_eq!(
        auth::consistency_summary(&failing),
        "Consistency: 1/7 checks passed\n  [FAIL] get_config: Server rejected getConfig: boom GetConfigRequest\n  [FAIL] nearest_dc: Error calling getNearestDc: boom GetNearestDcRequest\n  [FAIL] current_session: Could not retrieve current session\n  [OK] layer_match: Telethon layer=229, advertised schema layer=230, diff=1\n  [FAIL] lang_pack: lang_pack 'android' rejected: LANG_PACK_INVALID\n  [FAIL] app_update: Error calling getAppUpdate: boom GetAppUpdateRequest\n  [FAIL] terms_of_service: Error: boom GetTermsOfServiceUpdateRequest"
    );

    assert_eq!(auth::check_exception("kaput"), "Exception: kaput");
    assert_eq!(auth::get_config_detail(None), "Config OK (DC None)");
    assert_eq!(
        auth::app_update_detail(None),
        "Update available: v? (but request succeeded)"
    );
    assert_eq!(
        auth::CONSISTENCY_WARNING_PREFIX,
        "opentele2 consistency check issues:\n"
    );
}

// ------------------------------------------------------------ flow rules

#[test]
fn post_login_steps_are_1_5_0s_table() {
    use auth::PostLoginRequest as R;
    let table: Vec<(&str, Option<(u64, u64)>)> = auth::POST_LOGIN_STEPS
        .iter()
        .map(|step| (step.request.tl_name(), step.delay_ms))
        .collect();
    assert_eq!(
        table,
        [
            ("help.getConfig", None),
            ("help.getNearestDc", Some((100, 300))),
            ("account.updateStatus", Some((200, 400))),
            ("langpack.getLanguages", Some((100, 200))),
            ("help.getAppUpdate", Some((300, 500))),
            ("help.getTermsOfServiceUpdate", Some((100, 300))),
            ("help.getCountriesList", Some((50, 150))),
        ]
    );
    assert_eq!(auth::post_login_steps("tdesktop"), auth::POST_LOGIN_STEPS);
    // An empty lang_pack skips getLanguages and its sleep, nothing else.
    let skipped: Vec<R> = auth::post_login_steps("")
        .iter()
        .map(|step| step.request)
        .collect();
    assert_eq!(
        skipped,
        [
            R::GetConfig,
            R::GetNearestDc,
            R::UpdateStatus,
            R::GetAppUpdate,
            R::GetTermsOfServiceUpdate,
            R::GetCountriesList,
        ]
    );
    assert_eq!(auth::POST_LOGIN_APP_UPDATE_SOURCE, "");
    assert_eq!(auth::POST_LOGIN_COUNTRIES_LANG_CODE, "en");
}

#[test]
fn qr_login_constants_and_warnings_are_1_5_0s() {
    assert_eq!(auth::QR_LOGIN_ATTEMPTS, 5);
    assert_eq!(auth::QR_EXPIRE_SAFETY_SECONDS, 5);
    assert_eq!(
        auth::QR_LOGIN_TIMEOUT,
        "Something went wrong, i couldn't perform the QR login"
    );
    assert_eq!(
        auth::qr_attempt_timeout_warning(1, auth::QR_TIMEOUT_ERROR_TYPE),
        "\nQRLoginToNewClient attempt 1 failed because <class 'TimeoutError'>"
    );
    assert_eq!(
        auth::qr_attempt_retry_warning(5),
        "\nQRLoginToNewClient attempt 5 failed. Retrying.."
    );
    assert_eq!(
        auth::EXISTING_SESSION_KEPT,
        "\nCreateNewSession - a session file with the same name is already existed, returning the old session"
    );
    assert_eq!(
        auth::EXISTING_SESSION_REPLACED,
        "\nCreateNewSession - a session file with the same name is already existed, but its api_id is different from the current one, it will be overwritten"
    );
    assert_eq!(
        auth::SRP_ALGORITHM,
        "passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow"
    );
    assert_eq!(
        auth::unsupported_password_algorithm("PasswordKdfAlgoUnknown"),
        "unsupported password algorithm PasswordKdfAlgoUnknown"
    );
}

#[test]
fn session_row_from_authorization_reads_absent_flags_as_false() {
    let raw = auth::RawAuthorization {
        current: None,
        device_model: "Pixel 9",
        platform: "Android",
        system_version: "SDK 35",
        api_id: 6,
        app_name: "Telegram Android",
        app_version: "12.0.1",
        official_app: None,
    };
    assert_eq!(
        SessionRow::from_authorization(&raw),
        row(
            false,
            false,
            6,
            ["Pixel 9", "Android", "SDK 35", "Telegram Android", "12.0.1"]
        )
    );
    let flagged = auth::RawAuthorization {
        current: Some(true),
        official_app: Some(true),
        ..raw
    };
    let mapped = SessionRow::from_authorization(&flagged);
    assert!(mapped.current && mapped.official_app);
}

#[test]
fn check_all_is_the_run_all_order() {
    let names: Vec<&str> = Check::ALL.iter().map(|check| check.name()).collect();
    assert_eq!(
        names,
        [
            "get_config",
            "nearest_dc",
            "current_session",
            "layer_match",
            "lang_pack",
            "app_update",
            "terms_of_service",
        ]
    );
}

#[test]
fn consistency_report_wraps_a_raised_check_like_run_all() {
    use auth::CheckOutcome::{Finished, Raised};
    let failed = |detail: String| Finished {
        passed: false,
        detail,
    };
    // 1.5.0 run_all on a client whose every request raises "boom", with
    // check_lang_pack raising ValueError("bad pack").
    let report = auth::consistency_report([
        failed(auth::get_config_error("boom")),
        failed(auth::nearest_dc_error("boom")),
        failed(CURRENT_SESSION_MISSING.to_owned()),
        Finished {
            passed: true,
            detail: auth::layer_detail(229, 230),
        },
        Raised("bad pack".to_owned()),
        failed(auth::app_update_error("boom")),
        failed(auth::check_error("boom")),
    ]);
    let names: Vec<&str> = report.checks.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, Check::ALL.map(Check::name));
    assert_eq!(
        report.checks[4],
        result(Check::LangPack, false, "Exception: bad pack".to_owned())
    );
    assert!(!report.all_passed());
    assert_eq!(
        report.warning().as_deref(),
        Some(
            "opentele2 consistency check issues:\nConsistency: 1/7 checks passed\n  [FAIL] get_config: Server rejected getConfig: boom\n  [FAIL] nearest_dc: Error calling getNearestDc: boom\n  [FAIL] current_session: Could not retrieve current session\n  [OK] layer_match: Telethon layer=229, advertised schema layer=230, diff=1\n  [FAIL] lang_pack: Exception: bad pack\n  [FAIL] app_update: Error calling getAppUpdate: boom\n  [FAIL] terms_of_service: Error: boom"
        )
    );

    let passing = auth::consistency_report(std::array::from_fn(|_| Finished {
        passed: true,
        detail: "ok".to_owned(),
    }));
    assert!(passing.all_passed());
    assert_eq!(passing.warning(), None);
    assert!(
        passing
            .summary()
            .starts_with("Consistency: 7/7 checks passed\n")
    );
}

/// A source serving `words` as 8-byte little-endian draws, counting them.
fn word_source(
    words: &[u64],
) -> (
    impl FnMut(&mut [u8]) + '_,
    std::rc::Rc<std::cell::Cell<usize>>,
) {
    let count = std::rc::Rc::new(std::cell::Cell::new(0));
    let seen = std::rc::Rc::clone(&count);
    let source = move |buf: &mut [u8]| {
        let word = words[seen.get()];
        seen.set(seen.get() + 1);
        buf.copy_from_slice(&word.to_le_bytes());
    };
    (source, count)
}

#[test]
fn random_delay_redraws_the_biased_tail() {
    // 2^64 mod 201 is 151: words 0..=150 would favour the low values.
    let (mut source, draws) = word_source(&[150, 151]);
    assert_eq!(
        auth::random_delay_ms_with(100, 300, &mut source).unwrap(),
        251
    );
    assert_eq!(draws.get(), 2);

    let (mut source, draws) = word_source(&[u64::MAX]);
    // u64::MAX mod 201 is 150.
    assert_eq!(
        auth::random_delay_ms_with(100, 300, &mut source).unwrap(),
        250
    );
    assert_eq!(draws.get(), 1);

    // A one-value range and the whole u64 range need no redraw.
    let (mut source, _) = word_source(&[12345]);
    assert_eq!(auth::random_delay_ms_with(7, 7, &mut source).unwrap(), 7);
    let (mut source, _) = word_source(&[12345]);
    assert_eq!(
        auth::random_delay_ms_with(0, u64::MAX, &mut source).unwrap(),
        12345
    );
}

#[test]
fn random_delay_refuses_a_reversed_range() {
    let error = auth::random_delay_ms(300, 100).unwrap_err();
    assert_eq!(error.code(), "INVALID_INPUT");
    let mut never = |_: &mut [u8]| panic!("no draw for a reversed range");
    assert!(auth::random_delay_ms_with(2, 1, &mut never).is_err());
}

#[test]
fn random_delay_stays_in_the_inclusive_range() {
    let mut seen = [false; 2];
    for _ in 0..256 {
        let delay = auth::random_delay_ms(50, 51).unwrap();
        assert!((50..=51).contains(&delay));
        seen[usize::try_from(delay - 50).unwrap()] = true;
    }
    // Missing an end in 256 fair draws has a chance of 2^-255.
    assert_eq!(seen, [true, true]);
    for (low, high) in [(100, 300), (0, 0), (u64::MAX - 1, u64::MAX)] {
        assert!((low..=high).contains(&auth::random_delay_ms(low, high).unwrap()));
    }
}
