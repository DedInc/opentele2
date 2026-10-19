//! Tests for `session`: the 1.5.0 DC table, Telethon string sessions against
//! `tests/vectors/sessions.json`, mtcute v3 string sessions against byte
//! layouts written by hand from the TypeScript source, grammers-shaped
//! session data, `from_account` on the vector tdata accounts, and Telethon
//! version 8 session files against `sqlite3` dumps of files 1.5.0 wrote
//! (with the `telethon-sqlite` feature, also written and read back, and a
//! Telethon-written fixture under `tests/fixtures`).
//!
//! Key bytes are never printed: key comparisons use `assert!` without the
//! values.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use opentele2_core::api::{self, Client, Versions};
use opentele2_core::crypto::AuthKey;
use opentele2_core::session::telethon_file::{self, SessionRows};
use opentele2_core::session::{dc, grammers, mtcute, telethon};
use opentele2_core::tdata::TData;
use opentele2_core::tdata::account::Account;
use opentele2_core::tdata::mtp_config::{Environment, MtpConfig};
use opentele2_core::{Error, Result};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn read_json(name: &str) -> Value {
    let text = fs::read_to_string(vectors_dir().join(name)).expect("read vector file");
    serde_json::from_str(&text).expect("parse vector file")
}

fn code_of<T>(result: Result<T>) -> &'static str {
    match result {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(error) => error.code(),
    }
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("socket address literal")
}

/// A key whose byte `i` is `i + offset`, for layout tests.
fn counting_key(offset: u8) -> AuthKey {
    let mut bytes = [0u8; AuthKey::SIZE];
    for (i, byte) in (0u8..=255).zip(bytes.iter_mut()) {
        *byte = i.wrapping_add(offset);
    }
    AuthKey::new(bytes)
}

fn same_key(a: &AuthKey, b: &AuthKey) -> bool {
    a.as_bytes() == b.as_bytes()
}

/// The first TCP endpoint of each production DC in 1.5.0
/// (`src/td/configs.py` `kBuiltInDcs`, `kBuiltInDcsIPv6`), as (IPv4, IPv6).
fn expected_production(dc_id: i32) -> (SocketAddr, SocketAddr) {
    let (v4, v6) = match dc_id {
        1 => ("149.154.175.50:443", "[2001:0b28:f23d:f001::000a]:443"),
        2 => ("149.154.167.51:443", "[2001:067c:04e8:f002::000a]:443"),
        3 => ("149.154.175.100:443", "[2001:0b28:f23d:f003::000a]:443"),
        4 => ("149.154.167.91:443", "[2001:067c:04e8:f004::000a]:443"),
        5 => ("149.154.171.5:443", "[2001:0b28:f23f:f005::000a]:443"),
        other => panic!("no production DC {other}"),
    };
    (addr(v4), addr(v6))
}

// ---------------------------------------------------------------- dc table

#[test]
fn production_table_takes_the_first_endpoint() {
    for dc_id in dc::PRODUCTION_DC_IDS {
        let (v4, v6) = expected_production(dc_id);
        assert_eq!(dc::production(dc_id, false), Some(v4), "DC {dc_id} IPv4");
        assert_eq!(dc::production(dc_id, true), Some(v6), "DC {dc_id} IPv6");
    }
    // DC 2 is listed twice; the first entry wins over 95.161.76.100.
    assert_eq!(dc::PRODUCTION_IPV4[2].1, addr("95.161.76.100:443"));
    assert_eq!(dc::production(2, false), Some(addr("149.154.167.51:443")));
    for missing in [0, 6, -1, 10_002] {
        assert_eq!(dc::production(missing, false), None, "DC {missing}");
        assert_eq!(dc::production(missing, true), None, "DC {missing}");
    }
}

#[test]
fn test_table_matches_1_5_0() {
    assert_eq!(dc::test(1, false), Some(addr("149.154.175.10:443")));
    assert_eq!(dc::test(2, false), Some(addr("149.154.167.40:443")));
    assert_eq!(dc::test(3, false), Some(addr("149.154.175.117:443")));
    assert_eq!(dc::test(1, true), Some(addr("[2001:b28:f23d:f001::e]:443")));
    assert_eq!(dc::test(2, true), Some(addr("[2001:67c:4e8:f002::e]:443")));
    assert_eq!(dc::test(3, true), Some(addr("[2001:b28:f23d:f003::e]:443")));
    assert_eq!(dc::test(4, false), None);
    assert_eq!(dc::test(4, true), None);
}

// ---------------------------------------------------------------- telethon

#[test]
fn telethon_vectors_decode_and_reencode_exactly() {
    let vectors = read_json("sessions.json");
    let cases = vectors["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 7, "4 IPv4 + 3 IPv6 cases");
    for (n, case) in cases.iter().enumerate() {
        let string = case["string_session"].as_str().expect("string_session");
        let ip: std::net::IpAddr = case["ip"].as_str().expect("ip").parse().expect("ip");
        let port = u16::try_from(case["port"].as_u64().expect("port")).expect("port fits");
        let dc_id = u8::try_from(case["dc_id"].as_u64().expect("dc_id")).expect("dc fits");
        let key_hex = case["auth_key"].as_str().expect("auth_key");
        let version = case["ip_version"].as_u64().expect("ip_version");

        let session = telethon::StringSession::decode(string).expect("decode vector");
        assert_eq!(session.dc_id, dc_id, "case {n} dc");
        assert_eq!(session.addr, SocketAddr::new(ip, port), "case {n} address");
        assert_eq!(session.addr.is_ipv6(), version == 6, "case {n} family");
        assert!(
            hex::encode(session.auth_key.as_bytes()) == key_hex,
            "case {n} auth key differs"
        );
        assert_eq!(session.encode(), string, "case {n} re-encode");

        // Decoding accepts the body without base64 padding.
        let unpadded = string.trim_end_matches('=');
        assert_ne!(unpadded, string, "case {n} vector is padded");
        let again = telethon::StringSession::decode(unpadded).expect("decode unpadded");
        assert_eq!(again.encode(), string, "case {n} unpadded re-encode");

        // Encoding from the fields alone gives the vector.
        let built = telethon::StringSession {
            dc_id,
            addr: SocketAddr::new(ip, port),
            auth_key: AuthKey::from_slice(&hex::decode(key_hex).expect("hex")).expect("key"),
        };
        assert_eq!(built.encode(), string, "case {n} encode from fields");
    }
}

#[test]
fn telethon_layout_is_big_endian_struct() {
    let session = telethon::StringSession {
        dc_id: 4,
        addr: addr("10.20.30.40:5222"),
        auth_key: counting_key(7),
    };
    let encoded = session.encode();
    assert!(encoded.starts_with('1'));
    let body = URL_SAFE.decode(&encoded[1..]).expect("padded urlsafe body");
    let mut expected = vec![4, 10, 20, 30, 40, 0x14, 0x66];
    expected.extend_from_slice(counting_key(7).as_bytes());
    assert!(body == expected, "Telethon struct layout differs");
}

#[test]
fn telethon_malformed_inputs_are_errors() {
    let good = telethon::StringSession {
        dc_id: 2,
        addr: addr("192.0.2.1:443"),
        auth_key: counting_key(0),
    }
    .encode();
    assert_eq!(
        code_of(telethon::StringSession::decode("")),
        "QDATASTREAM_FAILED"
    );
    let wrong_version = format!("2{}", &good[1..]);
    assert_eq!(
        code_of(telethon::StringSession::decode(&wrong_version)),
        "QDATASTREAM_FAILED"
    );
    let not_base64 = format!("1{}", "!".repeat(352));
    assert_eq!(
        code_of(telethon::StringSession::decode(&not_base64)),
        "QDATASTREAM_FAILED"
    );
    // Standard (non-urlsafe) alphabet is rejected.
    let standard = good.replace('-', "+").replace('_', "/");
    if standard != good {
        assert_eq!(
            code_of(telethon::StringSession::decode(&standard)),
            "QDATASTREAM_FAILED"
        );
    }
    let short = format!("1{}", URL_SAFE.encode([0u8; telethon::IPV4_LEN - 1]));
    match telethon::StringSession::decode(&short) {
        Err(Error::BadLength {
            expected, actual, ..
        }) => {
            assert_eq!(expected, telethon::IPV4_LEN);
            assert_eq!(actual, telethon::IPV4_LEN - 1);
        }
        other => panic!("expected BadLength, got {:?}", other.map(|_| ())),
    }
    let between = format!("1{}", URL_SAFE.encode([0u8; telethon::IPV4_LEN + 4]));
    assert_eq!(
        code_of(telethon::StringSession::decode(&between)),
        "BAD_LENGTH"
    );
    let long = format!("1{}", URL_SAFE.encode([0u8; telethon::IPV6_LEN + 1]));
    assert_eq!(
        code_of(telethon::StringSession::decode(&long)),
        "BAD_LENGTH"
    );
    assert_eq!(code_of(telethon::StringSession::decode("1")), "BAD_LENGTH");
}

// ---------------------------------------------------------------- mtcute

/// TL `bytes` exactly as `TlBinaryWriter.bytes` in
/// `refs/mtcute-master/packages/tl-runtime/src/writer.ts`:
/// - `n <= 253`: one length byte `n`, the data, then zero padding so that
///   `1 + n + padding` is a multiple of 4;
/// - `n > 253`: the byte 254, `n` as 3 little-endian bytes, the data, then
///   zero padding so that `n + padding` is a multiple of 4 (the 4 header
///   bytes are already aligned).
///
/// Padding is relative to the start of the TL value, not of the buffer.
fn tl_bytes(data: &[u8]) -> Vec<u8> {
    let n = data.len();
    let mut out = Vec::new();
    let used = if n <= 253 {
        out.push(u8::try_from(n).expect("short length"));
        n + 1
    } else {
        out.push(254);
        out.extend_from_slice(&u32::try_from(n).expect("length").to_le_bytes()[..3]);
        n
    };
    out.extend_from_slice(data);
    out.resize(out.len() + (4 - used % 4) % 4, 0);
    out
}

/// `serializeBasicDcOption` (`packages/core/src/utils/dcs.ts`): raw bytes
/// `[2, id, flags]` (ipv6 = 1, mediaOnly = 2, testMode = 4), TL string IP,
/// TL `int` port (4 bytes little-endian).
fn dc_blob(id: u8, flags: u8, ip: &str, port: i32) -> Vec<u8> {
    let mut out = vec![2, id, flags];
    out.extend_from_slice(&tl_bytes(ip.as_bytes()));
    out.extend_from_slice(&port.to_le_bytes());
    out
}

fn snapshot_dcs() -> (mtcute::DcOption, mtcute::DcOption) {
    let main = mtcute::DcOption {
        id: 2,
        ip: "149.154.167.50".to_owned(),
        port: 443,
        ipv6: false,
        media_only: false,
    };
    let media = mtcute::DcOption {
        id: 2,
        ip: "149.154.167.222".to_owned(),
        port: 443,
        ipv6: false,
        media_only: true,
    };
    (main, media)
}

#[test]
fn mtcute_layout_with_media_and_self_matches_hand_built_bytes() {
    let (main, media) = snapshot_dcs();
    let session = mtcute::StringSession {
        primary_dc: main,
        media_dc: Some(media),
        self_user: Some((12345, false)),
        test_mode: false,
        auth_key: counting_key(3),
    };

    // "149.154.167.50" is 14 bytes: 1 + 14 = 15, so 1 padding byte.
    let main_blob = dc_blob(2, 0, "149.154.167.50", 443);
    let mut by_hand = vec![2, 2, 0, 14];
    by_hand.extend_from_slice(b"149.154.167.50");
    by_hand.extend_from_slice(&[0, 0xBB, 0x01, 0, 0]);
    assert_eq!(
        main_blob, by_hand,
        "helper agrees with the spelled-out blob"
    );
    assert_eq!(main_blob.len(), 23);
    // "149.154.167.222" is 15 bytes: 1 + 15 = 16, no padding.
    let media_blob = dc_blob(2, 2, "149.154.167.222", 443);
    assert_eq!(media_blob.len(), 23);

    let mut expected = vec![3]; // version
    expected.extend_from_slice(&5i32.to_le_bytes()); // flags: self (1) | media (4)
    expected.extend_from_slice(&tl_bytes(&main_blob)); // 1 + 23 = 24, no padding
    expected.extend_from_slice(&tl_bytes(&media_blob));
    expected.extend_from_slice(&12345i64.to_le_bytes()); // int53 user id
    expected.extend_from_slice(&0xBC79_9737u32.to_le_bytes()); // boolFalse
    // 256-byte key: long form 254 00 01 00, 256 % 4 == 0 so no padding.
    expected.extend_from_slice(&[254, 0, 1, 0]);
    expected.extend_from_slice(counting_key(3).as_bytes());
    assert_eq!(expected.len(), 1 + 4 + 24 + 24 + 8 + 4 + 4 + 256);

    let encoded = session.encode();
    assert!(!encoded.contains('='), "mtcute writes unpadded base64url");
    let decoded_bytes = URL_SAFE_NO_PAD.decode(&encoded).expect("base64url");
    assert!(decoded_bytes == expected, "mtcute byte layout differs");
}

#[test]
fn mtcute_ipv6_test_mode_layout_matches_hand_built_bytes() {
    let session = mtcute::StringSession {
        primary_dc: mtcute::DcOption::new(2, addr("[2001:67c:4e8:f002::e]:443")),
        media_dc: None,
        self_user: None,
        test_mode: true,
        auth_key: counting_key(9),
    };
    assert_eq!(session.primary_dc.ip, "2001:67c:4e8:f002::e");
    // 20-byte IP: 1 + 20 = 21, so 3 padding bytes; flags ipv6 | testMode.
    let mut blob = vec![2, 2, 1 | 4, 20];
    blob.extend_from_slice(b"2001:67c:4e8:f002::e");
    blob.extend_from_slice(&[0, 0, 0]);
    blob.extend_from_slice(&443i32.to_le_bytes());
    assert_eq!(blob, dc_blob(2, 5, "2001:67c:4e8:f002::e", 443));
    assert_eq!(blob.len(), 31);

    let mut expected = vec![3, 0, 0, 0, 0];
    expected.push(31); // 1 + 31 = 32, no padding
    expected.extend_from_slice(&blob);
    expected.extend_from_slice(&[254, 0, 1, 0]);
    expected.extend_from_slice(counting_key(9).as_bytes());

    let decoded_bytes = URL_SAFE_NO_PAD.decode(session.encode()).expect("base64url");
    assert!(decoded_bytes == expected, "mtcute IPv6 layout differs");
}

#[test]
fn mtcute_matches_the_reference_snapshots_up_to_the_key() {
    // Inline snapshots of `writeStringSession` in
    // packages/core/src/highlevel/utils/string-session.test.ts; they use a
    // 32-byte zero key, so only the bytes before the key TL value compare.
    let (main, media) = snapshot_dcs();
    let cases = [
        (
            Some(media.clone()),
            None,
            false,
            "AwQAAAAXAgIADjE0OS4xNTQuMTY3LjUwALsBAAAXAgICDzE0OS4xNTQuMTY3LjIyMrsBAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            None,
            None,
            false,
            "AwAAAAAXAgIADjE0OS4xNTQuMTY3LjUwALsBAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            Some(media.clone()),
            Some((12345, false)),
            false,
            "AwUAAAAXAgIADjE0OS4xNTQuMTY3LjUwALsBAAAXAgICDzE0OS4xNTQuMTY3LjIyMrsBAAA5MAAAAAAAADeXebwgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            Some(media),
            Some((12345, false)),
            true,
            "AwUAAAAXAgIEDjE0OS4xNTQuMTY3LjUwALsBAAAXAgIGDzE0OS4xNTQuMTY3LjIyMrsBAAA5MAAAAAAAADeXebwgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    ];
    for (n, (media_dc, self_user, test_mode, snapshot)) in cases.into_iter().enumerate() {
        let reference = URL_SAFE_NO_PAD
            .decode(snapshot)
            .expect("snapshot base64url");
        // Reference tail: TL bytes of 32 zero bytes, 1 + 32 = 33, 3 padding.
        let reference_key_len = 1 + 32 + 3;
        let prefix = &reference[..reference.len() - reference_key_len];
        assert_eq!(reference[prefix.len()], 32, "snapshot {n} key length byte");

        let ours = mtcute::StringSession {
            primary_dc: main.clone(),
            media_dc,
            self_user,
            test_mode,
            auth_key: AuthKey::new([0; AuthKey::SIZE]),
        };
        let bytes = URL_SAFE_NO_PAD.decode(ours.encode()).expect("base64url");
        assert_eq!(&bytes[..prefix.len()], prefix, "snapshot {n} prefix");
        assert_eq!(bytes.len(), prefix.len() + 4 + 256, "snapshot {n} key tail");
        // The reference session itself has a 32-byte key, which the core
        // rejects as a bad length.
        assert_eq!(
            code_of(mtcute::StringSession::decode(snapshot)),
            "BAD_LENGTH"
        );
    }
}

#[test]
fn mtcute_round_trips() {
    let (main, media) = snapshot_dcs();
    let sessions = [
        mtcute::StringSession {
            primary_dc: main.clone(),
            media_dc: Some(media),
            self_user: Some((6_000_000_456, true)),
            test_mode: false,
            auth_key: counting_key(1),
        },
        mtcute::StringSession {
            primary_dc: mtcute::DcOption::new(1, addr("[2001:b28:f23d:f001::e]:80")),
            media_dc: None,
            self_user: Some((mtcute::MAX_USER_ID, false)),
            test_mode: true,
            auth_key: counting_key(2),
        },
        mtcute::StringSession {
            primary_dc: mtcute::DcOption {
                ip: "2001:0b28:f23d:f001:0000:0000:0000:000a".to_owned(),
                ipv6: true,
                ..main
            },
            media_dc: None,
            self_user: None,
            test_mode: false,
            auth_key: counting_key(4),
        },
    ];
    for (n, session) in sessions.iter().enumerate() {
        let encoded = session.encode();
        let decoded = mtcute::StringSession::decode(&encoded).expect("decode");
        assert_eq!(
            decoded.primary_dc, session.primary_dc,
            "session {n} primary"
        );
        assert_eq!(decoded.media_dc, session.media_dc, "session {n} media");
        assert_eq!(decoded.self_user, session.self_user, "session {n} self");
        assert_eq!(
            decoded.test_mode, session.test_mode,
            "session {n} test mode"
        );
        assert!(
            same_key(&decoded.auth_key, &session.auth_key),
            "session {n} key"
        );
        assert_eq!(decoded.encode(), encoded, "session {n} re-encode");

        // Padded base64url decodes too.
        let padded = format!("{encoded}{}", "=".repeat((4 - encoded.len() % 4) % 4));
        let again = mtcute::StringSession::decode(&padded).expect("decode padded");
        assert_eq!(again.encode(), encoded, "session {n} padded re-encode");
    }
}

#[test]
fn mtcute_legacy_inputs_decode() {
    // Version-1 DC option and the legacy session test flag (2), as in the
    // reference `readStringSession` tests, with a 256-byte key.
    let mut v1_blob = vec![1, 2, 0];
    v1_blob.extend_from_slice(&tl_bytes(b"149.154.167.50"));
    v1_blob.extend_from_slice(&443i32.to_le_bytes());
    let mut raw = vec![3];
    raw.extend_from_slice(&2i32.to_le_bytes());
    raw.extend_from_slice(&tl_bytes(&v1_blob));
    raw.extend_from_slice(&tl_bytes(counting_key(5).as_bytes()));
    let session = mtcute::StringSession::decode(&URL_SAFE_NO_PAD.encode(&raw)).expect("decode");
    assert!(session.test_mode);
    assert_eq!(session.primary_dc.ip, "149.154.167.50");
    assert!(session.media_dc.is_none() && session.self_user.is_none());
    // Re-encoded as version 2 with the test flag on the DC option.
    let bytes = URL_SAFE_NO_PAD.decode(session.encode()).expect("base64url");
    assert_eq!(&bytes[..5], &[3, 0, 0, 0, 0]);
    assert_eq!(&bytes[6..9], &[2, 2, 4]);
}

/// A valid session with a user and no media DC, as raw bytes.
fn mtcute_raw() -> Vec<u8> {
    let (main, _) = snapshot_dcs();
    let session = mtcute::StringSession {
        primary_dc: main,
        media_dc: None,
        self_user: Some((12345, false)),
        test_mode: false,
        auth_key: counting_key(6),
    };
    URL_SAFE_NO_PAD.decode(session.encode()).expect("base64url")
}

#[test]
fn mtcute_malformed_inputs_are_errors() {
    let decode = |raw: &[u8]| mtcute::StringSession::decode(&URL_SAFE_NO_PAD.encode(raw));
    let raw = mtcute_raw();
    // Layout: 0 version, 1..5 flags, 5 blob length (23), 6..29 blob,
    // 29..37 user id, 37..41 bool, 41.. key.
    assert!(decode(&raw).is_ok());

    assert_eq!(
        code_of(mtcute::StringSession::decode("")),
        "QDATASTREAM_FAILED"
    );
    assert_eq!(
        code_of(mtcute::StringSession::decode("A*")),
        "QDATASTREAM_FAILED"
    );
    let standard = URL_SAFE.encode(&raw).replace('-', "+").replace('_', "/");
    if standard.contains(['+', '/']) {
        assert_eq!(
            code_of(mtcute::StringSession::decode(&standard)),
            "QDATASTREAM_FAILED"
        );
    }

    let mutate = |at: usize, value: u8| {
        let mut copy = raw.clone();
        copy[at] = value;
        code_of(decode(&copy))
    };
    assert_eq!(mutate(0, 2), "QDATASTREAM_FAILED", "version 2");
    assert_eq!(
        mutate(1, 1 | 8),
        "QDATASTREAM_FAILED",
        "unknown session flag"
    );
    assert_eq!(
        mutate(1, 1 | 4),
        "QDATASTREAM_FAILED",
        "media flag without media"
    );
    assert_eq!(mutate(5, 255), "QDATASTREAM_FAILED", "length byte 255");
    assert_eq!(mutate(6, 3), "QDATASTREAM_FAILED", "DC option version 3");
    assert_eq!(mutate(8, 8), "QDATASTREAM_FAILED", "unknown DC flag");
    assert_eq!(mutate(24, 1), "QDATASTREAM_FAILED", "non-zero TL padding");
    assert_eq!(mutate(10, 0xFF), "QDATASTREAM_FAILED", "IP not UTF-8");
    assert_eq!(mutate(27, 1), "QDATASTREAM_FAILED", "port above u16");
    assert_eq!(mutate(36, 0x80), "QDATASTREAM_FAILED", "negative user id");
    assert_eq!(
        mutate(35, 0x20),
        "QDATASTREAM_FAILED",
        "user id above 2^53 - 1"
    );
    assert_eq!(mutate(37, 0), "QDATASTREAM_FAILED", "bad Bool");
    assert_eq!(
        mutate(42, 2),
        "QDATASTREAM_FAILED",
        "key length past the end"
    );

    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(
        code_of(decode(&trailing)),
        "QDATASTREAM_FAILED",
        "trailing byte"
    );
    for cut in [1, 5, 20, 40, raw.len() - 1] {
        assert_eq!(
            code_of(decode(&raw[..cut])),
            "QDATASTREAM_FAILED",
            "cut at {cut}"
        );
    }

    // Long-form length for a short value.
    let mut long_form = raw[..5].to_vec();
    long_form.extend_from_slice(&[254, 23, 0, 0]);
    long_form.extend_from_slice(&raw[6..29]);
    long_form.extend_from_slice(&raw[29..]);
    assert_eq!(
        code_of(decode(&long_form)),
        "QDATASTREAM_FAILED",
        "long form"
    );

    // Primary and media DC disagreeing on test mode.
    let mut mixed = vec![3];
    mixed.extend_from_slice(&4i32.to_le_bytes());
    mixed.extend_from_slice(&tl_bytes(&dc_blob(2, 0, "149.154.167.50", 443)));
    mixed.extend_from_slice(&tl_bytes(&dc_blob(2, 2 | 4, "149.154.167.222", 443)));
    mixed.extend_from_slice(&tl_bytes(counting_key(0).as_bytes()));
    assert_eq!(
        code_of(decode(&mixed)),
        "QDATASTREAM_FAILED",
        "mixed test mode"
    );

    // A key of the wrong size.
    let mut short_key = raw[..41].to_vec();
    short_key.extend_from_slice(&tl_bytes(&[0; 32]));
    match decode(&short_key) {
        Err(Error::BadLength {
            expected, actual, ..
        }) => {
            assert_eq!((expected, actual), (AuthKey::SIZE, 32));
        }
        other => panic!("expected BadLength, got {:?}", other.map(|_| ())),
    }
}

// ---------------------------------------------------------------- accounts

/// Every account of a vector folder with its manifest entry.
fn vector_accounts(folder: &str) -> Vec<(Account, Value)> {
    let manifest = read_json("tdata.json");
    let entry = &manifest["folders"][folder];
    let passcode = entry["passcode"].as_str().expect("passcode").as_bytes();
    let key_file = entry["key_file"].as_str().expect("key_file");
    let tdata = TData::load(vectors_dir().join(folder), passcode, Some(key_file)).expect("load");
    let wanted = entry["accounts"].as_array().expect("accounts");
    assert_eq!(tdata.accounts.len(), wanted.len(), "{folder} account count");
    tdata
        .accounts
        .into_iter()
        .map(|account| {
            let want = wanted
                .iter()
                .find(|w| w["index"].as_i64() == Some(i64::from(account.index)))
                .expect("manifest entry")
                .clone();
            (account, want)
        })
        .collect()
}

fn check_account(folder: &str, account: &Account, want: &Value) {
    let main_dc = i32::try_from(want["main_dc"].as_i64().expect("main_dc")).expect("dc");
    let user_id = want["user_id"].as_u64().expect("user_id");
    let key_hex = want["auth_key"].as_str().expect("auth_key");
    assert_eq!(account.main_dc, main_dc, "{folder} main dc");
    let (v4, v6) = expected_production(main_dc);

    for (ipv6, expected) in [(false, v4), (true, v6)] {
        let session = telethon::StringSession::from_account(account, ipv6).expect("telethon");
        assert_eq!(i32::from(session.dc_id), main_dc, "{folder} telethon dc");
        assert_eq!(session.addr, expected, "{folder} telethon address");
        assert!(
            hex::encode(session.auth_key.as_bytes()) == key_hex,
            "{folder} telethon key differs"
        );
        let encoded = session.encode();
        let decoded = telethon::StringSession::decode(&encoded).expect("decode");
        assert_eq!(decoded.addr, expected, "{folder} telethon decoded address");
        assert_eq!(decoded.encode(), encoded, "{folder} telethon re-encode");

        let session = mtcute::StringSession::from_account(account, ipv6).expect("mtcute");
        assert_eq!(
            i32::from(session.primary_dc.id),
            main_dc,
            "{folder} mtcute dc"
        );
        assert_eq!(session.primary_dc.ip, expected.ip().to_string());
        assert_eq!(session.primary_dc.port, 443);
        assert_eq!(session.primary_dc.ipv6, ipv6);
        assert!(!session.primary_dc.media_only && !session.test_mode);
        assert!(session.media_dc.is_none());
        assert_eq!(
            session.self_user,
            Some((user_id, false)),
            "{folder} mtcute self"
        );
        assert!(
            hex::encode(session.auth_key.as_bytes()) == key_hex,
            "{folder} mtcute key differs"
        );
        let encoded = session.encode();
        let decoded = mtcute::StringSession::decode(&encoded).expect("decode");
        assert_eq!(decoded.primary_dc, session.primary_dc);
        assert_eq!(decoded.self_user, session.self_user);
        assert_eq!(decoded.encode(), encoded, "{folder} mtcute re-encode");
    }

    let data = grammers::SessionData::from_account(account).expect("grammers");
    assert_eq!(data.home_dc, main_dc, "{folder} home dc");
    let mut ids: Vec<i32> = data.dc_options.keys().copied().collect();
    ids.sort_unstable();
    assert_eq!(ids, dc::PRODUCTION_DC_IDS, "{folder} dc ids");
    for (id, option) in &data.dc_options {
        let (v4, v6) = expected_production(*id);
        assert_eq!(option.id, *id);
        assert_eq!(SocketAddr::V4(option.ipv4), v4, "{folder} DC {id} IPv4");
        assert_eq!(SocketAddr::V6(option.ipv6), v6, "{folder} DC {id} IPv6");
        match &option.auth_key {
            Some(key) => {
                assert_eq!(*id, main_dc, "{folder} only the main DC has a key");
                assert!(
                    hex::encode(key.as_bytes()) == key_hex,
                    "{folder} grammers key"
                );
            }
            None => assert_ne!(*id, main_dc, "{folder} main DC lacks its key"),
        }
    }
}

#[test]
fn from_account_on_plain_vector_accounts() {
    for folder in ["tdata_plain/performance_on", "tdata_plain/performance_off"] {
        let accounts = vector_accounts(folder);
        let dcs: Vec<i32> = accounts.iter().map(|(a, _)| a.main_dc).collect();
        assert_eq!(dcs, [2, 4], "{folder} main DCs");
        for (account, want) in &accounts {
            check_account(folder, account, want);
        }
        let main = &accounts[0].0;
        let session = telethon::StringSession::from_account(main, false).expect("telethon");
        assert_eq!(session.addr, addr("149.154.167.51:443"));
    }
}

#[test]
fn from_account_on_passcode_vector_accounts() {
    // One Argon2id folder only; debug builds derive it slowly.
    let folder = "tdata_passcode/performance_on";
    let accounts = vector_accounts(folder);
    let dcs: Vec<i32> = accounts.iter().map(|(a, _)| a.main_dc).collect();
    assert_eq!(dcs, [1, 5], "{folder} main DCs");
    for (account, want) in &accounts {
        check_account(folder, account, want);
    }
}

#[test]
fn from_account_errors() {
    let unknown_dc = Account::new(0, 1, 7, vec![(7, counting_key(0))]).expect("account");
    assert_eq!(
        code_of(telethon::StringSession::from_account(&unknown_dc, false)),
        "TDATA_BAD_CONFIG_DATA"
    );
    assert_eq!(
        code_of(mtcute::StringSession::from_account(&unknown_dc, true)),
        "TDATA_BAD_CONFIG_DATA"
    );
    assert_eq!(
        code_of(grammers::SessionData::from_account(&unknown_dc)),
        "TDATA_BAD_CONFIG_DATA"
    );

    let mut keyless = Account::new(0, 1, 2, vec![(2, counting_key(0))]).expect("account");
    keyless.keys[0].0 = 4;
    assert_eq!(
        code_of(telethon::StringSession::from_account(&keyless, false)),
        "TDATA_AUTH_KEY_NOT_FOUND"
    );
    assert_eq!(
        code_of(mtcute::StringSession::from_account(&keyless, false)),
        "TDATA_AUTH_KEY_NOT_FOUND"
    );
    assert_eq!(
        code_of(grammers::SessionData::from_account(&keyless)),
        "TDATA_AUTH_KEY_NOT_FOUND"
    );
}

/// 1.5.0's `Serialize()` of a production config whose DC options were
/// cleared and rebuilt (the `CUSTOM_CONFIG` of `tests/tdata_read.rs`): DC 2
/// has IPv4 TCP `203.0.113.2:443` first and IPv6 TCP `2001:db8::2` first,
/// DC 1 `198.51.100.1` and `2001:db8::1`, DC 3 only IPv4 `198.51.100.3`.
const CUSTOM_CONFIG: &str = "000000010000000000000149fffffffe000000080000000200000005000001bb0000000b323030313a6462383a3a32000000000000000200000000000001bb0000000b3230332e302e3131332e32000000000000000200000400000020fb0000000b3230332e302e3131332e33000000100102030405060708090a0b0c0d0e0f100000000200000002000000500000000b3230332e302e3131332e34000000000000000200000011000001bb0000000c323030313a6462383a3a3232000000000000000100000010000001bb0000000c3139382e35312e3130302e31000000000000000100000401000001bb0000000b323030313a6462383a3a3100000020abababababababababababababababababababababababababababababababab0000000300000008000001bb0000000c3139382e35312e3130302e330000000000000001000000cb00000003010203000000030100010000014100002710000000640001d4c00000138800007530000003e8000493e000007530000005dc000000c80002a3000002a3000002a300000000010000001e0000000500000005000000640000001a00680074007400700073003a002f002f0074002e006d0065002f00093a8000004e2000015f90000075300000271000000004000000000000000100000000000004000000000227648000000000000005fffffff90000000800670069006600730000000c00760065006e007500650073";

fn account_with_config(main_dc: i32, config: Option<Vec<u8>>) -> Account {
    let mut account =
        Account::new(0, 77, main_dc, vec![(main_dc, counting_key(9))]).expect("account");
    account.config = config;
    account
}

#[test]
fn from_account_prefers_the_stored_config() {
    let config = hex::decode(CUSTOM_CONFIG).expect("hex");
    let account = account_with_config(2, Some(config.clone()));
    // Endpoints chosen by 1.5.0 (`endpoints(MainDcId)`, then
    // `_select_endpoint_address`, then the first TCP endpoint).
    for (ipv6, expected) in [
        (false, addr("203.0.113.2:443")),
        (true, addr("[2001:db8::2]:443")),
    ] {
        assert_ne!(
            dc::production(2, ipv6),
            Some(expected),
            "differs from table"
        );
        let session = telethon::StringSession::from_account(&account, ipv6).expect("telethon");
        assert_eq!((session.dc_id, session.addr), (2, expected), "telethon");
        assert!(same_key(&session.auth_key, &counting_key(9)));
        let session = mtcute::StringSession::from_account(&account, ipv6).expect("mtcute");
        assert_eq!(session.primary_dc, mtcute::DcOption::new(2, expected));
        assert!(!session.test_mode);
    }

    let data = grammers::SessionData::from_account(&account).expect("grammers");
    let mut ids: Vec<i32> = data.dc_options.keys().copied().collect();
    ids.sort_unstable();
    assert_eq!(ids, [1, 2], "DC 3 has no IPv6 endpoint");
    let home = &data.dc_options[&2];
    assert_eq!(SocketAddr::V4(home.ipv4), addr("203.0.113.2:443"));
    assert_eq!(SocketAddr::V6(home.ipv6), addr("[2001:db8::2]:443"));
    assert!(home.auth_key.is_some() && data.dc_options[&1].auth_key.is_none());

    // DC 3 falls back to its IPv4 endpoint when IPv6 is asked for.
    let dc3 = account_with_config(3, Some(config.clone()));
    let session = telethon::StringSession::from_account(&dc3, true).expect("DC 3");
    assert_eq!(session.addr, addr("198.51.100.3:443"));
    assert_eq!(
        code_of(grammers::SessionData::from_account(&dc3)),
        "TDATA_BAD_CONFIG_DATA"
    );
    // DC 5 is in the built-in table but not in the stored config.
    let dc5 = account_with_config(5, Some(config));
    assert_eq!(
        code_of(telethon::StringSession::from_account(&dc5, false)),
        "TDATA_BAD_CONFIG_DATA"
    );
    assert_eq!(
        code_of(mtcute::StringSession::from_account(&dc5, false)),
        "TDATA_BAD_CONFIG_DATA"
    );

    // No config bytes, or bytes that do not parse: the production endpoints.
    for config in [None, Some(vec![0, 0, 0, 1])] {
        let account = account_with_config(2, config);
        let session = telethon::StringSession::from_account(&account, false).expect("table");
        assert_eq!(session.addr, addr("149.154.167.51:443"));
    }
}

#[test]
fn from_account_with_a_stored_test_config() {
    let test = MtpConfig::new(Environment::Test)
        .serialize()
        .expect("serialize");
    let account = account_with_config(2, Some(test));
    let session = telethon::StringSession::from_account(&account, false).expect("telethon");
    assert_eq!(session.addr, addr("149.154.167.40:443"));
    let session = mtcute::StringSession::from_account(&account, true).expect("mtcute");
    assert_eq!(session.primary_dc.ip, "2001:67c:4e8:f002::e");
    assert!(session.test_mode);
    let decoded = mtcute::StringSession::decode(&session.encode()).expect("decode");
    assert!(decoded.test_mode);
}

#[test]
fn debug_output_never_shows_key_bytes() {
    let key = counting_key(0x41);
    let session = telethon::StringSession {
        dc_id: 2,
        addr: addr("149.154.167.51:443"),
        auth_key: key.clone(),
    };
    let text = format!("{session:?}");
    let hex_key = hex::encode(key.as_bytes());
    assert!(!text.contains(&hex_key[..16]), "Debug leaks key bytes");
    assert!(!text.contains("65, 66, 67"), "Debug leaks key bytes");
}

// ---------------------------------------------------------------- telethon file

/// Python `sqlite3` `iterdump()` of the file 1.5.0 writes with
/// `write_session_file(base, 2, "149.154.167.51", 443, bytes(range(256)))`
/// into an empty directory (`OPENTELE_NO_FETCH=1`, SQLite 3.45.3). The key
/// blob, `counting_key(0)`, is masked as `<KEY>`.
const V150_DUMP: [&str; 10] = [
    "BEGIN TRANSACTION;",
    "CREATE TABLE entities (id integer primary key, hash integer not null, username text, phone integer, name text, date integer);",
    "CREATE TABLE sent_files (md5_digest blob, file_size integer, type integer, id integer, hash integer, primary key(md5_digest, file_size, type));",
    "CREATE TABLE sessions (dc_id integer primary key, server_address text, port integer, auth_key blob, takeout_id integer, tmp_auth_key blob);",
    "INSERT INTO \"sessions\" VALUES(2,'149.154.167.51',443,X'<KEY>',NULL,NULL);",
    "CREATE TABLE update_state (id integer primary key, pts integer, qts integer, date integer, seq integer);",
    "CREATE TABLE version (version integer primary key);",
    "INSERT INTO \"version\" VALUES(8);",
    "COMMIT;",
    "",
];

/// The dump lines without the trailing empty entry kept for formatting.
fn v150_dump() -> Vec<String> {
    V150_DUMP
        .iter()
        .filter(|line| !line.is_empty())
        .map(|line| (*line).to_owned())
        .collect()
}

/// The text 1.5.0's built-in table gives each production DC
/// (`src/td/configs.py`), as (IPv4, IPv6).
fn table_text_1_5_0(dc_id: i32) -> (&'static str, &'static str) {
    match dc_id {
        1 => ("149.154.175.50", "2001:0b28:f23d:f001:0000:0000:0000:000a"),
        2 => ("149.154.167.51", "2001:067c:04e8:f002:0000:0000:0000:000a"),
        3 => ("149.154.175.100", "2001:0b28:f23d:f003:0000:0000:0000:000a"),
        4 => ("149.154.167.91", "2001:067c:04e8:f004:0000:0000:0000:000a"),
        5 => ("149.154.171.5", "2001:0b28:f23f:f005:0000:0000:0000:000a"),
        other => panic!("no production DC {other}"),
    }
}

#[test]
fn telethon_file_schema_matches_1_5_0() {
    let dump = v150_dump();
    let names: Vec<&str> = telethon_file::SCHEMA.iter().map(|t| t.name).collect();
    assert_eq!(
        names,
        [
            "version",
            "sessions",
            "entities",
            "sent_files",
            "update_state"
        ]
    );
    for table in &telethon_file::SCHEMA {
        // SQLite stores `create table` as `CREATE TABLE` in sqlite_master.
        let body = table.ddl.strip_prefix("create table ").expect("ddl prefix");
        let line = format!("CREATE TABLE {body};");
        assert!(dump.contains(&line), "{} DDL differs: {line}", table.name);
        let open = body.find('(').expect("column list");
        assert_eq!(&body[..open - 1], table.name);
        // Every declared column, in order, before any table constraint.
        let list = &body[open + 1..body.len() - 1];
        let list = list.split(", primary key(").next().expect("columns");
        let declared: Vec<&str> = list
            .split(", ")
            .map(|column| column.split(' ').next().expect("column name"))
            .collect();
        assert_eq!(declared, table.columns, "{} columns", table.name);
    }
    assert_eq!(telethon_file::VERSION, 8);
    assert!(dump.contains(&"INSERT INTO \"version\" VALUES(8);".to_owned()));
    assert_eq!(telethon_file::DELETE_VERSION, "delete from version");
    assert_eq!(
        telethon_file::INSERT_VERSION,
        "insert into version values (?)"
    );
    assert_eq!(telethon_file::DELETE_SESSIONS, "delete from sessions");
    assert_eq!(
        telethon_file::INSERT_SESSION,
        "insert into sessions values (?, ?, ?, ?, ?, ?)"
    );
    assert_eq!(
        telethon_file::INSERT_SESSION.matches('?').count(),
        telethon_file::SCHEMA[1].columns.len()
    );
}

#[test]
fn telethon_file_rows_from_vector_accounts() {
    for folder in ["tdata_plain/performance_on", "tdata_plain/performance_off"] {
        for (account, want) in &vector_accounts(folder) {
            let key_hex = want["auth_key"].as_str().expect("auth_key");
            let (v4, v6) = table_text_1_5_0(account.main_dc);
            for (ipv6, text) in [(false, v4), (true, v6)] {
                let rows = SessionRows::from_account(account, ipv6).expect("rows");
                let string = telethon::StringSession::from_account(account, ipv6).expect("string");
                assert_eq!(rows.dc_id, account.main_dc, "{folder} dc");
                assert_eq!(rows.server_address, text, "{folder} address text");
                assert_eq!(rows.port, 443);
                assert_eq!(
                    rows.server_address.parse::<std::net::IpAddr>().ok(),
                    Some(string.addr.ip()),
                    "{folder} same endpoint as StringSession"
                );
                assert!(rows.takeout_id.is_none());
                assert!(
                    hex::encode(rows.auth_key.as_bytes()) == key_hex,
                    "{folder} rows key differs"
                );
            }
        }
    }
}

#[test]
fn telethon_file_rows_from_stored_config_keep_its_text() {
    let config = hex::decode(CUSTOM_CONFIG).expect("hex");
    let account = account_with_config(2, Some(config.clone()));
    for (ipv6, text) in [(false, "203.0.113.2"), (true, "2001:db8::2")] {
        let rows = SessionRows::from_account(&account, ipv6).expect("rows");
        assert_eq!((rows.dc_id, rows.server_address.as_str()), (2, text));
        assert_eq!(rows.port, 443);
        assert!(same_key(&rows.auth_key, &counting_key(9)));
    }
    let dc3 = account_with_config(3, Some(config.clone()));
    let rows = SessionRows::from_account(&dc3, true).expect("DC 3");
    assert_eq!(rows.server_address, "198.51.100.3");
    let dc5 = account_with_config(5, Some(config));
    assert_eq!(
        code_of(SessionRows::from_account(&dc5, false)),
        "TDATA_BAD_CONFIG_DATA"
    );

    let test = MtpConfig::new(Environment::Test)
        .serialize()
        .expect("serialize");
    let rows = SessionRows::from_account(&account_with_config(2, Some(test)), false).expect("test");
    assert_eq!(rows.server_address, "149.154.167.40");

    let unknown_dc = Account::new(0, 1, 7, vec![(7, counting_key(0))]).expect("account");
    assert_eq!(
        code_of(SessionRows::from_account(&unknown_dc, false)),
        "TDATA_BAD_CONFIG_DATA"
    );
    let mut keyless = Account::new(0, 1, 2, vec![(2, counting_key(0))]).expect("account");
    keyless.keys[0].0 = 4;
    assert_eq!(
        code_of(SessionRows::from_account(&keyless, false)),
        "TDATA_AUTH_KEY_NOT_FOUND"
    );
}

#[test]
fn telethon_file_pair_paths_match_1_5_0() {
    // 1.5.0 `_normalize_base_path(p) + ".session"` and `+ ".json"`.
    let cases = [
        ("acc", "acc.session", "acc.json"),
        ("acc.session", "acc.session", "acc.json"),
        ("acc.json", "acc.session", "acc.json"),
        (
            "acc.session.json",
            "acc.session.session",
            "acc.session.json",
        ),
        ("acc.json.session", "acc.session", "acc.json"),
        ("dir/acc.session", "dir/acc.session", "dir/acc.json"),
        ("acc.SESSION", "acc.SESSION.session", "acc.SESSION.json"),
        (".session", ".session", ".json"),
        ("acc.sessions", "acc.sessions.session", "acc.sessions.json"),
        ("a.session.session", "a.session.session", "a.session.json"),
        ("a.json.json", "a.json.session", "a.json.json"),
        ("", ".session", ".json"),
        ("dir/", "dir/.session", "dir/.json"),
        ("acc.session/", "acc.session/.session", "acc.session/.json"),
    ];
    for (base, session, json) in cases {
        let (got_session, got_json) = telethon_file::pair_paths(base);
        assert_eq!(got_session, PathBuf::from(session), "{base:?} session");
        assert_eq!(got_json, PathBuf::from(json), "{base:?} json");
    }
    // 1.5.0 `write_session_file`: the suffix is appended unless present.
    for (path, full) in [
        ("acc", "acc.session"),
        ("acc.session", "acc.session"),
        ("acc.json", "acc.json.session"),
        ("acc.SESSION", "acc.SESSION.session"),
    ] {
        assert_eq!(telethon_file::session_path(path), PathBuf::from(full));
    }
}

#[test]
fn telethon_file_companion_json_is_the_session_json() {
    let profile = api::profile(Client::Desktop, &Versions::offline());
    let mut extra = serde_json::Map::new();
    extra.insert("session_file".to_owned(), "acc".into());
    extra.insert("id".to_owned(), 77.into());
    let json = telethon_file::companion_json(&profile, Some(&extra));
    assert_eq!(json, profile.to_session_json(Some(&extra)));
    assert_eq!(json["session_file"], "acc");
    assert_eq!(json["id"], 77);
    assert_eq!(
        telethon_file::companion_json(&profile, None),
        profile.to_session_json(None)
    );
}

#[cfg(feature = "telethon-sqlite")]
mod telethon_sqlite {
    use super::{Path, PathBuf, SessionRows, code_of, counting_key, fs, same_key, telethon_file};
    use opentele2_core::crypto::AuthKey;
    use rusqlite::Connection;

    /// A fresh directory under `CARGO_TARGET_TMPDIR` for one test.
    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("telethon_file")
            .join(name);
        if dir.exists() {
            fs::remove_dir_all(&dir).expect("clear scratch dir");
        }
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/telethon_v8.session")
    }

    /// The synthetic key of the fixture: byte `i` is `255 - i`.
    fn fixture_key() -> AuthKey {
        let mut bytes = [0u8; AuthKey::SIZE];
        for (i, byte) in (0u8..=255).zip(bytes.iter_mut()) {
            *byte = 255 - i;
        }
        AuthKey::new(bytes)
    }

    fn rows(
        dc_id: i32,
        server_address: &str,
        key: AuthKey,
        takeout_id: Option<i64>,
    ) -> SessionRows {
        SessionRows {
            dc_id,
            server_address: server_address.to_owned(),
            port: 443,
            auth_key: key,
            takeout_id,
        }
    }

    /// Python `sqlite3` `iterdump()` for tables, with `key`'s blob masked as
    /// `<KEY>` so a failing comparison never prints key bytes; panics when
    /// the dump holds no blob of `key`.
    fn dump(path: &Path, key: &AuthKey) -> Vec<String> {
        let conn = Connection::open(path).expect("open dump");
        let mut lines = vec!["BEGIN TRANSACTION;".to_owned()];
        let mut tables = conn
            .prepare(
                "SELECT name, sql FROM sqlite_master \
                 WHERE sql NOT NULL AND type == 'table' ORDER BY name",
            )
            .expect("prepare");
        let tables: Vec<(String, String)> = tables
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query")
            .collect::<rusqlite::Result<_>>()
            .expect("tables");
        for (name, sql) in tables {
            lines.push(format!("{sql};"));
            let mut columns = conn
                .prepare(&format!("pragma table_info(\"{name}\")"))
                .expect("pragma");
            let columns: Vec<String> = columns
                .query_map([], |row| row.get(1))
                .expect("columns")
                .collect::<rusqlite::Result<_>>()
                .expect("columns");
            let values = columns
                .iter()
                .map(|column| format!("'||quote(\"{column}\")||'"))
                .collect::<Vec<_>>()
                .join(",");
            let query = format!("SELECT 'INSERT INTO \"{name}\" VALUES({values})' FROM \"{name}\"");
            let mut statement = conn.prepare(&query).expect("rows");
            let inserts: Vec<String> = statement
                .query_map([], |row| row.get(0))
                .expect("rows")
                .collect::<rusqlite::Result<_>>()
                .expect("rows");
            lines.extend(inserts.into_iter().map(|line| format!("{line};")));
        }
        lines.push("COMMIT;".to_owned());
        let blob = format!("X'{}'", hex::encode_upper(key.as_bytes()));
        assert!(
            lines.iter().any(|line| line.contains(&blob)),
            "dump holds no blob of the key"
        );
        lines
            .into_iter()
            .map(|line| line.replace(&blob, "X'<KEY>'"))
            .collect()
    }

    fn inserts(lines: &[String]) -> Vec<&str> {
        lines
            .iter()
            .map(String::as_str)
            .filter(|line| line.starts_with("INSERT"))
            .collect()
    }

    fn check_rows(got: &SessionRows, want: &SessionRows) {
        assert_eq!(got.dc_id, want.dc_id);
        assert_eq!(got.server_address, want.server_address);
        assert_eq!(got.port, want.port);
        assert_eq!(got.takeout_id, want.takeout_id);
        assert!(same_key(&got.auth_key, &want.auth_key), "auth key differs");
    }

    #[test]
    fn written_file_dumps_as_1_5_0_writes_it() {
        let dir = scratch("dump");
        let written = rows(2, "149.154.167.51", counting_key(0), None);
        let path = telethon_file::write_session_file(dir.join("v150"), &written).expect("write");
        assert_eq!(path, dir.join("v150.session"));
        assert_eq!(dump(&path, &counting_key(0)), super::v150_dump());
    }

    #[test]
    fn pre_v8_file_is_rebuilt_as_1_5_0_does() {
        let dir = scratch("rebuild");
        let path = dir.join("old.session");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "create table version (version integer primary key);
             insert into version values (7);
             create table sessions (dc_id integer primary key, server_address text,
                 port integer, auth_key blob, takeout_id integer);
             insert into sessions values (1, 'x', 1, x'00', 5);",
        )
        .expect("v7 schema");
        conn.close().expect("close");
        let written = rows(2, "149.154.167.51", counting_key(0), None);
        telethon_file::write_session_file(&path, &written).expect("write");
        assert_eq!(dump(&path, &counting_key(0)), super::v150_dump());
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = scratch("round_trip");
        let first = rows(2, "149.154.167.51", counting_key(0), None);
        let path =
            telethon_file::write_session_file(dir.join("acc.session"), &first).expect("write");
        check_rows(
            &telethon_file::read_session_file(&path).expect("read"),
            &first,
        );
        // Without the suffix the reader finds the same file.
        check_rows(
            &telethon_file::read_session_file(dir.join("acc")).expect("read"),
            &first,
        );

        // Rewriting a current file replaces its one sessions row.
        let second = rows(
            5,
            "2001:0b28:f23f:f005:0000:0000:0000:000a",
            counting_key(3),
            Some(-42),
        );
        telethon_file::write_session_file(&path, &second).expect("rewrite");
        check_rows(
            &telethon_file::read_session_file(&path).expect("read"),
            &second,
        );
        let lines = dump(&path, &counting_key(3));
        assert_eq!(
            inserts(&lines),
            [
                "INSERT INTO \"sessions\" VALUES(5,'2001:0b28:f23f:f005:0000:0000:0000:000a',443,X'<KEY>',-42,NULL);",
                "INSERT INTO \"version\" VALUES(8);",
            ]
        );
    }

    #[test]
    fn reads_the_telethon_v8_fixture() {
        let path = fixture();
        let before = fs::read(&path).expect("read fixture");
        let got = telethon_file::read_session_file(&path).expect("read");
        check_rows(
            &got,
            &rows(4, "149.154.167.91", fixture_key(), Some(1_234_567)),
        );
        assert_eq!(fs::read(&path).expect("reread"), before, "fixture modified");
    }

    #[test]
    fn writing_over_the_fixture_keeps_its_schema_as_1_5_0_does() {
        let dir = scratch("over_fixture");
        let path = dir.join("over.session");
        fs::copy(fixture(), &path).expect("copy fixture");
        let creates = |lines: &[String]| -> Vec<String> {
            lines
                .iter()
                .filter(|line| line.starts_with("CREATE"))
                .cloned()
                .collect()
        };
        let telethon_schema = creates(&dump(&path, &fixture_key()));
        assert!(
            telethon_schema.iter().any(|line| line.contains('\n')),
            "Telethon writes multi-line DDL"
        );
        let written = rows(
            2,
            "2001:067c:04e8:f002:0000:0000:0000:000a",
            counting_key(0),
            None,
        );
        telethon_file::write_session_file(&path, &written).expect("write");
        let lines = dump(&path, &counting_key(0));
        assert_eq!(creates(&lines), telethon_schema, "schema kept");
        // 1.5.0 `write_session_file` on a copy of the fixture, same values.
        assert_eq!(
            inserts(&lines),
            [
                "INSERT INTO \"sessions\" VALUES(2,'2001:067c:04e8:f002:0000:0000:0000:000a',443,X'<KEY>',NULL,NULL);",
                "INSERT INTO \"version\" VALUES(8);",
            ]
        );
        check_rows(
            &telethon_file::read_session_file(&path).expect("read"),
            &written,
        );
    }

    #[test]
    fn read_errors() {
        let dir = scratch("errors");
        assert_eq!(
            code_of(telethon_file::read_session_file(dir.join("missing"))),
            "TFILE_NOT_FOUND"
        );

        let text = dir.join("text.session");
        fs::write(&text, b"not a database, just text that is long enough").expect("write");
        assert_eq!(code_of(telethon_file::read_session_file(&text)), "IO");

        let empty_rows = dir.join("empty.session");
        let written = rows(2, "149.154.167.51", counting_key(0), None);
        telethon_file::write_session_file(&empty_rows, &written).expect("write");
        let conn = Connection::open(&empty_rows).expect("open");
        conn.execute("delete from sessions", []).expect("delete");
        assert_eq!(
            code_of(telethon_file::read_session_file(&empty_rows)),
            "TDATA_AUTH_KEY_NOT_FOUND"
        );
        conn.execute(
            "insert into sessions values (2, '149.154.167.51', 443, x'', null, x'')",
            [],
        )
        .expect("keyless row");
        assert_eq!(
            code_of(telethon_file::read_session_file(&empty_rows)),
            "TDATA_AUTH_KEY_NOT_FOUND"
        );
        conn.execute("update sessions set auth_key = x'0102'", [])
            .expect("short key");
        assert_eq!(
            code_of(telethon_file::read_session_file(&empty_rows)),
            "BAD_LENGTH"
        );
        conn.execute(
            "update sessions set auth_key = ?1, port = 70000",
            [counting_key(0).as_bytes().as_slice()],
        )
        .expect("bad port");
        assert_eq!(
            code_of(telethon_file::read_session_file(&empty_rows)),
            "TDATA_BAD_CONFIG_DATA"
        );
        conn.execute("update sessions set port = 443", [])
            .expect("port");
        conn.execute("update version set version = 7", [])
            .expect("version");
        assert_eq!(
            code_of(telethon_file::read_session_file(&empty_rows)),
            "QDATASTREAM_FAILED"
        );
        conn.execute("update version set version = 8", [])
            .expect("version");
        conn.execute("alter table sessions drop column tmp_auth_key", [])
            .expect("drop column");
        assert_eq!(
            code_of(telethon_file::read_session_file(&empty_rows)),
            "QDATASTREAM_FAILED"
        );
    }
}
