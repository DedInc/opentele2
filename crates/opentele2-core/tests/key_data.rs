//! Tests for `tdata::key_data` against the four 1.5.0 vector folders in
//! `tests/vectors` (described by `tdata.json`) and the `argon2id_wrap` case of
//! `crypto.json`, plus synthetic malformed trailers.
//!
//! Argon2id derivations are slow in debug builds; only three tests run one:
//! the two passcode folders and the wrong-passcode case. Key bytes are never
//! printed: comparisons of key material use `assert!` without the values.

use std::fs;
use std::path::{Path, PathBuf};

use opentele2_core::crypto::AuthKey;
use opentele2_core::qt::QWriter;
use opentele2_core::tdata::key_data::{
    self, AccountsInfo, KDF_ARGON2ID, KDF_PBKDF2, KDF_SCRYPT, KEY_DATA_FORMAT_VERSION,
    KEY_DATA_MAGIC, KeyData, KeyDataTrailer, PasscodeKdf, create_passcode_key,
    decrypt_accounts_info, default_passcode_kdf, open_local_key, unwrap_local_key, wrap_local_key,
};
use opentele2_core::{Error, Result, tdf};
use serde_json::Value;

/// Telegram Desktop version stored in every vector key file.
const VECTOR_APP_VERSION: u32 = 7_003_001;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn manifest(file: &str) -> Value {
    let text = fs::read_to_string(vectors_dir().join(file)).expect("read vector manifest");
    serde_json::from_str(&text).expect("parse vector manifest")
}

fn code_of<T>(result: Result<T>) -> &'static str {
    match result {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(error) => error.code(),
    }
}

/// Reads and parses the key file of a vector folder.
fn load(folder: &str) -> (tdf::TdfFile, KeyData) {
    let entry = &manifest("tdata.json")["folders"][folder];
    let key_file = entry["key_file"].as_str().expect("key_file");
    let file = tdf::read(vectors_dir().join(folder), &key_data::file_name(key_file))
        .expect("read key file");
    let data = KeyData::parse(&file.payload).expect("parse key data");
    (file, data)
}

/// Round-trips, opens, and decodes one vector folder.
fn check_folder(folder: &str, passcode_lock: bool) {
    let entry = manifest("tdata.json")["folders"][folder].clone();
    let (file, data) = load(folder);
    assert_eq!(file.version, VECTOR_APP_VERSION, "{folder} version");
    assert!(
        data.encode().expect("encode key data") == file.payload,
        "{folder} key data does not re-encode to identical bytes"
    );

    let trailer = data.trailer.as_ref().expect("7.3 trailer");
    if passcode_lock {
        assert!(data.key_encrypted.is_none(), "{folder} open wrap not null");
        assert_eq!(trailer.committed, 1, "{folder} committed");
        assert_eq!(trailer.wraps.len(), 1, "{folder} wrap count");
        assert_eq!(
            trailer.wraps[0].kdf,
            default_passcode_kdf(),
            "{folder} wrap kdf"
        );
    } else {
        assert!(data.key_encrypted.is_some(), "{folder} open wrap missing");
        assert_eq!(trailer.committed, 0, "{folder} committed");
        assert!(trailer.wraps.is_empty(), "{folder} has wraps");
    }

    let passcode = entry["passcode"].as_str().expect("passcode").as_bytes();
    let opened = open_local_key(&data, passcode).expect("open local key");
    let info = decrypt_accounts_info(&data, &opened.local_key, passcode).expect("accounts info");
    let indices: Vec<i32> = entry["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .map(|a| i32::try_from(a["index"].as_i64().expect("index")).expect("i32 index"))
        .collect();
    let main = entry["main_account_index"].as_i64().expect("main index");
    assert_eq!(info.indices, indices, "{folder} account indices");
    // 1.5.0 makes the account whose index is the active one main, else the
    // first loaded account (the vectors store an active index of -1).
    let effective_main = if info.indices.contains(&info.active_index) {
        info.active_index
    } else {
        info.indices[0]
    };
    assert_eq!(
        i64::from(effective_main),
        main,
        "{folder} main account index"
    );

    // The recovered keys re-wrap and unwrap consistently.
    let rewrapped = wrap_local_key(&opened.local_key, &opened.passcode_key, &[0; 12])
        .expect("re-wrap local key");
    let unwrapped = unwrap_local_key(&rewrapped, &opened.passcode_key).expect("unwrap");
    assert!(
        unwrapped.as_bytes() == opened.local_key.as_bytes(),
        "{folder} re-wrapped local key differs"
    );
}

#[test]
fn plain_performance_on_round_trips_and_opens() {
    check_folder("tdata_plain/performance_on", false);
}

#[test]
fn plain_performance_off_round_trips_and_opens() {
    check_folder("tdata_plain/performance_off", false);
}

#[test]
fn passcode_performance_on_round_trips_and_opens() {
    check_folder("tdata_passcode/performance_on", true);
}

#[test]
fn passcode_performance_off_round_trips_and_opens() {
    check_folder("tdata_passcode/performance_off", true);
}

#[test]
fn wrong_passcode_is_bad_decrypt_key() {
    let (_, data) = load("tdata_passcode/performance_off");
    assert_eq!(
        code_of(open_local_key(&data, b"not-the-passcode")),
        "TDATA_BAD_DECRYPT_KEY"
    );
}

#[test]
fn passcode_without_live_wrap_is_bad_decrypt_key() {
    let (_, data) = load("tdata_plain/performance_on");
    assert!(matches!(
        open_local_key(&data, b"opentele2"),
        Err(Error::BadDecryptKey)
    ));
}

#[test]
fn empty_passcode_with_app_lock_is_bad_decrypt_key() {
    let (_, data) = load("tdata_passcode/performance_on");
    assert!(matches!(
        open_local_key(&data, b""),
        Err(Error::BadDecryptKey)
    ));
}

#[test]
fn accounts_info_failure_maps_like_start_modern() {
    let wrong = AuthKey::new([7; AuthKey::SIZE]);
    let (_, locked) = load("tdata_passcode/performance_on");
    assert!(matches!(
        decrypt_accounts_info(&locked, &wrong, b""),
        Err(Error::BadDecryptKey)
    ));
    let (_, plain) = load("tdata_plain/performance_on");
    assert!(matches!(
        decrypt_accounts_info(&plain, &wrong, b""),
        Err(Error::KeyDataInvalid)
    ));
}

#[test]
fn legacy_layout_round_trips_and_opens() {
    let (_, mut data) = load("tdata_plain/performance_on");
    data.trailer = None;
    let payload = data.encode().expect("encode legacy");
    let legacy = KeyData::parse(&payload).expect("parse legacy");
    assert!(legacy.trailer.is_none());
    assert!(
        legacy.encode().expect("re-encode") == payload,
        "legacy key data does not re-encode to identical bytes"
    );
    let opened = open_local_key(&legacy, b"").expect("open legacy");
    let info = decrypt_accounts_info(&legacy, &opened.local_key, b"").expect("accounts info");
    assert_eq!(info.indices, vec![0, 1]);
}

/// One raw wrap: kind, generation, memory, time, parallelism, salt length.
type RawWrap = (u32, u32, u32, u32, u32, usize);

const ARGON2_WRAP: RawWrap = (KDF_ARGON2ID, 1, 65_536, 8, 1, 32);

fn trailer_blob(magic: u32, format: u32, committed: u32, wraps: &[RawWrap]) -> Vec<u8> {
    let mut writer = QWriter::new();
    writer.write_u32(magic);
    writer.write_u32(format);
    writer.write_u32(committed);
    writer.write_u32(u32::try_from(wraps.len()).expect("wrap count"));
    for &(kind, generation, memory, time, parallelism, salt_len) in wraps {
        for value in [kind, generation, memory, time, parallelism] {
            writer.write_u32(value);
        }
        writer
            .write_bytearray(Some(&vec![1; salt_len]))
            .expect("salt");
        writer.write_bytearray(Some(&[2; 288])).expect("key");
    }
    writer.into_bytes()
}

fn payload_with(salt_len: usize, trailer: Option<&[u8]>) -> Vec<u8> {
    let mut writer = QWriter::new();
    writer
        .write_bytearray(Some(&vec![3; salt_len]))
        .expect("salt");
    writer.write_bytearray(None).expect("open wrap");
    writer.write_bytearray(Some(&[4; 48])).expect("info");
    if let Some(blob) = trailer {
        writer.write_bytearray(Some(blob)).expect("trailer");
    }
    writer.into_bytes()
}

fn parse_trailer(blob: &[u8]) -> Result<KeyData> {
    KeyData::parse(&payload_with(32, Some(blob)))
}

#[test]
fn malformed_trailers_are_key_data_invalid() {
    let wrap = ARGON2_WRAP;
    let cases: [(&str, Vec<u8>); 7] = [
        ("bad magic", trailer_blob(0x4B44_3201, 2, 1, &[wrap])),
        ("3 wraps at format 2", {
            let wraps = [
                wrap,
                (wrap.0, 2, wrap.2, wrap.3, wrap.4, 32),
                (wrap.0, 3, wrap.2, wrap.3, wrap.4, 32),
            ];
            trailer_blob(KEY_DATA_MAGIC, 2, 1, &wraps)
        }),
        ("17 wraps at format 3", {
            let wraps: Vec<RawWrap> = (1..=17)
                .map(|g| (KDF_ARGON2ID, g, 65_536, 8, 1, 32))
                .collect();
            trailer_blob(KEY_DATA_MAGIC, 3, 1, &wraps)
        }),
        (
            "kind 0",
            trailer_blob(KEY_DATA_MAGIC, 2, 1, &[(KDF_PBKDF2, 1, 65_536, 8, 1, 32)]),
        ),
        (
            "argon2 memory below 8 * lanes",
            trailer_blob(KEY_DATA_MAGIC, 2, 1, &[(KDF_ARGON2ID, 1, 15, 8, 2, 32)]),
        ),
        (
            "short wrap salt",
            trailer_blob(KEY_DATA_MAGIC, 2, 1, &[(KDF_ARGON2ID, 1, 65_536, 8, 1, 7)]),
        ),
        (
            "duplicate generation",
            trailer_blob(KEY_DATA_MAGIC, 2, 1, &[wrap, wrap]),
        ),
    ];
    for (name, blob) in cases {
        let result = parse_trailer(&blob);
        assert!(
            matches!(result, Err(Error::KeyDataInvalid)),
            "{name}: {result:?}"
        );
    }
    assert_eq!(
        code_of(parse_trailer(&trailer_blob(0, 2, 1, &[]))),
        "TDATA_KEY_DATA_INVALID"
    );
}

#[test]
fn bad_salt_and_truncation_fail() {
    let trailer = trailer_blob(KEY_DATA_MAGIC, 2, 1, &[ARGON2_WRAP]);
    assert!(matches!(
        KeyData::parse(&payload_with(31, Some(&trailer))),
        Err(Error::KeyDataInvalid)
    ));
    assert!(matches!(
        parse_trailer(&trailer[..trailer.len() - 1]),
        Err(Error::QDataStreamFailed)
    ));
    assert!(matches!(
        parse_trailer(&trailer[..15]),
        Err(Error::QDataStreamFailed)
    ));
    let payload = payload_with(32, None);
    assert!(matches!(
        KeyData::parse(&payload[..payload.len() - 1]),
        Err(Error::QDataStreamFailed)
    ));
}

#[test]
fn newer_format_reads_known_prefix_and_writes_format_2() {
    let wraps: Vec<RawWrap> = (1..=3)
        .map(|g| (KDF_SCRYPT, g, 131_072, 8, 1, 32))
        .collect();
    let mut blob = trailer_blob(KEY_DATA_MAGIC, 3, 2, &wraps);
    blob.extend_from_slice(&[9; 8]);
    let data = parse_trailer(&blob).expect("newer format parses");
    let trailer = data.trailer.as_ref().expect("trailer");
    assert_eq!(trailer.committed, 2);
    assert_eq!(trailer.wraps.len(), 3);
    assert_eq!(trailer.live_wraps().count(), 1);

    // 1.5.0 keeps only the live wraps before writing back.
    let live = KeyDataTrailer {
        committed: trailer.committed,
        wraps: trailer.live_wraps().cloned().collect(),
    };
    let encoded = live.encode().expect("encode trailer");
    assert_eq!(&encoded[4..8], &KEY_DATA_FORMAT_VERSION.to_be_bytes());
    assert_eq!(KeyDataTrailer::parse(&encoded).expect("reparse"), live);
}

#[test]
fn over_cap_cost_parses_and_fails_at_open_and_creation() {
    let over: RawWrap = (KDF_ARGON2ID, 1, 262_145, 8, 1, 32);
    let data =
        parse_trailer(&trailer_blob(KEY_DATA_MAGIC, 2, 1, &[over])).expect("over-cap parses");
    assert!(matches!(
        open_local_key(&data, b"opentele2"),
        Err(Error::BadDecryptKey)
    ));
    let wrap = &data.trailer.as_ref().expect("trailer").wraps[0];
    assert!(!wrap.kdf.cost_within_limits());
    assert!(matches!(
        create_passcode_key(b"opentele2", &wrap.salt, &wrap.kdf),
        Err(Error::KeyDataInvalid)
    ));
}

#[test]
fn create_passcode_key_rejects_unusable_inputs() {
    let kdf = default_passcode_kdf();
    let salt = [5; 32];
    assert!(matches!(
        create_passcode_key(b"", &salt, &kdf),
        Err(Error::KeyDataInvalid)
    ));
    assert!(matches!(
        create_passcode_key(b"x", &salt[..7], &kdf),
        Err(Error::KeyDataInvalid)
    ));
    let pbkdf2 = PasscodeKdf {
        kind: KDF_PBKDF2,
        ..kdf
    };
    assert!(matches!(
        create_passcode_key(b"x", &salt, &pbkdf2),
        Err(Error::KeyDataInvalid)
    ));
}

#[test]
fn kdf_validity_and_limits() {
    let kdf = default_passcode_kdf();
    assert_eq!(
        (
            kdf.kind,
            kdf.generation,
            kdf.memory,
            kdf.time,
            kdf.parallelism
        ),
        (KDF_ARGON2ID, 1, 65_536, 8, 1)
    );
    assert!(kdf.valid() && kdf.cost_within_limits());
    let scrypt = PasscodeKdf {
        kind: KDF_SCRYPT,
        generation: 1,
        memory: 131_072,
        time: 8,
        parallelism: 1,
    };
    assert!(scrypt.valid() && scrypt.cost_within_limits());
    assert!(
        !PasscodeKdf {
            memory: 131_071,
            ..scrypt
        }
        .valid()
    );
    assert!(!PasscodeKdf { time: 0, ..scrypt }.valid());
    assert!(
        !PasscodeKdf {
            parallelism: 17,
            ..scrypt
        }
        .cost_within_limits()
    );
    assert!(
        !PasscodeKdf {
            memory: (1 << 20) * 2,
            ..scrypt
        }
        .cost_within_limits()
    );
    assert!(!PasscodeKdf { time: 65, ..kdf }.cost_within_limits());
    assert!(PasscodeKdf { kind: 9, ..kdf }.cost_within_limits());
    assert!(!PasscodeKdf { kind: 9, ..kdf }.valid());
}

#[test]
fn argon2id_wrap_vector_wraps_and_unwraps() {
    let case = &manifest("crypto.json")["argon2id_wrap"];
    let bytes = |key: &str| hex::decode(case[key].as_str().expect("hex field")).expect("hex");
    let local = AuthKey::from_slice(&bytes("local_key")).expect("local key");
    let wrap_key = AuthKey::from_slice(&bytes("wrap_key")).expect("wrap key");
    let wrapped = wrap_local_key(&local, &wrap_key, &bytes("padding")).expect("wrap");
    assert!(
        wrapped == bytes("key_encrypted"),
        "wrapped key differs from 1.5.0"
    );
    let unwrapped = unwrap_local_key(&wrapped, &wrap_key).expect("unwrap");
    assert!(
        unwrapped.as_bytes() == local.as_bytes(),
        "unwrapped key differs"
    );

    assert!(matches!(
        unwrap_local_key(&wrapped, &local),
        Err(Error::BadDecryptKey)
    ));
    assert!(matches!(
        unwrap_local_key(&wrapped[..16], &wrap_key),
        Err(Error::BadDecryptKey)
    ));
    assert!(matches!(
        wrap_local_key(&local, &wrap_key, &[0; 11]),
        Err(Error::BadLength { .. })
    ));
}

#[test]
fn accounts_info_decoding() {
    let encode = |values: &[i32]| {
        let mut writer = QWriter::new();
        for &value in values {
            writer.write_i32(value);
        }
        writer.into_bytes()
    };
    let info = AccountsInfo::parse(&encode(&[2, 0, 3, 3])).expect("with active");
    assert_eq!((info.indices, info.active_index), (vec![0, 3], 3));
    let info = AccountsInfo::parse(&encode(&[1, 4])).expect("without active");
    assert_eq!((info.indices, info.active_index), (vec![4], 0));
    assert!(matches!(
        AccountsInfo::parse(&encode(&[0])),
        Err(Error::KeyDataInvalid)
    ));
    assert!(matches!(
        AccountsInfo::parse(&encode(&[-1])),
        Err(Error::KeyDataInvalid)
    ));
    assert!(matches!(
        AccountsInfo::parse(&encode(&[i32::MAX, 1])),
        Err(Error::QDataStreamFailed)
    ));
}
