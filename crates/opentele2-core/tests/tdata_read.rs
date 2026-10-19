//! Tests for `tdata::account`, `tdata::map`, and `TData::load` against the
//! four 1.5.0 vector folders in `tests/vectors` (described by `tdata.json`),
//! plus synthetic blobs and damaged copies of a vector folder.
//!
//! Argon2id derivations are slow in debug builds; only the two passcode
//! folders run one. Key bytes are never printed: comparisons of key material
//! use `assert!` without the values.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use opentele2_core::crypto::AuthKey;
use opentele2_core::qt::QWriter;
use opentele2_core::tdata::TData;
use opentele2_core::tdata::account::{Account, data_name, data_name_key, file_part, folder_name};
use opentele2_core::tdata::map::{self, MapData, MapEntry};
use opentele2_core::{Error, Result};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn folder_entry(folder: &str) -> Value {
    let text = fs::read_to_string(vectors_dir().join("tdata.json")).expect("read vector manifest");
    let manifest: Value = serde_json::from_str(&text).expect("parse vector manifest");
    manifest["folders"][folder].clone()
}

fn code_of<T>(result: Result<T>) -> &'static str {
    match result {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(error) => error.code(),
    }
}

/// Loads one vector folder and checks every field of its manifest entry.
fn check_folder(folder: &str) {
    let entry = folder_entry(folder);
    let dir = vectors_dir().join(folder);
    let key_file = entry["key_file"].as_str().expect("key_file");
    let passcode = entry["passcode"].as_str().expect("passcode").as_bytes();
    let performance = entry["performance_mode"].as_bool().expect("mode");
    let files: Vec<&str> = entry["files"]
        .as_array()
        .expect("files")
        .iter()
        .map(|f| f.as_str().expect("file name"))
        .collect();

    let tdata = TData::load(&dir, passcode, Some(key_file)).expect("load tdata");
    assert_eq!(tdata.key_file, key_file, "{folder} key file");
    // Every vector stores -1, so the main account falls back to the first.
    assert_eq!(tdata.active_index, -1, "{folder} active index");
    let main = tdata.main_account().expect("main account");
    assert_eq!(
        i64::from(main.index),
        entry["main_account_index"].as_i64().expect("main index"),
        "{folder} main account index"
    );

    let expected = entry["accounts"].as_array().expect("accounts");
    assert_eq!(
        tdata.accounts.len(),
        expected.len(),
        "{folder} account count"
    );
    for (account, want) in tdata.accounts.iter().zip(expected) {
        let index = account.index;
        assert_eq!(
            i64::from(index),
            want["index"].as_i64().expect("index"),
            "{folder} index"
        );
        assert_eq!(
            account.user_id,
            want["user_id"].as_u64().expect("user id"),
            "{folder}/{index} user id"
        );
        assert_eq!(
            i64::from(account.main_dc),
            want["main_dc"].as_i64().expect("main dc"),
            "{folder}/{index} main dc"
        );
        let key = account.auth_key().expect("main auth key");
        assert!(
            hex::encode(key.as_bytes()) == want["auth_key"].as_str().expect("auth key"),
            "{folder}/{index} auth key differs from 1.5.0"
        );

        // The account's files are where the helpers say they are.
        let part = folder_name(&data_name(key_file, index));
        assert!(files.contains(&format!("{part}s").as_str()), "{part}s");
        assert!(
            files.contains(&format!("{part}/maps").as_str()),
            "{part}/maps"
        );
        assert_eq!(
            account.config.is_some(),
            !performance,
            "{folder}/{index} config presence"
        );
        assert_eq!(
            account.map.version, 7_003_001,
            "{folder}/{index} map version"
        );
        assert_eq!(account.map.stopped_at, None, "{folder}/{index} map stop");

        // MtpAuthorization re-encodes to the exact bytes 1.5.0 wrote.
        let blob =
            Account::read_mtp_authorization(&dir, &data_name(key_file, index), &tdata.local_key)
                .expect("read mtp authorization");
        let parsed = Account::parse_mtp_authorization(index, &blob).expect("parse blob");
        assert!(
            parsed.encode_mtp_authorization().expect("encode") == blob,
            "{folder}/{index} MtpAuthorization does not re-encode identically"
        );
    }
}

#[test]
fn plain_performance_on_loads() {
    check_folder("tdata_plain/performance_on");
}

#[test]
fn plain_performance_off_loads() {
    check_folder("tdata_plain/performance_off");
}

#[test]
fn passcode_performance_on_loads() {
    check_folder("tdata_passcode/performance_on");
}

#[test]
fn passcode_performance_off_loads() {
    check_folder("tdata_passcode/performance_off");
}

#[test]
fn data_and_folder_names_match_the_vectors() {
    assert_eq!(data_name("data", 0), "data");
    assert_eq!(data_name("data", 1), "data#2");
    assert_eq!(data_name("da#ta", 0), "data");
    assert_eq!(data_name("data", -1), "data");
    assert_eq!(data_name("data", i32::MAX), "data#2147483648");
    assert_eq!(folder_name("data"), "D877F783D5D3EF8C");
    assert_eq!(folder_name("data#2"), "A7FDF864FBC10B77");
    assert_eq!(file_part(data_name_key("data")), folder_name("data"));
    assert_eq!(file_part(0x0123_4567_89AB_CDEF), "FEDCBA9876543210");
}

#[test]
fn load_errors_match_1_5_0() {
    let plain = vectors_dir().join("tdata_plain/performance_on");
    assert!(matches!(
        TData::load(&plain, b"opentele2", None),
        Err(Error::BadDecryptKey)
    ));
    assert_eq!(
        code_of(TData::load(&plain, b"", Some("other"))),
        "TFILE_NOT_FOUND"
    );
    assert_eq!(
        code_of(TData::load(vectors_dir().join("missing"), b"", None)),
        "TFILE_NOT_FOUND"
    );
}

/// Copies `tdata_plain/<mode>` into a fresh directory under the target tmp dir.
fn scratch_copy(mode: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let source = vectors_dir().join("tdata_plain").join(mode);
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "tdata_read_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    if target.exists() {
        fs::remove_dir_all(&target).expect("clear scratch");
    }
    copy_tree(&source, &target);
    target
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create scratch dir");
    for item in fs::read_dir(from).expect("read dir") {
        let item = item.expect("dir entry");
        let path = item.path();
        let dest = to.join(item.file_name());
        if path.is_dir() {
            copy_tree(&path, &dest);
        } else {
            fs::copy(&path, &dest).expect("copy file");
        }
    }
}

#[test]
fn broken_accounts_are_skipped_and_none_left_is_an_error() {
    let dir = scratch_copy("performance_off");
    let first = folder_name(&data_name("data", 0));
    let second = folder_name(&data_name("data", 1));

    fs::remove_file(dir.join(&first).join("maps")).expect("remove first map");
    fs::remove_file(dir.join(&second).join("configs")).expect("remove second config");
    let tdata = TData::load(&dir, b"", None).expect("one account left");
    assert_eq!(tdata.accounts.len(), 1);
    assert_eq!(tdata.accounts[0].index, 1);
    assert!(tdata.accounts[0].config.is_none(), "config should be gone");
    assert_eq!(tdata.main_account().expect("main").index, 1);

    fs::remove_file(dir.join(format!("{second}s"))).expect("remove second mtp data");
    assert!(matches!(
        TData::load(&dir, b"", None),
        Err(Error::AuthKeyNotFound)
    ));
    fs::remove_dir_all(&dir).expect("clean scratch");
}

#[test]
fn account_read_reports_the_failing_file() {
    let dir = scratch_copy("performance_on");
    let first = folder_name(&data_name("data", 0));
    let tdata = TData::load(&dir, b"", None).expect("load");
    let key = &tdata.local_key;

    let wrong = AuthKey::new([7; AuthKey::SIZE]);
    assert!(matches!(
        Account::read(&dir, "data", 0, &wrong),
        Err(Error::ReadMapDataFailed)
    ));
    assert!(matches!(
        MapData::read(dir.join(&first), &wrong),
        Err(Error::ReadMapDataFailed)
    ));
    assert!(matches!(
        Account::read_mtp_authorization(&dir, "data", &wrong),
        Err(Error::BadDecryptKey)
    ));
    fs::remove_file(dir.join(format!("{first}s"))).expect("remove mtp data");
    assert!(matches!(
        Account::read(&dir, "data", 0, key),
        Err(Error::FileNotFound)
    ));
    fs::remove_dir_all(&dir).expect("clean scratch");
}

/// Builds an `MtpAuthorization` blob from raw parts.
fn mtp_blob(head: &[i64], keys: &[(i32, u8)], destroy: &[(i32, u8)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &value in head {
        out.extend_from_slice(&value.to_be_bytes());
    }
    for list in [keys, destroy] {
        out.extend_from_slice(&i32::try_from(list.len()).expect("count").to_be_bytes());
        for &(dc, fill) in list {
            out.extend_from_slice(&dc.to_be_bytes());
            out.extend_from_slice(&[fill; AuthKey::SIZE]);
        }
    }
    out
}

/// Packs two `i32` into the `i64` whose big-endian bytes are both of them.
fn pair(high: i32, low: i32) -> i64 {
    (i64::from(high) << 32) | i64::from(low.cast_unsigned())
}

#[test]
fn mtp_authorization_wide_and_legacy_layouts() {
    let mut wide = mtp_blob(&[-1, 6_000_000_456], &[], &[]);
    wide.truncate(16);
    wide.extend_from_slice(&5_i32.to_be_bytes());
    wide.extend_from_slice(&mtp_blob(&[], &[(4, 1), (5, 2)], &[(3, 9)])[..]);
    let account = Account::parse_mtp_authorization(1, &wide).expect("wide");
    assert_eq!(
        (account.index, account.user_id, account.main_dc),
        (1, 6_000_000_456, 5)
    );
    assert_eq!(account.keys.len(), 2);
    assert_eq!(account.keys_to_destroy.len(), 1);
    assert!(
        account.auth_key().expect("main key").as_bytes() == &[2; AuthKey::SIZE],
        "main key is not the main DC's key"
    );
    assert!(
        account.encode_mtp_authorization().expect("encode") == wide,
        "wide blob does not re-encode identically"
    );

    // Legacy: i32 user id and main dc, re-encoded in the wide layout.
    let legacy = mtp_blob(&[pair(7, 2)], &[(2, 3)], &[]);
    let account = Account::parse_mtp_authorization(0, &legacy).expect("legacy");
    assert_eq!((account.user_id, account.main_dc), (7, 2));
    let reencoded = account.encode_mtp_authorization().expect("encode");
    assert_eq!(&reencoded[..8], &(-1_i64).to_be_bytes());
    let again = Account::parse_mtp_authorization(0, &reencoded).expect("reparse");
    assert_eq!((again.user_id, again.main_dc), (7, 2));

    // A negative main dc sign-extends into the tag, as in tdesktop.
    let mut tagged = mtp_blob(&[pair(7, -1), 9], &[], &[]);
    tagged.truncate(16);
    tagged.extend_from_slice(&2_i32.to_be_bytes());
    tagged.extend_from_slice(&mtp_blob(&[], &[(2, 4)], &[])[..]);
    let account = Account::parse_mtp_authorization(0, &tagged).expect("tagged");
    assert_eq!((account.user_id, account.main_dc), (9, 2));
}

#[test]
fn mtp_authorization_errors() {
    let no_main = mtp_blob(&[pair(7, 2)], &[(3, 3)], &[]);
    assert!(matches!(
        Account::parse_mtp_authorization(0, &no_main),
        Err(Error::AuthKeyNotFound)
    ));
    let full = mtp_blob(&[pair(7, 2)], &[(2, 3)], &[(4, 5)]);
    for cut in [0, 7, 11, 20, full.len() - 1] {
        assert!(
            matches!(
                Account::parse_mtp_authorization(0, &full[..cut]),
                Err(Error::QDataStreamFailed)
            ),
            "cut at {cut}"
        );
    }
    // A forged count fails at the first missing key instead of allocating.
    let mut forged = mtp_blob(&[pair(7, 2)], &[], &[]);
    forged.truncate(8);
    forged.extend_from_slice(&i32::MAX.to_be_bytes());
    assert!(matches!(
        Account::parse_mtp_authorization(0, &forged),
        Err(Error::QDataStreamFailed)
    ));
    // Negative counts read no key, so the main key is missing.
    let mut negative = forged.clone();
    negative.truncate(8);
    negative.extend_from_slice(&(-3_i32).to_be_bytes());
    negative.extend_from_slice(&0_i32.to_be_bytes());
    assert!(matches!(
        Account::parse_mtp_authorization(0, &negative),
        Err(Error::AuthKeyNotFound)
    ));
}

#[test]
fn map_entries_accept_the_1_5_0_shapes() {
    let mut w = QWriter::new();
    w.write_u32(map::LSK_SELF_SERIALIZED);
    w.write_bytearray(Some(b"self")).expect("self");
    w.write_u32(0x1E);
    w.write_u64(11);
    w.write_u32(map::LSK_DRAFT);
    w.write_u32(1);
    w.write_u64(12);
    w.write_u64(13);
    w.write_u32(0x10);
    for key in 1..=4 {
        w.write_u64(key);
    }
    w.write_u32(map::LSK_LEGACY_AUDIOS);
    w.write_u32(1);
    w.write_u64(1);
    w.write_u64(2);
    w.write_u64(3);
    w.write_i32(4);
    w.write_u32(map::LSK_WEBVIEW_TOKENS);
    w.write_bytearray(None).expect("bots");
    w.write_bytearray(Some(b"o")).expect("other");
    w.write_u32(map::LSK_WALLET_ENGINE_STORAGES);
    w.write_u32(1);
    w.write_u64(14);
    w.write_qstring(Some("w")).expect("name");
    let known = w.into_bytes();

    let (entries, stopped) = MapData::parse_entries(&known).expect("parse");
    assert_eq!(stopped, None);
    assert_eq!(
        entries,
        vec![
            MapEntry::SelfSerialized(Some(b"self".to_vec())),
            MapEntry::FileKeys {
                kind: 0x1E,
                keys: vec![11]
            },
            MapEntry::PeerKeys {
                kind: map::LSK_DRAFT,
                pairs: vec![(12, 13)]
            },
            MapEntry::FileKeys {
                kind: 0x10,
                keys: vec![1, 2, 3, 4]
            },
            MapEntry::LegacyLocations {
                kind: map::LSK_LEGACY_AUDIOS,
                items: vec![(1, 2, 3, 4)]
            },
            MapEntry::WebviewTokens {
                bots: None,
                other: Some(b"o".to_vec())
            },
            MapEntry::WalletEngineStorages(vec![(14, Some("w".to_owned()))]),
        ]
    );

    // An unknown type ends the entries and keeps what came before.
    let mut unknown = known.clone();
    unknown.extend_from_slice(&0x7F_u32.to_be_bytes());
    unknown.extend_from_slice(&[0xAA; 5]);
    let (entries, stopped) = MapData::parse_entries(&unknown).expect("unknown");
    assert_eq!((entries.len(), stopped), (7, Some(0x7F)));

    // A key type cut short reads as 0 in 1.5.0, which also ends the entries.
    let mut short = known.clone();
    short.extend_from_slice(&[0, 0]);
    let (entries, stopped) = MapData::parse_entries(&short).expect("short type");
    assert_eq!((entries.len(), stopped), (7, Some(0)));

    // A known entry cut short fails the map.
    assert!(matches!(
        MapData::parse_entries(&known[..known.len() - 1]),
        Err(Error::QDataStreamFailed)
    ));
    let mut forged = Vec::new();
    forged.extend_from_slice(&map::LSK_BOT_STORAGES.to_be_bytes());
    forged.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        MapData::parse_entries(&forged),
        Err(Error::QDataStreamFailed)
    ));
    assert_eq!(map::file_key_count(0x00), None);
    assert_eq!(map::file_key_count(0x14), Some(2));
    assert_eq!(map::file_key_count(0x16), Some(3));
    assert_eq!(map::file_key_count(0x0D), Some(1));
}
