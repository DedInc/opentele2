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

use opentele2_core::crypto::{self, AuthKey};
use opentele2_core::qt::QWriter;
use opentele2_core::tdata::TData;
use opentele2_core::tdata::account::{
    Account, DBI_APPLICATION_SETTINGS, DBI_CHAT_SIZE_MAX_OLD, DBI_DC_OPTION_OLD,
    DBI_DC_OPTION_OLD_OLD, DBI_DC_OPTIONS_OLD, DBI_KEY, DBI_MEGAGROUP_SIZE_MAX_OLD,
    DBI_MTP_AUTHORIZATION, DBI_SAVED_GIFS_LIMIT_OLD, DBI_STICKERS_FAVED_LIMIT_OLD,
    DBI_STICKERS_RECENT_LIMIT_OLD, DBI_USER, MTP_CONFIG_PRODUCTION, data_name, data_name_key,
    file_part, folder_name,
};
use opentele2_core::tdata::map::{self, MapData, MapEntry};
use opentele2_core::tdata::mtp_config::{
    DcOptions, Endpoint, Environment, FLAG_CDN, FLAG_IPV6, FLAG_MEDIA_ONLY, FLAG_SECRET,
    FLAG_STATIC, FLAG_TCPO_ONLY, MtpConfig, ProtocolEndpoints, RsaPublicKey, bare_dc_id,
};
use opentele2_core::tdf::{self, TdfFile};
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
        // The configs 1.5.0 wrote parse and re-serialize byte for byte.
        if let Some(config) = account.config.as_deref() {
            let parsed = MtpConfig::parse(config).expect("parse vector config");
            assert_eq!(
                parsed.serialize().expect("serialize"),
                config,
                "{folder}/{index} config does not re-serialize identically"
            );
            assert_eq!(config, MTP_CONFIG_PRODUCTION, "{folder}/{index} config");
            assert_eq!(parsed, account.mtp_config(), "{folder}/{index} mtp_config");
        }
        assert_eq!(
            account.mtp_config(),
            MtpConfig::new(Environment::Production),
            "{folder}/{index} default config"
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

fn hex_bytes(text: &str) -> Vec<u8> {
    hex::decode(text).expect("hex literal")
}

/// 1.5.0's `MTP.Config(Production)` with custom DC options and fields:
/// `_data` cleared, then through `applyOneGuarded`, in order, DC 2 IPv6
/// TCP-only `2001:db8::2`, `203.0.113.2`, secret `203.0.113.3:8443` (secret
/// bytes 1 to 16), a static duplicate of `203.0.113.2:443`, media-only
/// `203.0.113.4:80`, static IPv6 `2001:db8::22`; DC 1 static
/// `198.51.100.1`, IPv6 secret `2001:db8::1` (32 bytes 0xab);
/// `constructAddOne(10003, f_cdn, 198.51.100.3)`; DC 1001 `198.51.100.9`;
/// one CDN key (203, `010203`, `010001`); and chatSizeMax 321,
/// revokePrivateInbox, an empty txtDomainString, emoji U+2764, custom
/// reaction 2^63 + 5, ratingDecay -7, search bots `gifs` and `venues`. The
/// bytes are its `Serialize()`.
const CUSTOM_CONFIG: &str = "000000010000000000000149fffffffe000000080000000200000005000001bb0000000b323030313a6462383a3a32000000000000000200000000000001bb0000000b3230332e302e3131332e32000000000000000200000400000020fb0000000b3230332e302e3131332e33000000100102030405060708090a0b0c0d0e0f100000000200000002000000500000000b3230332e302e3131332e34000000000000000200000011000001bb0000000c323030313a6462383a3a3232000000000000000100000010000001bb0000000c3139382e35312e3130302e31000000000000000100000401000001bb0000000b323030313a6462383a3a3100000020abababababababababababababababababababababababababababababababab0000000300000008000001bb0000000c3139382e35312e3130302e330000000000000001000000cb00000003010203000000030100010000014100002710000000640001d4c00000138800007530000003e8000493e000007530000005dc000000c80002a3000002a3000002a300000000010000001e0000000500000005000000640000001a00680074007400700073003a002f002f0074002e006d0065002f00093a8000004e2000015f90000075300000271000000004000000000000000100000000000004000000000227648000000000000005fffffff90000000800670069006600730000000c00760065006e007500650073";

/// 1.5.0's `MTP.Config(Test).Serialize()`.
const TEST_CONFIG: &str = "000000010000000100000124fffffffe000000060000000100000010000001bb0000000e3134392e3135342e3137352e3130000000000000000100000011000001bb00000027323030313a306232383a663233643a663030313a303030303a303030303a303030303a30303065000000000000000200000010000001bb0000000e3134392e3135342e3136372e3430000000000000000200000011000001bb00000027323030313a303637633a303465383a663030323a303030303a303030303a303030303a30303065000000000000000300000010000001bb0000000f3134392e3135342e3137352e313137000000000000000300000011000001bb00000027323030313a306232383a663233643a663030333a303030303a303030303a303030303a303030650000000000000000000000c800002710000000640001d4c00000138800007530000003e8000493e000007530000005dc000000c80002a3000002a3000002a300000000000000001e0000000500000005000000640000001a00680074007400700073003a002f002f0074002e006d0065002f00093a8000004e2000015f900000753000002710000000020000001c00740061007000760033002e007300740065006c002e0063006f006d00000001000000000000040000000004d83ddc4d00000000000000000024ea00000000100069007a0067006900660062006f00740000001a0066006f007500720073007100750061007200650062006f0074";

fn endpoint(id: i32, flags: i32, ip: &str, port: i32, secret: &[u8]) -> Endpoint {
    Endpoint {
        id,
        flags,
        ip: ip.to_owned(),
        port,
        secret: secret.to_vec(),
    }
}

#[test]
fn default_configs_round_trip() {
    let production = MtpConfig::new(Environment::Production);
    assert_eq!(
        production.serialize().expect("serialize"),
        MTP_CONFIG_PRODUCTION
    );
    let parsed = MtpConfig::parse(&MTP_CONFIG_PRODUCTION).expect("parse");
    assert_eq!(parsed, production);
    assert_eq!(
        parsed.serialize().expect("serialize"),
        MTP_CONFIG_PRODUCTION
    );

    let test_bytes = hex_bytes(TEST_CONFIG);
    let test = MtpConfig::new(Environment::Test);
    assert_eq!(test.serialize().expect("serialize test"), test_bytes);
    let parsed = MtpConfig::parse(&test_bytes).expect("parse test");
    assert_eq!(parsed, test);
    assert_eq!(parsed.environment, Environment::Test);

    // The production endpoints are the built-in table, IPv4 then IPv6.
    let dc2 = production.endpoints(2).expect("DC 2");
    let ips: Vec<&str> = dc2.ipv4.tcp.iter().map(|e| e.ip.as_str()).collect();
    assert_eq!(ips, ["149.154.167.51", "95.161.76.100"]);
    assert_eq!(dc2.ipv4.http, dc2.ipv4.tcp);
    assert_eq!(
        dc2.ipv6.tcp,
        [endpoint(
            2,
            FLAG_STATIC | FLAG_IPV6,
            "2001:067c:04e8:f002:0000:0000:0000:000a",
            443,
            &[]
        )]
    );
    assert!(production.endpoints(6).is_none());
    assert!(production.endpoints(0).is_none());
}

#[test]
fn custom_config_matches_1_5_0() {
    let bytes = hex_bytes(CUSTOM_CONFIG);
    let parsed = MtpConfig::parse(&bytes).expect("parse custom");
    assert_eq!(parsed.serialize().expect("serialize"), bytes);
    let ids: Vec<i32> = parsed.dc_options.dcs().map(|(id, _)| id).collect();
    assert_eq!(ids, [2, 1, 3], "DCs in first-seen order, 1001 not stored");

    // The same config built through the Rust API serializes identically.
    let mut built = MtpConfig::new(Environment::Production);
    let secret: Vec<u8> = (1..=16).collect();
    let options = &mut built.dc_options;
    *options = DcOptions::default();
    options.add(2, FLAG_IPV6 | FLAG_TCPO_ONLY, "2001:db8::2", 443, &[]);
    options.add(2, 0, "203.0.113.2", 443, &[]);
    options.add(2, FLAG_SECRET, "203.0.113.3", 8443, &secret);
    options.add(2, FLAG_STATIC, "203.0.113.2", 443, &[]);
    options.add(2, FLAG_MEDIA_ONLY, "203.0.113.4", 80, &[]);
    options.add(2, FLAG_IPV6 | FLAG_STATIC, "2001:db8::22", 443, &[]);
    options.add(1, FLAG_STATIC, "198.51.100.1", 443, &[]);
    options.add(1, FLAG_IPV6 | FLAG_SECRET, "2001:db8::1", 443, &[0xAB; 32]);
    options.add_shifted(10_003, FLAG_CDN, "198.51.100.3", 443, &[]);
    options.add(1001, 0, "198.51.100.9", 443, &[]);
    options.cdn_public_keys.push(RsaPublicKey {
        dc_id: 203,
        n: vec![1, 2, 3],
        e: vec![1, 0, 1],
    });
    let fields = &mut built.fields;
    fields.chat_size_max = 321;
    fields.revoke_private_inbox = true;
    fields.txt_domain_string = String::new();
    fields.reaction_default_emoji = "\u{2764}".to_owned();
    fields.reaction_default_custom = (1 << 63) + 5;
    fields.rating_decay = -7;
    fields.gif_search_username = "gifs".to_owned();
    fields.venue_search_username = "venues".to_owned();
    assert_eq!(built.serialize().expect("serialize built"), bytes);
    assert_eq!(built.fields, parsed.fields);
    // As in 1.5.0 the temporary DC is kept in memory but never serialized.
    assert!(built.endpoints(1001).is_some());
    assert!(parsed.endpoints(1001).is_none());
    assert_eq!((bare_dc_id(10_003), bare_dc_id(-1)), (3, 9_999));

    // `config.endpoints(dc)` of 1.5.0, by family and protocol.
    let dc1 = parsed.endpoints(1).expect("DC 1");
    let v4 = endpoint(1, FLAG_STATIC, "198.51.100.1", 443, &[]);
    let v6 = endpoint(1, FLAG_IPV6 | FLAG_SECRET, "2001:db8::1", 443, &[0xAB; 32]);
    assert_eq!(dc1.ipv4.tcp, [v4]);
    assert_eq!(dc1.ipv4.http, dc1.ipv4.tcp);
    assert_eq!(dc1.ipv6.tcp, [v6]);
    assert_eq!(dc1.ipv6.http, Vec::<Endpoint>::new());

    let dc2 = parsed.endpoints(2).expect("DC 2");
    let plain = endpoint(2, 0, "203.0.113.2", 443, &[]);
    let secret_ep = endpoint(2, FLAG_SECRET, "203.0.113.3", 8443, &secret);
    let media = endpoint(2, FLAG_MEDIA_ONLY, "203.0.113.4", 80, &[]);
    let tcpo = endpoint(2, FLAG_IPV6 | FLAG_TCPO_ONLY, "2001:db8::2", 443, &[]);
    let v6_static = endpoint(2, FLAG_IPV6 | FLAG_STATIC, "2001:db8::22", 443, &[]);
    assert_eq!(dc2.ipv4.tcp, [plain.clone(), secret_ep, media.clone()]);
    assert_eq!(dc2.ipv4.http, [plain, media]);
    assert_eq!(dc2.ipv6.tcp, [tcpo, v6_static.clone()]);
    assert_eq!(dc2.ipv6.http, [v6_static]);

    let dc3 = parsed.endpoints(3).expect("DC 3");
    let cdn = endpoint(3, FLAG_CDN, "198.51.100.3", 443, &[]);
    assert_eq!(dc3.ipv4.tcp, [cdn]);
    assert_eq!(dc3.ipv4.http, dc3.ipv4.tcp);
    assert_eq!(dc3.ipv6, ProtocolEndpoints::default());

    // `_select_endpoint_address` then the first TCP endpoint.
    for (dc, ipv6, ip) in [
        (1, false, "198.51.100.1"),
        (1, true, "2001:db8::1"),
        (2, false, "203.0.113.2"),
        (2, true, "2001:db8::2"),
        (3, false, "198.51.100.3"),
        (3, true, "198.51.100.3"),
    ] {
        let chosen = parsed
            .endpoints(dc)
            .and_then(|e| e.select(ipv6).cloned())
            .expect("selected endpoint");
        assert_eq!(
            (chosen.id, chosen.ip.as_str(), chosen.port),
            (dc, ip, 443),
            "DC {dc} ipv6 {ipv6}"
        );
    }
}

/// Serialized DC options and the bytes 1.5.0 re-serializes them to.
const LEGACY_DC_OPTIONS: [(&str, &str, &str); 3] = [
    (
        "version 1, duplicate dropped, trailing bytes ignored",
        "ffffffff000000030000000200000000000001bb00000007312e322e332e34000000000000000200000000000001bb00000007312e322e332e340000000201020000000400000001000001bb000000033a3a3100000000ffff",
        "fffffffe000000020000000200000000000001bb00000007312e322e332e34000000000000000400000001000001bb000000033a3a310000000000000000",
    ),
    (
        "version 0, no secrets",
        "0000000200000005000000100000005000000007352e362e372e3800000005000000000000005100000007352e362e372e38",
        "fffffffe0000000200000005000000100000005000000007352e362e372e380000000000000005000000000000005100000007352e362e372e380000000000000000",
    ),
    (
        "version 2, DC -1 not serialized, null CDN exponent, trailing junk",
        "fffffffe00000001ffffffff00000000000001bb00000007392e392e392e390000000000000001000000cb000000020102ffffffff6a756e6b",
        "fffffffe0000000000000001000000cb00000002010200000000",
    ),
];

fn be(values: &[i32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

#[test]
fn dc_options_versions_and_errors_match_1_5_0() {
    for (what, input, output) in LEGACY_DC_OPTIONS {
        let options = DcOptions::parse(&hex_bytes(input)).expect(what);
        assert_eq!(
            hex::encode(options.serialize().expect("serialize")),
            output,
            "{what}"
        );
    }
    let empty = "fffffffe0000000000000000";
    for input in [Vec::new(), be(&[-2, 0, -4])] {
        let options = DcOptions::parse(&input).expect("empty options");
        assert_eq!(hex::encode(options.serialize().expect("serialize")), empty);
    }

    let one = |ip_size: i32, ip: &[u8], rest: &[u8]| {
        let mut out = be(&[-2, 1, 1, 0, 443, ip_size]);
        out.extend_from_slice(ip);
        out.extend_from_slice(rest);
        out
    };
    let mut cut_ip = one(7, b"1.1.1.1", &[0, 0, 0, 0]);
    // Four of the seven IP bytes remain.
    cut_ip.truncate(28);
    let cut_cdn = [be(&[-2, 0, 1, 203, 2]), vec![1]].concat();
    for (what, input, code) in [
        ("ip size 0", one(0, b"", &[]), "TDATA_BAD_CONFIG_DATA"),
        (
            "ip size 46",
            one(46, &[b'1'; 46], &[]),
            "TDATA_BAD_CONFIG_DATA",
        ),
        (
            "secret size 33",
            one(7, b"1.1.1.1", &[&be(&[33])[..], &[0; 33]].concat()),
            "TDATA_BAD_CONFIG_DATA",
        ),
        (
            "secret size -1",
            one(7, b"1.1.1.1", &be(&[-1])),
            "TDATA_BAD_CONFIG_DATA",
        ),
        // A cut-short endpoint reads its IP size as 0 first, as in 1.5.0.
        ("cut after count", be(&[-2, 1]), "TDATA_BAD_CONFIG_DATA"),
        (
            "non-ASCII ip",
            one(2, b"\xc3\xa9", &be(&[0])),
            "TDATA_BAD_CONFIG_DATA",
        ),
        ("cut ip", cut_ip, "QDATASTREAM_FAILED"),
        (
            "cut secret",
            one(7, b"1.1.1.1", &[&be(&[4])[..], b"ab"].concat()),
            "QDATASTREAM_FAILED",
        ),
        ("cut CDN key", cut_cdn, "QDATASTREAM_FAILED"),
        (
            "cut CDN count",
            [be(&[-2, 0]), vec![0, 0]].concat(),
            "QDATASTREAM_FAILED",
        ),
    ] {
        assert_eq!(code_of(DcOptions::parse(&input)), code, "{what}");
    }
}

#[test]
fn config_tail_and_errors_match_1_5_0() {
    let full = &MTP_CONFIG_PRODUCTION[..];
    // The fixed part ends 54 bytes before the end: the tail is the emoji
    // string (8 bytes), a u64, an i32, and two strings of 10 and 24 bytes.
    let head = full.len() - 54;
    for cut in [head, head + 16, head + 20] {
        let parsed = MtpConfig::parse(&full[..cut]).expect("config without tail");
        assert_eq!(
            parsed.serialize().expect("serialize"),
            full,
            "missing tail groups keep their defaults (cut {cut})"
        );
    }
    let trailing = [full, b"zz"].concat();
    assert_eq!(
        MtpConfig::parse(&trailing)
            .expect("trailing bytes")
            .serialize()
            .expect("serialize"),
        full
    );

    let version_2 = [&be(&[2])[..], &full[4..]].concat();
    let environment_2 = [&full[..4], &be(&[2])[..], &full[8..]].concat();
    for (what, input, code) in [
        ("version 2", version_2, "TDATA_BAD_CONFIG_DATA"),
        ("environment 2", environment_2, "TDATA_BAD_CONFIG_DATA"),
        ("empty", Vec::new(), "TDATA_BAD_CONFIG_DATA"),
        ("cut field", full[..head - 2].to_vec(), "QDATASTREAM_FAILED"),
        ("cut tail", full[..head + 22].to_vec(), "QDATASTREAM_FAILED"),
    ] {
        assert_eq!(code_of(MtpConfig::parse(&input)), code, "{what}");
    }

    // A config that does not parse falls back to the production default.
    let mut account =
        Account::new(0, 1, 2, vec![(2, AuthKey::new([1; AuthKey::SIZE]))]).expect("account");
    account.config = Some(full[..head - 2].to_vec());
    assert_eq!(
        account.mtp_config(),
        MtpConfig::new(Environment::Production)
    );
    account.config = Some(hex_bytes(TEST_CONFIG));
    assert_eq!(account.mtp_config().environment, Environment::Test);
}

/// The bytes a [`QWriter`] closure writes.
fn qt(write: impl FnOnce(&mut QWriter)) -> Vec<u8> {
    let mut writer = QWriter::new();
    write(&mut writer);
    writer.into_bytes()
}

fn key_block(dc: i32, fill: u8) -> Vec<u8> {
    [
        qt(|w| {
            w.write_u32(DBI_KEY);
            w.write_i32(dc);
        }),
        vec![fill; AuthKey::SIZE],
    ]
    .concat()
}

fn authorization_block(blob: Option<&[u8]>) -> Vec<u8> {
    qt(|w| {
        w.write_u32(DBI_MTP_AUTHORIZATION);
        w.write_bytearray(blob).expect("blob");
    })
}

/// Every legacy block 1.5.0's `ReadSetting` reads: user 7 on DC 2 with keys
/// for DC 4 and DC 2, and the blocks that leave the account unchanged.
fn legacy_mtp_data() -> Vec<u8> {
    let options = DcOptions::built_in(Environment::Production)
        .serialize()
        .expect("options");
    let settings = qt(|w| {
        w.write_u32(DBI_DC_OPTION_OLD_OLD);
        w.write_u32(2);
        w.write_qstring(Some("unused")).expect("host");
        w.write_qstring(Some("149.154.167.51")).expect("ip");
        w.write_u32(443);
        w.write_u32(DBI_DC_OPTION_OLD);
        w.write_u32(10_002);
        w.write_i32(FLAG_IPV6);
        w.write_qstring(Some("::1")).expect("ip");
        w.write_u32(443);
        w.write_u32(DBI_DC_OPTIONS_OLD);
        w.write_bytearray(Some(&options)).expect("options");
        w.write_u32(DBI_APPLICATION_SETTINGS);
        w.write_bytearray(Some(b"settings")).expect("settings");
        for id in [
            DBI_CHAT_SIZE_MAX_OLD,
            DBI_SAVED_GIFS_LIMIT_OLD,
            DBI_STICKERS_RECENT_LIMIT_OLD,
            DBI_STICKERS_FAVED_LIMIT_OLD,
            DBI_MEGAGROUP_SIZE_MAX_OLD,
        ] {
            w.write_u32(id);
            w.write_i32(5);
        }
        w.write_u32(DBI_USER);
        w.write_i32(7);
        w.write_u32(2);
    });
    [settings, key_block(4, 5), key_block(2, 3)].concat()
}

#[test]
fn legacy_dbi_blocks_make_the_account() {
    let data = legacy_mtp_data();
    let account = Account::parse_mtp_data(3, &data).expect("legacy account");
    assert_eq!((account.index, account.user_id, account.main_dc), (3, 7, 2));
    let dcs: Vec<i32> = account.keys.iter().map(|(dc, _)| *dc).collect();
    assert_eq!(dcs, [4, 2]);
    assert!(account.keys_to_destroy.is_empty() && account.config.is_none());
    assert!(
        account.auth_key().expect("main key").as_bytes() == &[3; AuthKey::SIZE],
        "main key is not the DC 2 legacy key"
    );

    // A non-empty MtpAuthorization blob wins over the legacy blocks; the
    // last blob counts, and an empty or null one is none.
    let mut blob = mtp_blob(&[-1, 9], &[], &[]);
    blob.truncate(16);
    blob.extend_from_slice(&4_i32.to_be_bytes());
    blob.extend_from_slice(&mtp_blob(&[], &[(4, 6)], &[]));
    let with_blob = [data.clone(), authorization_block(Some(&blob))].concat();
    let account = Account::parse_mtp_data(0, &with_blob).expect("blob account");
    assert_eq!((account.user_id, account.main_dc), (9, 4));
    for last in [Some(&[][..]), None] {
        let cleared = [with_blob.clone(), authorization_block(last)].concat();
        let account = Account::parse_mtp_data(0, &cleared).expect("cleared blob");
        assert_eq!((account.user_id, account.main_dc), (7, 2), "{last:?}");
    }

    // Negative legacy user ids sign-extend as in the legacy blob layout.
    let negative = [
        qt(|w| {
            w.write_u32(DBI_USER);
            w.write_i32(-5);
            w.write_u32(1);
        }),
        key_block(1, 8),
    ]
    .concat();
    let account = Account::parse_mtp_data(0, &negative).expect("negative user");
    assert_eq!(account.user_id, (-5_i64).cast_unsigned());
}

#[test]
fn legacy_dbi_block_errors() {
    let data = legacy_mtp_data();
    let unknown = [data.clone(), qt(|w| w.write_u32(0x7F))].concat();
    let mut cut_key = data.clone();
    cut_key.pop();
    let bad_options = [
        data.clone(),
        qt(|w| {
            w.write_u32(DBI_DC_OPTIONS_OLD);
            w.write_bytearray(Some(&be(&[-2, 1, 1, 0, 443, 0])))
                .expect("options");
        }),
    ]
    .concat();
    let user_only = qt(|w| {
        w.write_u32(DBI_USER);
        w.write_i32(7);
        w.write_u32(2);
    });
    let no_main_key = [user_only.clone(), key_block(4, 1)].concat();
    for (what, input, code) in [
        ("unknown block", unknown, "TDATA_INVALID_MAGIC"),
        ("cut key", cut_key, "QDATASTREAM_FAILED"),
        (
            "cut block id",
            [data, vec![0, 0]].concat(),
            "QDATASTREAM_FAILED",
        ),
        ("bad legacy options", bad_options, "TDATA_BAD_CONFIG_DATA"),
        ("nothing", Vec::new(), "TDATA_AUTH_KEY_NOT_FOUND"),
        ("user only", user_only, "TDATA_AUTH_KEY_NOT_FOUND"),
        (
            "key without user",
            key_block(2, 1),
            "TDATA_AUTH_KEY_NOT_FOUND",
        ),
        ("no main key", no_main_key, "TDATA_AUTH_KEY_NOT_FOUND"),
    ] {
        assert_eq!(code_of(Account::parse_mtp_data(0, &input)), code, "{what}");
    }
}

#[test]
fn legacy_mtp_data_file_loads() {
    let dir = scratch_copy("performance_on");
    let tdata = TData::load(&dir, b"", None).expect("load");
    let key = tdata.local_key.clone();
    let first = folder_name(&data_name("data", 0));
    let encrypted =
        crypto::encrypt_local(&legacy_mtp_data(), &key, |len| vec![0; len]).expect("encrypt");
    let payload = qt(|w| w.write_bytearray(Some(&encrypted)).expect("payload"));
    tdf::write(
        &dir,
        &first,
        &TdfFile {
            version: 7_003_001,
            payload,
        },
    )
    .expect("write mtp data");

    let tdata = TData::load(&dir, b"", None).expect("load legacy");
    let account = &tdata.accounts[0];
    assert_eq!((account.index, account.user_id, account.main_dc), (0, 7, 2));
    assert!(
        Account::read(&dir, "data", 0, &key).is_ok(),
        "Account::read takes the legacy blocks"
    );
    assert!(matches!(
        Account::read_mtp_authorization(&dir, "data", &key),
        Err(Error::AuthKeyNotFound)
    ));
    fs::remove_dir_all(&dir).expect("clean scratch");
}
