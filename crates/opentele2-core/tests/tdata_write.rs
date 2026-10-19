//! Tests for `TData::new` and `TData::save` against the four 1.5.0 vector
//! folders in `tests/vectors` (described by `tdata.json`).
//!
//! Each folder is rebuilt from its account inputs while the recorded
//! `os.urandom` draws are replayed in order, and the written files must be
//! byte-identical to what 1.5.0 wrote. The pre-7.3 folders under
//! `tdata_legacy` are loaded and saved the same way and must match what
//! 1.5.0 migrated them to. Key bytes are never printed: every
//! comparison of file or key bytes uses `assert!` without the values.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use opentele2_core::Error;
use opentele2_core::crypto::AuthKey;
use opentele2_core::tdata::account::{Account, MTP_CONFIG_PRODUCTION, data_name, folder_name};
use opentele2_core::tdata::key_data::{
    AccountsInfo, DEFAULT_WRAP_GENERATION, default_passcode_kdf,
};
use opentele2_core::tdata::map::{
    LSK_BOT_STORAGES, LSK_DRAFT, LSK_USER_SETTINGS, LSK_WALLET_ENGINE_STORAGES, LSK_WEBVIEW_TOKENS,
    MapData, MapEntry, NEW_ACCOUNT_SETTINGS_KEY,
};
use opentele2_core::tdata::{APP_VERSION, NEW_FOLDER_ACTIVE_INDEX, TData};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn folder_entry(folder: &str) -> Value {
    let text = fs::read_to_string(vectors_dir().join("tdata.json")).expect("read vector manifest");
    let manifest: Value = serde_json::from_str(&text).expect("parse vector manifest");
    manifest["folders"][folder].clone()
}

/// A fresh, empty directory under the target tmp dir.
fn scratch(label: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "tdata_write_{label}_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clear scratch");
    }
    dir
}

/// Serves recorded draws in order; panics when a draw has another size.
struct Replay {
    draws: Vec<Vec<u8>>,
    next: usize,
}

impl Replay {
    fn new(entry: &Value, skip: usize) -> Self {
        let draws = entry["rng_draws"]
            .as_array()
            .expect("rng_draws")
            .iter()
            .skip(skip)
            .map(|d| hex::decode(d.as_str().expect("draw hex")).expect("draw bytes"))
            .collect();
        Self { draws, next: 0 }
    }

    fn fill(&mut self, buf: &mut [u8]) {
        let draw = self.draws.get(self.next).unwrap_or_else(|| {
            panic!("draw {} of {} bytes was not recorded", self.next, buf.len())
        });
        assert_eq!(buf.len(), draw.len(), "draw {} has another size", self.next);
        buf.copy_from_slice(draw);
        self.next += 1;
    }

    fn finish(&self) {
        assert_eq!(self.next, self.draws.len(), "recorded draws left unused");
    }
}

/// Every file under `dir`, relative and with `/` separators, sorted.
fn listed_files(dir: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for item in fs::read_dir(dir).expect("read dir") {
            let path = item.expect("dir entry").path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let relative = path.strip_prefix(root).expect("relative path");
                let parts: Vec<_> = relative
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                out.push(parts.join("/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

fn manifest_files(entry: &Value) -> Vec<String> {
    entry["files"]
        .as_array()
        .expect("files")
        .iter()
        .map(|f| f.as_str().expect("file name").to_owned())
        .collect()
}

/// The written folder holds exactly the files of `folder`, byte for byte.
fn assert_same_folder(folder: &str, written: &Path) {
    let entry = folder_entry(folder);
    let expected = vectors_dir().join(folder);
    let files = manifest_files(&entry);
    assert_eq!(listed_files(written), files, "{folder} file list");
    assert_eq!(listed_files(&expected), files, "{folder} vector file list");
    for name in &files {
        let ours = fs::read(written.join(name)).expect("read written file");
        let theirs = fs::read(expected.join(name)).expect("read vector file");
        assert!(ours == theirs, "{folder}/{name} differs from 1.5.0");
    }
}

fn passcode_of(entry: &Value) -> &[u8] {
    entry["passcode"].as_str().expect("passcode").as_bytes()
}

fn accounts_of(entry: &Value) -> Vec<Account> {
    entry["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .map(|a| {
            let index = i32::try_from(a["index"].as_i64().expect("index")).expect("i32 index");
            let main_dc = i32::try_from(a["main_dc"].as_i64().expect("dc")).expect("i32 dc");
            let user_id = a["user_id"].as_u64().expect("user id");
            let key = hex::decode(a["auth_key"].as_str().expect("auth key")).expect("key hex");
            let key = AuthKey::from_slice(&key).expect("256-byte key");
            Account::new(index, user_id, main_dc, vec![(main_dc, key)]).expect("account")
        })
        .collect()
}

/// Draws 1.5.0 makes before the first file: pass, salt, open salt, and for
/// a passcode the wrap salt, then the 12 bytes of wrap padding.
fn key_generation_draws(entry: &Value) -> usize {
    let performance = entry["performance_mode"].as_bool().expect("mode");
    match (performance, passcode_of(entry).is_empty()) {
        (true, true) => 0,
        (false, true) => 4,
        (_, false) => 5,
    }
}

fn assert_same_accounts(folder: &str, loaded: &TData, built: &[Account], performance: bool) {
    assert_eq!(loaded.accounts.len(), built.len(), "{folder} account count");
    for (ours, want) in loaded.accounts.iter().zip(built) {
        let index = want.index;
        assert_eq!(ours.index, index, "{folder} index");
        assert_eq!(ours.user_id, want.user_id, "{folder}/{index} user id");
        assert_eq!(ours.main_dc, want.main_dc, "{folder}/{index} main dc");
        assert_eq!(ours.keys.len(), want.keys.len(), "{folder}/{index} keys");
        for ((dc, key), (want_dc, want_key)) in ours.keys.iter().zip(&want.keys) {
            assert_eq!(dc, want_dc, "{folder}/{index} key dc");
            assert!(
                key.as_bytes() == want_key.as_bytes(),
                "{folder}/{index} key differs"
            );
        }
        assert!(
            ours.keys_to_destroy.is_empty(),
            "{folder}/{index} keys to destroy"
        );
        assert!(
            ours.map.encode_entries().expect("encode map")
                == want.map.encode_entries().expect("encode map"),
            "{folder}/{index} map"
        );
        let config = ours.config.as_deref();
        if performance {
            assert!(
                config.is_none(),
                "{folder}/{index} config written in performance mode"
            );
        } else {
            assert!(
                config == Some(&MTP_CONFIG_PRODUCTION[..]),
                "{folder}/{index} config"
            );
        }
    }
}

/// Rebuilds `folder` from its inputs and draws, checks the bytes, loads the
/// result back, and re-saves the vector folder itself.
fn check_folder(folder: &str) {
    let entry = folder_entry(folder);
    let passcode = passcode_of(&entry);
    let performance = entry["performance_mode"].as_bool().expect("mode");

    let mut replay = Replay::new(&entry, 0);
    let mut rng = |buf: &mut [u8]| replay.fill(buf);
    let tdata = TData::new(accounts_of(&entry), passcode, performance, &mut rng).expect("new");
    assert_eq!(tdata.active_index, NEW_FOLDER_ACTIVE_INDEX);
    assert_eq!(tdata.app_version, APP_VERSION);
    let written = scratch("new");
    tdata.save(&written, &mut rng).expect("save");
    replay.finish();
    assert_same_folder(folder, &written);

    let loaded = TData::load(&written, passcode, None).expect("load written folder");
    assert!(
        loaded.local_key.as_bytes() == tdata.local_key.as_bytes(),
        "{folder} local key"
    );
    assert_eq!(
        loaded.active_index, NEW_FOLDER_ACTIVE_INDEX,
        "{folder} active index"
    );
    assert_same_accounts(folder, &loaded, &tdata.accounts, performance);
    fs::remove_dir_all(&written).expect("clean scratch");

    // Load-then-save of the vector folder: the loaded key file is kept, so
    // only the padding draws after key generation are made.
    let mut vector = TData::load(vectors_dir().join(folder), passcode, None).expect("load vector");
    vector.performance_mode = performance;
    let mut replay = Replay::new(&entry, key_generation_draws(&entry));
    let resaved = scratch("resave");
    vector
        .save(&resaved, &mut |buf| replay.fill(buf))
        .expect("re-save");
    replay.finish();
    assert_same_folder(folder, &resaved);
    fs::remove_dir_all(&resaved).expect("clean scratch");
}

#[test]
fn plain_performance_on_writes_like_1_5_0() {
    check_folder("tdata_plain/performance_on");
}

#[test]
fn plain_performance_off_writes_like_1_5_0() {
    check_folder("tdata_plain/performance_off");
}

#[test]
fn passcode_performance_on_writes_like_1_5_0() {
    check_folder("tdata_passcode/performance_on");
}

#[test]
fn passcode_performance_off_writes_like_1_5_0() {
    check_folder("tdata_passcode/performance_off");
}

#[test]
fn production_config_matches_the_vector_configs() {
    let tdata = TData::load(vectors_dir().join("tdata_plain/performance_off"), b"", None)
        .expect("load vector");
    assert_eq!(tdata.accounts.len(), 2);
    for account in &tdata.accounts {
        assert_eq!(
            account.config.as_deref(),
            Some(&MTP_CONFIG_PRODUCTION[..]),
            "decrypted configs of account {}",
            account.index
        );
    }
}

#[test]
fn save_random_writes_a_loadable_folder() {
    let entry = folder_entry("tdata_plain/performance_off");
    let mut tdata = TData::new(accounts_of(&entry), b"", true, &mut |_| {
        panic!("performance mode without a passcode draws nothing at creation")
    })
    .expect("new");
    tdata.performance_mode = false;
    tdata.active_index = 1;
    let dir = scratch("random");
    tdata.save_random(&dir).expect("save random");
    assert_eq!(listed_files(&dir), manifest_files(&entry));
    let loaded = TData::load(&dir, b"", None).expect("load");
    assert_eq!(loaded.active_index, 1);
    assert_eq!(loaded.main_account().expect("main").index, 1);
    assert_same_accounts("random", &loaded, &tdata.accounts, false);
    fs::remove_dir_all(&dir).expect("clean scratch");
}

#[test]
fn save_refuses_what_1_5_0_cannot_write() {
    let entry = folder_entry("tdata_plain/performance_on");
    let mut no_draw = |_: &mut [u8]| {};
    let tdata = TData::new(accounts_of(&entry), b"", true, &mut no_draw).expect("new");

    let mut empty = tdata.clone();
    empty.accounts.clear();
    assert!(matches!(
        empty.save(scratch("empty"), &mut no_draw),
        Err(Error::SaveFailed)
    ));

    let mut no_map = tdata.clone();
    no_map.accounts[0].map = MapData::default();
    assert!(matches!(
        no_map.save(scratch("nomap"), &mut no_draw),
        Err(Error::SaveFailed)
    ));
}

/// Loads the pre-7.3 vector `tdata_legacy/<name>`, saves it while the draws
/// 1.5.0's `SaveTData` made are replayed, and checks the migrated folder
/// against `tdata_legacy/<name>_saved` byte for byte.
fn check_legacy_migration(name: &str) {
    let source = format!("tdata_legacy/{name}");
    let target = format!("{source}_saved");
    let entry = folder_entry(&source);
    let saved_entry = folder_entry(&target);
    assert_eq!(saved_entry["source"].as_str(), Some(source.as_str()));
    let passcode = passcode_of(&entry);
    assert_eq!(passcode_of(&saved_entry), passcode, "{target} passcode");
    let accounts = accounts_of(&entry);

    let legacy = TData::load(vectors_dir().join(&source), passcode, None).expect("load legacy");
    assert!(legacy.key_data.trailer.is_none(), "{source} has a trailer");
    let main = legacy.main_account().expect("main account").index;
    assert_eq!(
        Some(i64::from(main)),
        entry["main_account_index"].as_i64(),
        "{source} main account"
    );
    assert_same_accounts(&source, &legacy, &accounts, false);

    let mut replay = Replay::new(&saved_entry, 0);
    let written = scratch("legacy");
    legacy
        .save(&written, &mut |buf| replay.fill(buf))
        .expect("save migrates the legacy key file");
    replay.finish();
    assert_same_folder(&target, &written);

    let migrated = TData::load(&written, passcode, None).expect("load migrated folder");
    assert!(
        migrated.local_key.as_bytes() == legacy.local_key.as_bytes(),
        "{target} local key"
    );
    assert_eq!(
        migrated.active_index, legacy.active_index,
        "{target} active"
    );
    assert_eq!(
        migrated.main_account().expect("main account").index,
        main,
        "{target} main account"
    );
    assert_same_accounts(&target, &migrated, &accounts, true);
    let trailer = migrated.key_data.trailer.as_ref().expect("7.3 trailer");
    if passcode.is_empty() {
        assert!(
            migrated.key_data.key_encrypted.is_some(),
            "{target} open wrap"
        );
        assert!(trailer.wraps.is_empty(), "{target} passcode wraps");
    } else {
        assert!(
            migrated.key_data.key_encrypted.is_none(),
            "{target} open wrap"
        );
        assert_eq!(trailer.committed, DEFAULT_WRAP_GENERATION);
        assert_eq!(trailer.wraps.len(), 1, "{target} passcode wraps");
        assert_eq!(trailer.wraps[0].kdf, default_passcode_kdf());
        assert!(matches!(
            TData::load(&written, b"", None),
            Err(Error::BadDecryptKey)
        ));
    }
    fs::remove_dir_all(&written).expect("clean scratch");
}

#[test]
fn legacy_plain_folder_migrates_like_1_5_0() {
    check_legacy_migration("plain");
}

#[test]
fn legacy_passcode_folder_migrates_like_1_5_0() {
    check_legacy_migration("passcode");
}

/// Loads `tdata_legacy/<name>`, migrates it in place with the first draws
/// 1.5.0's `SaveTData` made, then saves it twice with the remaining draws:
/// both saves write `tdata_legacy/<name>_saved` byte for byte, so the second
/// save does not migrate again.
fn check_migrate_then_save_twice(name: &str) {
    let source = format!("tdata_legacy/{name}");
    let target = format!("{source}_saved");
    let entry = folder_entry(&source);
    let saved_entry = folder_entry(&target);
    let passcode = passcode_of(&entry);
    let mut tdata = TData::load(vectors_dir().join(&source), passcode, None).expect("load legacy");
    let local_key = tdata.local_key.as_bytes().to_vec();

    let mut replay = Replay::new(&saved_entry, 0);
    assert!(
        tdata.migrate(&mut |buf| replay.fill(buf)).expect("migrate"),
        "{source} migrates"
    );
    let migration_draws = replay.next;
    assert!(migration_draws > 0, "{source} migration draws");
    assert!(
        tdata.key_data.trailer.is_some(),
        "{source} has a trailer now"
    );
    assert!(
        tdata.local_key.as_bytes() == local_key.as_slice(),
        "{source} local key"
    );
    let mut no_draw = |_: &mut [u8]| panic!("a migrated folder migrates again");
    assert!(!tdata.migrate(&mut no_draw).expect("migrate again"));

    for round in 0..2 {
        let mut replay = Replay::new(&saved_entry, migration_draws);
        let written = scratch(&format!("migrate_{round}"));
        tdata
            .save(&written, &mut |buf| replay.fill(buf))
            .expect("save migrated");
        replay.finish();
        assert_same_folder(&target, &written);
        fs::remove_dir_all(&written).expect("clean scratch");
    }

    let migrated = TData::load(vectors_dir().join(&target), passcode, None).expect("load saved");
    assert!(
        migrated.passcode_key.as_bytes() == tdata.passcode_key.as_bytes(),
        "{source} passcode key is the new wrap key"
    );
}

#[test]
fn legacy_plain_folder_migrates_once_then_saves_alike() {
    check_migrate_then_save_twice("plain");
}

#[test]
fn legacy_passcode_folder_migrates_once_then_saves_alike() {
    check_migrate_then_save_twice("passcode");
}

#[test]
fn legacy_layout_is_migrated_not_refused() {
    let entry = folder_entry("tdata_plain/performance_on");
    let mut no_draw = |_: &mut [u8]| {};
    let mut legacy = TData::new(accounts_of(&entry), b"", true, &mut no_draw).expect("new");
    legacy.key_data.trailer = None;
    let mut next = 0u8;
    let dir = scratch("legacy_new");
    legacy
        .save(&dir, &mut |buf| {
            for byte in buf {
                next = next.wrapping_add(1);
                *byte = next;
            }
        })
        .expect("save migrates");
    let loaded = TData::load(&dir, b"", None).expect("load migrated");
    assert!(
        loaded.key_data.trailer.is_some(),
        "migrated key file has a trailer"
    );
    assert!(
        loaded.key_data.salt != legacy.key_data.salt,
        "migration draws a fresh open salt"
    );
    assert!(
        loaded.local_key.as_bytes() == legacy.local_key.as_bytes(),
        "migration keeps the local key"
    );
    assert_same_accounts("legacy_new", &loaded, &legacy.accounts, true);
    fs::remove_dir_all(&dir).expect("clean scratch");
}

#[test]
fn debug_never_shows_the_passcode() {
    let entry = folder_entry("tdata_passcode/performance_on");
    let tdata = TData::load(
        vectors_dir().join("tdata_passcode/performance_on"),
        passcode_of(&entry),
        None,
    )
    .expect("load vector");
    let text = format!("{tdata:?}");
    let passcode = std::str::from_utf8(passcode_of(&entry)).expect("utf-8 passcode");
    assert!(!text.contains(passcode), "passcode leaked into Debug");
    assert!(!text.contains("passcode:"), "passcode field in Debug");
}

#[test]
fn new_account_needs_a_main_dc_key() {
    let key = AuthKey::new([3; AuthKey::SIZE]);
    assert!(matches!(
        Account::new(0, 1, 2, vec![(1, key)]),
        Err(Error::AuthKeyNotFound)
    ));
}

#[test]
fn accounts_info_encodes_count_indices_and_active() {
    let info = AccountsInfo {
        indices: vec![0, 3, -1],
        active_index: -1,
    };
    let encoded = info.encode().expect("encode");
    assert_eq!(
        hex::encode(&encoded),
        // count 3, indices 0, 3, -1, active -1
        "00000003_00000000_00000003_ffffffff_ffffffff".replace('_', "")
    );
    assert_eq!(AccountsInfo::parse(&encoded).expect("parse"), info);
}

#[test]
fn mtp_data_is_the_dbi_block() {
    let key = AuthKey::new([5; AuthKey::SIZE]);
    let account = Account::new(1, 7, 2, vec![(2, key)]).expect("account");
    let data = account.encode_mtp_data().expect("encode");
    let blob = account.encode_mtp_authorization().expect("blob");
    assert_eq!(&data[..4], &[0, 0, 0, 0x4B]);
    let len = u32::try_from(blob.len()).expect("len");
    assert_eq!(&data[4..8], &len.to_be_bytes());
    assert!(data[8..] == blob[..], "the block holds the blob");
}

fn u32_hex(value: u32) -> String {
    hex::encode(value.to_be_bytes())
}

fn u64_hex(value: u64) -> String {
    hex::encode(value.to_be_bytes())
}

#[test]
fn new_account_map_is_the_hardcoded_settings_key() {
    let map = MapData::new_account();
    assert_eq!(map.version, APP_VERSION);
    assert_eq!(
        hex::encode(map.encode_entries().expect("encode")),
        u32_hex(LSK_USER_SETTINGS) + &u64_hex(NEW_ACCOUNT_SETTINGS_KEY)
    );
}

#[test]
fn loaded_map_reencodes_in_the_1_5_0_shape() {
    let flag = 0x80u64 << 48;
    let map = MapData {
        entries: vec![
            // Background (old) and a later day key from the oldest type.
            MapEntry::FileKeys {
                kind: 0x14,
                keys: vec![11, 12],
            },
            MapEntry::FileKeys {
                kind: 0x08,
                keys: vec![13],
            },
            // Dropped: an old skip type and a legacy wallet key.
            MapEntry::FileKeys {
                kind: 0x0D,
                keys: vec![99],
            },
            MapEntry::FileKeys {
                kind: 0x1F,
                keys: vec![98],
            },
            // A zero key is not written.
            MapEntry::FileKeys {
                kind: 0x04,
                keys: vec![0],
            },
            // Old stickers fill the installed stickers key of the group.
            MapEntry::FileKeys {
                kind: 0x0B,
                keys: vec![21],
            },
            MapEntry::PeerKeys {
                kind: LSK_DRAFT,
                // A modern user, a legacy channel, then the user again.
                pairs: vec![(1, 5 | flag), (2, 0x2_0000_0007), (3, 5 | flag)],
            },
            MapEntry::PeerKeys {
                kind: LSK_DRAFT,
                // A legacy user equal to the modern one, an unknown type.
                pairs: vec![(4, 5), (6, 0x3_0000_0009)],
            },
            MapEntry::LegacyLocations {
                kind: 0x03,
                items: vec![(1, 2, 3, 4)],
            },
            MapEntry::SelfSerialized(Some(vec![0xAA])),
            MapEntry::SelfSerialized(Some(Vec::new())),
            MapEntry::WebviewTokens {
                bots: None,
                other: Some(vec![0xBB]),
            },
            MapEntry::WalletEngineStorages(vec![(1, Some("old".to_owned()))]),
            MapEntry::WalletEngineStorages(vec![(8, Some("b".to_owned())), (9, None)]),
            MapEntry::PeerKeys {
                kind: LSK_BOT_STORAGES,
                pairs: vec![(31, 0xF_0000_0001)],
            },
        ],
        ..MapData::default()
    };
    let expected = [
        // The self user is empty at the end, so it is not written.
        u32_hex(LSK_DRAFT),
        u32_hex(3),
        u64_hex(4) + &u64_hex(5 | flag),
        u64_hex(2) + &u64_hex(7 | (2 << 48) | flag),
        u64_hex(6) + &u64_hex(flag),
        // No draft positions.
        u32_hex(LSK_BOT_STORAGES),
        u32_hex(1),
        u64_hex(31) + &u64_hex(1 | (0x7F << 48) | flag),
        u32_hex(0x10),
        u64_hex(21) + &u64_hex(0) + &u64_hex(0) + &u64_hex(0),
        u32_hex(LSK_WEBVIEW_TOKENS),
        "ffffffff".to_owned() + "00000001bb",
        u32_hex(LSK_WALLET_ENGINE_STORAGES),
        u32_hex(2),
        u64_hex(9) + "00000000",
        u64_hex(8) + "000000020062",
        u32_hex(0x14),
        u64_hex(13) + &u64_hex(12),
    ]
    .concat();
    assert_eq!(hex::encode(map.encode_entries().expect("encode")), expected);
    // The same stream parsed by 1.5.0's `MapData._parseMapStream` and written
    // by `prepareToWrite` (the bytes after the length header).
    let from_1_5_0 = concat!(
        "00000001000000030000000000000004008000000000000500000000000000020082000000000007",
        "000000000000000600800000000000000000001d00000001000000000000001f00ff000000000001",
        "0000001000000000000000150000000000000000000000000000000000000000000000000000001",
        "9ffffffff00000001bb0000002100000002000000000000000900000000000000000000000800000",
        "002006200000014000000000000000d000000000000000c",
    );
    assert_eq!(expected, from_1_5_0);
}

#[test]
fn account_files_land_where_the_reader_looks() {
    let entry = folder_entry("tdata_plain/performance_on");
    let mut no_draw = |_: &mut [u8]| {};
    let mut tdata = TData::new(accounts_of(&entry), b"", true, &mut no_draw).expect("new");
    tdata.key_file = "other".to_owned();
    let dir = scratch("keyfile");
    tdata.save(&dir, &mut |_| {}).expect("save");
    let files = listed_files(&dir);
    for index in [0, 1] {
        let part = folder_name(&data_name("other", index));
        assert!(files.contains(&format!("{part}s")), "{part}s");
        assert!(files.contains(&format!("{part}/maps")), "{part}/maps");
    }
    assert!(files.contains(&"key_others".to_owned()));
    let loaded = TData::load(&dir, b"", Some("other")).expect("load");
    assert_eq!(loaded.accounts.len(), 2);
    fs::remove_dir_all(&dir).expect("clean scratch");
}

/// (user id, main DC, auth key) of every account input of `entry`.
fn account_inputs(entry: &Value) -> Vec<(u64, i32, AuthKey)> {
    accounts_of(entry)
        .iter()
        .map(|a| {
            (
                a.user_id,
                a.main_dc,
                a.auth_key().expect("main key").clone(),
            )
        })
        .collect()
}

/// Builds `folder` with `TData::new` on no account, adds its accounts one
/// by one with `add_account`, and saves it while the recorded draws are
/// replayed: the files are the ones 1.5.0 wrote, since without gaps the
/// lowest free index is 1.5.0's account count.
fn check_added_to_new_folder(folder: &str) {
    let entry = folder_entry(folder);
    let passcode = passcode_of(&entry);
    let performance = entry["performance_mode"].as_bool().expect("mode");
    let mut replay = Replay::new(&entry, 0);
    let mut rng = |buf: &mut [u8]| replay.fill(buf);
    let mut tdata = TData::new(Vec::new(), passcode, performance, &mut rng).expect("new");
    assert!(tdata.main_account().is_none(), "{folder} empty folder");
    for (want, (user_id, main_dc, key)) in (0..).zip(account_inputs(&entry)) {
        assert_eq!(tdata.add_account(user_id, main_dc, key).expect("add"), want);
        assert_eq!(tdata.main_account().expect("main").index, 0, "{folder}");
    }
    let written = scratch("added_new");
    tdata.save(&written, &mut rng).expect("save");
    replay.finish();
    assert_same_folder(folder, &written);
    let loaded = TData::load(&written, passcode, None).expect("load added folder");
    assert_same_accounts(folder, &loaded, &accounts_of(&entry), performance);
    assert_eq!(loaded.main_account().expect("main").index, 0);
    fs::remove_dir_all(&written).expect("clean scratch");
}

#[test]
fn accounts_added_to_a_new_plain_folder_write_like_1_5_0() {
    check_added_to_new_folder("tdata_plain/performance_on");
    check_added_to_new_folder("tdata_plain/performance_off");
}

#[test]
fn accounts_added_to_a_new_passcode_folder_write_like_1_5_0() {
    check_added_to_new_folder("tdata_passcode/performance_on");
    check_added_to_new_folder("tdata_passcode/performance_off");
}

/// Loads the vector `folder`, adds one account, and saves it: the recorded
/// draws are replayed while they fit, then counted bytes are drawn, so the
/// two loaded accounts are written byte for byte as 1.5.0 wrote them and
/// the added one follows. The reload holds all three.
fn check_added_to_loaded_folder(folder: &str) {
    let entry = folder_entry(folder);
    let passcode = passcode_of(&entry);
    let performance = entry["performance_mode"].as_bool().expect("mode");
    let mut tdata = TData::load(vectors_dir().join(folder), passcode, None).expect("load vector");
    tdata.performance_mode = performance;
    let main = tdata.main_account().expect("main").index;
    let key = AuthKey::new([0x5A; AuthKey::SIZE]);
    assert_eq!(tdata.add_account(777, 3, key).expect("add"), 2);
    assert_eq!(tdata.main_account().expect("main").index, main, "{folder}");

    let mut replay = Replay::new(&entry, key_generation_draws(&entry));
    let mut next = 0u8;
    let written = scratch("added_loaded");
    tdata
        .save(&written, &mut |buf| {
            let fits = replay
                .draws
                .get(replay.next)
                .is_some_and(|draw| draw.len() == buf.len());
            if fits {
                replay.fill(buf);
            } else {
                // Past the recorded draws: no draw from now on is replayed.
                replay.next = replay.draws.len();
                for byte in buf {
                    next = next.wrapping_add(1);
                    *byte = next;
                }
            }
        })
        .expect("save");
    let expected = vectors_dir().join(folder);
    let files = listed_files(&written);
    for name in manifest_files(&entry) {
        assert!(files.contains(&name), "{folder}/{name} written");
        if !name.starts_with("key_") {
            let ours = fs::read(written.join(&name)).expect("read written file");
            let theirs = fs::read(expected.join(&name)).expect("read vector file");
            assert!(ours == theirs, "{folder}/{name} differs from 1.5.0");
        }
    }
    let part = folder_name(&data_name("data", 2));
    assert!(files.contains(&format!("{part}s")), "{part}s");
    assert!(files.contains(&format!("{part}/maps")), "{part}/maps");

    let loaded = TData::load(&written, passcode, None).expect("load added folder");
    assert_same_accounts(folder, &loaded, &tdata.accounts, performance);
    assert_eq!(loaded.main_account().expect("main").index, main);
    fs::remove_dir_all(&written).expect("clean scratch");
}

#[test]
fn account_added_to_a_loaded_folder_saves_and_reloads() {
    check_added_to_loaded_folder("tdata_plain/performance_on");
    check_added_to_loaded_folder("tdata_passcode/performance_off");
}

#[test]
fn seventh_account_is_refused_like_1_5_0() {
    assert_eq!(TData::MAX_ACCOUNTS, 6);
    let mut no_draw = |_: &mut [u8]| {};
    let mut tdata = TData::new(Vec::new(), b"", true, &mut no_draw).expect("new");
    for want in 0..6_i32 {
        let key = AuthKey::new([want.to_le_bytes()[0] + 1; AuthKey::SIZE]);
        assert_eq!(tdata.add_account(100, 2, key).expect("add"), want);
    }
    let refused = tdata.add_account(100, 2, AuthKey::new([9; AuthKey::SIZE]));
    let error = refused.expect_err("seventh account");
    assert!(matches!(error, Error::MaxAccountLimit));
    assert_eq!(error.code(), "MAX_ACCOUNT_LIMIT");
    assert_eq!(tdata.accounts.len(), TData::MAX_ACCOUNTS);

    let mut loaded = TData::load(vectors_dir().join("tdata_plain/performance_on"), b"", None)
        .expect("load vector");
    for want in 2..6 {
        let key = AuthKey::new([7; AuthKey::SIZE]);
        assert_eq!(loaded.add_account(200, 4, key).expect("add"), want);
    }
    assert!(matches!(
        loaded.add_account(200, 4, AuthKey::new([7; AuthKey::SIZE])),
        Err(Error::MaxAccountLimit)
    ));
    let dir = scratch("six");
    loaded.save_random(&dir).expect("save six");
    let reloaded = TData::load(&dir, b"", None).expect("load six");
    let indices: Vec<i32> = reloaded.accounts.iter().map(|a| a.index).collect();
    assert_eq!(indices, [0, 1, 2, 3, 4, 5]);
    fs::remove_dir_all(&dir).expect("clean scratch");
}

/// tdesktop's rule, not 1.5.0's count: a folder holding indices `[0, 2]`
/// gets 1, never a second 2 that would overwrite the files of account 2.
#[test]
fn added_account_takes_the_lowest_free_index() {
    let entry = folder_entry("tdata_plain/performance_on");
    let mut accounts = accounts_of(&entry);
    accounts[1].index = 2;
    let mut no_draw = |_: &mut [u8]| {};
    let gapped = TData::new(accounts, b"", true, &mut no_draw).expect("new");
    let first = scratch("gap_first");
    gapped.save_random(&first).expect("save gapped");

    let mut tdata = TData::load(&first, b"", None).expect("load gapped");
    let indices: Vec<i32> = tdata.accounts.iter().map(|a| a.index).collect();
    assert_eq!(indices, [0, 2]);
    let key = AuthKey::new([0x3C; AuthKey::SIZE]);
    assert_eq!(tdata.add_account(888, 1, key).expect("add"), 1);
    assert_eq!(tdata.active_index, NEW_FOLDER_ACTIVE_INDEX);
    assert_eq!(tdata.main_account().expect("main").index, 0);
    assert_eq!(
        tdata
            .add_account(889, 1, AuthKey::new([0x3D; AuthKey::SIZE]))
            .expect("add"),
        3
    );

    let second = scratch("gap_second");
    tdata
        .save_random(&second)
        .expect("save with the added accounts");
    let files = listed_files(&second);
    for index in [0, 1, 2, 3] {
        let part = folder_name(&data_name("data", index));
        assert!(files.contains(&format!("{part}s")), "{part}s");
        assert!(files.contains(&format!("{part}/maps")), "{part}/maps");
    }
    let reloaded = TData::load(&second, b"", None).expect("reload");
    let indices: Vec<i32> = reloaded.accounts.iter().map(|a| a.index).collect();
    assert_eq!(indices, [0, 2, 1, 3]);
    let users: Vec<u64> = reloaded.accounts.iter().map(|a| a.user_id).collect();
    assert_eq!(users, [100_000_001, 5_000_000_123, 888, 889]);
    assert_same_accounts("gap", &reloaded, &tdata.accounts, true);
    fs::remove_dir_all(&first).expect("clean scratch");
    fs::remove_dir_all(&second).expect("clean scratch");
}

#[test]
fn empty_key_file_name_is_refused() {
    let mut no_draw = |_: &mut [u8]| {};
    let mut tdata = TData::new(Vec::new(), b"", true, &mut no_draw).expect("new");
    assert!(matches!(tdata.set_key_file(""), Err(Error::SaveFailed)));
    assert_eq!(tdata.key_file, "data");
    tdata.set_key_file("renamed").expect("rename");
    assert_eq!(tdata.key_file, "renamed");
}

// What 1.5.0 writes for key file "renamed" from tdata_plain/performance_on,
// captured with `python -c` (OPENTELE_NO_FETCH=1, output under target/):
// both accounts given the key file before `SaveTData()`, as
// `Account.FromTelethon` does with `owner.keyFile`.
const RENAMED_FILES_1_5_0: [&str; 5] = [
    "41C3059FCB9A4788/maps",
    "41C3059FCB9A4788s",
    "CAAC63A284752796/maps",
    "CAAC63A284752796s",
    "key_renameds",
];
// `SaveTData(keyFile="renamed")` on the first account alone. On both
// accounts 1.5.0 hands the raw name to every account, so the second one
// overwrites the first under `CAAC63A284752796` and the reload holds one
// account; the composed names above are the loadable layout.
const RENAMED_SINGLE_FILES_1_5_0: [&str; 3] =
    ["CAAC63A284752796/maps", "CAAC63A284752796s", "key_renameds"];

/// The files of `count` accounts under key file `name`, from the helpers.
fn composed_files(name: &str, count: i32) -> Vec<String> {
    let mut files: Vec<String> = (0..count)
        .flat_map(|index| {
            let part = folder_name(&data_name(name, index));
            [format!("{part}/maps"), format!("{part}s")]
        })
        .chain([format!("key_{name}s")])
        .collect();
    files.sort();
    files
}

#[test]
fn renamed_key_file_writes_the_1_5_0_names() {
    let folder = "tdata_plain/performance_on";
    let entry = folder_entry(folder);
    let mut tdata = TData::load(vectors_dir().join(folder), b"", None).expect("load vector");
    tdata.set_key_file("renamed").expect("rename");
    let mut replay = Replay::new(&entry, key_generation_draws(&entry));
    let written = scratch("renamed");
    tdata
        .save(&written, &mut |buf| replay.fill(buf))
        .expect("save renamed");
    replay.finish();
    let files = listed_files(&written);
    assert_eq!(files, RENAMED_FILES_1_5_0);
    assert_eq!(files, composed_files("renamed", 2));

    // Only the names change: each file holds the bytes 1.5.0 wrote.
    let expected = vectors_dir().join(folder);
    let renamed = |name: &str| {
        let mut name = name.replace("key_datas", "key_renameds");
        for index in [0, 1] {
            let from = folder_name(&data_name("data", index));
            let to = folder_name(&data_name("renamed", index));
            name = name.replace(&from, &to);
        }
        name
    };
    for name in manifest_files(&entry) {
        let ours = fs::read(written.join(renamed(&name))).expect("read written file");
        let theirs = fs::read(expected.join(&name)).expect("read vector file");
        assert!(ours == theirs, "{folder}/{name} differs once renamed");
    }
    let loaded = TData::load(&written, b"", Some("renamed")).expect("load renamed");
    assert_eq!(loaded.key_file, "renamed");
    assert_same_accounts(folder, &loaded, &tdata.accounts, true);
    assert!(matches!(
        TData::load(&written, b"", None),
        Err(Error::FileNotFound | Error::Io(_))
    ));
    fs::remove_dir_all(&written).expect("clean scratch");

    let mut single = TData::load(vectors_dir().join(folder), b"", None).expect("load vector");
    single.accounts.truncate(1);
    single.set_key_file("renamed").expect("rename");
    let written = scratch("renamed_single");
    single.save_random(&written).expect("save single");
    let files = listed_files(&written);
    assert_eq!(files, RENAMED_SINGLE_FILES_1_5_0);
    assert_eq!(files, composed_files("renamed", 1));
    let loaded = TData::load(&written, b"", Some("renamed")).expect("load single");
    assert_same_accounts(folder, &loaded, &single.accounts, true);
    fs::remove_dir_all(&written).expect("clean scratch");
}
