//! Tests for the tdata glue the bindings share: `DrawSource` with
//! `TData::{new,save,migrate}_with_draws`, `DrawOperation::from_name`,
//! `BatchOptions::from_threads`, `LoadRequest::new` and
//! `Error::detail_code`. The messages are the ones the Python and Node
//! bindings show. Key bytes are never printed: file and key bytes are
//! compared with `assert!` without the values.

use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use opentele2_core::batch::{BatchOptions, LoadRequest};
use opentele2_core::crypto::AuthKey;
use opentele2_core::tdata::account::Account;
use opentele2_core::tdata::key_data::AccountsInfo;
use opentele2_core::tdata::{DrawOperation, DrawSource, NEW_FOLDER_ACTIVE_INDEX, TData, draw_plan};
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

/// A fresh, empty directory under the target tmp dir.
fn scratch(label: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "tdata_glue_{label}_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clear scratch");
    }
    dir
}

/// The draws recorded for `entry`, after the first `skip`.
fn recorded_draws(entry: &Value, skip: usize) -> Vec<Vec<u8>> {
    entry["rng_draws"]
        .as_array()
        .expect("rng_draws")
        .iter()
        .skip(skip)
        .map(|d| hex::decode(d.as_str().expect("draw hex")).expect("draw bytes"))
        .collect()
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

/// The written folder holds exactly the files of the vector `folder`.
fn assert_same_folder(folder: &str, written: &Path) {
    let entry = folder_entry(folder);
    let expected = vectors_dir().join(folder);
    for name in entry["files"].as_array().expect("files") {
        let name = name.as_str().expect("file name");
        let ours = fs::read(written.join(name)).expect("read written file");
        let theirs = fs::read(expected.join(name)).expect("read vector file");
        assert!(ours == theirs, "{folder}/{name} differs from the vector");
    }
}

/// The `what` and `reason` of an [`Error::InvalidInput`].
fn invalid_input<T>(result: Result<T>) -> (&'static str, String) {
    match result {
        Err(Error::InvalidInput { what, reason }) => (what, reason),
        Err(other) => panic!("expected INVALID_INPUT, got {}", other.code()),
        Ok(_) => panic!("expected INVALID_INPUT, got Ok"),
    }
}

#[test]
fn replayed_new_and_save_write_the_vector_files() {
    let folder = "tdata_plain/performance_off";
    let entry = folder_entry(folder);
    let draws = recorded_draws(&entry, 0);
    let plan = draw_plan(DrawOperation::New {
        has_passcode: false,
        performance_mode: false,
    })
    .expect("new plan");
    let (new_draws, save_draws) = draws.split_at(plan.len());

    let tdata = TData::new_with_draws(
        accounts_of(&entry),
        b"",
        false,
        NEW_FOLDER_ACTIVE_INDEX,
        DrawSource::replay(new_draws.to_vec()),
    )
    .expect("new with draws");
    assert_eq!(tdata.active_index, NEW_FOLDER_ACTIVE_INDEX);
    let written = scratch("new");
    tdata
        .save_with_draws(&written, None, DrawSource::new(Some(save_draws.to_vec())))
        .expect("save with draws");
    assert_same_folder(folder, &written);
    fs::remove_dir_all(&written).expect("clean scratch");
}

#[test]
fn new_with_draws_stores_the_active_index() {
    let entry = folder_entry("tdata_plain/performance_on");
    let tdata = TData::new_with_draws(accounts_of(&entry), b"", true, 1, DrawSource::os())
        .expect("new with draws");
    assert_eq!(tdata.active_index, 1);
    let replayed = TData::new_with_draws(
        accounts_of(&entry),
        b"",
        true,
        0,
        DrawSource::replay(Vec::new()),
    )
    .expect("performance mode without a passcode draws nothing");
    assert_eq!(replayed.active_index, 0);
}

#[test]
fn replay_mismatches_give_the_binding_messages() {
    let entry = folder_entry("tdata_plain/performance_on");
    let new = |draws: Vec<Vec<u8>>, performance_mode: bool| {
        TData::new_with_draws(
            accounts_of(&entry),
            b"",
            performance_mode,
            NEW_FOLDER_ACTIVE_INDEX,
            DrawSource::replay(draws),
        )
    };
    assert_eq!(
        invalid_input(new(vec![vec![0; 255]], false)),
        (
            "draws",
            "draw 0 has 255 bytes, but 256 were drawn".to_owned()
        )
    );
    assert_eq!(
        invalid_input(new(Vec::new(), false)),
        (
            "draws",
            "draw 0 of 256 bytes was not given (0 draws given)".to_owned()
        )
    );
    assert_eq!(
        invalid_input(new(vec![vec![1; 4]], true)),
        ("draws", "1 of 1 draws were left unused".to_owned())
    );
}

/// A replay mismatch is reported before the save's own failure, as the
/// bindings check the draws first.
#[test]
fn save_reports_the_draw_failure_first() {
    let entry = folder_entry("tdata_plain/performance_on");
    let mut empty =
        TData::new_with_draws(accounts_of(&entry), b"", true, 0, DrawSource::os()).expect("new");
    empty.accounts.clear();
    assert!(matches!(
        empty.save_with_draws(scratch("empty"), None, DrawSource::os()),
        Err(Error::SaveFailed)
    ));
    assert_eq!(
        invalid_input(empty.save_with_draws(
            scratch("empty"),
            None,
            DrawSource::replay(vec![vec![0; 8]])
        )),
        ("draws", "1 of 1 draws were left unused".to_owned())
    );
}

/// The per-save `performance_mode` applies to that save only.
#[test]
fn save_with_draws_overrides_performance_mode_for_one_save() {
    let folder = "tdata_plain/performance_off";
    let entry = folder_entry(folder);
    let loaded = TData::load(vectors_dir().join(folder), b"", None).expect("load vector");
    assert!(loaded.performance_mode, "load turns performance mode on");
    let key_generation = draw_plan(DrawOperation::New {
        has_passcode: false,
        performance_mode: false,
    })
    .expect("new plan")
    .len();
    let written = scratch("override");
    loaded
        .save_with_draws(
            &written,
            Some(false),
            DrawSource::replay(recorded_draws(&entry, key_generation)),
        )
        .expect("save without performance mode");
    assert!(loaded.performance_mode, "the folder keeps its mode");
    assert_same_folder(folder, &written);
    fs::remove_dir_all(&written).expect("clean scratch");

    let random = scratch("override_os");
    loaded
        .save_with_draws(&random, Some(false), DrawSource::os())
        .expect("save from the OS source");
    let reloaded = TData::load(&random, b"", None).expect("load saved folder");
    assert!(
        reloaded.local_key.as_bytes() == loaded.local_key.as_bytes(),
        "local key"
    );
    assert!(
        reloaded
            .accounts
            .iter()
            .all(|account| account.config.is_some()),
        "performance mode off writes configs"
    );
    fs::remove_dir_all(&random).expect("clean scratch");
}

#[test]
fn migrate_with_draws_keeps_the_folder_on_a_mismatch() {
    let source = "tdata_legacy/plain";
    let saved = folder_entry(&format!("{source}_saved"));
    let mut tdata = TData::load(vectors_dir().join(source), b"", None).expect("load legacy");
    let plan = draw_plan(DrawOperation::Migrate(&tdata)).expect("migrate plan");
    assert!(!plan.is_empty(), "a legacy folder migrates");

    let (what, reason) = invalid_input(tdata.migrate_with_draws(DrawSource::replay(Vec::new())));
    assert_eq!(what, "draws");
    assert_eq!(
        reason,
        format!("draw 0 of {} bytes was not given (0 draws given)", plan[0])
    );
    assert!(tdata.key_data.trailer.is_none(), "the folder is unchanged");

    let draws = recorded_draws(&saved, 0)[..plan.len()].to_vec();
    assert!(
        tdata
            .migrate_with_draws(DrawSource::replay(draws))
            .expect("migrate")
    );
    assert!(tdata.key_data.trailer.is_some(), "the folder is migrated");
    assert!(
        !tdata
            .migrate_with_draws(DrawSource::replay(Vec::new()))
            .expect("migrate again")
    );
}

#[test]
fn draw_source_debug_shows_counts_only() {
    let source = DrawSource::new(Some(vec![vec![0xab; 3], vec![0xcd; 2]]));
    assert!(source.is_replay());
    assert_eq!(
        format!("{source:?}"),
        "DrawSource { replay_draws: 2, next: 0, failed: false }"
    );
    let os = DrawSource::new(None);
    assert!(!os.is_replay());
    assert_eq!(
        format!("{os:?}"),
        "DrawSource { source: \"os\", failed: false }"
    );
    os.finish().expect("an unused OS source finishes");
}

#[test]
fn draw_operation_from_name_has_the_binding_defaults_and_messages() {
    assert!(matches!(
        DrawOperation::from_name("new", None, None, None),
        Ok(DrawOperation::New {
            has_passcode: false,
            performance_mode: true,
        })
    ));
    assert!(matches!(
        DrawOperation::from_name("new", Some(true), Some(false), None),
        Ok(DrawOperation::New {
            has_passcode: true,
            performance_mode: false,
        })
    ));
    assert_eq!(
        invalid_input(DrawOperation::from_name("load", None, None, None)),
        (
            "operation",
            "unknown operation \"load\"; expected one of new, migrate, save".to_owned()
        )
    );
    assert_eq!(
        invalid_input(DrawOperation::from_name("save", None, None, None)),
        ("target", "the \"save\" plan takes a TData".to_owned())
    );
    assert_eq!(
        invalid_input(DrawOperation::from_name("migrate", None, None, None)),
        ("target", "the \"migrate\" plan takes a TData".to_owned())
    );

    let folder = TData::load(vectors_dir().join("tdata_plain/performance_on"), b"", None)
        .expect("load vector");
    let (what, _) = invalid_input(DrawOperation::from_name("new", None, None, Some(&folder)));
    assert_eq!(what, "target");
    for name in DrawOperation::NAMES {
        let target = (name != "new").then_some(&folder);
        let operation = DrawOperation::from_name(name, None, None, target).expect("known name");
        assert_eq!(operation.name(), name);
    }
    assert!(matches!(
        DrawOperation::from_name("migrate", Some(true), None, Some(&folder)),
        Ok(DrawOperation::Migrate(_))
    ));
    assert!(matches!(
        DrawOperation::from_name("save", None, None, Some(&folder)),
        Ok(DrawOperation::Save(_))
    ));
}

#[test]
fn load_many_threads_must_be_at_least_one() {
    let message = ("threads", "threads must be at least 1".to_owned());
    assert_eq!(
        BatchOptions::from_threads(None::<usize>).expect("default"),
        BatchOptions::default()
    );
    assert_eq!(
        BatchOptions::from_threads(Some(4_u32))
            .expect("four")
            .threads,
        NonZeroUsize::new(4)
    );
    assert_eq!(
        invalid_input(BatchOptions::from_threads(Some(0_usize))),
        message
    );
    assert_eq!(
        invalid_input(BatchOptions::from_threads(Some(0_u32))),
        message
    );
    assert_eq!(
        invalid_input(BatchOptions::from_threads(Some(-1_i64))),
        message
    );
}

#[test]
fn load_request_new_fills_every_field() {
    let request = LoadRequest::new("tdata", b"pass".to_vec(), Some("alt".to_owned()));
    assert_eq!(
        request,
        LoadRequest {
            dir: PathBuf::from("tdata"),
            passcode: b"pass".to_vec(),
            key_file: Some("alt".to_owned()),
        }
    );
    let plain = LoadRequest::new(PathBuf::from("tdata"), Vec::new(), None);
    assert_eq!(plain.passcode, Vec::<u8>::new());
    assert_eq!(plain.key_file, None);
}

#[test]
fn bad_accounts_count_has_its_detail_code() {
    let error = AccountsInfo::parse(&[0, 0, 0, 0]).expect_err("count 0");
    assert_eq!(error.code(), "TDATA_KEY_DATA_INVALID");
    assert_eq!(error.detail_code(), Some("BAD_ACCOUNTS_COUNT"));
    assert!(
        error.legacy_message().starts_with("Bad accounts count 0"),
        "legacy message"
    );
    assert_eq!(Error::SaveFailed.detail_code(), None);
    assert_eq!(Error::WrongPasscode.detail_code(), None);
}
