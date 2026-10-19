//! Tests for `batch::{load_many, map_many}` against the four vector folders
//! in `tests/vectors` (described by `tdata.json`).
//!
//! Results are compared with sequential `TData::load` item by item. Key
//! bytes are never printed: loaded folders are compared through their
//! `Debug` text (key ids only) and key bytes with `assert!` without values.

use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use opentele2_core::batch::{self, BatchOptions, LoadRequest, MAX_DEFAULT_THREADS};
use opentele2_core::tdata::TData;
use opentele2_core::{Error, Result};
use serde_json::Value;

// Batch results cross threads, so both must be `Send`; this fails to compile
// otherwise.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<TData>();
    assert_send::<Error>();
    assert_send::<Result<TData>>();
};

const FOLDERS: [&str; 4] = [
    "tdata_passcode/performance_off",
    "tdata_passcode/performance_on",
    "tdata_plain/performance_off",
    "tdata_plain/performance_on",
];

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn request_for(folder: &str) -> LoadRequest {
    let text = fs::read_to_string(vectors_dir().join("tdata.json")).expect("read vector manifest");
    let manifest: Value = serde_json::from_str(&text).expect("parse vector manifest");
    let entry = &manifest["folders"][folder];
    LoadRequest {
        dir: vectors_dir().join(folder),
        passcode: entry["passcode"]
            .as_str()
            .expect("passcode")
            .as_bytes()
            .to_vec(),
        key_file: Some(entry["key_file"].as_str().expect("key_file").to_owned()),
    }
}

fn threads(count: usize) -> BatchOptions {
    BatchOptions {
        threads: Some(NonZeroUsize::new(count).expect("non-zero thread count")),
    }
}

/// `Debug` of a loaded folder (key ids, never key bytes) or the error code.
fn outcome(result: &Result<TData>) -> String {
    match result {
        Ok(tdata) => format!("ok {tdata:?}"),
        Err(error) => format!("err {}", error.code()),
    }
}

/// Whether two results carry the same key bytes; errors carry none.
fn same_key_bytes(left: &Result<TData>, right: &Result<TData>) -> bool {
    match (left, right) {
        (Ok(left), Ok(right)) => {
            left.local_key.as_bytes() == right.local_key.as_bytes()
                && left.passcode_key.as_bytes() == right.passcode_key.as_bytes()
                && left.accounts.len() == right.accounts.len()
                && left.accounts.iter().zip(&right.accounts).all(|(a, b)| {
                    a.keys.len() == b.keys.len()
                        && a.keys
                            .iter()
                            .zip(&b.keys)
                            .all(|((dc_a, key_a), (dc_b, key_b))| {
                                dc_a == dc_b && key_a.as_bytes() == key_b.as_bytes()
                            })
                })
        }
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

#[test]
fn load_many_matches_sequential_load_in_order() {
    let missing = 4;
    let wrong_passcode = 7;
    let mut requests: Vec<LoadRequest> = Vec::new();
    for folder in FOLDERS {
        requests.push(request_for(folder));
    }
    requests.insert(
        missing,
        LoadRequest {
            dir: vectors_dir().join("tdata_missing"),
            passcode: Vec::new(),
            key_file: None,
        },
    );
    for folder in FOLDERS {
        requests.push(request_for(folder));
    }
    requests.insert(
        wrong_passcode,
        LoadRequest {
            passcode: b"not the passcode".to_vec(),
            ..request_for(FOLDERS[0])
        },
    );
    // The cheap plain folders a third time.
    requests.push(request_for(FOLDERS[2]));
    requests.push(request_for(FOLDERS[3]));

    let sequential: Vec<Result<TData>> = requests
        .iter()
        .map(|request| TData::load(&request.dir, &request.passcode, request.key_file.as_deref()))
        .collect();
    let expected: Vec<String> = sequential.iter().map(outcome).collect();
    for (index, line) in expected.iter().enumerate() {
        match index {
            4 => assert_eq!(line, "err TFILE_NOT_FOUND", "missing folder"),
            7 => assert_eq!(line, "err TDATA_BAD_DECRYPT_KEY", "wrong passcode"),
            _ => assert!(line.starts_with("ok "), "item {index} failed: {line:.40}"),
        }
    }

    for count in [1, 4] {
        let results = batch::load_many(&requests, &threads(count));
        assert_eq!(results.len(), requests.len(), "{count} threads: length");
        for (index, (got, want)) in results.iter().zip(&sequential).enumerate() {
            assert!(
                outcome(got) == expected[index],
                "{count} threads: item {index} differs from sequential load"
            );
            assert!(
                same_key_bytes(got, want),
                "{count} threads: item {index} key bytes differ"
            );
        }
    }
}

#[test]
fn map_many_preserves_order_and_per_item_results() {
    let items: Vec<u32> = (0..500).collect();
    let convert = |item: &u32| -> Result<u32> {
        if item % 7 == 3 {
            Err(Error::WrongPasscode)
        } else {
            Ok(item * 2)
        }
    };
    let want: Vec<String> = items
        .iter()
        .map(|item| format!("{:?}", convert(item).map_err(|error| error.code())))
        .collect();
    for options in [threads(1), threads(4), BatchOptions::default()] {
        let got: Vec<String> = batch::map_many(&items, &options, convert)
            .expect("pool builds")
            .into_iter()
            .map(|result| format!("{:?}", result.map_err(|error| error.code())))
            .collect();
        assert_eq!(got, want, "{options:?}");
    }
}

#[test]
fn empty_input_yields_empty_output() {
    assert!(batch::load_many(&[], &threads(4)).is_empty());
    let none: [u8; 0] = [];
    let mapped = batch::map_many(&none, &threads(4), |byte| *byte).expect("empty map");
    assert_eq!(mapped, Vec::<u8>::new());
}

#[test]
fn thread_count_defaults_to_capped_parallelism() {
    let available = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    assert_eq!(
        BatchOptions::default().thread_count(),
        available.min(MAX_DEFAULT_THREADS)
    );
    assert_eq!(MAX_DEFAULT_THREADS.get(), 16);
    // An explicit count is used as given, even above the default cap.
    assert_eq!(threads(64).thread_count().get(), 64);
}

#[test]
fn load_request_debug_hides_the_passcode() {
    let request = LoadRequest {
        dir: PathBuf::from("folder"),
        passcode: b"hunter2-secret".to_vec(),
        key_file: None,
    };
    let text = format!("{request:?}");
    assert!(!text.contains("hunter2"), "passcode leaked into Debug");
    assert!(text.contains("passcode_len: 14"), "{text}");
}

#[cfg(feature = "parallel")]
#[test]
fn pool_honours_requested_thread_count() {
    let items = [0u8; 64];
    for count in [1, 3, 4] {
        let seen = batch::map_many(&items, &threads(count), |_| {
            let name = std::thread::current().name().map(str::to_owned);
            (
                rayon::current_num_threads(),
                rayon::current_thread_index(),
                name,
            )
        })
        .expect("pool builds");
        for (threads_seen, index, name) in seen {
            assert_eq!(threads_seen, count, "pool size");
            assert!(index.is_some_and(|index| index < count), "{index:?}");
            assert!(
                name.as_deref()
                    .is_some_and(|name| name.starts_with("opentele2-batch-")),
                "ran outside the dedicated pool: {name:?}"
            );
        }
    }
    let default = BatchOptions::default();
    let sizes =
        batch::map_many(&items, &default, |_| rayon::current_num_threads()).expect("pool builds");
    assert!(
        sizes
            .iter()
            .all(|size| *size == default.thread_count().get())
    );
    // The calling thread is not a worker of any pool.
    assert_eq!(rayon::current_thread_index(), None);
}
