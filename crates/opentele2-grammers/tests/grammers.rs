//! Tests for `opentele2-grammers` over the vector tdata folders of
//! `opentele2-core` (`crates/opentele2-core/tests/vectors`): account to
//! grammers `SessionData` and back, the data seen through a `MemorySession`,
//! and connection params from a generated desktop profile.
//!
//! Key bytes are never printed: key comparisons use `assert!` without the
//! values, and no `SessionData` or `DcOption` is formatted with `Debug`.

use std::fs;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use grammers_session::storages::MemorySession;
use grammers_session::types::{PeerId, PeerInfo};
use grammers_session::{Session, SessionData};
use opentele2_core::api::{self, Client, Versions};
use opentele2_core::crypto::AuthKey;
use opentele2_core::session::dc;
use opentele2_core::tdata::TData;
use opentele2_core::tdata::account::Account;
use opentele2_core::{Error, Result};
use opentele2_grammers::{account_from_session, connection_params, session_data};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../opentele2-core/tests/vectors")
}

/// One vector account with its manifest values: (account, user id, main DC,
/// key bytes).
struct Vector {
    account: Account,
    user_id: u64,
    main_dc: i32,
    key: [u8; AuthKey::SIZE],
}

fn hex_key(text: &str) -> [u8; AuthKey::SIZE] {
    let bytes = hex::decode(text).expect("hex key");
    <[u8; AuthKey::SIZE]>::try_from(bytes.as_slice()).expect("256-byte key")
}

/// Every account of a vector folder, checked against `tdata.json`.
fn vector_accounts(folder: &str) -> Vec<Vector> {
    let text = fs::read_to_string(vectors_dir().join("tdata.json")).expect("read manifest");
    let manifest: Value = serde_json::from_str(&text).expect("parse manifest");
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
                .expect("manifest entry");
            Vector {
                user_id: want["user_id"].as_u64().expect("user_id"),
                main_dc: i32::try_from(want["main_dc"].as_i64().expect("main_dc")).expect("dc"),
                key: hex_key(want["auth_key"].as_str().expect("auth_key")),
                account,
            }
        })
        .collect()
}

/// Runs a future that completes without waiting, as every `MemorySession`
/// future does.
fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("future did not complete at once"),
    }
}

fn code_of<T>(result: Result<T>) -> &'static str {
    match result {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(error) => error.code(),
    }
}

/// A key whose byte `i` is `i + offset`.
fn counting_key(offset: u8) -> AuthKey {
    let mut bytes = [0u8; AuthKey::SIZE];
    for (i, byte) in (0u8..=255).zip(bytes.iter_mut()) {
        *byte = i.wrapping_add(offset);
    }
    AuthKey::new(bytes)
}

fn check_session_data(folder: &str, vector: &Vector, data: &SessionData) {
    assert_eq!(data.home_dc, vector.main_dc, "{folder} home dc");
    let mut ids: Vec<i32> = data.dc_options.keys().copied().collect();
    ids.sort_unstable();
    assert_eq!(ids, dc::PRODUCTION_DC_IDS, "{folder} dc ids");
    for (id, option) in &data.dc_options {
        assert_eq!(option.id, *id, "{folder} DC {id} id");
        let v4 = dc::production(*id, false).expect("IPv4");
        let v6 = dc::production(*id, true).expect("IPv6");
        assert_eq!(
            std::net::SocketAddr::V4(option.ipv4),
            v4,
            "{folder} DC {id}"
        );
        assert_eq!(
            std::net::SocketAddr::V6(option.ipv6),
            v6,
            "{folder} DC {id}"
        );
        if *id == vector.main_dc {
            assert!(
                option.auth_key == Some(vector.key),
                "{folder} DC {id} key differs"
            );
        } else {
            assert!(option.auth_key.is_none(), "{folder} DC {id} has a key");
        }
    }
    let user = i64::try_from(vector.user_id).expect("user id");
    let peer = PeerId::user(user).expect("user peer");
    assert_eq!(data.peer_infos.len(), 1, "{folder} cached peers");
    assert_eq!(
        data.peer_infos.get(&peer),
        Some(&PeerInfo::User {
            id: user,
            auth: None,
            bot: Some(false),
            is_self: Some(true),
        }),
        "{folder} self user"
    );
}

fn check_round_trip(folder: &str, vector: &Vector) {
    let data = session_data(&vector.account);
    check_session_data(folder, vector, &data);

    let back = account_from_session(&data, vector.account.index).expect("account");
    assert_eq!(back.index, vector.account.index, "{folder} index");
    assert_eq!(back.user_id, vector.user_id, "{folder} user id");
    assert_eq!(back.main_dc, vector.main_dc, "{folder} main dc");
    assert_eq!(back.keys.len(), 1, "{folder} key count");
    assert_eq!(back.keys[0].0, vector.main_dc, "{folder} key dc");
    let key = back.auth_key().expect("main key");
    assert!(
        key.as_bytes() == &vector.key,
        "{folder} round-trip key differs"
    );
    assert!(
        session_data(&back).dc_options[&vector.main_dc].auth_key == Some(vector.key),
        "{folder} second pass key differs"
    );
}

fn check_memory_session(folder: &str, vector: &Vector) {
    let session = MemorySession::from(session_data(&vector.account));
    assert_eq!(
        session.home_dc_id().expect("home dc"),
        vector.main_dc,
        "{folder} session home dc"
    );
    for id in dc::PRODUCTION_DC_IDS {
        let option = session.dc_option(id).expect("dc option").expect("known DC");
        assert_eq!(option.id, id, "{folder} session DC {id}");
        if id == vector.main_dc {
            assert!(
                option.auth_key == Some(vector.key),
                "{folder} session key differs"
            );
        } else {
            assert!(option.auth_key.is_none(), "{folder} session DC {id} key");
        }
    }
    let user = i64::try_from(vector.user_id).expect("user id");
    let peer = ready(session.peer(PeerId::user(user).expect("user peer"))).expect("peer");
    assert!(
        matches!(peer, Some(PeerInfo::User { id, is_self: Some(true), .. }) if id == user),
        "{folder} session self user"
    );
}

#[test]
fn plain_vector_accounts_round_trip() {
    for folder in ["tdata_plain/performance_on", "tdata_plain/performance_off"] {
        let accounts = vector_accounts(folder);
        let dcs: Vec<i32> = accounts.iter().map(|v| v.account.main_dc).collect();
        assert_eq!(dcs, [2, 4], "{folder} main DCs");
        for vector in &accounts {
            check_round_trip(folder, vector);
            check_memory_session(folder, vector);
        }
    }
}

#[test]
fn passcode_vector_accounts_round_trip() {
    // One Argon2id folder only; debug builds derive it slowly.
    let folder = "tdata_passcode/performance_on";
    let accounts = vector_accounts(folder);
    let dcs: Vec<i32> = accounts.iter().map(|v| v.account.main_dc).collect();
    assert_eq!(dcs, [1, 5], "{folder} main DCs");
    for vector in &accounts {
        check_round_trip(folder, vector);
        check_memory_session(folder, vector);
    }
}

#[test]
fn account_from_session_errors() {
    // grammers' default data knows the DCs but holds no key.
    assert_eq!(
        code_of(account_from_session(&SessionData::default(), 0)),
        "TDATA_AUTH_KEY_NOT_FOUND"
    );

    let account = Account::new(0, 777, 2, vec![(2, counting_key(0))]).expect("account");

    let mut no_home_option = session_data(&account);
    no_home_option.dc_options.remove(&2);
    assert_eq!(
        code_of(account_from_session(&no_home_option, 0)),
        "TDATA_AUTH_KEY_NOT_FOUND"
    );

    let mut no_self = session_data(&account);
    no_self.peer_infos.clear();
    assert_eq!(
        code_of(account_from_session(&no_self, 0)),
        "TDATA_BAD_CONFIG_DATA"
    );

    let mut self_unset = session_data(&account);
    for info in self_unset.peer_infos.values_mut() {
        if let PeerInfo::User { is_self, .. } = info {
            *is_self = Some(false);
        }
    }
    assert_eq!(
        code_of(account_from_session(&self_unset, 0)),
        "TDATA_BAD_CONFIG_DATA"
    );

    let mut two_selves = session_data(&account);
    let other = PeerInfo::User {
        id: 778,
        auth: None,
        bot: Some(false),
        is_self: Some(true),
    };
    two_selves.peer_infos.insert(other.id(), other);
    assert_eq!(
        code_of(account_from_session(&two_selves, 0)),
        "TDATA_BAD_CONFIG_DATA"
    );
}

#[test]
fn accounts_session_data_cannot_express() {
    // A main DC outside the production table: no option carries the key.
    let unknown_dc = Account::new(0, 777, 7, vec![(7, counting_key(1))]).expect("account");
    let data = session_data(&unknown_dc);
    assert_eq!(data.home_dc, 7);
    assert!(data.dc_options.values().all(|o| o.auth_key.is_none()));
    assert!(matches!(
        account_from_session(&data, 0),
        Err(Error::AuthKeyNotFound)
    ));

    // No key for the main DC.
    let mut keyless = Account::new(0, 777, 2, vec![(2, counting_key(2))]).expect("account");
    keyless.keys[0].0 = 4;
    let data = session_data(&keyless);
    assert!(data.dc_options.values().all(|o| o.auth_key.is_none()));
    assert!(matches!(
        account_from_session(&data, 0),
        Err(Error::AuthKeyNotFound)
    ));

    // A user id outside grammers' range: no self user.
    for user_id in [0, 1 << 40, u64::MAX] {
        let account = Account::new(0, user_id, 2, vec![(2, counting_key(3))]).expect("account");
        let data = session_data(&account);
        assert!(data.peer_infos.is_empty(), "user id {user_id}");
        assert!(matches!(
            account_from_session(&data, 0),
            Err(Error::BadConfigData)
        ));
    }

    // The largest user id grammers accepts survives the round trip.
    let account = Account::new(3, 0xff_ffff_ffff, 5, vec![(5, counting_key(4))]).expect("account");
    let back = account_from_session(&session_data(&account), 3).expect("account");
    assert_eq!(
        (back.index, back.user_id, back.main_dc),
        (3, 0xff_ffff_ffff, 5)
    );
}

#[test]
fn connection_params_copy_a_desktop_profile() {
    let versions = Versions::offline();
    for seed in ["opentele2", "grammers", "fingerprint"] {
        let profile = api::generate(Client::Desktop, Some(seed), &versions).expect("profile");
        let params = connection_params(&profile);
        assert_eq!(params.device_model, profile.device_model, "{seed} device");
        assert_eq!(
            params.system_version, profile.system_version,
            "{seed} system"
        );
        assert_eq!(params.app_version, profile.app_version, "{seed} app");
        assert_eq!(
            params.system_lang_code, profile.system_lang_code,
            "{seed} system lang"
        );
        assert_eq!(params.lang_code, profile.lang_code, "{seed} lang");
        assert!(!params.use_ipv6, "{seed} IPv6 is the grammers default");
        assert_eq!(
            params.updates_channel_capacity.get(),
            100,
            "{seed} capacity"
        );
    }
}
