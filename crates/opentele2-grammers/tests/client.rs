//! Tests for the `client` flows of `opentele2-grammers`, each driven by a
//! fake [`Invoker`] that answers with canned grammers TL objects, plus one
//! ignored live smoke test.
//!
//! Key bytes and passwords are never printed: key comparisons use
//! `assert!` without the values, and no session data is formatted.

#![cfg(feature = "client")]

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};

use grammers_client::tl::{self, Deserializable, Identifiable, RemoteCall, Serializable};
use grammers_mtsender::{InvocationError, RpcError};
use grammers_session::Session;
use grammers_session::storages::MemorySession;
use grammers_session::types::{PeerId, PeerInfo};
use opentele2_core::api::{self, Versions};
use opentele2_core::auth::{self, Check, ConsistencyExpectations};
use opentele2_core::crypto::AuthKey;
use opentele2_core::tdata::account::Account;
use opentele2_grammers::client::{
    self, ClientError, Invoker, POST_LOGIN_DELAYS_MS, QR_LOGIN_ATTEMPTS, QR_LOGIN_TIMEOUT,
    USER_ID_UNRESOLVED,
};
use opentele2_grammers::session_data;
use tl::functions::account as account_fn;
use tl::functions::auth as auth_fn;
use tl::functions::help as help_fn;

/// A canned answer: the serialized return value, or an RPC error.
type Reply = Result<Vec<u8>, RpcError>;

/// One request the fake saw: its constructor id, its bytes, and the home
/// DC of the fake's session when it arrived (0 without a session).
#[derive(Clone)]
struct Call {
    id: u32,
    bytes: Vec<u8>,
    home_dc: i32,
}

/// An [`Invoker`] that answers from a script of (constructor id, reply)
/// in order, panicking on any request it does not expect.
struct Fake {
    name: &'static str,
    session: Option<Arc<MemorySession>>,
    script: Mutex<VecDeque<(u32, Reply)>>,
    calls: Mutex<Vec<Call>>,
}

impl Fake {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            session: None,
            script: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn with_session(name: &'static str, session: &Arc<MemorySession>) -> Self {
        Self {
            session: Some(Arc::clone(session)),
            ..Self::new(name)
        }
    }

    /// Answers the next `R` with `value`.
    fn ok<R>(&self, value: &R::Return) -> &Self
    where
        R: RemoteCall + Identifiable,
        R::Return: Serializable,
    {
        self.script
            .lock()
            .expect("script")
            .push_back((R::CONSTRUCTOR_ID, Ok(value.to_bytes())));
        self
    }

    /// Fails the next `R` with RPC error `code` `name`.
    fn fail<R: Identifiable>(&self, code: i32, name: &str) -> &Self {
        self.script
            .lock()
            .expect("script")
            .push_back((R::CONSTRUCTOR_ID, Err(rpc(code, name))));
        self
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("calls").clone()
    }

    fn call_ids(&self) -> Vec<u32> {
        self.calls().iter().map(|call| call.id).collect()
    }

    fn assert_done(&self) {
        let left = self.script.lock().expect("script").len();
        assert_eq!(left, 0, "{}: {left} scripted replies unused", self.name);
    }
}

impl Invoker for Fake {
    fn invoke<R>(
        &self,
        request: &R,
    ) -> impl Future<Output = Result<R::Return, InvocationError>> + Send
    where
        R: RemoteCall + Sync,
    {
        let bytes = request.to_bytes();
        let id = u32::from_le_bytes(bytes[..4].try_into().expect("constructor id"));
        let home_dc = self
            .session
            .as_ref()
            .map_or(0, |session| session.home_dc_id().expect("home dc"));
        self.calls
            .lock()
            .expect("calls")
            .push(Call { id, bytes, home_dc });
        let next = self.script.lock().expect("script").pop_front();
        let (want, reply) = next.unwrap_or_else(|| {
            panic!("{}: unexpected {}", self.name, tl::name_for_id(id));
        });
        assert_eq!(
            tl::name_for_id(id),
            tl::name_for_id(want),
            "{}: request out of script order",
            self.name
        );
        async move {
            reply
                .map(|bytes| R::Return::from_bytes(&bytes).expect("canned reply decodes"))
                .map_err(InvocationError::Rpc)
        }
    }
}

fn rpc(code: i32, name: &str) -> RpcError {
    RpcError {
        code,
        name: name.to_owned(),
        value: None,
        caused_by: None,
    }
}

const SELF_ID: i64 = 777_000_111;
const ACCESS_HASH: i64 = -4_242_424_242;
const API_ID: i32 = 2040;
const API_HASH: &str = "b18441a1ff607e10a989891a5462e627";

/// Telegram's 2048-bit 2FA prime, which the core accepts with `g` 3.
const TELEGRAM_PRIME: &str = concat!(
    "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f",
    "48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37",
    "20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64",
    "2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4",
    "a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754",
    "fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4",
    "e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f",
    "0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b",
);

fn user(id: i64) -> tl::enums::User {
    tl::enums::User::User(tl::types::User {
        is_self: true,
        contact: false,
        mutual_contact: false,
        deleted: false,
        bot: false,
        bot_chat_history: false,
        bot_nochats: false,
        verified: false,
        restricted: false,
        min: false,
        bot_inline_geo: false,
        support: false,
        scam: false,
        apply_min_photo: false,
        fake: false,
        bot_attach_menu: false,
        premium: false,
        attach_menu_enabled: false,
        bot_can_edit: false,
        close_friend: false,
        stories_hidden: false,
        stories_unavailable: false,
        contact_require_premium: false,
        bot_business: false,
        bot_has_main_app: false,
        bot_forum_view: false,
        bot_forum_can_manage_topics: false,
        bot_can_manage_bots: false,
        bot_guestchat: false,
        bot_guard: false,
        id,
        access_hash: Some(ACCESS_HASH),
        first_name: Some("Fake".to_owned()),
        last_name: None,
        username: None,
        phone: None,
        photo: None,
        status: None,
        bot_info_version: None,
        restriction_reason: None,
        bot_inline_placeholder: None,
        lang_code: None,
        emoji_status: None,
        usernames: None,
        stories_max_id: None,
        color: None,
        profile_color: None,
        bot_active_users: None,
        bot_verification_icon: None,
        send_paid_messages_stars: None,
        linked_community_id: None,
    })
}

fn login(id: i64) -> tl::enums::auth::Authorization {
    tl::enums::auth::Authorization::Authorization(tl::types::auth::Authorization {
        setup_password_required: false,
        otherwise_relogin_days: None,
        tmp_sessions: None,
        future_auth_token: None,
        user: user(id),
    })
}

fn token(bytes: &[u8]) -> tl::enums::auth::LoginToken {
    tl::enums::auth::LoginToken::Token(tl::types::auth::LoginToken {
        expires: 1_900_000_000,
        token: bytes.to_vec(),
    })
}

fn migrate_to(dc_id: i32, bytes: &[u8]) -> tl::enums::auth::LoginToken {
    tl::enums::auth::LoginToken::MigrateTo(tl::types::auth::LoginTokenMigrateTo {
        dc_id,
        token: bytes.to_vec(),
    })
}

fn success(id: i64) -> tl::enums::auth::LoginToken {
    tl::enums::auth::LoginToken::Success(tl::types::auth::LoginTokenSuccess {
        authorization: login(id),
    })
}

fn session_entry(
    hash: i64,
    current: bool,
    official: bool,
    api_id: i32,
) -> tl::types::Authorization {
    tl::types::Authorization {
        current,
        official_app: official,
        password_pending: false,
        encrypted_requests_disabled: false,
        call_requests_disabled: false,
        unconfirmed: false,
        hash,
        device_model: format!("Device {hash}"),
        platform: "Windows".to_owned(),
        system_version: "Windows 11".to_owned(),
        api_id,
        app_name: "Telegram Desktop".to_owned(),
        app_version: "6.0.2 x64".to_owned(),
        date_created: 1_700_000_000,
        date_active: 1_700_000_100,
        ip: "203.0.113.7".to_owned(),
        country: "Nowhere".to_owned(),
        region: String::new(),
    }
}

fn authorizations(list: Vec<tl::types::Authorization>) -> tl::enums::account::Authorizations {
    tl::enums::account::Authorizations::Authorizations(tl::types::account::Authorizations {
        authorization_ttl_days: 180,
        authorizations: list
            .into_iter()
            .map(tl::enums::Authorization::Authorization)
            .collect(),
    })
}

fn password(algo: Option<tl::enums::PasswordKdfAlgo>) -> tl::enums::account::Password {
    tl::enums::account::Password::Password(tl::types::account::Password {
        has_recovery: false,
        has_secure_values: false,
        has_password: algo.is_some(),
        srp_b: algo.as_ref().map(|_| vec![0x5a; 255]),
        srp_id: algo.as_ref().map(|_| 0x0123_4567_89ab_cdef),
        current_algo: algo,
        hint: None,
        email_unconfirmed_pattern: None,
        new_algo: tl::enums::PasswordKdfAlgo::Unknown,
        new_secure_algo: tl::enums::SecurePasswordKdfAlgo::Unknown,
        secure_random: vec![7; 32],
        pending_reset_date: None,
        login_email_pattern: None,
    })
}

fn srp_algo() -> tl::enums::PasswordKdfAlgo {
    tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(
        tl::types::PasswordKdfAlgoSha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow {
            salt1: vec![1; 40],
            salt2: vec![2; 16],
            g: 3,
            p: hex::decode(TELEGRAM_PRIME).expect("prime"),
        },
    )
}

fn get_state() -> tl::enums::updates::State {
    tl::enums::updates::State::State(tl::types::updates::State {
        pts: 1,
        qts: 0,
        date: 1_700_000_000,
        seq: 1,
        unread_count: 0,
    })
}

fn config(this_dc: i32) -> tl::enums::Config {
    tl::enums::Config::Config(tl::types::Config {
        default_p2p_contacts: false,
        preload_featured_stickers: false,
        revoke_pm_inbox: false,
        blocked_mode: false,
        force_try_ipv6: false,
        date: 1_700_000_000,
        expires: 1_700_003_600,
        test_mode: false,
        this_dc,
        dc_options: Vec::new(),
        dc_txt_domain_name: "apv3.stel.com".to_owned(),
        chat_size_max: 200,
        megagroup_size_max: 200_000,
        forwarded_count_max: 100,
        online_update_period_ms: 210_000,
        offline_blur_timeout_ms: 5000,
        offline_idle_timeout_ms: 30_000,
        online_cloud_timeout_ms: 300_000,
        notify_cloud_delay_ms: 30_000,
        notify_default_delay_ms: 1500,
        push_chat_period_ms: 60_000,
        push_chat_limit: 2,
        edit_time_limit: 172_800,
        revoke_time_limit: i32::MAX,
        revoke_pm_time_limit: i32::MAX,
        rating_e_decay: 2_419_200,
        stickers_recent_limit: 200,
        channels_read_media_period: 604_800,
        tmp_sessions: None,
        call_receive_timeout_ms: 20_000,
        call_ring_timeout_ms: 90_000,
        call_connect_timeout_ms: 30_000,
        call_packet_timeout_ms: 10_000,
        me_url_prefix: "https://t.me/".to_owned(),
        autoupdate_url_prefix: None,
        gif_search_username: None,
        venue_search_username: None,
        img_search_username: None,
        static_maps_provider: None,
        caption_length_max: 1024,
        message_length_max: 4096,
        webfile_dc_id: 4,
        suggested_lang_code: None,
        lang_pack_version: None,
        base_lang_pack_version: None,
        reactions_default: None,
        autologin_token: None,
    })
}

fn language(code: &str) -> tl::enums::LangPackLanguage {
    tl::enums::LangPackLanguage::Language(tl::types::LangPackLanguage {
        official: true,
        rtl: false,
        beta: false,
        name: code.to_owned(),
        native_name: code.to_owned(),
        lang_code: code.to_owned(),
        base_lang_code: None,
        plural_code: code.to_owned(),
        strings_count: 10,
        translated_count: 10,
        translations_url: format!("https://translations.telegram.org/{code}/"),
    })
}

fn new_session(home_dc: i32) -> Arc<MemorySession> {
    let account =
        Account::new(0, 1, home_dc, vec![(home_dc, AuthKey::new([9; 256]))]).expect("account");
    let mut data = session_data(&account);
    // A fresh client session: the DC table, no key and no peers.
    for option in data.dc_options.values_mut() {
        option.auth_key = None;
    }
    data.peer_infos.clear();
    Arc::new(MemorySession::from(data))
}

fn cached_self(session: &MemorySession, id: i64) -> Option<PeerInfo> {
    let peer = PeerId::user(id).expect("user peer");
    futures_ready(session.peer(peer)).expect("peer")
}

/// Runs a `MemorySession` future, which completes without waiting.
fn futures_ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("session future did not complete at once"),
    }
}

#[tokio::test]
async fn qr_login_accepts_the_token_and_caches_the_self_user() {
    let session = new_session(2);
    let new = Fake::with_session("new", &session);
    let authorized = Fake::new("authorized");
    new.ok::<auth_fn::ExportLoginToken>(&token(b"first"))
        .ok::<auth_fn::ExportLoginToken>(&success(SELF_ID));
    authorized.ok::<auth_fn::AcceptLoginToken>(&tl::enums::Authorization::Authorization(
        session_entry(5, false, true, API_ID),
    ));

    let id = client::qr_login(&authorized, &new, &*session, API_ID, API_HASH, None)
        .await
        .expect("login");
    assert_eq!(id, SELF_ID);
    new.assert_done();
    authorized.assert_done();

    let export = auth_fn::ExportLoginToken {
        api_id: API_ID,
        api_hash: API_HASH.to_owned(),
        except_ids: Vec::new(),
    };
    assert_eq!(new.calls()[0].bytes, export.to_bytes(), "export request");
    let accept = auth_fn::AcceptLoginToken {
        token: b"first".to_vec(),
    };
    assert_eq!(
        authorized.calls()[0].bytes,
        accept.to_bytes(),
        "accept request"
    );
    assert!(matches!(
        cached_self(&session, SELF_ID),
        Some(PeerInfo::User { id: SELF_ID, auth: Some(auth), bot: Some(false), is_self: Some(true) })
            if auth.hash() == ACCESS_HASH
    ));
}

#[tokio::test]
async fn qr_login_succeeds_on_the_first_export() {
    let session = new_session(2);
    let new = Fake::with_session("new", &session);
    let authorized = Fake::new("authorized");
    new.ok::<auth_fn::ExportLoginToken>(&success(SELF_ID));

    let id = client::qr_login(&authorized, &new, &*session, API_ID, API_HASH, None)
        .await
        .expect("login");
    assert_eq!(id, SELF_ID);
    assert!(authorized.calls().is_empty(), "nothing to accept");
    new.assert_done();
}

#[tokio::test]
async fn qr_login_follows_a_dc_migration() {
    let session = new_session(2);
    let new = Fake::with_session("new", &session);
    let authorized = Fake::new("authorized");
    new.ok::<auth_fn::ExportLoginToken>(&token(b"first"))
        .ok::<auth_fn::ExportLoginToken>(&migrate_to(4, b"moved"))
        .ok::<auth_fn::ImportLoginToken>(&success(SELF_ID));
    authorized.ok::<auth_fn::AcceptLoginToken>(&tl::enums::Authorization::Authorization(
        session_entry(5, false, true, API_ID),
    ));

    let id = client::qr_login(&authorized, &new, &*session, API_ID, API_HASH, None)
        .await
        .expect("login");
    assert_eq!(id, SELF_ID);
    new.assert_done();
    assert_eq!(session.home_dc_id().expect("home dc"), 4, "home DC moved");
    let calls = new.calls();
    let import = auth_fn::ImportLoginToken {
        token: b"moved".to_vec(),
    };
    assert_eq!(calls[2].bytes, import.to_bytes(), "import request");
    let dcs: Vec<i32> = calls.iter().map(|call| call.home_dc).collect();
    assert_eq!(dcs, [2, 2, 4], "the import runs on the new DC");

    // A migration on the first export is followed the same way.
    let session = new_session(1);
    let new = Fake::with_session("new", &session);
    new.ok::<auth_fn::ExportLoginToken>(&migrate_to(5, b"moved"))
        .ok::<auth_fn::ImportLoginToken>(&success(SELF_ID));
    let id = client::qr_login(
        &Fake::new("authorized"),
        &new,
        &*session,
        API_ID,
        API_HASH,
        None,
    )
    .await
    .expect("login");
    assert_eq!(id, SELF_ID);
    assert_eq!(session.home_dc_id().expect("home dc"), 5);
    new.assert_done();
}

/// A new client whose second export asks for the 2FA password.
fn two_factor_script() -> (Arc<MemorySession>, Fake, Fake) {
    let session = new_session(2);
    let new = Fake::with_session("new", &session);
    let authorized = Fake::new("authorized");
    new.ok::<auth_fn::ExportLoginToken>(&token(b"first"))
        .fail::<auth_fn::ExportLoginToken>(401, "SESSION_PASSWORD_NEEDED");
    authorized.ok::<auth_fn::AcceptLoginToken>(&tl::enums::Authorization::Authorization(
        session_entry(5, false, true, API_ID),
    ));
    (session, new, authorized)
}

#[tokio::test]
async fn qr_login_checks_the_2fa_password() {
    let (session, new, authorized) = two_factor_script();
    new.ok::<account_fn::GetPassword>(&password(Some(srp_algo())))
        .ok::<auth_fn::CheckPassword>(&login(SELF_ID));

    let id = client::qr_login(
        &authorized,
        &new,
        &*session,
        API_ID,
        API_HASH,
        Some("correct horse"),
    )
    .await
    .expect("login");
    assert_eq!(id, SELF_ID);
    new.assert_done();
    let check = new.calls().pop().expect("checkPassword");
    assert_eq!(check.id, auth_fn::CheckPassword::CONSTRUCTOR_ID);
    // checkPassword, inputCheckPasswordSRP, srp_id, then A (256 bytes,
    // 4-byte length prefix) and M1 (32 bytes, 1-byte prefix, padded).
    assert_eq!(
        check.bytes[4..8],
        tl::types::InputCheckPasswordSrp::CONSTRUCTOR_ID.to_le_bytes()
    );
    assert_eq!(check.bytes[8..16], 0x0123_4567_89ab_cdef_i64.to_le_bytes());
    assert_eq!(check.bytes.len(), 16 + 4 + 256 + 36, "A and M1 sizes");
    assert!(cached_self(&session, SELF_ID).is_some(), "self user cached");
}

#[tokio::test]
async fn qr_login_2fa_errors() {
    // No password: 1.5.0's NoPasswordProvided, before account.getPassword.
    let (session, new, authorized) = two_factor_script();
    let error = client::qr_login(&authorized, &new, &*session, API_ID, API_HASH, None)
        .await
        .expect_err("needs a password");
    assert!(matches!(error, ClientError::NoPasswordProvided));
    assert_eq!(error.to_string(), auth::NO_PASSWORD_PROVIDED);
    new.assert_done();

    // A wrong password: PasswordIncorrect.
    let (session, new, authorized) = two_factor_script();
    new.ok::<account_fn::GetPassword>(&password(Some(srp_algo())))
        .fail::<auth_fn::CheckPassword>(400, "PASSWORD_HASH_INVALID");
    let error = client::qr_login(
        &authorized,
        &new,
        &*session,
        API_ID,
        API_HASH,
        Some("wrong"),
    )
    .await
    .expect_err("wrong password");
    assert!(
        matches!(&error, ClientError::PasswordIncorrect(rpc) if rpc.name == "PASSWORD_HASH_INVALID")
    );
    assert!(cached_self(&session, SELF_ID).is_none(), "no self user");
    new.assert_done();

    // No SRP algorithm: Telethon's unsupported password algorithm.
    let (session, new, authorized) = two_factor_script();
    new.ok::<account_fn::GetPassword>(&password(None));
    let error = client::qr_login(&authorized, &new, &*session, API_ID, API_HASH, Some("pw"))
        .await
        .expect_err("no algorithm");
    assert!(matches!(error, ClientError::UnsupportedPasswordAlgorithm));
    new.assert_done();

    // Other checkPassword failures pass through.
    let (session, new, authorized) = two_factor_script();
    new.ok::<account_fn::GetPassword>(&password(Some(srp_algo())))
        .fail::<auth_fn::CheckPassword>(420, "FLOOD_WAIT");
    let error = client::qr_login(&authorized, &new, &*session, API_ID, API_HASH, Some("pw"))
        .await
        .expect_err("flood");
    assert!(
        matches!(error, ClientError::Invocation(InvocationError::Rpc(ref rpc)) if rpc.code == 420)
    );
}

#[tokio::test]
async fn qr_login_reraises_auth_token_errors() {
    for (name, want) in [
        ("AUTH_TOKEN_ALREADY_ACCEPTED", "already"),
        ("AUTH_TOKEN_EXPIRED", "expired"),
        ("AUTH_TOKEN_INVALID", "invalid"),
    ] {
        let session = new_session(2);
        let new = Fake::with_session("new", &session);
        let authorized = Fake::new("authorized");
        new.ok::<auth_fn::ExportLoginToken>(&token(b"first"));
        authorized.fail::<auth_fn::AcceptLoginToken>(400, name);
        let error = client::qr_login(&authorized, &new, &*session, API_ID, API_HASH, None)
            .await
            .expect_err(name);
        let got = match &error {
            ClientError::AuthTokenAlreadyAccepted(rpc) => ("already", rpc),
            ClientError::AuthTokenExpired(rpc) => ("expired", rpc),
            ClientError::AuthTokenInvalid(rpc) => ("invalid", rpc),
            other => panic!("{name}: {other}"),
        };
        assert_eq!((got.0, got.1.name.as_str()), (want, name));
        new.assert_done();
    }

    // Any other failure stops the login at once.
    let session = new_session(2);
    let new = Fake::with_session("new", &session);
    new.fail::<auth_fn::ExportLoginToken>(400, "API_ID_INVALID");
    let error = client::qr_login(
        &Fake::new("authorized"),
        &new,
        &*session,
        API_ID,
        API_HASH,
        None,
    )
    .await
    .expect_err("bad api id");
    assert!(
        matches!(error, ClientError::Invocation(InvocationError::Rpc(ref rpc)) if rpc.name == "API_ID_INVALID")
    );
    new.assert_done();
}

#[tokio::test]
async fn qr_login_times_out_after_every_attempt() {
    let session = new_session(2);
    let new = Fake::with_session("new", &session);
    let authorized = Fake::new("authorized");
    for attempt in 0..QR_LOGIN_ATTEMPTS {
        if attempt > 0 {
            new.fail::<tl::functions::updates::GetState>(401, "AUTH_KEY_UNREGISTERED");
        }
        new.ok::<auth_fn::ExportLoginToken>(&token(b"first"))
            .ok::<auth_fn::ExportLoginToken>(&token(b"again"));
        authorized.ok::<auth_fn::AcceptLoginToken>(&tl::enums::Authorization::Authorization(
            session_entry(5, false, true, API_ID),
        ));
    }
    let error = client::qr_login(&authorized, &new, &*session, API_ID, API_HASH, None)
        .await
        .expect_err("timeout");
    assert!(matches!(error, ClientError::QrLoginTimeout));
    assert_eq!(error.to_string(), QR_LOGIN_TIMEOUT);
    new.assert_done();
    authorized.assert_done();
}

#[tokio::test]
async fn qr_login_stops_once_authorised_on_a_retry() {
    let session = new_session(2);
    let new = Fake::with_session("new", &session);
    let authorized = Fake::new("authorized");
    new.ok::<auth_fn::ExportLoginToken>(&token(b"first"))
        .ok::<auth_fn::ExportLoginToken>(&token(b"again"))
        .ok::<tl::functions::updates::GetState>(&get_state())
        .ok::<tl::functions::users::GetUsers>(&vec![user(SELF_ID)]);
    authorized.ok::<auth_fn::AcceptLoginToken>(&tl::enums::Authorization::Authorization(
        session_entry(5, false, true, API_ID),
    ));
    let id = client::qr_login(&authorized, &new, &*session, API_ID, API_HASH, None)
        .await
        .expect("login");
    assert_eq!(id, SELF_ID);
    new.assert_done();
}

#[tokio::test]
async fn get_me_id_reads_the_self_user() {
    let fake = Fake::new("client");
    fake.ok::<tl::functions::users::GetUsers>(&vec![user(SELF_ID)]);
    assert_eq!(client::get_me_id(&fake).await.expect("id"), SELF_ID);
    let request = tl::functions::users::GetUsers {
        id: vec![tl::enums::InputUser::UserSelf],
    };
    assert_eq!(fake.calls()[0].bytes, request.to_bytes());

    fake.ok::<tl::functions::users::GetUsers>(&Vec::new());
    let error = client::get_me_id(&fake).await.expect_err("no user");
    assert!(matches!(error, ClientError::UserIdUnresolved));
    assert_eq!(error.to_string(), USER_ID_UNRESOLVED);
}

#[tokio::test]
async fn session_admin_lists_and_formats_sessions() {
    let list = vec![
        session_entry(11, false, false, 12345),
        session_entry(22, true, true, API_ID),
        session_entry(33, false, true, 6),
    ];
    let fake = Fake::new("client");
    for _ in 0..4 {
        fake.ok::<account_fn::GetAuthorizations>(&authorizations(list.clone()));
    }

    let all = client::sessions(&fake).await.expect("sessions");
    assert_eq!(all, list);
    let current = client::current_session(&fake).await.expect("current");
    assert_eq!(current.map(|s| s.hash), Some(22));
    assert!(client::is_official_app(&fake).await.expect("official"));

    let table = client::sessions_table(&fake).await.expect("table");
    let rows: Vec<auth::SessionRow> = list.iter().map(client::session_row).collect();
    assert_eq!(table, auth::format_sessions(&rows));
    assert_eq!(
        rows[1],
        auth::SessionRow {
            current: true,
            device_model: "Device 22".to_owned(),
            platform: "Windows".to_owned(),
            system_version: "Windows 11".to_owned(),
            api_id: API_ID,
            app_name: "Telegram Desktop".to_owned(),
            app_version: "6.0.2 x64".to_owned(),
            official_app: true,
        }
    );
    fake.assert_done();

    // No current session, or an unofficial one: not an official app.
    fake.ok::<account_fn::GetAuthorizations>(&authorizations(vec![session_entry(
        1, false, true, API_ID,
    )]))
    .ok::<account_fn::GetAuthorizations>(&authorizations(vec![session_entry(
        1, true, false, 12345,
    )]));
    assert!(!client::is_official_app(&fake).await.expect("none current"));
    assert!(!client::is_official_app(&fake).await.expect("unofficial"));
    fake.assert_done();
}

#[tokio::test]
async fn terminate_session_maps_the_150_errors() {
    let fake = Fake::new("client");
    fake.ok::<account_fn::ResetAuthorization>(&true);
    client::terminate_session(&fake, 99).await.expect("reset");
    let request = account_fn::ResetAuthorization { hash: 99 };
    assert_eq!(fake.calls()[0].bytes, request.to_bytes());

    fake.fail::<account_fn::ResetAuthorization>(406, "FRESH_RESET_AUTHORISATION_FORBIDDEN");
    let error = client::terminate_session(&fake, 99)
        .await
        .expect_err("fresh");
    assert!(matches!(
        error,
        ClientError::FreshResetAuthorisationForbidden(_)
    ));
    assert_eq!(error.to_string(), auth::FRESH_RESET_FORBIDDEN);

    fake.fail::<account_fn::ResetAuthorization>(400, "HASH_INVALID");
    let error = client::terminate_session(&fake, 99)
        .await
        .expect_err("hash");
    assert!(matches!(error, ClientError::HashInvalid(_)));
    assert_eq!(error.to_string(), auth::HASH_INVALID);

    fake.fail::<account_fn::ResetAuthorization>(500, "INTERNAL");
    let error = client::terminate_session(&fake, 99)
        .await
        .expect_err("other");
    assert!(matches!(error, ClientError::Invocation(_)));
    fake.assert_done();
}

#[tokio::test]
async fn terminate_all_sessions_spares_the_current_one() {
    let fake = Fake::new("client");
    fake.ok::<account_fn::GetAuthorizations>(&authorizations(vec![
        session_entry(11, false, false, 12345),
        session_entry(22, true, true, API_ID),
        session_entry(33, false, true, 6),
    ]))
    .ok::<account_fn::ResetAuthorization>(&true)
    .ok::<account_fn::ResetAuthorization>(&true);
    assert_eq!(client::terminate_all_sessions(&fake).await.expect("all"), 2);
    let calls = fake.calls();
    assert_eq!(
        calls[1].bytes,
        account_fn::ResetAuthorization { hash: 11 }.to_bytes()
    );
    assert_eq!(
        calls[2].bytes,
        account_fn::ResetAuthorization { hash: 33 }.to_bytes()
    );
    fake.assert_done();

    // The first failure stops the loop.
    fake.ok::<account_fn::GetAuthorizations>(&authorizations(vec![
        session_entry(11, false, false, 12345),
        session_entry(33, false, true, 6),
    ]))
    .fail::<account_fn::ResetAuthorization>(406, "FRESH_RESET_AUTHORISATION_FORBIDDEN");
    let error = client::terminate_all_sessions(&fake)
        .await
        .expect_err("fresh");
    assert!(matches!(
        error,
        ClientError::FreshResetAuthorisationForbidden(_)
    ));
    fake.assert_done();
}

fn desktop_expectations() -> ConsistencyExpectations {
    ConsistencyExpectations::for_client(api::Client::Desktop, &Versions::offline())
}

#[tokio::test]
async fn consistency_checks_pass() {
    let expectations = desktop_expectations();
    assert_eq!(expectations.lang_pack, "tdesktop");
    let fake = Fake::new("client");
    fake.ok::<help_fn::GetConfig>(&config(2))
        .ok::<help_fn::GetNearestDc>(&tl::enums::NearestDc::Dc(tl::types::NearestDc {
            country: "NL".to_owned(),
            this_dc: 2,
            nearest_dc: 4,
        }))
        .ok::<account_fn::GetAuthorizations>(&authorizations(vec![
            session_entry(11, false, false, 12345),
            session_entry(22, true, true, API_ID),
        ]))
        .ok::<tl::functions::langpack::GetLanguages>(&vec![language("en"), language("ru")])
        .ok::<help_fn::GetAppUpdate>(&tl::enums::help::AppUpdate::NoAppUpdate)
        .ok::<help_fn::GetTermsOfServiceUpdate>(&tl::enums::help::TermsOfServiceUpdate::Empty(
            tl::types::help::TermsOfServiceUpdateEmpty {
                expires: 1_700_086_400,
            },
        ));

    let results = client::run_consistency_checks(&fake, &expectations).await;
    fake.assert_done();
    let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, Check::ALL.map(Check::name));
    assert!(
        results.iter().all(|r| r.passed),
        "{}",
        auth::consistency_summary(&results)
    );
    let details: Vec<String> = results.iter().map(|r| r.detail.clone()).collect();
    let row = client::session_row(&session_entry(22, true, true, API_ID));
    assert_eq!(
        details,
        [
            auth::get_config_detail(Some(2)),
            auth::nearest_dc_detail("NL", 2, 4),
            auth::current_session_detail(&row),
            expectations.layer_result(tl::LAYER).detail,
            auth::lang_pack_detail("tdesktop", 2),
            auth::NO_APP_UPDATE.to_owned(),
            auth::TERMS_OF_SERVICE_OK.to_owned(),
        ]
    );
    let request = tl::functions::langpack::GetLanguages {
        lang_pack: "tdesktop".to_owned(),
    };
    assert_eq!(fake.calls()[3].bytes, request.to_bytes());
}

#[tokio::test]
async fn consistency_checks_fail() {
    let expectations = desktop_expectations();
    let fake = Fake::new("client");
    fake.fail::<help_fn::GetConfig>(400, "CONNECTION_API_ID_INVALID")
        .fail::<help_fn::GetNearestDc>(500, "INTERNAL")
        .fail::<account_fn::GetAuthorizations>(401, "AUTH_KEY_UNREGISTERED")
        .fail::<tl::functions::langpack::GetLanguages>(400, "LANG_PACK_INVALID")
        .fail::<help_fn::GetAppUpdate>(400, "SOURCE_INVALID")
        .fail::<help_fn::GetTermsOfServiceUpdate>(500, "INTERNAL");
    let mut library = expectations.clone();
    // A layer far from the advertised one fails layer_match as well.
    library.advertised_layer = tl::LAYER + 16;

    let results = client::run_consistency_checks(&fake, &library).await;
    fake.assert_done();
    assert!(
        results.iter().all(|r| !r.passed),
        "{}",
        auth::consistency_summary(&results)
    );
    let error = |code: i32, name: &str| InvocationError::Rpc(rpc(code, name)).to_string();
    let details: Vec<String> = results.iter().map(|r| r.detail.clone()).collect();
    assert_eq!(
        details,
        [
            auth::get_config_error(&error(400, "CONNECTION_API_ID_INVALID")),
            auth::nearest_dc_error(&error(500, "INTERNAL")),
            auth::check_error(&error(401, "AUTH_KEY_UNREGISTERED")),
            auth::layer_detail(tl::LAYER, tl::LAYER + 16),
            auth::lang_pack_error("tdesktop", &error(400, "LANG_PACK_INVALID")),
            auth::app_update_error(&error(400, "SOURCE_INVALID")),
            auth::check_error(&error(500, "INTERNAL")),
        ]
    );
}

#[tokio::test]
async fn consistency_checks_other_outcomes() {
    // No current session, an unofficial one, an offered update, and an
    // empty lang_pack, which is skipped without a request.
    let mut expectations = desktop_expectations();
    expectations.lang_pack = String::new();
    let update = tl::enums::help::AppUpdate::Update(tl::types::help::AppUpdate {
        can_not_skip: false,
        id: 1,
        version: "9.9.9".to_owned(),
        text: String::new(),
        entities: Vec::new(),
        document: None,
        url: None,
        sticker: None,
    });
    let terms =
        tl::enums::help::TermsOfServiceUpdate::Empty(tl::types::help::TermsOfServiceUpdateEmpty {
            expires: 1,
        });
    for (sessions, passed, detail) in [
        (
            vec![session_entry(1, false, true, API_ID)],
            false,
            auth::CURRENT_SESSION_MISSING.to_owned(),
        ),
        (
            vec![session_entry(1, true, false, 12345)],
            false,
            auth::current_session_detail(&client::session_row(&session_entry(
                1, true, false, 12345,
            ))),
        ),
    ] {
        let fake = Fake::new("client");
        fake.ok::<help_fn::GetConfig>(&config(4))
            .ok::<help_fn::GetNearestDc>(&tl::enums::NearestDc::Dc(tl::types::NearestDc {
                country: "DE".to_owned(),
                this_dc: 4,
                nearest_dc: 4,
            }))
            .ok::<account_fn::GetAuthorizations>(&authorizations(sessions))
            .ok::<help_fn::GetAppUpdate>(&update)
            .ok::<help_fn::GetTermsOfServiceUpdate>(&terms);
        let results = client::run_consistency_checks(&fake, &expectations).await;
        fake.assert_done();
        assert_eq!(
            (results[2].passed, results[2].detail.as_str()),
            (passed, detail.as_str())
        );
        assert!(results[4].passed);
        assert_eq!(results[4].detail, auth::LANG_PACK_EMPTY);
        assert!(results[5].passed);
        assert_eq!(results[5].detail, auth::app_update_detail(Some("9.9.9")));
    }
}

#[tokio::test]
async fn tdata_from_client_uses_the_home_dc_key_and_get_me() {
    let key = AuthKey::new([0x3c; 256]);
    let account = Account::new(0, 1, 4, vec![(4, key.clone())]).expect("account");
    let session = MemorySession::from(session_data(&account));
    let fake = Fake::new("client");
    fake.ok::<tl::functions::users::GetUsers>(&vec![user(SELF_ID)]);

    let tdata = client::tdata_from_client(&fake, &session, b"", &mut |_| {
        panic!("performance mode without a passcode draws nothing")
    })
    .await
    .expect("tdata");
    fake.assert_done();
    assert_eq!(tdata.accounts.len(), 1);
    let built = &tdata.accounts[0];
    assert_eq!(
        (built.index, built.user_id, built.main_dc),
        (0, u64::try_from(SELF_ID).expect("id"), 4)
    );
    assert!(
        built.auth_key().map(AuthKey::as_bytes) == Some(key.as_bytes()),
        "home DC key differs"
    );
    assert!(tdata.performance_mode);

    // An account at another index, through account_from_client.
    fake.ok::<tl::functions::users::GetUsers>(&vec![user(SELF_ID)]);
    let other = client::account_from_client(&fake, &session, 3)
        .await
        .expect("account");
    assert_eq!(other.index, 3);

    // No key on the home DC.
    let mut keyless = session_data(&account);
    for option in keyless.dc_options.values_mut() {
        option.auth_key = None;
    }
    let keyless = MemorySession::from(keyless);
    let error = client::account_from_client(&Fake::new("unused"), &keyless, 0)
        .await
        .expect_err("no key");
    assert!(matches!(
        error,
        ClientError::Core(opentele2_core::Error::AuthKeyNotFound)
    ));

    // A user id that is not a tdata user id.
    fake.ok::<tl::functions::users::GetUsers>(&vec![tl::enums::User::Empty(
        tl::types::UserEmpty { id: -5 },
    )]);
    let error = client::account_from_client(&fake, &session, 0)
        .await
        .expect_err("negative id");
    assert!(matches!(
        error,
        ClientError::Core(opentele2_core::Error::BadConfigData {
            context: opentele2_core::ConfigFailure::BadUserId { user_id: -5 }
        })
    ));
    fake.assert_done();
}

#[tokio::test]
async fn post_login_requests_follow_the_150_steps() {
    let fake = Fake::new("client");
    fake.ok::<help_fn::GetConfig>(&config(2))
        .fail::<help_fn::GetNearestDc>(500, "INTERNAL")
        .ok::<account_fn::UpdateStatus>(&true)
        .ok::<tl::functions::langpack::GetLanguages>(&vec![language("en")])
        .ok::<help_fn::GetAppUpdate>(&tl::enums::help::AppUpdate::NoAppUpdate)
        .ok::<help_fn::GetTermsOfServiceUpdate>(&tl::enums::help::TermsOfServiceUpdate::Empty(
            tl::types::help::TermsOfServiceUpdateEmpty { expires: 1 },
        ))
        .ok::<help_fn::GetCountriesList>(&tl::enums::help::CountriesList::NotModified);
    let delays = Mutex::new(Vec::new());
    let failed = client::post_login_requests(&fake, "tdesktop", |min, max| {
        delays.lock().expect("delays").push((min, max));
        std::future::ready(())
    })
    .await;
    fake.assert_done();
    assert_eq!(failed, 1);
    let want: Vec<(u64, u64)> = POST_LOGIN_DELAYS_MS.iter().flatten().copied().collect();
    assert_eq!(*delays.lock().expect("delays"), want);
    let calls = fake.calls();
    assert_eq!(
        calls[2].bytes,
        account_fn::UpdateStatus { offline: false }.to_bytes()
    );
    assert_eq!(
        calls[6].bytes,
        help_fn::GetCountriesList {
            lang_code: "en".to_owned(),
            hash: 0
        }
        .to_bytes()
    );

    // An empty lang_pack skips langpack.getLanguages and its delay.
    let fake = Fake::new("client");
    fake.ok::<help_fn::GetConfig>(&config(2))
        .ok::<help_fn::GetNearestDc>(&tl::enums::NearestDc::Dc(tl::types::NearestDc {
            country: "NL".to_owned(),
            this_dc: 2,
            nearest_dc: 2,
        }))
        .ok::<account_fn::UpdateStatus>(&true)
        .ok::<help_fn::GetAppUpdate>(&tl::enums::help::AppUpdate::NoAppUpdate)
        .ok::<help_fn::GetTermsOfServiceUpdate>(&tl::enums::help::TermsOfServiceUpdate::Empty(
            tl::types::help::TermsOfServiceUpdateEmpty { expires: 1 },
        ))
        .ok::<help_fn::GetCountriesList>(&tl::enums::help::CountriesList::NotModified);
    let count = Mutex::new(0);
    let failed = client::post_login_requests(&fake, "", |_, _| {
        *count.lock().expect("count") += 1;
        std::future::ready(())
    })
    .await;
    fake.assert_done();
    assert_eq!(failed, 0);
    assert_eq!(*count.lock().expect("count"), 5);
    assert!(
        !fake
            .call_ids()
            .contains(&tl::functions::langpack::GetLanguages::CONSTRUCTOR_ID)
    );
}

/// Logs a real tdata account in through grammers and runs the read-only
/// flows. Set `OPENTELE2_LIVE_TDATA` to a tdata folder (and
/// `OPENTELE2_LIVE_PASSCODE` when it has one); the main account is used
/// with the desktop profile. Nothing secret is printed.
#[tokio::test]
#[ignore = "needs the network and a real tdata folder"]
async fn live_smoke() {
    use grammers_client::{Client, SenderPool};
    use opentele2_core::tdata::TData;

    let folder = std::env::var("OPENTELE2_LIVE_TDATA").expect("OPENTELE2_LIVE_TDATA");
    let passcode = std::env::var("OPENTELE2_LIVE_PASSCODE").unwrap_or_default();
    let tdata = TData::load(&folder, passcode.as_bytes(), None).expect("load tdata");
    let account = tdata.main_account().expect("main account").clone();
    let versions = Versions::offline();
    let profile = api::profile(api::Client::Desktop, &versions);

    let session = Arc::new(MemorySession::from(session_data(&account)));
    let pool = SenderPool::with_configuration(
        Arc::clone(&session),
        profile.api_id,
        opentele2_grammers::connection_params(&profile),
    );
    let runner = tokio::spawn(pool.runner.run());
    let grammers = Client::new(pool.handle);

    let id = client::get_me_id(&grammers).await.expect("get_me");
    assert_eq!(u64::try_from(id).ok(), Some(account.user_id), "self user");
    let rows: Vec<auth::SessionRow> = client::sessions(&grammers)
        .await
        .expect("sessions")
        .iter()
        .map(client::session_row)
        .collect();
    assert!(rows.iter().any(|row| row.current), "a current session");
    let expectations = ConsistencyExpectations::new(&profile, &versions);
    let results = client::run_consistency_checks(&grammers, &expectations).await;
    assert_eq!(results.len(), Check::ALL.len());
    println!("{}", auth::consistency_summary(&results));

    grammers.disconnect();
    runner.await.expect("runner");
}
