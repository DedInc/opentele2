//! grammers 0.11 sessions and connection params from opentele2 accounts and
//! API profiles, and back.
//!
//! - [`session_data`] turns a tdata [`Account`] into a
//!   [`grammers_session::SessionData`], ready for
//!   `MemorySession::from` or [`SessionData::import_to`].
//! - [`account_from_session`] is its inverse: the home DC key and the self
//!   user of a [`SessionData`] become an [`Account`].
//! - [`connection_params`] copies the `initConnection` fields of an
//!   [`ApiProfile`] into a [`grammers_mtsender::ConnectionParams`].
//!
//! The core crate never depends on grammers; this crate is the optional
//! bridge. The profile's `api_id` is passed to grammers separately (for
//! example to `SenderPool::new`), and its `api_hash` at sign-in.
//!
//! # Fingerprint gap
//!
//! grammers 0.11 builds `initConnection` itself in `SenderPool`
//! (`grammers-mtsender` `sender_pool.rs`) and always sends `lang_pack: ""`
//! and `params: None`. [`ConnectionParams`] has no field for either, so the
//! profile's [`ApiProfile::lang_pack`] (`tdesktop` for the desktop profile)
//! is dropped, and no `params` JSON object is sent. A session driven by
//! grammers with a desktop profile is therefore not byte-identical on the
//! wire to Telegram Desktop: the device, system, app and language fields
//! match, those two do not.
//!
//! Closing the gap needs an upstream change in `grammers-mtsender`: a
//! `lang_pack: String` and a `params: Option<JsonValue>` field (the TL
//! `JSONValue`) on `ConnectionParams`, defaulting to `""` and `None`, which
//! `SenderPool` copies into `InitConnection` in place of the hardcoded
//! values. Once released, [`connection_params`] fills both from the
//! profile.
//!
//! # Keys
//!
//! [`SessionData`] and its `DcOption` derive `Debug` and print the raw auth
//! key; do not log them. opentele2's [`AuthKey`] prints its key id only.

use std::collections::HashMap;
use std::net::SocketAddr;

use grammers_mtsender::ConnectionParams;
use grammers_session::SessionData;
use grammers_session::types::{DcOption, PeerId, PeerInfo, UpdatesState};
use opentele2_core::api::ApiProfile;
use opentele2_core::crypto::AuthKey;
use opentele2_core::session::dc;
use opentele2_core::tdata::account::Account;
use opentele2_core::{Error, Result};

/// The self user of `account` as grammers caches it: a user peer with
/// `is_self` set and `bot` false (tdata holds user accounts only), and no
/// access hash, which the self user does not need. `None` when the user id
/// is outside grammers' user id range.
fn self_user(account: &Account) -> Option<PeerInfo> {
    let id = i64::try_from(account.user_id).ok()?;
    PeerId::user(id)?;
    Some(PeerInfo::User {
        id,
        auth: None,
        bot: Some(false),
        is_self: Some(true),
    })
}

/// grammers session data for `account`.
///
/// - `home_dc` is the account's main DC.
/// - `dc_options` holds every production DC of the core table
///   ([`dc::PRODUCTION_DC_IDS`]) with its first IPv4 and IPv6 endpoint, as
///   [`opentele2_core::session::grammers::SessionData::from_account`] does.
///   Only the main DC carries a key, the account's main DC key.
/// - `peer_infos` holds the self user, keyed by its user id as
///   `Session::cache_peer` keys it.
/// - `updates_state` is empty, so grammers fetches it on first use.
///
/// The conversion cannot fail. An account it cannot fully express yields
/// data that [`account_from_session`] rejects: a main DC outside the
/// production table or a missing main DC key leaves no key in the data, and
/// a user id outside grammers' range (1 to `0xffffffffff`) leaves no self
/// user.
#[must_use]
pub fn session_data(account: &Account) -> SessionData {
    let key = account.auth_key().map(|key| *key.as_bytes());
    let dc_options = dc::PRODUCTION_DC_IDS
        .iter()
        .filter_map(
            |&id| match (dc::production(id, false), dc::production(id, true)) {
                (Some(SocketAddr::V4(ipv4)), Some(SocketAddr::V6(ipv6))) => Some((
                    id,
                    DcOption {
                        id,
                        ipv4,
                        ipv6,
                        auth_key: key.filter(|_| id == account.main_dc),
                    },
                )),
                _ => None,
            },
        )
        .collect();
    let peer_infos: HashMap<PeerId, PeerInfo> = self_user(account)
        .map(|info| (info.id(), info))
        .into_iter()
        .collect();
    SessionData {
        home_dc: account.main_dc,
        dc_options,
        peer_infos,
        updates_state: UpdatesState::default(),
    }
}

/// The account at `index` for grammers session data: the key of the home
/// DC and the user id of the self user, with the home DC as main DC.
///
/// Keys of other DCs, cached peers and the updates state are not part of a
/// tdata account and are dropped.
///
/// # Errors
/// - [`Error::AuthKeyNotFound`] when the home DC has no option or no key.
/// - [`Error::BadConfigData`] when no cached user has `is_self` set, when
///   users with different ids have it set, or when the self user id is
///   negative.
pub fn account_from_session(data: &SessionData, index: i32) -> Result<Account> {
    let key = data
        .dc_options
        .get(&data.home_dc)
        .and_then(|option| option.auth_key)
        .ok_or(Error::AuthKeyNotFound)?;
    let mut self_ids = data.peer_infos.values().filter_map(|info| match info {
        PeerInfo::User {
            id,
            is_self: Some(true),
            ..
        } => Some(*id),
        _ => None,
    });
    let user_id = self_ids.next().ok_or(Error::BadConfigData)?;
    if self_ids.any(|other| other != user_id) {
        return Err(Error::BadConfigData);
    }
    let user_id = u64::try_from(user_id).map_err(|_| Error::BadConfigData)?;
    Account::new(
        index,
        user_id,
        data.home_dc,
        vec![(data.home_dc, AuthKey::new(key))],
    )
}

/// grammers connection params for `profile`: `device_model`,
/// `system_version`, `app_version`, `system_lang_code` and `lang_code` from
/// the profile, every other field the grammers default.
///
/// `api_id` and `api_hash` are not connection params, and `lang_pack` has
/// no field in grammers 0.11; see the [crate docs](crate#fingerprint-gap).
#[must_use]
pub fn connection_params(profile: &ApiProfile) -> ConnectionParams {
    ConnectionParams {
        device_model: profile.device_model.clone(),
        system_version: profile.system_version.clone(),
        app_version: profile.app_version.clone(),
        system_lang_code: profile.system_lang_code.clone(),
        lang_code: profile.lang_code.clone(),
        ..ConnectionParams::default()
    }
}
