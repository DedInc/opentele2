//! The opentele2 1.5.0 client flows over grammers-client 0.11 (feature
//! `client`).
//!
//! Every flow runs over an [`Invoker`], which [`grammers_client::Client`]
//! implements, so it can also run over a fake that returns canned TL
//! objects. Flows that change or read session state (the home DC, the
//! cached self user, the home DC key) also take the grammers [`Session`]
//! the client's `SenderPool` was built with: grammers 0.11 keeps the
//! client's session private.
//!
//! - Login: [`qr_login`] is 1.5.0's `_performQRLogin` with `_handle2FA`,
//!   and [`post_login_requests`] its `_run_post_login_requests`.
//! - Self user: [`get_me_id`].
//! - Session admin: [`sessions`], [`current_session`],
//!   [`terminate_session`], [`terminate_all_sessions`], [`session_row`],
//!   [`sessions_table`] and [`is_official_app`].
//! - Consistency: [`run_consistency_checks`], the seven checks of 1.5.0
//!   `ConsistencyChecker.run_all`.
//! - tdata: [`account_from_client`] and [`tdata_from_client`], 1.5.0
//!   `Account.FromTelethon` with `UseCurrentSession`.
//!
//! # Gaps against 1.5.0
//!
//! - QR login waits for no `updateLoginToken`. 1.5.0 accepts the token on
//!   the authorised client, waits for that update on the new one
//!   (`QRLogin.wait`) and exports the token again. grammers 0.11 delivers
//!   updates only through `SenderPool::updates`, which the caller owns, so
//!   [`qr_login`] exports the token again as soon as
//!   `auth.acceptLoginToken` returns, which the server answers after it has
//!   authorised the token. An export that still yields a plain
//!   `auth.loginToken` counts as 1.5.0's timed-out attempt, so
//!   [`auth::QR_EXPIRE_SAFETY_SECONDS`] has no wait to extend.
//! - The crate has no warning channel: 1.5.0's per-attempt
//!   [`auth::qr_attempt_timeout_warning`] and
//!   [`auth::qr_attempt_retry_warning`] are not emitted, and the
//!   consistency warning is left to the caller
//!   ([`ConsistencyReport::warning`]).
//! - `QRLoginToNewClient`'s connect, its first `_switch_dc` to the
//!   authorised client's DC and its existing-session branch are left to
//!   the caller, who builds the new client's session; a home DC that
//!   differs is handled by the `auth.loginTokenMigrateTo` step. 1.5.0 warns
//!   [`auth::EXISTING_SESSION_KEPT`] or [`auth::EXISTING_SESSION_REPLACED`]
//!   there. A caller replacing a session of another `api_id` replaces it
//!   locally only, as 1.5.0 deletes the session file: it drops that
//!   session and builds the new client on a fresh one, and never sends
//!   `auth.logOut`, which would end the authorisation on the server. No
//!   flow here logs out.
//! - A DC migration sets the session's home DC and invokes
//!   `auth.importLoginToken` there; grammers' private
//!   `disconnect_from_dc` of the old DC is not reachable, so its idle
//!   connection stays open until the pool quits.
//! - The `lang_pack` check asks about the profile's `lang_pack`
//!   ([`ConsistencyExpectations::lang_pack`]); grammers 0.11 sends an
//!   empty one in `initConnection` (see the
//!   [crate docs](crate#fingerprint-gap)), where 1.5.0 asks about the one
//!   the session sends.
//! - Error details are grammers' [`InvocationError`] texts where 1.5.0
//!   prints Telethon's.

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;

use grammers_client::Client;
use grammers_client::tl::{self, RemoteCall};
use grammers_mtsender::{InvocationError, RpcError};
use grammers_session::Session;
use grammers_session::types::{PeerAuth, PeerInfo};
use opentele2_core::auth::{
    self, Check, CheckOutcome, ConsistencyExpectations, ConsistencyReport, PostLoginRequest,
    RawAuthorization, SessionRow, SrpError, SrpParams,
};
use opentele2_core::crypto::AuthKey;
use opentele2_core::tdata::TData;
use opentele2_core::tdata::account::Account;

/// Something that invokes grammers TL functions: [`Client`], or a fake in
/// tests.
pub trait Invoker: Sync {
    /// Invokes `request` on the home DC and returns the server's answer.
    fn invoke<R>(
        &self,
        request: &R,
    ) -> impl Future<Output = Result<R::Return, InvocationError>> + Send
    where
        R: RemoteCall + Sync;
}

impl Invoker for Client {
    fn invoke<R>(
        &self,
        request: &R,
    ) -> impl Future<Output = Result<R::Return, InvocationError>> + Send
    where
        R: RemoteCall + Sync,
    {
        Client::invoke(self, request)
    }
}

/// The 1.5.0 `TelethonUnauthorized` message when the self user is unknown.
pub use opentele2_core::auth::USER_ID_UNRESOLVED;

/// Why a flow failed, named after the 1.5.0 exception it raises.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// `NoPasswordProvided`: the account has 2FA and no password was given.
    NoPasswordProvided,
    /// `PasswordIncorrect`: `auth.checkPassword` failed with
    /// `PASSWORD_HASH_INVALID`.
    PasswordIncorrect(RpcError),
    /// `AuthTokenAlreadyAcceptedError`, re-raised by 1.5.0.
    AuthTokenAlreadyAccepted(RpcError),
    /// `AuthTokenExpiredError`, re-raised by 1.5.0.
    AuthTokenExpired(RpcError),
    /// `AuthTokenInvalidError`, re-raised by 1.5.0.
    AuthTokenInvalid(RpcError),
    /// `TimeoutError`: every QR login attempt ended without a login
    /// ([`auth::QR_LOGIN_TIMEOUT`]).
    QrLoginTimeout,
    /// `FreshResetAuthorisationForbiddenError` of `TerminateSession`.
    FreshResetAuthorisationForbidden(RpcError),
    /// `HashInvalidError` of `TerminateSession`.
    HashInvalid(RpcError),
    /// The account's password uses an algorithm other than
    /// [`auth::SRP_ALGORITHM`] (Telethon `compute_check`), named by its
    /// Telethon class name: `PasswordKdfAlgoUnknown`, or `NoneType`
    /// without one.
    UnsupportedPasswordAlgorithm(String),
    /// The SRP check could not be computed.
    Srp(SrpError),
    /// The server answered a login with `auth.authorizationSignUpRequired`.
    SignUpRequired,
    /// `TelethonUnauthorized`: the self user could not be resolved.
    UserIdUnresolved,
    /// Any other request or session failure.
    Invocation(InvocationError),
    /// An opentele2 core failure, such as a missing home DC key.
    Core(opentele2_core::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPasswordProvided => f.write_str(auth::NO_PASSWORD_PROVIDED),
            Self::PasswordIncorrect(error)
            | Self::AuthTokenAlreadyAccepted(error)
            | Self::AuthTokenExpired(error)
            | Self::AuthTokenInvalid(error) => write!(f, "{error}"),
            Self::QrLoginTimeout => f.write_str(auth::QR_LOGIN_TIMEOUT),
            Self::FreshResetAuthorisationForbidden(_) => f.write_str(auth::FRESH_RESET_FORBIDDEN),
            Self::HashInvalid(_) => f.write_str(auth::HASH_INVALID),
            Self::UnsupportedPasswordAlgorithm(algorithm) => {
                f.write_str(&auth::unsupported_password_algorithm(algorithm))
            }
            Self::Srp(error) => write!(f, "{error}"),
            Self::SignUpRequired => f.write_str(auth::SIGN_UP_REQUIRED),
            Self::UserIdUnresolved => f.write_str(USER_ID_UNRESOLVED),
            Self::Invocation(error) => write!(f, "{error}"),
            Self::Core(error) => write!(f, "{error}"),
        }
    }
}

impl StdError for ClientError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::PasswordIncorrect(error)
            | Self::AuthTokenAlreadyAccepted(error)
            | Self::AuthTokenExpired(error)
            | Self::AuthTokenInvalid(error)
            | Self::FreshResetAuthorisationForbidden(error)
            | Self::HashInvalid(error) => Some(error),
            Self::Srp(error) => Some(error),
            Self::Invocation(error) => Some(error),
            Self::Core(error) => Some(error),
            _ => None,
        }
    }
}

impl From<InvocationError> for ClientError {
    fn from(error: InvocationError) -> Self {
        Self::Invocation(error)
    }
}

impl From<opentele2_core::Error> for ClientError {
    fn from(error: opentele2_core::Error) -> Self {
        Self::Core(error)
    }
}

/// A session error as grammers reports it.
fn session_error<E: Into<Box<dyn StdError + Send + Sync>>>(error: E) -> InvocationError {
    InvocationError::Session(error.into())
}

/// The RPC error inside `error` when its name is `name`.
fn rpc_named(error: &InvocationError, name: &str) -> Option<RpcError> {
    match error {
        InvocationError::Rpc(rpc) if rpc.is(name) => Some(rpc.clone()),
        _ => None,
    }
}

/// Whether the session behind `invoker` is authorised: `updates.getState`
/// succeeds, as grammers' `Client::is_authorized` asks; a 401 is `false`.
///
/// # Errors
/// [`ClientError::Invocation`] for any failure other than a 401.
pub async fn is_authorized<I: Invoker>(invoker: &I) -> Result<bool, ClientError> {
    match invoker.invoke(&tl::functions::updates::GetState {}).await {
        Ok(_) => Ok(true),
        Err(InvocationError::Rpc(error)) if error.code == 401 => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Caches `user` as the session's self user, as Telethon `_on_login` and
/// grammers' login completion do, and returns its id.
async fn on_login<S>(session: &S, user: &tl::enums::User) -> Result<i64, ClientError>
where
    S: Session + ?Sized,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let info = match user {
        tl::enums::User::User(user) => PeerInfo::User {
            id: user.id,
            auth: user.access_hash.map(PeerAuth::from_hash),
            bot: Some(user.bot),
            is_self: Some(true),
        },
        tl::enums::User::Empty(user) => PeerInfo::User {
            id: user.id,
            auth: None,
            bot: None,
            is_self: Some(true),
        },
    };
    session.cache_peer(info).await.map_err(session_error)?;
    Ok(user.id())
}

/// The token an `auth.LoginToken` carries, and the response after a DC
/// migration: an `auth.loginTokenMigrateTo` moves the session's home DC to
/// its DC and is replaced by `auth.importLoginToken` there (1.5.0
/// `_switch_dc` then `ImportLoginTokenRequest`).
async fn follow_migration<N, S>(
    new: &N,
    session: &S,
    response: tl::enums::auth::LoginToken,
) -> Result<tl::enums::auth::LoginToken, InvocationError>
where
    N: Invoker,
    S: Session + ?Sized,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    match response {
        tl::enums::auth::LoginToken::MigrateTo(migrate) => {
            session
                .set_home_dc_id(migrate.dc_id)
                .await
                .map_err(session_error)?;
            new.invoke(&tl::functions::auth::ImportLoginToken {
                token: migrate.token,
            })
            .await
        }
        other => Ok(other),
    }
}

/// `auth.exportLoginToken` on `new` with no ignored ids, as Telethon
/// `qr_login()` sends it, followed through a migration.
async fn export_login_token<N, S>(
    new: &N,
    session: &S,
    api_id: i32,
    api_hash: &str,
) -> Result<tl::enums::auth::LoginToken, InvocationError>
where
    N: Invoker,
    S: Session + ?Sized,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let response = new
        .invoke(&tl::functions::auth::ExportLoginToken {
            api_id,
            api_hash: api_hash.to_owned(),
            except_ids: Vec::new(),
        })
        .await?;
    follow_migration(new, session, response).await
}

/// One 1.5.0 QR login attempt: the authorisation it ended with, or `None`
/// when the token was not accepted in time.
async fn qr_login_attempt<A, N, S>(
    authorized: &A,
    new: &N,
    session: &S,
    api_id: i32,
    api_hash: &str,
) -> Result<Option<tl::enums::auth::Authorization>, InvocationError>
where
    A: Invoker,
    N: Invoker,
    S: Session + ?Sized,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let token = match export_login_token(new, session, api_id, api_hash).await? {
        tl::enums::auth::LoginToken::Success(success) => return Ok(Some(success.authorization)),
        tl::enums::auth::LoginToken::Token(token) => token.token,
        tl::enums::auth::LoginToken::MigrateTo(migrate) => migrate.token,
    };
    authorized
        .invoke(&tl::functions::auth::AcceptLoginToken { token })
        .await?;
    // QRLogin.wait: export again once the token is accepted.
    match export_login_token(new, session, api_id, api_hash).await? {
        tl::enums::auth::LoginToken::Success(success) => Ok(Some(success.authorization)),
        _ => Ok(None),
    }
}

/// The self user of a login answer.
fn authorized_user(
    authorization: tl::enums::auth::Authorization,
) -> Result<tl::enums::User, ClientError> {
    match authorization {
        tl::enums::auth::Authorization::Authorization(authorization) => Ok(authorization.user),
        tl::enums::auth::Authorization::SignUpRequired(_) => Err(ClientError::SignUpRequired),
    }
}

/// The `inputCheckPasswordSRP` for `password` against `info` (Telethon
/// `compute_check`), through [`auth::srp_check_random`].
///
/// Only [`auth::SRP_ALGORITHM`] is supported; any other algorithm is named
/// by its Telethon class name, as the Python binding names it. Without
/// `srp_id` or `srp_B` the check runs with id 0 and an empty `B`, which
/// the core refuses as [`SrpError::BadB`], as the Python binding does; the
/// wire carries the three under one flag, so a decoded answer has either
/// all of them or none.
fn password_check(
    info: &tl::types::account::Password,
    password: &str,
) -> Result<tl::enums::InputCheckPasswordSrp, ClientError> {
    let algo = match &info.current_algo {
        Some(tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(
            algo,
        )) => algo,
        Some(tl::enums::PasswordKdfAlgo::Unknown) => {
            return Err(ClientError::UnsupportedPasswordAlgorithm(
                "PasswordKdfAlgoUnknown".to_owned(),
            ));
        }
        None => {
            return Err(ClientError::UnsupportedPasswordAlgorithm(
                "NoneType".to_owned(),
            ));
        }
    };
    let (srp_id, srp_b) = auth::srp_inputs(info.srp_id, info.srp_b.as_deref());
    let params = SrpParams {
        srp_id,
        g: algo.g,
        p: &algo.p,
        salt1: &algo.salt1,
        salt2: &algo.salt2,
        srp_b: &srp_b,
    };
    let check = auth::srp_check_random(&params, password).map_err(ClientError::Srp)?;
    Ok(tl::enums::InputCheckPasswordSrp::Srp(
        tl::types::InputCheckPasswordSrp {
            srp_id: check.srp_id,
            a: check.a.to_vec(),
            m1: check.m1.to_vec(),
        },
    ))
}

/// 1.5.0 `_handle2FA`: `account.getPassword`, then `auth.checkPassword`
/// with the SRP check of `password`.
async fn two_factor<N, S>(new: &N, session: &S, password: Option<&str>) -> Result<i64, ClientError>
where
    N: Invoker,
    S: Session + ?Sized,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let password = password.ok_or(ClientError::NoPasswordProvided)?;
    let tl::enums::account::Password::Password(info) =
        new.invoke(&tl::functions::account::GetPassword {}).await?;
    let check = password_check(&info, password)?;
    match new
        .invoke(&tl::functions::auth::CheckPassword { password: check })
        .await
    {
        Ok(authorization) => on_login(session, &authorized_user(authorization)?).await,
        Err(error) => Err(match rpc_named(&error, auth::RPC_PASSWORD_HASH_INVALID) {
            Some(rpc) => ClientError::PasswordIncorrect(rpc),
            None => error.into(),
        }),
    }
}

/// Logs the session behind `new` in through the authorised client
/// `authorized` by QR login, as 1.5.0 `_performQRLogin` does, and returns
/// the user id.
///
/// `new_session` is the session `new`'s `SenderPool` was built with; it
/// receives the home DC of a migration and the self user. Each of up to
/// [`auth::QR_LOGIN_ATTEMPTS`] attempts:
///
/// 1. From the second attempt on, stops when `new` is already authorised
///    ([`is_authorized`]) and returns [`get_me_id`].
/// 2. `auth.exportLoginToken` on `new` with `api_id` and `api_hash`; an
///    `auth.loginTokenMigrateTo` sets the home DC and is followed by
///    `auth.importLoginToken`. An `auth.loginTokenSuccess` logs in.
/// 3. `auth.acceptLoginToken` with the token on `authorized`.
/// 4. The export again (see the [module docs](self#gaps-against-150)): a
///    success logs in, a plain token ends the attempt.
///
/// `SESSION_PASSWORD_NEEDED` at any step runs 1.5.0 `_handle2FA`:
/// `account.getPassword`, then `auth.checkPassword` with
/// [`auth::srp_check_random`] of `password`.
///
/// # Errors
/// - [`ClientError::NoPasswordProvided`] when 2FA is needed and `password`
///   is `None`; [`ClientError::PasswordIncorrect`] when it is wrong;
///   [`ClientError::UnsupportedPasswordAlgorithm`] for an algorithm other
///   than [`auth::SRP_ALGORITHM`] and [`ClientError::Srp`] when the
///   password parameters are unusable.
/// - [`ClientError::AuthTokenAlreadyAccepted`],
///   [`ClientError::AuthTokenExpired`] and [`ClientError::AuthTokenInvalid`]
///   for the RPC errors of those names.
/// - [`ClientError::QrLoginTimeout`] when no attempt logged in.
/// - [`ClientError::SignUpRequired`] for a sign-up answer, and
///   [`ClientError::Invocation`] for any other failure.
pub async fn qr_login<A, N, S>(
    authorized: &A,
    new: &N,
    new_session: &S,
    api_id: i32,
    api_hash: &str,
    password: Option<&str>,
) -> Result<i64, ClientError>
where
    A: Invoker,
    N: Invoker,
    S: Session + ?Sized,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    for attempt in 0..auth::QR_LOGIN_ATTEMPTS {
        if attempt > 0 && is_authorized(new).await? {
            return get_me_id(new).await;
        }
        match qr_login_attempt(authorized, new, new_session, api_id, api_hash).await {
            Ok(Some(authorization)) => {
                return on_login(new_session, &authorized_user(authorization)?).await;
            }
            Ok(None) => {}
            Err(error) if rpc_named(&error, auth::RPC_SESSION_PASSWORD_NEEDED).is_some() => {
                return two_factor(new, new_session, password).await;
            }
            Err(InvocationError::Rpc(rpc)) if rpc.is(auth::RPC_AUTH_TOKEN_ALREADY_ACCEPTED) => {
                return Err(ClientError::AuthTokenAlreadyAccepted(rpc));
            }
            Err(InvocationError::Rpc(rpc)) if rpc.is(auth::RPC_AUTH_TOKEN_EXPIRED) => {
                return Err(ClientError::AuthTokenExpired(rpc));
            }
            Err(InvocationError::Rpc(rpc)) if rpc.is(auth::RPC_AUTH_TOKEN_INVALID) => {
                return Err(ClientError::AuthTokenInvalid(rpc));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(ClientError::QrLoginTimeout)
}

/// 1.5.0 `_run_post_login_requests`: the steps of
/// [`auth::post_login_steps`] for `lang_pack` (`help.getConfig`,
/// `help.getNearestDc`, `account.updateStatus(offline=false)`,
/// `langpack.getLanguages` only for a non-empty `lang_pack`,
/// `help.getAppUpdate(source="")`, `help.getTermsOfServiceUpdate` and
/// `help.getCountriesList("en", 0)`), each after `delay(min_ms, max_ms)`
/// of its [`auth::PostLoginStep::delay_ms`] where it has one. 1.5.0 sleeps
/// [`auth::random_delay_ms`]`(min_ms, max_ms)` milliseconds; `delay` does
/// the waiting, so the caller picks the timer.
///
/// Failures are ignored, as in 1.5.0; the number of requests that failed
/// is returned.
pub async fn post_login_requests<I, D, F>(invoker: &I, lang_pack: &str, mut delay: D) -> usize
where
    I: Invoker,
    D: FnMut(u64, u64) -> F + Send,
    F: Future<Output = ()> + Send,
{
    let mut failed = 0;
    for step in auth::post_login_steps(lang_pack) {
        if let Some((min, max)) = step.delay_ms {
            delay(min, max).await;
        }
        let ok = match step.request {
            PostLoginRequest::GetConfig => invoker
                .invoke(&tl::functions::help::GetConfig {})
                .await
                .is_ok(),
            PostLoginRequest::GetNearestDc => invoker
                .invoke(&tl::functions::help::GetNearestDc {})
                .await
                .is_ok(),
            PostLoginRequest::UpdateStatus => invoker
                .invoke(&tl::functions::account::UpdateStatus { offline: false })
                .await
                .is_ok(),
            PostLoginRequest::GetLanguages => invoker
                .invoke(&tl::functions::langpack::GetLanguages {
                    lang_pack: lang_pack.to_owned(),
                })
                .await
                .is_ok(),
            PostLoginRequest::GetAppUpdate => invoker
                .invoke(&tl::functions::help::GetAppUpdate {
                    source: auth::POST_LOGIN_APP_UPDATE_SOURCE.to_owned(),
                })
                .await
                .is_ok(),
            PostLoginRequest::GetTermsOfServiceUpdate => invoker
                .invoke(&tl::functions::help::GetTermsOfServiceUpdate {})
                .await
                .is_ok(),
            PostLoginRequest::GetCountriesList => invoker
                .invoke(&tl::functions::help::GetCountriesList {
                    lang_code: auth::POST_LOGIN_COUNTRIES_LANG_CODE.to_owned(),
                    hash: 0,
                })
                .await
                .is_ok(),
        };
        failed += usize::from(!ok);
    }
    failed
}

/// The id of the self user: `users.getUsers([inputUserSelf])`, as
/// Telethon `get_me` and grammers `Client::get_me` ask.
///
/// # Errors
/// - [`ClientError::UserIdUnresolved`] when the server returns no user.
/// - [`ClientError::Invocation`] when the request fails.
pub async fn get_me_id<I: Invoker>(invoker: &I) -> Result<i64, ClientError> {
    let users = invoker
        .invoke(&tl::functions::users::GetUsers {
            id: vec![tl::enums::InputUser::UserSelf],
        })
        .await?;
    users
        .first()
        .map(tl::enums::User::id)
        .ok_or(ClientError::UserIdUnresolved)
}

/// Every session of the account, 1.5.0 `GetSessions`
/// (`account.getAuthorizations`).
///
/// # Errors
/// [`ClientError::Invocation`] when the request fails.
pub async fn sessions<I: Invoker>(
    invoker: &I,
) -> Result<Vec<tl::types::Authorization>, ClientError> {
    let tl::enums::account::Authorizations::Authorizations(list) = invoker
        .invoke(&tl::functions::account::GetAuthorizations {})
        .await?;
    Ok(list
        .authorizations
        .into_iter()
        .map(|tl::enums::Authorization::Authorization(authorization)| authorization)
        .collect())
}

/// The session flagged `current`, 1.5.0 `GetCurrentSession`.
///
/// # Errors
/// As [`sessions`].
pub async fn current_session<I: Invoker>(
    invoker: &I,
) -> Result<Option<tl::types::Authorization>, ClientError> {
    Ok(sessions(invoker)
        .await?
        .into_iter()
        .find(|authorization| authorization.current))
}

/// Ends the session `hash`, 1.5.0 `TerminateSession`
/// (`account.resetAuthorization`).
///
/// # Errors
/// - [`ClientError::FreshResetAuthorisationForbidden`] for
///   `FRESH_RESET_AUTHORISATION_FORBIDDEN`.
/// - [`ClientError::HashInvalid`] for `HASH_INVALID`.
/// - [`ClientError::Invocation`] for any other failure.
pub async fn terminate_session<I: Invoker>(invoker: &I, hash: i64) -> Result<(), ClientError> {
    match invoker
        .invoke(&tl::functions::account::ResetAuthorization { hash })
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => Err(
            if let Some(rpc) = rpc_named(&error, auth::RPC_FRESH_RESET_AUTHORISATION_FORBIDDEN) {
                ClientError::FreshResetAuthorisationForbidden(rpc)
            } else if let Some(rpc) = rpc_named(&error, auth::RPC_HASH_INVALID) {
                ClientError::HashInvalid(rpc)
            } else {
                error.into()
            },
        ),
    }
}

/// Ends every session but the current one, in list order, 1.5.0
/// `TerminateAllSessions`, and returns how many were ended.
///
/// # Errors
/// As [`sessions`] and [`terminate_session`]; the first failure stops the
/// loop, as in 1.5.0.
pub async fn terminate_all_sessions<I: Invoker>(invoker: &I) -> Result<usize, ClientError> {
    let mut ended = 0;
    for authorization in sessions(invoker).await? {
        if !authorization.current {
            terminate_session(invoker, authorization.hash).await?;
            ended += 1;
        }
    }
    Ok(ended)
}

/// The 1.5.0 `PrintSessions` fields of `authorization`, through
/// [`SessionRow::from_authorization`]; grammers always decodes the
/// `current` and `official_app` flags.
#[must_use]
pub fn session_row(authorization: &tl::types::Authorization) -> SessionRow {
    SessionRow::from_authorization(&RawAuthorization {
        current: Some(authorization.current),
        device_model: &authorization.device_model,
        platform: &authorization.platform,
        system_version: &authorization.system_version,
        api_id: authorization.api_id,
        app_name: &authorization.app_name,
        app_version: &authorization.app_version,
        official_app: Some(authorization.official_app),
    })
}

/// The table 1.5.0 `PrintSessions` prints ([`auth::format_sessions`]) for
/// the account's sessions.
///
/// # Errors
/// As [`sessions`].
pub async fn sessions_table<I: Invoker>(invoker: &I) -> Result<String, ClientError> {
    let rows: Vec<SessionRow> = sessions(invoker).await?.iter().map(session_row).collect();
    Ok(auth::format_sessions(&rows))
}

/// Whether the server flags the current session `official_app`, 1.5.0
/// `is_official_app`; `false` without a current session.
///
/// # Errors
/// As [`sessions`].
pub async fn is_official_app<I: Invoker>(invoker: &I) -> Result<bool, ClientError> {
    Ok(current_session(invoker)
        .await?
        .is_some_and(|authorization| authorization.official_app))
}

/// A check that ended with its own result.
fn finished(passed: bool, detail: String) -> CheckOutcome {
    CheckOutcome::Finished { passed, detail }
}

async fn check_get_config<I: Invoker>(invoker: &I) -> CheckOutcome {
    match invoker.invoke(&tl::functions::help::GetConfig {}).await {
        Ok(tl::enums::Config::Config(config)) => {
            finished(true, auth::get_config_detail(Some(config.this_dc)))
        }
        Err(error) => finished(false, auth::get_config_error(&error.to_string())),
    }
}

async fn check_nearest_dc<I: Invoker>(invoker: &I) -> CheckOutcome {
    match invoker.invoke(&tl::functions::help::GetNearestDc {}).await {
        Ok(tl::enums::NearestDc::Dc(nearest)) => finished(
            true,
            auth::nearest_dc_detail(&nearest.country, nearest.this_dc, nearest.nearest_dc),
        ),
        Err(error) => finished(false, auth::nearest_dc_error(&error.to_string())),
    }
}

async fn check_current_session<I: Invoker>(invoker: &I) -> CheckOutcome {
    match current_session(invoker).await {
        Ok(Some(authorization)) => {
            let row = session_row(&authorization);
            finished(row.official_app, auth::current_session_detail(&row))
        }
        Ok(None) => finished(false, auth::CURRENT_SESSION_MISSING.to_owned()),
        Err(error) => finished(false, auth::check_error(&error.to_string())),
    }
}

fn check_layer_match(expectations: &ConsistencyExpectations) -> CheckOutcome {
    let result = expectations.layer_result(tl::LAYER);
    finished(result.passed, result.detail)
}

async fn check_lang_pack<I: Invoker>(
    invoker: &I,
    expectations: &ConsistencyExpectations,
) -> CheckOutcome {
    if expectations.lang_pack_skipped() {
        return finished(true, auth::LANG_PACK_EMPTY.to_owned());
    }
    let lang_pack = &expectations.lang_pack;
    match invoker
        .invoke(&tl::functions::langpack::GetLanguages {
            lang_pack: lang_pack.clone(),
        })
        .await
    {
        Ok(languages) => finished(true, auth::lang_pack_detail(lang_pack, languages.len())),
        Err(error) => finished(false, auth::lang_pack_error(lang_pack, &error.to_string())),
    }
}

async fn check_app_update<I: Invoker>(invoker: &I) -> CheckOutcome {
    match invoker
        .invoke(&tl::functions::help::GetAppUpdate {
            source: String::new(),
        })
        .await
    {
        Ok(tl::enums::help::AppUpdate::NoAppUpdate) => {
            finished(true, auth::NO_APP_UPDATE.to_owned())
        }
        Ok(tl::enums::help::AppUpdate::Update(update)) => {
            finished(true, auth::app_update_detail(Some(&update.version)))
        }
        Err(error) => finished(false, auth::app_update_error(&error.to_string())),
    }
}

async fn check_terms_of_service<I: Invoker>(invoker: &I) -> CheckOutcome {
    match invoker
        .invoke(&tl::functions::help::GetTermsOfServiceUpdate {})
        .await
    {
        Ok(_) => finished(true, auth::TERMS_OF_SERVICE_OK.to_owned()),
        Err(error) => finished(false, auth::check_error(&error.to_string())),
    }
}

/// Runs `check` over `invoker`.
async fn run_check<I: Invoker>(
    invoker: &I,
    expectations: &ConsistencyExpectations,
    check: Check,
) -> CheckOutcome {
    match check {
        Check::GetConfig => check_get_config(invoker).await,
        Check::NearestDc => check_nearest_dc(invoker).await,
        Check::CurrentSession => check_current_session(invoker).await,
        Check::LayerMatch => check_layer_match(expectations),
        Check::LangPack => check_lang_pack(invoker, expectations).await,
        Check::AppUpdate => check_app_update(invoker).await,
        Check::TermsOfService => check_terms_of_service(invoker).await,
    }
}

/// The seven checks of 1.5.0 `ConsistencyChecker.run_all`, run one after
/// the other in [`Check::ALL`] order, as [`auth::consistency_report`]
/// builds the report from their outcomes.
///
/// - `get_config`, `nearest_dc`, `app_update` and `terms_of_service` pass
///   when their request succeeds.
/// - `current_session` passes when the current session is flagged
///   `official_app`.
/// - `layer_match` compares grammers' [`tl::LAYER`] with
///   [`ConsistencyExpectations::layer_result`].
/// - `lang_pack` asks `langpack.getLanguages` about the expected
///   `lang_pack`, and passes without a request when it is empty.
///
/// No check raises out of its own handling, so 1.5.0's `Exception:` entry
/// ([`auth::check_exception`]) never appears.
/// [`ConsistencyReport::summary`] is 1.5.0's report text and
/// [`ConsistencyReport::warning`] the warning its `auto_warn` emits, which
/// this crate leaves to the caller.
pub async fn run_consistency_checks<I: Invoker>(
    invoker: &I,
    expectations: &ConsistencyExpectations,
) -> ConsistencyReport {
    let [c0, c1, c2, c3, c4, c5, c6] = Check::ALL;
    auth::consistency_report([
        run_check(invoker, expectations, c0).await,
        run_check(invoker, expectations, c1).await,
        run_check(invoker, expectations, c2).await,
        run_check(invoker, expectations, c3).await,
        run_check(invoker, expectations, c4).await,
        run_check(invoker, expectations, c5).await,
        run_check(invoker, expectations, c6).await,
    ])
}

/// The account at `index` for the session behind `invoker`, 1.5.0
/// `Account.FromTelethon` with `UseCurrentSession`: the home DC of
/// `session` as main DC with its key, and the user id of [`get_me_id`].
///
/// # Errors
/// - [`ClientError::Core`] with [`opentele2_core::Error::AuthKeyNotFound`]
///   when the home DC has no key, and with
///   [`opentele2_core::Error::BadConfigData`] for a negative user id.
/// - As [`get_me_id`], and [`ClientError::Invocation`] when the session
///   cannot be read.
pub async fn account_from_client<I, S>(
    invoker: &I,
    session: &S,
    index: i32,
) -> Result<Account, ClientError>
where
    I: Invoker,
    S: Session + ?Sized,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let home_dc = session.home_dc_id().map_err(session_error)?;
    let key = session
        .dc_option(home_dc)
        .map_err(session_error)?
        .and_then(|option| option.auth_key)
        .ok_or(opentele2_core::Error::AuthKeyNotFound)?;
    let user_id = get_me_id(invoker).await?;
    let user_id = u64::try_from(user_id).map_err(|_| opentele2_core::Error::BadConfigData {
        context: opentele2_core::ConfigFailure::BadUserId { user_id },
    })?;
    Ok(Account::new(
        index,
        user_id,
        home_dc,
        vec![(home_dc, AuthKey::new(key))],
    )?)
}

/// A new tdata folder holding the session behind `invoker` as its only
/// account (index 0), as 1.5.0 `FromTelethon` builds one without an owner:
/// [`account_from_client`], then [`TData::new`] with `passcode`,
/// performance mode on (the 1.5.0 default) and `rng`.
///
/// 1.5.0's `CreateNewSession` flag first logs a new session in by QR
/// login; run [`qr_login`] and pass the new client and its session here.
///
/// # Errors
/// As [`account_from_client`] and [`TData::new`].
pub async fn tdata_from_client<I, S>(
    invoker: &I,
    session: &S,
    passcode: &[u8],
    rng: &mut (dyn FnMut(&mut [u8]) + Send),
) -> Result<TData, ClientError>
where
    I: Invoker,
    S: Session + ?Sized,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let account = account_from_client(invoker, session, 0).await?;
    Ok(TData::new(vec![account], passcode, true, rng)?)
}
