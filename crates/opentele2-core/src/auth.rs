//! The client-independent parts of login, session admin and consistency
//! checks.
//!
//! The flows themselves run on each ecosystem's own client; this module
//! holds the pure pieces they share:
//!
//! - Login: [`qr_login_url`] is the `tg://login` URL of Telethon
//!   `QRLogin.url`, and [`srp_check`] computes the `InputCheckPasswordSRP`
//!   values of Telethon `password.compute_check` over
//!   [`grammers_crypto::two_factor_auth::calculate_2fa`].
//! - Session admin: [`format_sessions`] is the table `PrintSessions`
//!   prints, drawn by [`format_table`] (`PrettyTable`),
//!   [`OFFICIAL_API_IDS`] the api ids of the official profiles, and
//!   the `TerminateSession` and `_handle2FA` messages are constants.
//!   [`SessionRow::from_authorization`] maps a client's raw fields.
//! - Login flow: the post-login sequence ([`POST_LOGIN_STEPS`]) with its
//!   sleeps ([`random_delay_ms`]), the QR login constants and warnings
//!   ([`QR_LOGIN_ATTEMPTS`], [`qr_attempt_timeout_warning`]) and the 2FA
//!   algorithm name ([`SRP_ALGORITHM`]), the `srp_id`/`srp_B` rule
//!   ([`srp_inputs`]), the RPC error names the flows match (`RPC_*`), and
//!   the code and exception class of each flow failure ([`FlowFailure`]).
//! - Consistency: [`ConsistencyExpectations`] says what each of the seven
//!   `ConsistencyChecker` checks ([`Check`]) expects for a profile, and
//!   [`CheckResult`] with [`consistency_summary`] and the detail builders
//!   produce its report text; [`consistency_report`] builds the report
//!   from each check's [`CheckOutcome`].

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use grammers_crypto::two_factor_auth::{calculate_2fa, check_p_and_g};
use sha2::{Digest, Sha256};

use crate::api::{self, ApiProfile, Client, LAYER, Versions};
use crate::fingerprint::{self, Issue};

/// The scheme and query key in front of a QR login token.
pub const QR_LOGIN_URL_PREFIX: &str = "tg://login?token=";

/// The URL a QR login code carries for the `auth.exportLoginToken` `token`:
/// [`QR_LOGIN_URL_PREFIX`] and the token in URL-safe base64 without `=`
/// padding, as Telethon `QRLogin.url` builds it.
#[must_use]
pub fn qr_login_url(token: &[u8]) -> String {
    format!("{QR_LOGIN_URL_PREFIX}{}", URL_SAFE_NO_PAD.encode(token))
}

/// The size in bytes of the SRP numbers: the 2048-bit prime `p`, `A`, `B`
/// and the secret exponent `a` (Telethon `SIZE_FOR_HASH`).
pub const SRP_NUMBER_SIZE: usize = 256;

/// The 2048-bit prime Telegram uses for 2FA; Telethon accepts it with
/// `g` 3, 4, 5 or 7 without testing it (`check_prime_and_good`).
const KNOWN_GOOD_PRIME: [u8; SRP_NUMBER_SIZE] = crate::tdata::hex_bytes(concat!(
    "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f",
    "48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37",
    "20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64",
    "2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4",
    "a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754",
    "fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4",
    "e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f",
    "0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b",
));

/// How many secret exponents [`srp_check`] draws before it gives up.
/// Telethon draws until one is good; a draw fails with a chance near
/// 2^-64, so only a broken random source reaches this bound.
const SRP_MAX_DRAWS: usize = 32;

/// The `account.Password` fields [`srp_check`] needs, for the
/// `passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow`
/// algorithm (the only one Telethon `compute_check` supports).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrpParams<'a> {
    /// `account.Password.srp_id`, passed through to the check.
    pub srp_id: i64,
    /// The algorithm's `g`.
    pub g: i32,
    /// The algorithm's `p`, big-endian.
    pub p: &'a [u8],
    /// The algorithm's `salt1`.
    pub salt1: &'a [u8],
    /// The algorithm's `salt2`.
    pub salt2: &'a [u8],
    /// `account.Password.srp_B`, big-endian.
    pub srp_b: &'a [u8],
}

/// The values of an `inputCheckPasswordSRP`.
///
/// `Debug` shows the `srp_id` only: `m1` proves knowledge of the password.
#[derive(Clone, PartialEq, Eq)]
pub struct SrpCheck {
    /// The `srp_id` of the [`SrpParams`].
    pub srp_id: i64,
    /// `A = g^a mod p`, big-endian in 256 bytes.
    pub a: [u8; SRP_NUMBER_SIZE],
    /// The proof `M1`.
    pub m1: [u8; 32],
}

impl fmt::Debug for SrpCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrpCheck")
            .field("srp_id", &self.srp_id)
            .finish_non_exhaustive()
    }
}

/// Why [`srp_check`] refused the parameters; the messages are Telethon's
/// `ValueError` texts where it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SrpError {
    /// `p` is not a 2048-bit safe prime in 256 bytes, or `g` is not a
    /// generator Telegram allows for it.
    #[error("bad p/g in password")]
    BadPrimeOrGenerator,
    /// `srp_B` is not in `1..p`, or is longer than 256 bytes.
    #[error("bad b in check")]
    BadB,
    /// The random source gave no usable secret exponent.
    #[error("no usable random SRP exponent was drawn")]
    NoGoodRandom,
    /// The operating system's random source failed.
    #[error("the system random source failed")]
    RandomUnavailable,
}

impl SrpError {
    /// The stable error code of the refusal, in the style of
    /// [`crate::Error::code`]: `SRP_BAD_PRIME_OR_GENERATOR`, `SRP_BAD_B`,
    /// `SRP_NO_GOOD_RANDOM` or `SRP_RANDOM_UNAVAILABLE`. The Python binding
    /// raises it as is; the Node binding prefixes `OT_`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::BadPrimeOrGenerator => "SRP_BAD_PRIME_OR_GENERATOR",
            Self::BadB => "SRP_BAD_B",
            Self::NoGoodRandom => "SRP_NO_GOOD_RANDOM",
            Self::RandomUnavailable => "SRP_RANDOM_UNAVAILABLE",
        }
    }

    /// The class name of the exception raised for the refusal, in the
    /// style of [`crate::Error::legacy_class`] and the single source the
    /// bindings use: `ValueError` for every refusal (Telethon
    /// `compute_check` raises it).
    #[must_use]
    pub fn legacy_class(self) -> &'static str {
        match self {
            Self::BadPrimeOrGenerator
            | Self::BadB
            | Self::NoGoodRandom
            | Self::RandomUnavailable => "ValueError",
        }
    }
}

/// The `srp_id` and `srp_B` [`SrpParams`] takes from an `account.Password`
/// whose fields are `srp_id` and `srp_b`, the rule both bindings share:
/// both as given when both are present, otherwise id 0 and an empty `B`,
/// which [`srp_check`] refuses with [`SrpError::BadB`] (Telethon cannot
/// run the check without them either).
#[must_use]
pub fn srp_inputs(srp_id: Option<i64>, srp_b: Option<&[u8]>) -> (i64, Vec<u8>) {
    match (srp_id, srp_b) {
        (Some(srp_id), Some(srp_b)) => (srp_id, srp_b.to_vec()),
        _ => (0, Vec::new()),
    }
}

/// The RPC error `auth.checkPassword` fails with for a wrong password; the
/// flows raise it as [`FlowFailure::PasswordIncorrect`].
pub const RPC_PASSWORD_HASH_INVALID: &str = "PASSWORD_HASH_INVALID";

/// The RPC error of a QR login step on an account with 2FA; the flows then
/// run `_handle2FA`.
pub const RPC_SESSION_PASSWORD_NEEDED: &str = "SESSION_PASSWORD_NEEDED";

/// The RPC error `account.resetAuthorization` fails with within 24 hours of
/// login ([`FlowFailure::FreshResetForbidden`]).
pub const RPC_FRESH_RESET_AUTHORISATION_FORBIDDEN: &str = "FRESH_RESET_AUTHORISATION_FORBIDDEN";

/// The RPC error `account.resetAuthorization` fails with for an unknown
/// hash ([`FlowFailure::HashInvalid`]).
pub const RPC_HASH_INVALID: &str = "HASH_INVALID";

/// The RPC error of a QR login token accepted already; the flows re-raise it.
pub const RPC_AUTH_TOKEN_ALREADY_ACCEPTED: &str = "AUTH_TOKEN_ALREADY_ACCEPTED";

/// The RPC error of an expired QR login token; the flows re-raise it.
pub const RPC_AUTH_TOKEN_EXPIRED: &str = "AUTH_TOKEN_EXPIRED";

/// The RPC error of an invalid QR login token; the flows re-raise it.
pub const RPC_AUTH_TOKEN_INVALID: &str = "AUTH_TOKEN_INVALID";

/// The `TelethonUnauthorized` message when the self user of a client
/// cannot be resolved.
pub const USER_ID_UNRESOLVED: &str = "Could not resolve the account's user id";

/// The message of a login the server answered with
/// `auth.authorizationSignUpRequired` ([`FlowFailure::SignUpRequired`]).
pub const SIGN_UP_REQUIRED: &str = "the server asked to sign up instead of logging in";

/// Why a login or session admin flow failed, for the bindings to name their
/// errors from one table ([`FlowFailure::code`], [`FlowFailure::legacy_class`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FlowFailure {
    /// 2FA is needed and no password was given ([`NO_PASSWORD_PROVIDED`]).
    NoPasswordProvided,
    /// `auth.checkPassword` failed with [`RPC_PASSWORD_HASH_INVALID`].
    PasswordIncorrect,
    /// [`RPC_AUTH_TOKEN_ALREADY_ACCEPTED`], re-raised.
    AuthTokenAlreadyAccepted,
    /// [`RPC_AUTH_TOKEN_EXPIRED`], re-raised.
    AuthTokenExpired,
    /// [`RPC_AUTH_TOKEN_INVALID`], re-raised.
    AuthTokenInvalid,
    /// No QR login attempt logged in ([`QR_LOGIN_TIMEOUT`]).
    QrLoginTimeout,
    /// `TerminateSession` hit [`RPC_FRESH_RESET_AUTHORISATION_FORBIDDEN`]
    /// ([`FRESH_RESET_FORBIDDEN`]).
    FreshResetForbidden,
    /// `TerminateSession` hit [`RPC_HASH_INVALID`] ([`HASH_INVALID`]).
    HashInvalid,
    /// The password uses an algorithm other than [`SRP_ALGORITHM`]
    /// ([`unsupported_password_algorithm`]).
    UnsupportedPasswordAlgorithm,
    /// A login was answered with a sign-up request ([`SIGN_UP_REQUIRED`]).
    SignUpRequired,
    /// The self user could not be resolved ([`USER_ID_UNRESOLVED`]).
    UserIdUnresolved,
    /// The sessions could not be fetched ([`SESSIONS_UNAVAILABLE`]).
    SessionsUnavailable,
}

impl FlowFailure {
    /// Every flow failure, in declaration order.
    pub const ALL: [Self; 12] = [
        Self::NoPasswordProvided,
        Self::PasswordIncorrect,
        Self::AuthTokenAlreadyAccepted,
        Self::AuthTokenExpired,
        Self::AuthTokenInvalid,
        Self::QrLoginTimeout,
        Self::FreshResetForbidden,
        Self::HashInvalid,
        Self::UnsupportedPasswordAlgorithm,
        Self::SignUpRequired,
        Self::UserIdUnresolved,
        Self::SessionsUnavailable,
    ];

    /// The stable error code of the failure, in the style of
    /// [`SrpError::code`]; the Node binding prefixes `OT_`, for example
    /// `OT_PASSWORD_INCORRECT`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NoPasswordProvided => "NO_PASSWORD_PROVIDED",
            Self::PasswordIncorrect => "PASSWORD_INCORRECT",
            Self::AuthTokenAlreadyAccepted => "AUTH_TOKEN_ALREADY_ACCEPTED",
            Self::AuthTokenExpired => "AUTH_TOKEN_EXPIRED",
            Self::AuthTokenInvalid => "AUTH_TOKEN_INVALID",
            Self::QrLoginTimeout => "QR_LOGIN_TIMEOUT",
            Self::FreshResetForbidden => "FRESH_RESET_FORBIDDEN",
            Self::HashInvalid => "HASH_INVALID",
            Self::UnsupportedPasswordAlgorithm => "UNSUPPORTED_PASSWORD_ALGORITHM",
            Self::SignUpRequired => "SIGN_UP_REQUIRED",
            Self::UserIdUnresolved => "USER_ID_UNRESOLVED",
            Self::SessionsUnavailable => "SESSIONS_UNAVAILABLE",
        }
    }

    /// The class name of the exception raised for the failure, the
    /// single source the bindings name their flow errors after: an
    /// opentele2 class (`NoPasswordProvided`, `PasswordIncorrect`,
    /// `TelethonUnauthorized`, `OpenTeleException`), a Telethon RPC error
    /// class (`AuthTokenExpiredError`, `HashInvalidError`, ...) or a builtin
    /// (`TimeoutError`, and `ValueError` from Telethon `compute_check` for
    /// an unsupported algorithm). A sign-up answer,
    /// [`FlowFailure::SignUpRequired`], gives `SignUpRequired`.
    #[must_use]
    pub fn legacy_class(self) -> &'static str {
        match self {
            Self::NoPasswordProvided => "NoPasswordProvided",
            Self::PasswordIncorrect => "PasswordIncorrect",
            Self::AuthTokenAlreadyAccepted => "AuthTokenAlreadyAcceptedError",
            Self::AuthTokenExpired => "AuthTokenExpiredError",
            Self::AuthTokenInvalid => "AuthTokenInvalidError",
            Self::QrLoginTimeout => "TimeoutError",
            Self::FreshResetForbidden => "FreshResetAuthorisationForbiddenError",
            Self::HashInvalid => "HashInvalidError",
            Self::UnsupportedPasswordAlgorithm => "ValueError",
            Self::SignUpRequired => "SignUpRequired",
            Self::UserIdUnresolved => "TelethonUnauthorized",
            Self::SessionsUnavailable => "OpenTeleException",
        }
    }
}

/// The `inputCheckPasswordSRP` for `password` (Telethon
/// `password.compute_check`), drawing each 256-byte secret exponent `a`
/// from `rng`.
///
/// As in Telethon, `p` and `g` are checked first (the known Telegram prime
/// with `g` 3, 4, 5 or 7 is accepted as is; any other pair must pass
/// [`check_p_and_g`]), then `0 < B < p`. An `a` is drawn again while
/// `A = g^a mod p` is not within 2^1984 of both 0 and `p`, or
/// `u = H(A | B)` is zero. The password is UTF-8 encoded, as Telethon does.
///
/// Unlike Telethon, `p` must be exactly 256 bytes, `srp_B` at most 256
/// bytes, and drawing stops after a bounded number of bad exponents.
/// Telethon's `bad g_b` check on `(B - k·g^x) mod p` is not repeated: that
/// value stays inside grammers-crypto, and an honest server fails it with a
/// chance near 2^-64.
///
/// # Errors
/// - [`SrpError::BadPrimeOrGenerator`] for a bad `p` or `g`.
/// - [`SrpError::BadB`] for a bad `srp_B`.
/// - [`SrpError::NoGoodRandom`] when every draw was unusable.
///
/// # Panics
/// When a `p` other than Telegram's known prime is tested and the
/// operating system's random source fails (grammers-crypto's prime test
/// needs it).
pub fn srp_check(
    params: &SrpParams<'_>,
    password: &str,
    rng: &mut dyn FnMut(&mut [u8]),
) -> Result<SrpCheck, SrpError> {
    srp_check_with(params, password, &mut |buf| {
        rng(buf);
        Ok(())
    })
}

/// [`srp_check`] with exponents from the operating system's CSPRNG.
///
/// # Errors
/// [`SrpError::RandomUnavailable`] when the system random source fails,
/// otherwise as [`srp_check`].
///
/// # Panics
/// As [`srp_check`].
pub fn srp_check_random(params: &SrpParams<'_>, password: &str) -> Result<SrpCheck, SrpError> {
    srp_check_with(params, password, &mut |buf| {
        crate::crypto::random_fill(buf).map_err(|_| SrpError::RandomUnavailable)
    })
}

fn srp_check_with(
    params: &SrpParams<'_>,
    password: &str,
    rng: &mut dyn FnMut(&mut [u8]) -> Result<(), SrpError>,
) -> Result<SrpCheck, SrpError> {
    let p: &[u8; SRP_NUMBER_SIZE] = params
        .p
        .try_into()
        .map_err(|_| SrpError::BadPrimeOrGenerator)?;
    if !good_prime_and_generator(p, params.g) {
        return Err(SrpError::BadPrimeOrGenerator);
    }
    let b = pad_number(params.srp_b).ok_or(SrpError::BadB)?;
    if b.iter().all(|&byte| byte == 0) || b >= *p {
        return Err(SrpError::BadB);
    }

    let mut secret = [0u8; SRP_NUMBER_SIZE];
    let mut outcome = Err(SrpError::NoGoodRandom);
    for _ in 0..SRP_MAX_DRAWS {
        if let Err(error) = rng(&mut secret) {
            outcome = Err(error);
            break;
        }
        let (m1, a) = calculate_2fa(
            params.salt1,
            params.salt2,
            p,
            &params.g,
            b.to_vec(),
            secret.to_vec(),
            password.as_bytes(),
        );
        let u: [u8; 32] = Sha256::new()
            .chain_update(a)
            .chain_update(b)
            .finalize()
            .into();
        if is_good_mod_exp_first(&a, p) && u.iter().any(|&byte| byte != 0) {
            outcome = Ok(SrpCheck {
                srp_id: params.srp_id,
                a,
                m1,
            });
            break;
        }
    }
    secret.fill(0);
    // Keeps the fill from being removed as a store nobody reads.
    std::hint::black_box(&mut secret);
    outcome
}

/// Telethon `check_prime_and_good` for a 256-byte `p`.
fn good_prime_and_generator(p: &[u8; SRP_NUMBER_SIZE], g: i32) -> bool {
    if *p == KNOWN_GOOD_PRIME && matches!(g, 3 | 4 | 5 | 7) {
        return true;
    }
    // A 2048-bit prime and a `g` grammers-crypto knows; it panics on others.
    p[0] & 0x80 != 0 && (2..=7).contains(&g) && check_p_and_g(p, &g)
}

/// `number` left-padded with zeros to 256 bytes; `None` when it is longer.
fn pad_number(number: &[u8]) -> Option<[u8; SRP_NUMBER_SIZE]> {
    let mut out = [0u8; SRP_NUMBER_SIZE];
    let start = SRP_NUMBER_SIZE.checked_sub(number.len())?;
    out[start..].copy_from_slice(number);
    Some(out)
}

/// The bit length of a big-endian number.
fn bit_length(number: &[u8]) -> usize {
    number
        .iter()
        .position(|&byte| byte != 0)
        .map_or(0, |first| {
            (number.len() - first) * 8 - number[first].leading_zeros() as usize
        })
}

/// Telethon `is_good_mod_exp_first`: `0 <= p - value`, and both
/// `p - value` and `value` have at least 2048 - 64 bits.
fn is_good_mod_exp_first(value: &[u8; SRP_NUMBER_SIZE], p: &[u8; SRP_NUMBER_SIZE]) -> bool {
    const MIN_BITS: usize = 2048 - 64;
    if value > p {
        return false;
    }
    let mut diff = [0u8; SRP_NUMBER_SIZE];
    let mut borrow = 0u8;
    for i in (0..SRP_NUMBER_SIZE).rev() {
        let (digit, under) = p[i].overflowing_sub(value[i]);
        let (digit, under_borrow) = digit.overflowing_sub(borrow);
        diff[i] = digit;
        borrow = u8::from(under || under_borrow);
    }
    bit_length(&diff) >= MIN_BITS && bit_length(value) >= MIN_BITS
}

/// The `NoPasswordProvided` message of a QR login that needs 2FA
/// when no password was given.
pub const NO_PASSWORD_PROVIDED: &str = "Two-step verification is enabled for this account.\n\
     You need to provide the `password` to argument";

/// The `FreshResetAuthorisationForbiddenError` message of
/// `TerminateSession`.
pub const FRESH_RESET_FORBIDDEN: &str = "You can't logout other sessions if less than 24 hours \
     have passed since you logged on the current session.";

/// The `HashInvalidError` message of `TerminateSession`.
pub const HASH_INVALID: &str = "The provided hash is invalid.";

/// The `OpenTeleException` message of `PrintSessions` when the
/// sessions cannot be fetched.
pub const SESSIONS_UNAVAILABLE: &str = "Could not fetch the account's sessions";

/// The TL name of the only 2FA algorithm [`srp_check`] supports (Telethon
/// `compute_check`); Telethon's class of it is the same name with a
/// capital `P`.
pub const SRP_ALGORITHM: &str = "passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow";

/// The Telethon `compute_check` `ValueError` text for a 2FA algorithm other
/// than [`SRP_ALGORITHM`], named `algorithm` (Telethon gives its class name).
#[must_use]
pub fn unsupported_password_algorithm(algorithm: &str) -> String {
    format!("unsupported password algorithm {algorithm}")
}

/// How many QR login attempts `_performQRLogin` makes by default
/// (`_DEFAULT_REQUEST_RETRIES`; a client's integer `request_retries`
/// replaces it).
pub const QR_LOGIN_ATTEMPTS: u32 = 5;

/// How many seconds past a QR token's expiry the QR login waits for it to
/// be accepted (`_QR_EXPIRE_SAFETY_SECONDS`).
pub const QR_EXPIRE_SAFETY_SECONDS: u64 = 5;

/// The `TimeoutError` message when no QR login attempt logged in.
pub const QR_LOGIN_TIMEOUT: &str = "Something went wrong, i couldn't perform the QR login";

/// Python 3.11+ `str(type(e))` of the timeout a QR login wait raises, as
/// [`qr_attempt_timeout_warning`] shows it.
pub const QR_TIMEOUT_ERROR_TYPE: &str = "<class 'TimeoutError'>";

/// The warning of QR login attempt `attempt_number` (from 1) that
/// timed out with an error whose Python `str(type(e))` is `error_type`
/// ([`QR_TIMEOUT_ERROR_TYPE`] on Python 3.11 and later).
#[must_use]
pub fn qr_attempt_timeout_warning(attempt_number: u32, error_type: &str) -> String {
    format!("\nQRLoginToNewClient attempt {attempt_number} failed because {error_type}")
}

/// The warning after QR login attempt `attempt_number` (from 1)
/// failed, emitted after [`qr_attempt_timeout_warning`].
#[must_use]
pub fn qr_attempt_retry_warning(attempt_number: u32) -> String {
    format!("\nQRLoginToNewClient attempt {attempt_number} failed. Retrying..")
}

/// The `_handleExistingSession` warning when the new client already
/// holds a session of the same `api_id`, which is returned.
pub const EXISTING_SESSION_KEPT: &str = "\nCreateNewSession - a session file with the same name \
     is already existed, returning the old session";

/// The `_handleExistingSession` warning when the new client already
/// holds a session of another `api_id`, which is deleted and logged in again.
pub const EXISTING_SESSION_REPLACED: &str = "\nCreateNewSession - a session file with the same \
     name is already existed, but its api_id is different from the current one, it will be \
     overwritten";

/// A request of the post-login sequence ([`POST_LOGIN_STEPS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostLoginRequest {
    /// `help.getConfig`.
    GetConfig,
    /// `help.getNearestDc`.
    GetNearestDc,
    /// `account.updateStatus` with `offline = false`.
    UpdateStatus,
    /// `langpack.getLanguages` with the client's `lang_pack`.
    GetLanguages,
    /// `help.getAppUpdate` with `source = ""`.
    GetAppUpdate,
    /// `help.getTermsOfServiceUpdate`.
    GetTermsOfServiceUpdate,
    /// `help.getCountriesList` with `lang_code = "en"` and `hash = 0`.
    GetCountriesList,
}

impl PostLoginRequest {
    /// The TL name of the request, such as `help.getConfig`.
    #[must_use]
    pub fn tl_name(self) -> &'static str {
        match self {
            Self::GetConfig => "help.getConfig",
            Self::GetNearestDc => "help.getNearestDc",
            Self::UpdateStatus => "account.updateStatus",
            Self::GetLanguages => "langpack.getLanguages",
            Self::GetAppUpdate => "help.getAppUpdate",
            Self::GetTermsOfServiceUpdate => "help.getTermsOfServiceUpdate",
            Self::GetCountriesList => "help.getCountriesList",
        }
    }
}

/// The `source` of the post-login `help.getAppUpdate`.
pub const POST_LOGIN_APP_UPDATE_SOURCE: &str = "";

/// The `lang_code` of the post-login `help.getCountriesList`; its `hash`
/// is 0.
pub const POST_LOGIN_COUNTRIES_LANG_CODE: &str = "en";

/// One step of the post-login sequence: a random sleep in
/// `delay_ms`, then the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PostLoginStep {
    /// The request.
    pub request: PostLoginRequest,
    /// The inclusive range in milliseconds of the sleep before the request
    /// ([`random_delay_ms`]); `None` for no sleep.
    pub delay_ms: Option<(u64, u64)>,
}

impl PostLoginStep {
    /// Whether the step runs, sleep included, for a client whose
    /// `lang_pack` is `lang_pack`: `langpack.getLanguages` only runs for a
    /// non-empty one.
    #[must_use]
    pub fn runs_for(&self, lang_pack: &str) -> bool {
        self.request != PostLoginRequest::GetLanguages || !lang_pack.is_empty()
    }
}

/// The post-login sequence, in order; a failed request is skipped.
pub const POST_LOGIN_STEPS: [PostLoginStep; 7] = [
    PostLoginStep {
        request: PostLoginRequest::GetConfig,
        delay_ms: None,
    },
    PostLoginStep {
        request: PostLoginRequest::GetNearestDc,
        delay_ms: Some((100, 300)),
    },
    PostLoginStep {
        request: PostLoginRequest::UpdateStatus,
        delay_ms: Some((200, 400)),
    },
    PostLoginStep {
        request: PostLoginRequest::GetLanguages,
        delay_ms: Some((100, 200)),
    },
    PostLoginStep {
        request: PostLoginRequest::GetAppUpdate,
        delay_ms: Some((300, 500)),
    },
    PostLoginStep {
        request: PostLoginRequest::GetTermsOfServiceUpdate,
        delay_ms: Some((100, 300)),
    },
    PostLoginStep {
        request: PostLoginRequest::GetCountriesList,
        delay_ms: Some((50, 150)),
    },
];

/// The [`POST_LOGIN_STEPS`] that run for `lang_pack`
/// ([`PostLoginStep::runs_for`]), in order.
#[must_use]
pub fn post_login_steps(lang_pack: &str) -> Vec<PostLoginStep> {
    POST_LOGIN_STEPS
        .into_iter()
        .filter(|step| step.runs_for(lang_pack))
        .collect()
}

/// A random whole number of milliseconds in `min_ms..=max_ms`, uniform,
/// from the operating system's CSPRNG ([`crate::crypto::random_fill`]): the
/// range of Python `random.randint(min_ms, max_ms)`.
///
/// # Errors
/// - [`crate::Error::InvalidInput`] when `min_ms > max_ms`, where
///   `random.randint` raises `ValueError`.
/// - [`crate::Error::Io`] when the system random source fails.
pub fn random_delay_ms(min_ms: u64, max_ms: u64) -> crate::Result<u64> {
    uniform_inclusive(min_ms, max_ms, &mut crate::crypto::random_fill)
}

/// [`random_delay_ms`] drawing its 8-byte little-endian words from `rng`.
///
/// A word below `2^64 mod (max_ms - min_ms + 1)` is drawn again, so every
/// value is equally likely.
///
/// # Errors
/// [`crate::Error::InvalidInput`] when `min_ms > max_ms`.
pub fn random_delay_ms_with(
    min_ms: u64,
    max_ms: u64,
    rng: &mut dyn FnMut(&mut [u8]),
) -> crate::Result<u64> {
    uniform_inclusive(min_ms, max_ms, &mut |buf| {
        rng(buf);
        Ok(())
    })
}

fn uniform_inclusive(
    min: u64,
    max: u64,
    fill: &mut dyn FnMut(&mut [u8]) -> crate::Result<()>,
) -> crate::Result<u64> {
    if min > max {
        return Err(crate::Error::InvalidInput {
            what: "delay range",
            reason: format!("min {min} is above max {max}"),
        });
    }
    let mut draw = || -> crate::Result<u64> {
        let mut word = [0u8; 8];
        fill(&mut word)?;
        Ok(u64::from_le_bytes(word))
    };
    let Some(span) = (max - min).checked_add(1) else {
        // The whole `u64` range: every word is a value.
        return draw();
    };
    // `2^64 mod span`: the words below it are the incomplete last block.
    let rejected = (u64::MAX % span + 1) % span;
    loop {
        let word = draw()?;
        if word >= rejected {
            return Ok(min + word % span);
        }
    }
}

/// The `api_id` of every official profile in [`api::profile`], in
/// [`Client::ALL`] order without repeats (the web clients share one).
pub const OFFICIAL_API_IDS: [i32; 6] = [2040, 6, 21724, 10840, 2834, 2496];

/// Whether `api_id` is the id of an official profile ([`OFFICIAL_API_IDS`]).
///
/// The server's `official_app` flag on the session is the authority; this
/// is the local view of the ids opentele2 ships.
#[must_use]
pub fn is_official_api_id(api_id: i32) -> bool {
    OFFICIAL_API_IDS.contains(&api_id)
}

/// The fields of an `authorization` that `PrintSessions` shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SessionRow {
    /// `current`; an absent flag is `false`.
    pub current: bool,
    /// `device_model`.
    pub device_model: String,
    /// `platform`.
    pub platform: String,
    /// `system_version`.
    pub system_version: String,
    /// `api_id`.
    pub api_id: i32,
    /// `app_name`.
    pub app_name: String,
    /// `app_version`.
    pub app_version: String,
    /// `official_app`; an absent flag is `false`.
    pub official_app: bool,
}

/// The column labels of the `PrintSessions` table, in order.
pub const SESSION_COLUMNS: [&str; 7] = [
    " ",
    "Device",
    "Platform",
    "System",
    "API_ID",
    "App name",
    "Official App",
];

/// The fields of an `authorization` as a client library returns them,
/// before [`SessionRow::from_authorization`] maps them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RawAuthorization<'a> {
    /// `current`; `None` when the flag is absent.
    pub current: Option<bool>,
    /// `device_model`.
    pub device_model: &'a str,
    /// `platform`.
    pub platform: &'a str,
    /// `system_version`.
    pub system_version: &'a str,
    /// `api_id`.
    pub api_id: i32,
    /// `app_name`.
    pub app_name: &'a str,
    /// `app_version`.
    pub app_version: &'a str,
    /// `official_app`; `None` when the flag is absent.
    pub official_app: Option<bool>,
}

impl SessionRow {
    /// The row of an `authorization`: an absent
    /// `current` or `official_app` flag is `false` (Python `bool(None)`),
    /// every other field is copied.
    #[must_use]
    pub fn from_authorization(raw: &RawAuthorization<'_>) -> Self {
        Self {
            current: raw.current.unwrap_or(false),
            device_model: raw.device_model.to_owned(),
            platform: raw.platform.to_owned(),
            system_version: raw.system_version.to_owned(),
            api_id: raw.api_id,
            app_name: raw.app_name.to_owned(),
            app_version: raw.app_version.to_owned(),
            official_app: raw.official_app.unwrap_or(false),
        }
    }

    /// The row's cells under [`SESSION_COLUMNS`] at position `index` in the
    /// list: `Current` or the index, the fields, `app_name app_version`,
    /// and `✔` or `✖`.
    #[must_use]
    pub fn cells(&self, index: usize) -> [String; 7] {
        [
            if self.current {
                "Current".to_owned()
            } else {
                index.to_string()
            },
            self.device_model.clone(),
            self.platform.clone(),
            self.system_version.clone(),
            self.api_id.to_string(),
            format!("{} {}", self.app_name, self.app_version),
            if self.official_app { "✔" } else { "✖" }.to_owned(),
        ]
    }
}

/// The table `PrintSessions` prints for `rows`, without the trailing
/// newline `print` adds: [`format_table`] of [`SESSION_COLUMNS`] and
/// [`SessionRow::cells`] with a split before row 1 (`PrettyTable(table,
/// [1])`).
///
/// With no rows the table is the header alone.
#[must_use]
pub fn format_sessions(rows: &[SessionRow]) -> String {
    let cells: Vec<[String; 7]> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| row.cells(index))
        .collect();
    format_table(&SESSION_COLUMNS, &cells, &[1])
}

/// `PrettyTable(table, addSplit)` for a table whose
/// first row has the keys `headers`, in order, and whose rows hold the
/// cells under them, already converted with `str()`.
///
/// Each column is as wide as its longest cell or header, counted in
/// Unicode scalar values as Python `len` does, plus two; text is centred
/// with the odd space on the right. A splitter line opens and closes the
/// table and follows the header, and another goes before every row whose
/// index is in `add_split`. Lines end in `\n` except the last.
///
/// A row shorter than `headers` gets empty cells and cells past the last
/// header are ignored; with no rows the table is the header alone.
#[must_use]
pub fn format_table<H, R, C>(headers: &[H], rows: &[R], add_split: &[usize]) -> String
where
    H: AsRef<str>,
    R: AsRef<[C]>,
    C: AsRef<str>,
{
    fn cell<'a, R: AsRef<[C]>, C: AsRef<str> + 'a>(row: &'a R, column: usize) -> &'a str {
        row.as_ref().get(column).map_or("", AsRef::as_ref)
    }
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(column, header)| {
            rows.iter()
                .map(|row| cell(row, column).chars().count())
                .fold(header.as_ref().chars().count(), usize::max)
        })
        .collect();
    let splitter = format!(
        "|{}|\n",
        widths
            .iter()
            .map(|width| "-".repeat(width + 2))
            .collect::<Vec<_>>()
            .join("+")
    );

    let mut out = splitter.clone();
    out.push_str(&table_line(headers.iter().map(AsRef::as_ref), &widths));
    out.push_str(&splitter);
    for (index, row) in rows.iter().enumerate() {
        if add_split.contains(&index) {
            out.push_str(&splitter);
        }
        let texts = (0..widths.len()).map(|column| cell(row, column));
        out.push_str(&table_line(texts, &widths));
    }
    out.push_str(splitter.trim_end_matches('\n'));
    out
}

/// One `PrettyTable` line: each text centred in its width plus two,
/// the odd space on the right.
fn table_line<'a>(texts: impl Iterator<Item = &'a str>, widths: &[usize]) -> String {
    let padded: Vec<String> = texts
        .zip(widths)
        .map(|(text, width)| {
            let space = width + 2 - text.chars().count();
            let left = space / 2;
            format!("{}{text}{}", " ".repeat(left), " ".repeat(space - left))
        })
        .collect();
    format!("|{}|\n", padded.join("|"))
}

/// The seven checks of `ConsistencyChecker.run_all`, in its order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    /// `help.getConfig` succeeds.
    GetConfig,
    /// `help.getNearestDc` succeeds.
    NearestDc,
    /// The current session exists and the server flags it `official_app`.
    CurrentSession,
    /// The library's TL layer is within [`LAYER_TOLERANCE`] of [`LAYER`].
    LayerMatch,
    /// `langpack.getLanguages` accepts the profile's `lang_pack`; an empty
    /// one passes without a request.
    LangPack,
    /// `help.getAppUpdate` succeeds, whether or not it offers an update.
    AppUpdate,
    /// `help.getTermsOfServiceUpdate` succeeds.
    TermsOfService,
}

impl Check {
    /// Every check, in `run_all` order.
    pub const ALL: [Self; 7] = [
        Self::GetConfig,
        Self::NearestDc,
        Self::CurrentSession,
        Self::LayerMatch,
        Self::LangPack,
        Self::AppUpdate,
        Self::TermsOfService,
    ];

    /// The check name, as in the report.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::GetConfig => "get_config",
            Self::NearestDc => "nearest_dc",
            Self::CurrentSession => "current_session",
            Self::LayerMatch => "layer_match",
            Self::LangPack => "lang_pack",
            Self::AppUpdate => "app_update",
            Self::TermsOfService => "terms_of_service",
        }
    }
}

/// The largest distance between the library's TL layer and [`LAYER`] the
/// `layer_match` check passes.
pub const LAYER_TOLERANCE: u32 = 15;

/// The `current_session` detail when there is no current session.
pub const CURRENT_SESSION_MISSING: &str = "Could not retrieve current session";

/// The `lang_pack` detail for an empty `lang_pack`.
pub const LANG_PACK_EMPTY: &str = "lang_pack is empty (web client mode)";

/// The `app_update` detail for `help.noAppUpdate`.
pub const NO_APP_UPDATE: &str = "No update available (app_version accepted)";

/// The `terms_of_service` detail on success.
pub const TERMS_OF_SERVICE_OK: &str = "ToS check OK";

/// The text in front of the summary the checker warns with when a check fails
/// and `auto_warn` is on.
pub const CONSISTENCY_WARNING_PREFIX: &str = "opentele2 consistency check issues:\n";

/// What the seven [`Check`]s expect from a session that uses a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyExpectations {
    /// The profile's `api_id`, reported by `current_session`.
    pub api_id: i32,
    /// Whether `api_id` is official; the server marks sessions of other ids
    /// `official_app = false`, which fails `current_session`.
    pub official_api_id: bool,
    /// The profile's `lang_pack`, which the `lang_pack` check asks
    /// `langpack.getLanguages` about.
    pub lang_pack: String,
    /// The layer `layer_match` compares the library's layer with.
    pub advertised_layer: i32,
    /// The largest layer distance `layer_match` passes.
    pub layer_tolerance: u32,
    /// The `app_version` the session sends, which `app_update` reports on.
    pub app_version: String,
    /// The app version comparison against the known versions
    /// ([`fingerprint::check_versions`]); empty when the version is current.
    pub version_issues: Vec<Issue>,
}

impl ConsistencyExpectations {
    /// The expectations for a session with `profile`, compared against
    /// `versions`.
    #[must_use]
    pub fn new(profile: &ApiProfile, versions: &Versions) -> Self {
        Self {
            api_id: profile.api_id,
            official_api_id: is_official_api_id(profile.api_id),
            lang_pack: profile.lang_pack.clone(),
            advertised_layer: LAYER,
            layer_tolerance: LAYER_TOLERANCE,
            app_version: profile.app_version.clone(),
            version_issues: fingerprint::check_versions(profile, versions),
        }
    }

    /// The expectations for the default profile of `client`.
    #[must_use]
    pub fn for_client(client: Client, versions: &Versions) -> Self {
        Self::new(&api::profile(client, versions), versions)
    }

    /// Whether `lang_pack` passes without asking the server.
    #[must_use]
    pub fn lang_pack_skipped(&self) -> bool {
        self.lang_pack.is_empty()
    }

    /// Whether `layer_match` passes for a library built for `library_layer`.
    #[must_use]
    pub fn layer_matches(&self, library_layer: i32) -> bool {
        library_layer.abs_diff(self.advertised_layer) <= self.layer_tolerance
    }

    /// Whether the app version is as recent as the known versions.
    #[must_use]
    pub fn app_version_current(&self) -> bool {
        self.version_issues.is_empty()
    }

    /// The `layer_match` result for a library built for `library_layer`.
    #[must_use]
    pub fn layer_result(&self, library_layer: i32) -> CheckResult {
        CheckResult {
            name: Check::LayerMatch.name().to_owned(),
            passed: self.layer_matches(library_layer),
            detail: layer_detail(library_layer, self.advertised_layer),
        }
    }
}

/// One entry of a `ConsistencyReport`, without the server response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CheckResult {
    /// The check name, [`Check::name`] or the name of a check that raised.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// The detail text.
    pub detail: String,
}

/// `ConsistencyReport.summary`: a count line, then one
/// `  [OK] name: detail` or `  [FAIL] name: detail` line per check.
#[must_use]
pub fn consistency_summary(results: &[CheckResult]) -> String {
    let passed = results.iter().filter(|result| result.passed).count();
    let mut lines = vec![format!(
        "Consistency: {passed}/{} checks passed",
        results.len()
    )];
    lines.extend(results.iter().map(|result| {
        let status = if result.passed { "OK" } else { "FAIL" };
        format!("  [{status}] {}: {}", result.name, result.detail)
    }));
    lines.join("\n")
}

/// How one [`Check`] ended, as a facade ran it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CheckOutcome {
    /// The check returned a result with this pass flag and detail text.
    Finished {
        /// Whether the check passed.
        passed: bool,
        /// The detail, from the detail builders of this module.
        detail: String,
    },
    /// The check raised out of its own handling, with this error text
    /// (Python `str(e)`); it fails with the [`check_exception`] detail.
    Raised(String),
}

impl CheckOutcome {
    /// The report entry of `check` ending this way.
    #[must_use]
    pub fn into_result(self, check: Check) -> CheckResult {
        let (passed, detail) = match self {
            Self::Finished { passed, detail } => (passed, detail),
            Self::Raised(error) => (false, check_exception(&error)),
        };
        CheckResult {
            name: check.name().to_owned(),
            passed,
            detail,
        }
    }
}

/// A `ConsistencyReport`, without the server responses: one entry
/// per [`Check`], in [`Check::ALL`] order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConsistencyReport {
    /// The entries, in [`Check::ALL`] order.
    pub checks: Vec<CheckResult>,
}

impl ConsistencyReport {
    /// Whether every check passed (`all_passed`).
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|result| result.passed)
    }

    /// The report text (`summary`), [`consistency_summary`] of the entries.
    #[must_use]
    pub fn summary(&self) -> String {
        consistency_summary(&self.checks)
    }

    /// The warning `run_all` emits with `auto_warn` on:
    /// [`CONSISTENCY_WARNING_PREFIX`] and the summary when a check failed,
    /// `None` when all passed.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        (!self.all_passed()).then(|| format!("{CONSISTENCY_WARNING_PREFIX}{}", self.summary()))
    }
}

/// The report `ConsistencyChecker.run_all` builds from the outcome of
/// each check, `outcomes[i]` being that of `Check::ALL[i]`: every entry is
/// named after its check, and a check that raised fails with the
/// [`check_exception`] detail.
#[must_use]
pub fn consistency_report(outcomes: [CheckOutcome; 7]) -> ConsistencyReport {
    ConsistencyReport {
        checks: Check::ALL
            .into_iter()
            .zip(outcomes)
            .map(|(check, outcome)| outcome.into_result(check))
            .collect(),
    }
}

/// Python's `str` of a bool.
fn py_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

/// The `get_config` detail on success; an absent `this_dc` prints `None`.
#[must_use]
pub fn get_config_detail(this_dc: Option<i32>) -> String {
    match this_dc {
        Some(dc) => format!("Config OK (DC {dc})"),
        None => "Config OK (DC None)".to_owned(),
    }
}

/// The `get_config` detail when the request fails with `error`.
#[must_use]
pub fn get_config_error(error: &str) -> String {
    format!("Server rejected getConfig: {error}")
}

/// The `nearest_dc` detail on success.
#[must_use]
pub fn nearest_dc_detail(country: &str, this_dc: i32, nearest_dc: i32) -> String {
    format!("country='{country}', this_dc={this_dc}, nearest_dc={nearest_dc}")
}

/// The `nearest_dc` detail when the request fails with `error`.
#[must_use]
pub fn nearest_dc_error(error: &str) -> String {
    format!("Error calling getNearestDc: {error}")
}

/// The `current_session` detail for the current session `row`; the check
/// passes when `row.official_app` is set.
#[must_use]
pub fn current_session_detail(row: &SessionRow) -> String {
    format!(
        "api_id={}, official={}, device='{}', app='{} {}'",
        row.api_id,
        py_bool(row.official_app),
        row.device_model,
        row.app_name,
        row.app_version
    )
}

/// The `layer_match` detail; it names the library layer after Telethon.
#[must_use]
pub fn layer_detail(library_layer: i32, advertised_layer: i32) -> String {
    format!(
        "Telethon layer={library_layer}, advertised schema layer={advertised_layer}, diff={}",
        library_layer.abs_diff(advertised_layer)
    )
}

/// The `lang_pack` detail when the server lists `languages` languages.
#[must_use]
pub fn lang_pack_detail(lang_pack: &str, languages: usize) -> String {
    format!("lang_pack '{lang_pack}' valid ({languages} languages)")
}

/// The `lang_pack` detail when the server rejects it with `error`.
#[must_use]
pub fn lang_pack_error(lang_pack: &str, error: &str) -> String {
    format!("lang_pack '{lang_pack}' rejected: {error}")
}

/// The `app_update` detail when an update is offered; an update without a
/// version prints `?`.
#[must_use]
pub fn app_update_detail(version: Option<&str>) -> String {
    format!(
        "Update available: v{} (but request succeeded)",
        version.unwrap_or("?")
    )
}

/// The `app_update` detail when the request fails with `error`.
#[must_use]
pub fn app_update_error(error: &str) -> String {
    format!("Error calling getAppUpdate: {error}")
}

/// The `current_session` and `terms_of_service` detail when the request
/// fails with `error`.
#[must_use]
pub fn check_error(error: &str) -> String {
    format!("Error: {error}")
}

/// The detail of a check that raised `error` out of its own handling.
#[must_use]
pub fn check_exception(error: &str) -> String {
    format!("Exception: {error}")
}
