//! The session codecs re-exported by [`crate::session`].
//!
//! Malformed input maps onto existing [`Error`] variants:
//! [`Error::BadLength`] when a decoded buffer or key has the wrong size, and
//! [`Error::QDataStreamFailed`] for every other undecodable input (bad
//! base64, wrong version, cut-short or trailing data, bad flags). A main DC
//! without a usable endpoint (outside the built-in table, or missing from
//! the stored config or without a TCP endpoint there, or with an endpoint
//! whose IP or port does not parse) is [`Error::BadConfigData`], and an
//! account without a key for its main DC is [`Error::AuthKeyNotFound`].

use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use base64::engine::general_purpose::{
    URL_SAFE, URL_SAFE_NO_PAD, URL_SAFE_NO_PAD_INDIFFERENT, URL_SAFE_PAD_INDIFFERENT,
};

use crate::crypto::AuthKey;
use crate::session::dc;
use crate::tdata::account::Account;
use crate::tdata::mtp_config::{Endpoint, Environment, MtpConfig};
use crate::{ConfigFailure, Error, Result};

/// The account's stored config ([`Account::mtp_config`]); `None` when it has
/// no config bytes, and the built-in table applies.
fn stored_config(account: &Account) -> Option<MtpConfig> {
    account.config.as_ref().map(|_| account.mtp_config())
}

/// The address of a config endpoint, as Telethon packs it
/// (`ipaddress.ip_address(ip)` and a `u16` port).
fn endpoint_addr(endpoint: &Endpoint) -> Result<SocketAddr> {
    let ip: IpAddr = endpoint.ip.parse().map_err(|_| Error::BadConfigData {
        context: ConfigFailure::BadEndpointIp,
    })?;
    let port = u16::try_from(endpoint.port).map_err(|_| Error::BadConfigData {
        context: ConfigFailure::PortOutOfRange {
            port: i64::from(endpoint.port),
        },
    })?;
    Ok(SocketAddr::new(ip, port))
}

/// The endpoint 1.5.0 connects an account to (`src/tl/telethon.py`,
/// `FromTDesktop`), whether it is a test server, and the main DC key, in the
/// order 1.5.0 checks them (endpoints first, then the key).
///
/// With a stored config the endpoint is
/// [`crate::tdata::mtp_config::Endpoints::select`] of the main DC's
/// endpoints; without one it is [`dc::production`].
fn account_endpoint(account: &Account, ipv6: bool) -> Result<(SocketAddr, bool, &AuthKey)> {
    let (addr, _, test, key) = account_target(account, ipv6)?;
    Ok((addr, test, key))
}

/// [`account_endpoint`] with the address text 1.5.0 hands Telethon's
/// `set_dc` (`auth_session.set_dc(endpoint.id, endpoint.ip, endpoint.port)`):
/// the stored config's IP text verbatim, or the text of the built-in table
/// (`src/td/configs.py`: dotted IPv4, IPv6 with all eight groups as four
/// lowercase hex digits).
pub(super) fn account_target(
    account: &Account,
    ipv6: bool,
) -> Result<(SocketAddr, String, bool, &AuthKey)> {
    let not_found = Error::BadConfigData {
        context: ConfigFailure::DcNotFound {
            dc_id: account.main_dc,
        },
    };
    let (addr, ip_text, test) = if let Some(config) = stored_config(account) {
        let endpoints = config.endpoints(account.main_dc).ok_or(not_found)?;
        let endpoint = endpoints.select(ipv6).ok_or(Error::BadConfigData {
            context: ConfigFailure::NoTcpEndpoint,
        })?;
        (
            endpoint_addr(endpoint)?,
            endpoint.ip.clone(),
            config.environment == Environment::Test,
        )
    } else {
        let addr = dc::production(account.main_dc, ipv6).ok_or(not_found)?;
        (addr, table_text(addr.ip()), false)
    };
    let key = account.auth_key().ok_or(Error::AuthKeyNotFound)?;
    Ok((addr, ip_text, test, key))
}

/// An address of the built-in table as 1.5.0 spells it.
fn table_text(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip
            .segments()
            .iter()
            .map(|group| format!("{group:04x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

/// The main DC id as one byte; every id of the built-in table fits.
fn dc_byte(dc_id: i32) -> Result<u8> {
    u8::try_from(dc_id).map_err(|_| Error::BadConfigData {
        context: ConfigFailure::DcIdOutOfRange {
            dc_id: i64::from(dc_id),
        },
    })
}

/// A forward-only reader over a decoded session buffer.
struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.rest.len() < len {
            return Err(Error::QDataStreamFailed { context: None });
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn finish(&self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::QDataStreamFailed { context: None })
        }
    }
}

/// Telethon `StringSession`
/// (`refs/telethon/telethon/sessions/string.py`).
///
/// The string is the version `'1'` followed by padded urlsafe base64 of the
/// big-endian struct `>B{4|16}sH256s`: DC id, packed IP address, port, and
/// the 256-byte auth key. A 4-byte address is IPv4, a 16-byte one IPv6.
pub mod telethon {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{Cursor, Engine, URL_SAFE, URL_SAFE_PAD_INDIFFERENT, account_endpoint, dc_byte};
    use crate::crypto::AuthKey;
    use crate::tdata::account::Account;
    use crate::{Error, Result};

    /// The version prefix of every string (`CURRENT_VERSION`).
    pub const VERSION: char = '1';

    /// Decoded size of a session with an IPv4 address, in bytes.
    pub const IPV4_LEN: usize = 1 + 4 + 2 + AuthKey::SIZE;

    /// Decoded size of a session with an IPv6 address, in bytes.
    pub const IPV6_LEN: usize = 1 + 16 + 2 + AuthKey::SIZE;

    /// One Telethon string session.
    #[derive(Debug, Clone)]
    pub struct StringSession {
        /// DC id (`dc_id`).
        pub dc_id: u8,
        /// Server address and port (`server_address`, `port`).
        pub addr: SocketAddr,
        /// The auth key. Telethon treats an all-zero key as no key.
        pub auth_key: AuthKey,
    }

    impl StringSession {
        /// The session 1.5.0 builds for `account` (`TelegramClient.FromTDesktop`):
        /// the first TCP endpoint of the main DC, IPv6 when `ipv6` is set
        /// (`use_ipv6`) and the DC has one, and the main DC key. The
        /// endpoints come from the account's stored config
        /// ([`Account::mtp_config`], `config.endpoints(MainDcId)`) when it
        /// has config bytes, else from [`crate::session::dc`].
        ///
        /// # Errors
        /// - [`Error::BadConfigData`] when the main DC has no usable
        ///   endpoint (see the [module docs](super)).
        /// - [`Error::AuthKeyNotFound`] when the account has no main DC key.
        pub fn from_account(account: &Account, ipv6: bool) -> Result<Self> {
            let (addr, _, key) = account_endpoint(account, ipv6)?;
            Ok(Self {
                dc_id: dc_byte(account.main_dc)?,
                addr,
                auth_key: key.clone(),
            })
        }

        /// Encodes the session as `StringSession.save` does: [`VERSION`] and
        /// padded urlsafe base64.
        #[must_use]
        pub fn encode(&self) -> String {
            let mut body = Vec::with_capacity(IPV6_LEN);
            body.push(self.dc_id);
            match self.addr.ip() {
                IpAddr::V4(ip) => body.extend_from_slice(&ip.octets()),
                IpAddr::V6(ip) => body.extend_from_slice(&ip.octets()),
            }
            body.extend_from_slice(&self.addr.port().to_be_bytes());
            body.extend_from_slice(self.auth_key.as_bytes());
            let mut out = String::from(VERSION);
            out.push_str(&URL_SAFE.encode(body));
            out
        }

        /// Decodes a string session; base64 padding is optional.
        ///
        /// # Errors
        /// - [`Error::QDataStreamFailed`] when the version is not
        ///   [`VERSION`] or the body is not urlsafe base64.
        /// - [`Error::BadLength`] when the body is neither [`IPV4_LEN`] nor
        ///   [`IPV6_LEN`] bytes.
        pub fn decode(string: &str) -> Result<Self> {
            let body = string
                .strip_prefix(VERSION)
                .ok_or(Error::QDataStreamFailed { context: None })?;
            let bytes = URL_SAFE_PAD_INDIFFERENT
                .decode(body)
                .map_err(|_| Error::QDataStreamFailed { context: None })?;
            let ipv6 = match bytes.len() {
                IPV4_LEN => false,
                IPV6_LEN => true,
                actual => {
                    return Err(Error::BadLength {
                        what: "Telethon string session",
                        expected: if actual > IPV4_LEN {
                            IPV6_LEN
                        } else {
                            IPV4_LEN
                        },
                        actual,
                    });
                }
            };
            let mut cursor = Cursor::new(&bytes);
            let dc_id = cursor.u8()?;
            let ip = if ipv6 {
                IpAddr::V6(Ipv6Addr::from(cursor.array::<16>()?))
            } else {
                IpAddr::V4(Ipv4Addr::from(cursor.array::<4>()?))
            };
            let port = u16::from_be_bytes(cursor.array()?);
            let auth_key = AuthKey::new(cursor.array()?);
            cursor.finish()?;
            Ok(Self {
                dc_id,
                addr: SocketAddr::new(ip, port),
                auth_key,
            })
        }
    }
}

/// mtcute string session version 3
/// (`refs/mtcute-master/packages/core/src/highlevel/utils/string-session.ts`,
/// DC options from `packages/core/src/utils/dcs.ts`).
///
/// Layout, TL little-endian throughout: the version byte `3`; an `int` of
/// flags ([`FLAG_SELF`], [`FLAG_MEDIA_DC`]); TL `bytes` of the primary DC
/// option; TL `bytes` of the media DC option when [`FLAG_MEDIA_DC`] is set;
/// when [`FLAG_SELF`] is set an `int53` user id (8 bytes) and a TL `Bool`;
/// then TL `bytes` of the auth key. A DC option blob is the three raw bytes
/// [`DC_OPTION_VERSION`], DC id, flags ([`DC_IPV6`], [`DC_MEDIA_ONLY`],
/// [`DC_TEST_MODE`]), a TL `string` IP address and an `int` port.
///
/// TL `bytes` of length `n <= 253` is the byte `n`, the data, and zero
/// padding to a multiple of 4 of `n + 1`; a longer one is the byte `254`, `n`
/// as 3 little-endian bytes, the data, and padding to a multiple of 4 of
/// `n`. Padding counts from the start of the TL value, not of the buffer.
///
/// Assumption: the encoder calls `base64.encode(bytes, true)` and the decoder
/// `base64.decode(string, true)` from `@fuman/utils` 0.0.21, which is not in
/// the references. Both are taken to be the urlsafe alphabet; the encoder is
/// taken to omit padding, as the unpadded snapshots in
/// `string-session.test.ts` show. Decoding accepts padding or none.
///
/// Decoding is stricter than mtcute, so that an accepted string encodes back
/// to itself: unknown flag bits, non-zero padding, non-canonical TL lengths,
/// trailing bytes, a negative or over-`2^53 - 1` user id, and invalid UTF-8
/// are rejected. Two legacy inputs decode but do not re-encode verbatim: a
/// DC option of version 1 and the session flag [`FLAG_TEST_MODE_OLD`] both
/// re-encode as version 2 with the test mode in the DC option flags.
pub mod mtcute {
    use std::net::SocketAddr;

    use super::{
        Cursor, Engine, URL_SAFE_NO_PAD, URL_SAFE_NO_PAD_INDIFFERENT, account_endpoint, dc_byte,
    };
    use crate::crypto::AuthKey;
    use crate::tdata::account::Account;
    use crate::{Error, Result};

    /// The session version byte; mtcute writes and reads only this one.
    pub const VERSION: u8 = 3;
    /// Session flag: a user id and bot flag follow the DC options.
    pub const FLAG_SELF: i32 = 1;
    /// Legacy session flag read by mtcute: both DCs are test DCs.
    pub const FLAG_TEST_MODE_OLD: i32 = 2;
    /// Session flag: a separate media DC option follows the primary one.
    pub const FLAG_MEDIA_DC: i32 = 4;

    /// The DC option blob version mtcute writes; version 1 is also read.
    pub const DC_OPTION_VERSION: u8 = 2;
    /// DC option flag: the address is IPv6.
    pub const DC_IPV6: u8 = 1;
    /// DC option flag: the DC serves media only.
    pub const DC_MEDIA_ONLY: u8 = 2;
    /// DC option flag: the DC is a test DC (version 2 only).
    pub const DC_TEST_MODE: u8 = 4;

    /// TL `boolTrue` constructor.
    pub const BOOL_TRUE: u32 = 0x9972_75B5;
    /// TL `boolFalse` constructor.
    pub const BOOL_FALSE: u32 = 0xBC79_9737;
    /// The largest user id an `int53` (a JavaScript number) holds exactly.
    pub const MAX_USER_ID: u64 = (1 << 53) - 1;

    /// One DC option (`BasicDcOption`) without its test mode, which the
    /// session holds once for both DCs.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DcOption {
        /// DC id (`id`), written as one byte.
        pub id: u8,
        /// IP address text (`ipAddress`), kept verbatim.
        pub ip: String,
        /// Port (`port`).
        pub port: u16,
        /// Whether the address is IPv6 (`ipv6`).
        pub ipv6: bool,
        /// Whether the DC serves media only (`mediaOnly`).
        pub media_only: bool,
    }

    impl DcOption {
        /// A non-media option for `addr`, the IP in its canonical text.
        #[must_use]
        pub fn new(id: u8, addr: SocketAddr) -> Self {
            Self {
                id,
                ip: addr.ip().to_string(),
                port: addr.port(),
                ipv6: addr.is_ipv6(),
                media_only: false,
            }
        }

        /// `serializeBasicDcOption`.
        fn serialize(&self, test_mode: bool) -> Vec<u8> {
            let mut flags = 0;
            for (set, bit) in [
                (self.ipv6, DC_IPV6),
                (self.media_only, DC_MEDIA_ONLY),
                (test_mode, DC_TEST_MODE),
            ] {
                if set {
                    flags |= bit;
                }
            }
            let mut out = vec![DC_OPTION_VERSION, self.id, flags];
            write_bytes(&mut out, self.ip.as_bytes());
            out.extend_from_slice(&i32::from(self.port).to_le_bytes());
            out
        }

        /// `parseBasicDcOption`, returning the option and its test mode.
        fn parse(blob: &[u8]) -> Result<(Self, bool)> {
            let mut cursor = Cursor::new(blob);
            let [version, id, flags] = cursor.array()?;
            if !matches!(version, 1 | DC_OPTION_VERSION)
                || flags & !(DC_IPV6 | DC_MEDIA_ONLY | DC_TEST_MODE) != 0
            {
                return Err(Error::QDataStreamFailed { context: None });
            }
            let ip = String::from_utf8(read_bytes(&mut cursor)?.to_vec())
                .map_err(|_| Error::QDataStreamFailed { context: None })?;
            let port = u16::try_from(i32::from_le_bytes(cursor.array()?))
                .map_err(|_| Error::QDataStreamFailed { context: None })?;
            cursor.finish()?;
            let option = Self {
                id,
                ip,
                port,
                ipv6: flags & DC_IPV6 != 0,
                media_only: flags & DC_MEDIA_ONLY != 0,
            };
            Ok((
                option,
                version == DC_OPTION_VERSION && flags & DC_TEST_MODE != 0,
            ))
        }
    }

    /// One mtcute string session (`StringSessionData`, version 3).
    #[derive(Debug, Clone)]
    pub struct StringSession {
        /// The primary DC (`primaryDcs.main`).
        pub primary_dc: DcOption,
        /// A separate media DC (`primaryDcs.media`); `None` when the media
        /// DC is the primary one.
        pub media_dc: Option<DcOption>,
        /// The logged-in user as (user id, is bot) (`self`).
        pub self_user: Option<(u64, bool)>,
        /// Whether both DCs are test DCs (`testMode`).
        pub test_mode: bool,
        /// The auth key (`authKey`).
        pub auth_key: AuthKey,
    }

    impl StringSession {
        /// The session for `account`: the endpoint of the main DC chosen as
        /// in [`super::telethon::StringSession::from_account`] (IP in its
        /// canonical text), no separate media DC, the account's user id with
        /// `is_bot` false, test mode when the stored config is a test one,
        /// and the main DC key.
        ///
        /// # Errors
        /// - [`Error::BadConfigData`] when the main DC has no usable
        ///   endpoint (see the [module docs](super)).
        /// - [`Error::AuthKeyNotFound`] when the account has no main DC key.
        pub fn from_account(account: &Account, ipv6: bool) -> Result<Self> {
            let (addr, test_mode, key) = account_endpoint(account, ipv6)?;
            Ok(Self {
                primary_dc: DcOption::new(dc_byte(account.main_dc)?, addr),
                media_dc: None,
                self_user: Some((account.user_id, false)),
                test_mode,
                auth_key: key.clone(),
            })
        }

        /// Encodes the session as `writeStringSession` does, in unpadded
        /// base64url. A user id above [`MAX_USER_ID`] is written as its 8
        /// little-endian bytes, which mtcute cannot read exactly.
        #[must_use]
        pub fn encode(&self) -> String {
            let mut flags = 0;
            if self.self_user.is_some() {
                flags |= FLAG_SELF;
            }
            if self.media_dc.is_some() {
                flags |= FLAG_MEDIA_DC;
            }
            let mut out = vec![VERSION];
            out.extend_from_slice(&flags.to_le_bytes());
            write_bytes(&mut out, &self.primary_dc.serialize(self.test_mode));
            if let Some(media) = &self.media_dc {
                write_bytes(&mut out, &media.serialize(self.test_mode));
            }
            if let Some((user_id, is_bot)) = self.self_user {
                out.extend_from_slice(&user_id.to_le_bytes());
                let flag = if is_bot { BOOL_TRUE } else { BOOL_FALSE };
                out.extend_from_slice(&flag.to_le_bytes());
            }
            write_bytes(&mut out, self.auth_key.as_bytes());
            URL_SAFE_NO_PAD.encode(out)
        }

        /// Decodes a version 3 string session (`readStringSession`); base64
        /// padding is optional.
        ///
        /// # Errors
        /// - [`Error::QDataStreamFailed`] for input that is not base64url,
        ///   not version 3, cut short, has trailing bytes, or breaks a rule
        ///   in the [module docs](self), and when the primary and media DC
        ///   disagree on test mode.
        /// - [`Error::BadLength`] when the auth key is not 256 bytes.
        pub fn decode(string: &str) -> Result<Self> {
            let bytes = URL_SAFE_NO_PAD_INDIFFERENT
                .decode(string)
                .map_err(|_| Error::QDataStreamFailed { context: None })?;
            let mut cursor = Cursor::new(&bytes);
            if cursor.u8()? != VERSION {
                return Err(Error::QDataStreamFailed { context: None });
            }
            let flags = i32::from_le_bytes(cursor.array()?);
            if flags & !(FLAG_SELF | FLAG_TEST_MODE_OLD | FLAG_MEDIA_DC) != 0 {
                return Err(Error::QDataStreamFailed { context: None });
            }
            let (primary_dc, primary_test) = DcOption::parse(read_bytes(&mut cursor)?)?;
            let media = if flags & FLAG_MEDIA_DC == 0 {
                None
            } else {
                Some(DcOption::parse(read_bytes(&mut cursor)?)?)
            };
            let test_mode = if flags & FLAG_TEST_MODE_OLD != 0 {
                true
            } else {
                let media_test = media.as_ref().map_or(primary_test, |(_, test)| *test);
                if media_test != primary_test {
                    return Err(Error::QDataStreamFailed { context: None });
                }
                primary_test
            };
            let self_user = if flags & FLAG_SELF == 0 {
                None
            } else {
                let user_id = u64::from_le_bytes(cursor.array()?);
                if user_id > MAX_USER_ID {
                    return Err(Error::QDataStreamFailed { context: None });
                }
                let is_bot = match u32::from_le_bytes(cursor.array()?) {
                    BOOL_TRUE => true,
                    BOOL_FALSE => false,
                    _ => return Err(Error::QDataStreamFailed { context: None }),
                };
                Some((user_id, is_bot))
            };
            let auth_key = AuthKey::from_slice(read_bytes(&mut cursor)?)?;
            cursor.finish()?;
            Ok(Self {
                primary_dc,
                media_dc: media.map(|(option, _)| option),
                self_user,
                test_mode,
                auth_key,
            })
        }
    }

    /// Bytes of zero padding after a TL `bytes` value of `len` data bytes.
    const fn padding(len: usize) -> usize {
        let used = if len <= 253 { len + 1 } else { len };
        (4 - used % 4) % 4
    }

    /// TL `bytes` (`TlBinaryWriter.bytes`). As in mtcute, only the low 24
    /// bits of a length above 253 are written; every value here is far
    /// shorter.
    fn write_bytes(out: &mut Vec<u8>, data: &[u8]) {
        match u8::try_from(data.len()) {
            Ok(len) if len <= 253 => out.push(len),
            _ => {
                out.push(254);
                let len = u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes();
                out.extend_from_slice(&len[..3]);
            }
        }
        out.extend_from_slice(data);
        out.resize(out.len() + padding(data.len()), 0);
    }

    /// TL `bytes` (`TlBinaryReader.bytes`), rejecting the byte 255, a long
    /// form for a length that fits the short one, and non-zero padding.
    fn read_bytes<'a>(cursor: &mut Cursor<'a>) -> Result<&'a [u8]> {
        let len = match cursor.u8()? {
            254 => {
                let [a, b, c] = cursor.array()?;
                let len = usize::from(a) | usize::from(b) << 8 | usize::from(c) << 16;
                if len <= 253 {
                    return Err(Error::QDataStreamFailed { context: None });
                }
                len
            }
            255 => return Err(Error::QDataStreamFailed { context: None }),
            len => usize::from(len),
        };
        let data = cursor.take(len)?;
        if cursor.take(padding(len))?.iter().any(|&b| b != 0) {
            return Err(Error::QDataStreamFailed { context: None });
        }
        Ok(data)
    }
}

/// Plain structs shaped like grammers 0.11 `SessionData` and `DcOption`,
/// with no grammers dependency. A grammers key is `Option<[u8; 256]>`; here
/// it is an [`AuthKey`] whose [`AuthKey::as_bytes`] is that array.
pub mod grammers {
    use std::collections::HashMap;
    use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

    use super::{endpoint_addr, stored_config};
    use crate::crypto::AuthKey;
    use crate::session::dc;
    use crate::tdata::account::Account;
    use crate::tdata::mtp_config::MtpConfig;
    use crate::{ConfigFailure, Error, Result};

    /// The first IPv4 and IPv6 endpoint of every production DC of [`dc`].
    fn built_in_options() -> Result<HashMap<i32, (SocketAddrV4, SocketAddrV6)>> {
        dc::PRODUCTION_DC_IDS
            .iter()
            .map(
                |&id| match (dc::production(id, false), dc::production(id, true)) {
                    (Some(SocketAddr::V4(ipv4)), Some(SocketAddr::V6(ipv6))) => {
                        Ok((id, (ipv4, ipv6)))
                    }
                    _ => Err(Error::BadConfigData {
                        context: ConfigFailure::DcNotFound { dc_id: id },
                    }),
                },
            )
            .collect()
    }

    /// Every DC of `config` whose endpoints, chosen as 1.5.0 chooses them
    /// with and without IPv6, are an IPv4 and an IPv6 address.
    fn config_options(config: &MtpConfig) -> HashMap<i32, (SocketAddrV4, SocketAddrV6)> {
        config
            .dc_options
            .dcs()
            .filter_map(|(id, _)| {
                let endpoints = config.endpoints(id)?;
                let ipv4 = endpoint_addr(endpoints.select(false)?).ok()?;
                let ipv6 = endpoint_addr(endpoints.select(true)?).ok()?;
                match (ipv4, ipv6) {
                    (SocketAddr::V4(ipv4), SocketAddr::V6(ipv6)) => Some((id, (ipv4, ipv6))),
                    _ => None,
                }
            })
            .collect()
    }

    /// One DC (`grammers_session::DcOption`).
    #[derive(Debug, Clone)]
    pub struct DcOption {
        /// DC id.
        pub id: i32,
        /// IPv4 endpoint.
        pub ipv4: SocketAddrV4,
        /// IPv6 endpoint.
        pub ipv6: SocketAddrV6,
        /// The auth key for this DC, if any.
        pub auth_key: Option<AuthKey>,
    }

    /// Session data (`grammers_session::SessionData`), DC fields only.
    #[derive(Debug, Clone)]
    pub struct SessionData {
        /// The home DC id.
        pub home_dc: i32,
        /// Every known DC by id.
        pub dc_options: HashMap<i32, DcOption>,
    }

    impl SessionData {
        /// Session data for `account`: `home_dc` is the main DC, and
        /// `dc_options` holds DCs with an IPv4 and an IPv6 endpoint. With
        /// stored config bytes ([`Account::mtp_config`]) those are the DCs
        /// of the config whose endpoints, chosen as in
        /// [`super::telethon::StringSession::from_account`] without and with
        /// IPv6, are an IPv4 and an IPv6 address; without them, every
        /// production DC of [`dc`] with its first IPv4 and IPv6 endpoint.
        /// Only the main DC carries a key, the account's main DC key.
        ///
        /// # Errors
        /// - [`Error::BadConfigData`] when the main DC is not among the DCs.
        /// - [`Error::AuthKeyNotFound`] when the account has no main DC key.
        pub fn from_account(account: &Account) -> Result<Self> {
            let options = match stored_config(account) {
                Some(config) => config_options(&config),
                None => built_in_options()?,
            };
            if !options.contains_key(&account.main_dc) {
                return Err(Error::BadConfigData {
                    context: ConfigFailure::DcNotFound {
                        dc_id: account.main_dc,
                    },
                });
            }
            let key = account.auth_key().ok_or(Error::AuthKeyNotFound)?;
            let dc_options = options
                .into_iter()
                .map(|(id, (ipv4, ipv6))| {
                    let option = DcOption {
                        id,
                        ipv4,
                        ipv6,
                        auth_key: (id == account.main_dc).then(|| key.clone()),
                    };
                    (id, option)
                })
                .collect();
            Ok(Self {
                home_dc: account.main_dc,
                dc_options,
            })
        }
    }
}
