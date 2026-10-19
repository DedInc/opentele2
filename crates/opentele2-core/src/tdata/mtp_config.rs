//! The MTP config of an account (`MTP::Config`, `MTP::ConfigFields` and
//! `MTP::DcOptions`), as 1.5.0 reads and writes it (`src/td/mtp.py`, after
//! tdesktop's `mtproto_config.cpp` and `mtproto_dc_options.cpp`).
//!
//! A serialized config is the `i32` version [`CONFIG_VERSION`], the `i32`
//! environment, the serialized [`DcOptions`] as a `QByteArray`, the 30 fields
//! of [`ConfigFields`] in declaration order (`bool` as `i32` 1 or 0, strings
//! as `QString`), then an optional tail appended by newer tdesktop: the
//! default reaction emoji and custom reaction id, the rating decay, and the
//! GIF and venue search usernames. Each tail group is read only when bytes
//! remain; [`MtpConfig::serialize`] always writes all of them.
//!
//! Serialized DC options start with `i32` minus the version (a non-negative
//! first value is the endpoint count of the version 0 layout), then the
//! endpoint count and per endpoint `i32` DC id, flags, port, IP size and the
//! ASCII IP, from version 1 on a secret size and the secret, and from
//! version 2 on a CDN key count and per key an `i32` DC id and the RSA
//! modulus and exponent as `QByteArray`. Endpoints are grouped per DC in
//! first-seen order, and an endpoint whose IP and port a DC already has is
//! dropped (`applyOneGuarded`), so re-serializing a config tdesktop wrote
//! gives back the same bytes.
//!
//! Reads mirror 1.5.0's `QDataStream`: a read past the end yields zero or
//! empty values and fails the stream, which is checked where 1.5.0 checks it,
//! so a cut-short config fails with the same error as in 1.5.0.

use crate::qt::{NULL_LENGTH, QWriter};
use crate::{Error, Result};

/// Version of the serialized config (`MTP.Config.kVersion`).
pub const CONFIG_VERSION: i32 = 1;

/// Version [`DcOptions::serialize`] writes (`MTP.DcOptions.kVersion`).
pub const DC_OPTIONS_VERSION: i32 = 2;

/// Longest IP address a serialized endpoint may hold, in bytes.
pub const MAX_IP_SIZE: i32 = 45;

/// Longest endpoint secret, in bytes.
pub const MAX_SECRET_SIZE: i32 = 32;

/// DCs whose bare id is this or above (temporary main DCs) are not
/// serialized.
pub const MAX_SERIALIZED_DC_ID: i32 = 1000;

/// Multiplier of the shift in a shifted DC id (`DcId.kDcShift`).
pub const DC_SHIFT: i32 = 10_000;

/// Endpoint flag: the address is IPv6 (`f_ipv6`).
pub const FLAG_IPV6: i32 = 1 << 0;
/// Endpoint flag: the endpoint serves media only (`f_media_only`).
pub const FLAG_MEDIA_ONLY: i32 = 1 << 1;
/// Endpoint flag: the endpoint speaks TCP only (`f_tcpo_only`).
pub const FLAG_TCPO_ONLY: i32 = 1 << 2;
/// Endpoint flag: the endpoint is a CDN (`f_cdn`).
pub const FLAG_CDN: i32 = 1 << 3;
/// Endpoint flag: the endpoint is built in or static (`f_static`).
pub const FLAG_STATIC: i32 = 1 << 4;
/// Endpoint flag: connect to this port only (`ThisPortOnly`).
pub const FLAG_THIS_PORT_ONLY: i32 = 1 << 5;
/// Endpoint flag: the endpoint has a secret (`f_secret`).
pub const FLAG_SECRET: i32 = 1 << 10;

const PORT: i32 = 443;

/// A built-in DC list as (DC id, IP address).
type BuiltInDcs = &'static [(i32, &'static str)];

// The built-in DC lists of 1.5.0 (`src/td/configs.py`, `BuiltInDc`), the
// IPv6 addresses in the long form 1.5.0 serializes.
const BUILT_IN_DCS: [(i32, &str); 6] = [
    (1, "149.154.175.50"),
    (2, "149.154.167.51"),
    (2, "95.161.76.100"),
    (3, "149.154.175.100"),
    (4, "149.154.167.91"),
    (5, "149.154.171.5"),
];
const BUILT_IN_DCS_IPV6: [(i32, &str); 5] = [
    (1, "2001:0b28:f23d:f001:0000:0000:0000:000a"),
    (2, "2001:067c:04e8:f002:0000:0000:0000:000a"),
    (3, "2001:0b28:f23d:f003:0000:0000:0000:000a"),
    (4, "2001:067c:04e8:f004:0000:0000:0000:000a"),
    (5, "2001:0b28:f23f:f005:0000:0000:0000:000a"),
];
const BUILT_IN_DCS_TEST: [(i32, &str); 3] = [
    (1, "149.154.175.10"),
    (2, "149.154.167.40"),
    (3, "149.154.175.117"),
];
const BUILT_IN_DCS_IPV6_TEST: [(i32, &str); 3] = [
    (1, "2001:0b28:f23d:f001:0000:0000:0000:000e"),
    (2, "2001:067c:04e8:f002:0000:0000:0000:000e"),
    (3, "2001:0b28:f23d:f003:0000:0000:0000:000e"),
];

/// The bare DC id of a shifted one (`DcId.BareDcId`): the remainder of
/// [`DC_SHIFT`], never negative, as Python's `%` gives it.
#[must_use]
pub const fn bare_dc_id(shifted: i32) -> i32 {
    shifted.rem_euclid(DC_SHIFT)
}

/// Server environment of a config (`MTP.Environment`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Production servers, stored as 0.
    Production,
    /// Test servers, stored as 1.
    Test,
}

impl Environment {
    /// The stored value.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Production => 0,
            Self::Test => 1,
        }
    }

    /// The environment stored as `code`; `None` for any other value (1.5.0
    /// raises `ValueError`).
    #[must_use]
    pub const fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Production),
            1 => Some(Self::Test),
            _ => None,
        }
    }
}

/// A big-endian reader that behaves like 1.5.0's `QDataStream`: a read past
/// the end takes what is left, yields zero or empty values, and marks the
/// stream failed for a later [`Stream::status`].
struct Stream<'a> {
    data: &'a [u8],
    pos: usize,
    failed: bool,
}

impl<'a> Stream<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            failed: false,
        }
    }

    const fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn raw(&mut self, len: usize) -> &'a [u8] {
        let end = self.pos.saturating_add(len).min(self.data.len());
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        if bytes.len() < len {
            self.failed = true;
        }
        bytes
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.raw(N).try_into().ok()
    }

    fn i32(&mut self) -> i32 {
        self.array().map_or(0, i32::from_be_bytes)
    }

    fn u64(&mut self) -> u64 {
        self.array().map_or(0, u64::from_be_bytes)
    }

    fn bool(&mut self) -> bool {
        self.i32() == 1
    }

    /// `raw(size)` for a size read as `i32`, which the callers bound first.
    fn sized(&mut self, size: i32) -> &'a [u8] {
        self.raw(usize::try_from(size).unwrap_or_default())
    }

    /// A length-prefixed block; empty when the prefix is cut short or null.
    fn block(&mut self) -> &'a [u8] {
        let Some(len) = self.array().map(u32::from_be_bytes) else {
            return &[];
        };
        if len == NULL_LENGTH {
            return &[];
        }
        self.raw(usize::try_from(len).unwrap_or(usize::MAX))
    }

    /// A `QString`; a null one reads as empty, as in 1.5.0.
    ///
    /// Code units that are not UTF-16BE fail at once with
    /// [`Error::QDataStreamFailed`] (1.5.0 raises `UnicodeDecodeError`).
    fn qstring(&mut self) -> Result<String> {
        let (units, rest) = self.block().as_chunks::<2>();
        if !rest.is_empty() {
            return Err(Error::QDataStreamFailed { context: None });
        }
        char::decode_utf16(units.iter().map(|&unit| u16::from_be_bytes(unit)))
            .collect::<std::result::Result<String, _>>()
            .map_err(|_| Error::QDataStreamFailed { context: None })
    }

    /// `ExpectStreamStatus`.
    const fn status(&self) -> Result<()> {
        if self.failed {
            Err(Error::QDataStreamFailed { context: None })
        } else {
            Ok(())
        }
    }
}

/// `n` as the `i32` length prefix 1.5.0 writes.
fn len_i32(n: usize) -> Result<i32> {
    i32::try_from(n).map_err(|_| Error::QDataStreamFailed { context: None })
}

/// One DC endpoint (`MTP.DcOptions.Endpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// DC id, as stored.
    pub id: i32,
    /// `FLAG_*` bits.
    pub flags: i32,
    /// IP address text, ASCII, kept verbatim.
    pub ip: String,
    /// Port.
    pub port: i32,
    /// Secret; empty for none.
    pub secret: Vec<u8>,
}

/// One CDN RSA public key (`MTP.RSAPublicKey`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// DC id of the CDN.
    pub dc_id: i32,
    /// Modulus bytes.
    pub n: Vec<u8>,
    /// Exponent bytes.
    pub e: Vec<u8>,
}

/// The DC options of a config (`MTP.DcOptions`): endpoints grouped per DC
/// id in first-seen order, and the CDN public keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DcOptions {
    dcs: Vec<(i32, Vec<Endpoint>)>,
    /// CDN public keys, in file order.
    pub cdn_public_keys: Vec<RsaPublicKey>,
}

impl DcOptions {
    /// The built-in options of `environment` (`constructFromBuiltIn`): every
    /// built-in IPv4 endpoint with [`FLAG_STATIC`], then every IPv6 one with
    /// [`FLAG_STATIC`] and [`FLAG_IPV6`], port 443, no secret.
    #[must_use]
    pub fn built_in(environment: Environment) -> Self {
        let (ipv4, ipv6): (BuiltInDcs, BuiltInDcs) = match environment {
            Environment::Production => (&BUILT_IN_DCS, &BUILT_IN_DCS_IPV6),
            Environment::Test => (&BUILT_IN_DCS_TEST, &BUILT_IN_DCS_IPV6_TEST),
        };
        let mut options = Self::default();
        for (list, flags) in [(ipv4, FLAG_STATIC), (ipv6, FLAG_STATIC | FLAG_IPV6)] {
            for &(id, ip) in list {
                options.add(id, flags, ip, PORT, &[]);
            }
        }
        options
    }

    /// Adds an endpoint to DC `id` unless that DC already has one with the
    /// same IP and port (`applyOneGuarded`).
    pub fn add(&mut self, id: i32, flags: i32, ip: &str, port: i32, secret: &[u8]) {
        let endpoint = Endpoint {
            id,
            flags,
            ip: ip.to_owned(),
            port,
            secret: secret.to_vec(),
        };
        match self.dcs.iter_mut().find(|(dc, _)| *dc == id) {
            Some((_, list)) => {
                if !list.iter().any(|e| e.ip == ip && e.port == port) {
                    list.push(endpoint);
                }
            }
            None => self.dcs.push((id, vec![endpoint])),
        }
    }

    /// [`DcOptions::add`] under the bare id of `shifted_id`
    /// (`constructAddOne`).
    pub fn add_shifted(&mut self, shifted_id: i32, flags: i32, ip: &str, port: i32, secret: &[u8]) {
        self.add(bare_dc_id(shifted_id), flags, ip, port, secret);
    }

    /// The endpoints of DC `id`, in insertion order; `None` for an unknown
    /// DC.
    #[must_use]
    pub fn dc(&self, id: i32) -> Option<&[Endpoint]> {
        self.dcs
            .iter()
            .find(|(dc, _)| *dc == id)
            .map(|(_, list)| list.as_slice())
    }

    /// Every DC as (id, endpoints), in first-seen order.
    pub fn dcs(&self) -> impl Iterator<Item = (i32, &[Endpoint])> {
        self.dcs.iter().map(|(id, list)| (*id, list.as_slice()))
    }

    /// Parses serialized DC options (`constructFromSerialized`) in any of
    /// the versions 0, 1 and 2. Bytes after the endpoints (version 0 and 1)
    /// or after the CDN keys are ignored.
    ///
    /// # Errors
    /// - [`Error::BadConfigData`] for an IP size outside 1 to
    ///   [`MAX_IP_SIZE`], a secret size outside 0 to [`MAX_SECRET_SIZE`], or
    ///   an IP that is not ASCII (1.5.0 raises `UnicodeDecodeError`).
    /// - [`Error::QDataStreamFailed`] when an endpoint or CDN key is cut
    ///   short.
    pub fn parse(serialized: &[u8]) -> Result<Self> {
        let mut stream = Stream::new(serialized);
        let minus_version = stream.i32();
        let version = if minus_version < 0 {
            -i64::from(minus_version)
        } else {
            0
        };
        let count = if version > 0 {
            stream.i32()
        } else {
            minus_version
        };
        let mut options = Self::default();
        for _ in 0..count {
            let id = stream.i32();
            let flags = stream.i32();
            let port = stream.i32();
            let ip_size = stream.i32();
            if !(1..=MAX_IP_SIZE).contains(&ip_size) {
                return Err(Error::BadConfigData);
            }
            let ip = stream.sized(ip_size);
            if !ip.is_ascii() {
                return Err(Error::BadConfigData);
            }
            let ip = String::from_utf8_lossy(ip).into_owned();
            let mut secret: &[u8] = &[];
            if version > 0 {
                let secret_size = stream.i32();
                if !(0..=MAX_SECRET_SIZE).contains(&secret_size) {
                    return Err(Error::BadConfigData);
                }
                secret = stream.sized(secret_size);
            }
            stream.status()?;
            options.add(id, flags, &ip, port, secret);
        }
        if !stream.at_end() && version > 1 {
            let keys = stream.i32();
            stream.status()?;
            for _ in 0..keys {
                let dc_id = stream.i32();
                let n = stream.block().to_vec();
                let e = stream.block().to_vec();
                stream.status()?;
                options.cdn_public_keys.push(RsaPublicKey { dc_id, n, e });
            }
        }
        Ok(options)
    }

    /// Serializes the options as version [`DC_OPTIONS_VERSION`]
    /// (`Serialize`), leaving out every DC whose bare id is
    /// [`MAX_SERIALIZED_DC_ID`] or above.
    ///
    /// # Errors
    /// - [`Error::BadConfigData`] when an IP is not ASCII.
    /// - [`Error::QDataStreamFailed`] when a count, IP, secret or key does
    ///   not fit its length prefix.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let endpoints: Vec<&Endpoint> = self
            .dcs
            .iter()
            .filter(|(id, _)| bare_dc_id(*id) < MAX_SERIALIZED_DC_ID)
            .flat_map(|(_, list)| list)
            .collect();
        let mut out = Vec::new();
        let put = |out: &mut Vec<u8>, value: i32| out.extend_from_slice(&value.to_be_bytes());
        put(&mut out, -DC_OPTIONS_VERSION);
        put(&mut out, len_i32(endpoints.len())?);
        for endpoint in endpoints {
            if !endpoint.ip.is_ascii() {
                return Err(Error::BadConfigData);
            }
            put(&mut out, endpoint.id);
            put(&mut out, endpoint.flags);
            put(&mut out, endpoint.port);
            put(&mut out, len_i32(endpoint.ip.len())?);
            out.extend_from_slice(endpoint.ip.as_bytes());
            put(&mut out, len_i32(endpoint.secret.len())?);
            out.extend_from_slice(&endpoint.secret);
        }
        put(&mut out, len_i32(self.cdn_public_keys.len())?);
        let mut keys = QWriter::new();
        for key in &self.cdn_public_keys {
            keys.write_i32(key.dc_id);
            keys.write_bytearray(Some(&key.n))?;
            keys.write_bytearray(Some(&key.e))?;
        }
        out.extend_from_slice(keys.as_bytes());
        Ok(out)
    }
}

/// The endpoints of one address family, by protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolEndpoints {
    /// Every endpoint of the family, in insertion order.
    pub tcp: Vec<Endpoint>,
    /// The endpoints without [`FLAG_TCPO_ONLY`] and [`FLAG_SECRET`].
    pub http: Vec<Endpoint>,
}

/// The endpoints of one DC by address family and protocol, as 1.5.0's
/// `MTP.Config.endpoints` returns them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoints {
    /// Endpoints without [`FLAG_IPV6`].
    pub ipv4: ProtocolEndpoints,
    /// Endpoints with [`FLAG_IPV6`].
    pub ipv6: ProtocolEndpoints,
}

impl Endpoints {
    /// The endpoint 1.5.0's Telethon conversion connects to
    /// (`src/tl/telethon.py`, `_select_endpoint_address` then the first
    /// TCP endpoint): the IPv6 family when `ipv6` is set and it has a TCP
    /// endpoint, else the IPv4 family; `None` when that family has no TCP
    /// endpoint.
    #[must_use]
    pub fn select(&self, ipv6: bool) -> Option<&Endpoint> {
        let family = if ipv6 && !self.ipv6.tcp.is_empty() {
            &self.ipv6
        } else {
            &self.ipv4
        };
        family.tcp.first()
    }
}

/// The config fields (`MTP.ConfigFields`), each named after its 1.5.0
/// attribute and listed in serialization order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFields {
    /// `chatSizeMax`.
    pub chat_size_max: i32,
    /// `megagroupSizeMax`.
    pub megagroup_size_max: i32,
    /// `forwardedCountMax`.
    pub forwarded_count_max: i32,
    /// `onlineUpdatePeriod`.
    pub online_update_period: i32,
    /// `offlineBlurTimeout`.
    pub offline_blur_timeout: i32,
    /// `offlineIdleTimeout`.
    pub offline_idle_timeout: i32,
    /// `onlineFocusTimeout`.
    pub online_focus_timeout: i32,
    /// `onlineCloudTimeout`.
    pub online_cloud_timeout: i32,
    /// `notifyCloudDelay`.
    pub notify_cloud_delay: i32,
    /// `notifyDefaultDelay`.
    pub notify_default_delay: i32,
    /// `savedGifsLimit`.
    pub saved_gifs_limit: i32,
    /// `editTimeLimit`.
    pub edit_time_limit: i32,
    /// `revokeTimeLimit`.
    pub revoke_time_limit: i32,
    /// `revokePrivateTimeLimit`.
    pub revoke_private_time_limit: i32,
    /// `revokePrivateInbox`; read as true only for the stored `i32` 1.
    pub revoke_private_inbox: bool,
    /// `stickersRecentLimit`.
    pub stickers_recent_limit: i32,
    /// `stickersFavedLimit`.
    pub stickers_faved_limit: i32,
    /// `pinnedDialogsCountMax`.
    pub pinned_dialogs_count_max: i32,
    /// `pinnedDialogsInFolderMax`.
    pub pinned_dialogs_in_folder_max: i32,
    /// `internalLinksDomain`.
    pub internal_links_domain: String,
    /// `channelsReadMediaPeriod`.
    pub channels_read_media_period: i32,
    /// `callReceiveTimeoutMs`.
    pub call_receive_timeout_ms: i32,
    /// `callRingTimeoutMs`.
    pub call_ring_timeout_ms: i32,
    /// `callConnectTimeoutMs`.
    pub call_connect_timeout_ms: i32,
    /// `callPacketTimeoutMs`.
    pub call_packet_timeout_ms: i32,
    /// `webFileDcId`.
    pub web_file_dc_id: i32,
    /// `txtDomainString`.
    pub txt_domain_string: String,
    /// `phoneCallsEnabled`; read as true only for the stored `i32` 1.
    pub phone_calls_enabled: bool,
    /// `blockedMode`; read as true only for the stored `i32` 1.
    pub blocked_mode: bool,
    /// `captionLengthMax`.
    pub caption_length_max: i32,
    /// `reactionDefaultEmoji` (optional tail).
    pub reaction_default_emoji: String,
    /// `reactionDefaultCustom` (optional tail).
    pub reaction_default_custom: u64,
    /// `ratingDecay` (optional tail).
    pub rating_decay: i32,
    /// `gifSearchUsername` (optional tail).
    pub gif_search_username: String,
    /// `venueSearchUsername` (optional tail).
    pub venue_search_username: String,
}

impl ConfigFields {
    /// The defaults of a new `MTP.Config(environment)`: the
    /// `MTP.ConfigFields` defaults with the web file DC, TXT domain and
    /// search bots of `environment`.
    #[must_use]
    pub fn new(environment: Environment) -> Self {
        let test = environment == Environment::Test;
        let pick = |test_value: &str, production: &str| {
            if test { test_value } else { production }.to_owned()
        };
        Self {
            chat_size_max: 200,
            megagroup_size_max: 10_000,
            forwarded_count_max: 100,
            online_update_period: 120_000,
            offline_blur_timeout: 5_000,
            offline_idle_timeout: 30_000,
            online_focus_timeout: 1_000,
            online_cloud_timeout: 300_000,
            notify_cloud_delay: 30_000,
            notify_default_delay: 1_500,
            saved_gifs_limit: 200,
            edit_time_limit: 172_800,
            revoke_time_limit: 172_800,
            revoke_private_time_limit: 172_800,
            revoke_private_inbox: false,
            stickers_recent_limit: 30,
            stickers_faved_limit: 5,
            pinned_dialogs_count_max: 5,
            pinned_dialogs_in_folder_max: 100,
            internal_links_domain: "https://t.me/".to_owned(),
            channels_read_media_period: 86_400 * 7,
            call_receive_timeout_ms: 20_000,
            call_ring_timeout_ms: 90_000,
            call_connect_timeout_ms: 30_000,
            call_packet_timeout_ms: 10_000,
            web_file_dc_id: if test { 2 } else { 4 },
            txt_domain_string: pick("tapv3.stel.com", "apv3.stel.com"),
            phone_calls_enabled: true,
            blocked_mode: false,
            caption_length_max: 1_024,
            reaction_default_emoji: "\u{1F44D}".to_owned(),
            reaction_default_custom: 0,
            rating_decay: 2_419_200,
            gif_search_username: pick("izgifbot", "gif"),
            venue_search_username: pick("foursquarebot", "foursquare"),
        }
    }

    /// Reads the 30 fixed fields and the optional tail over the defaults.
    fn read(&mut self, stream: &mut Stream<'_>) -> Result<()> {
        self.chat_size_max = stream.i32();
        self.megagroup_size_max = stream.i32();
        self.forwarded_count_max = stream.i32();
        self.online_update_period = stream.i32();
        self.offline_blur_timeout = stream.i32();
        self.offline_idle_timeout = stream.i32();
        self.online_focus_timeout = stream.i32();
        self.online_cloud_timeout = stream.i32();
        self.notify_cloud_delay = stream.i32();
        self.notify_default_delay = stream.i32();
        self.saved_gifs_limit = stream.i32();
        self.edit_time_limit = stream.i32();
        self.revoke_time_limit = stream.i32();
        self.revoke_private_time_limit = stream.i32();
        self.revoke_private_inbox = stream.bool();
        self.stickers_recent_limit = stream.i32();
        self.stickers_faved_limit = stream.i32();
        self.pinned_dialogs_count_max = stream.i32();
        self.pinned_dialogs_in_folder_max = stream.i32();
        self.internal_links_domain = stream.qstring()?;
        self.channels_read_media_period = stream.i32();
        self.call_receive_timeout_ms = stream.i32();
        self.call_ring_timeout_ms = stream.i32();
        self.call_connect_timeout_ms = stream.i32();
        self.call_packet_timeout_ms = stream.i32();
        self.web_file_dc_id = stream.i32();
        self.txt_domain_string = stream.qstring()?;
        self.phone_calls_enabled = stream.bool();
        self.blocked_mode = stream.bool();
        self.caption_length_max = stream.i32();
        // Each group was appended by a later tdesktop (mtproto_config.cpp).
        if !stream.at_end() {
            self.reaction_default_emoji = stream.qstring()?;
            self.reaction_default_custom = stream.u64();
        }
        if !stream.at_end() {
            self.rating_decay = stream.i32();
        }
        if !stream.at_end() {
            self.gif_search_username = stream.qstring()?;
            self.venue_search_username = stream.qstring()?;
        }
        Ok(())
    }

    /// Writes every field, the optional tail included.
    fn write(&self, out: &mut QWriter) -> Result<()> {
        let flag = |value: bool| i32::from(value);
        for value in [
            self.chat_size_max,
            self.megagroup_size_max,
            self.forwarded_count_max,
            self.online_update_period,
            self.offline_blur_timeout,
            self.offline_idle_timeout,
            self.online_focus_timeout,
            self.online_cloud_timeout,
            self.notify_cloud_delay,
            self.notify_default_delay,
            self.saved_gifs_limit,
            self.edit_time_limit,
            self.revoke_time_limit,
            self.revoke_private_time_limit,
            flag(self.revoke_private_inbox),
            self.stickers_recent_limit,
            self.stickers_faved_limit,
            self.pinned_dialogs_count_max,
            self.pinned_dialogs_in_folder_max,
        ] {
            out.write_i32(value);
        }
        out.write_qstring(Some(&self.internal_links_domain))?;
        for value in [
            self.channels_read_media_period,
            self.call_receive_timeout_ms,
            self.call_ring_timeout_ms,
            self.call_connect_timeout_ms,
            self.call_packet_timeout_ms,
            self.web_file_dc_id,
        ] {
            out.write_i32(value);
        }
        out.write_qstring(Some(&self.txt_domain_string))?;
        out.write_i32(flag(self.phone_calls_enabled));
        out.write_i32(flag(self.blocked_mode));
        out.write_i32(self.caption_length_max);
        out.write_qstring(Some(&self.reaction_default_emoji))?;
        out.write_u64(self.reaction_default_custom);
        out.write_i32(self.rating_decay);
        out.write_qstring(Some(&self.gif_search_username))?;
        out.write_qstring(Some(&self.venue_search_username))
    }
}

/// An account's MTP config (`MTP.Config`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtpConfig {
    /// Server environment.
    pub environment: Environment,
    /// The DC options.
    pub dc_options: DcOptions,
    /// Every config field.
    pub fields: ConfigFields,
}

impl MtpConfig {
    /// A new config of `environment` (`MTP.Config(environment)`): the
    /// built-in DC options and the default fields. The production one
    /// serializes to [`crate::tdata::account::MTP_CONFIG_PRODUCTION`].
    #[must_use]
    pub fn new(environment: Environment) -> Self {
        Self {
            environment,
            dc_options: DcOptions::built_in(environment),
            fields: ConfigFields::new(environment),
        }
    }

    /// Parses a serialized config (`MTP.Config.FromSerialized`). A missing
    /// tail group keeps its default; bytes after the tail are ignored.
    ///
    /// # Errors
    /// - [`Error::BadConfigData`] when the version is not
    ///   [`CONFIG_VERSION`] or the environment is neither 0 nor 1 (1.5.0
    ///   raises `OpenTeleException` and `ValueError`), and as
    ///   [`DcOptions::parse`].
    /// - [`Error::QDataStreamFailed`] when the config is cut short or a
    ///   string is not UTF-16, and as [`DcOptions::parse`].
    pub fn parse(serialized: &[u8]) -> Result<Self> {
        let mut stream = Stream::new(serialized);
        if stream.i32() != CONFIG_VERSION {
            return Err(Error::BadConfigData);
        }
        let environment = Environment::from_code(stream.i32()).ok_or(Error::BadConfigData)?;
        let options = stream.block();
        let mut fields = ConfigFields::new(environment);
        fields.read(&mut stream)?;
        stream.status()?;
        Ok(Self {
            environment,
            dc_options: DcOptions::parse(options)?,
            fields,
        })
    }

    /// Serializes the config as 1.5.0's `MTP.Config.Serialize` does.
    ///
    /// # Errors
    /// As [`DcOptions::serialize`], and [`Error::QDataStreamFailed`] when a
    /// string does not fit its length prefix.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let options = self.dc_options.serialize()?;
        let mut out = QWriter::new();
        out.write_i32(CONFIG_VERSION);
        out.write_i32(self.environment.code());
        out.write_bytearray(Some(&options))?;
        self.fields.write(&mut out)?;
        Ok(out.into_bytes())
    }

    /// The endpoints of DC `dc_id` by address family and protocol
    /// (`MTP.Config.endpoints`), in insertion order; `None` when the config
    /// has no such DC (1.5.0 raises `TDataDcIdNotFound`).
    #[must_use]
    pub fn endpoints(&self, dc_id: i32) -> Option<Endpoints> {
        let list = self.dc_options.dc(dc_id)?;
        let mut result = Endpoints::default();
        for endpoint in list {
            if dc_id != 0 && endpoint.id != dc_id {
                continue;
            }
            let family = if endpoint.flags & FLAG_IPV6 != 0 {
                &mut result.ipv6
            } else {
                &mut result.ipv4
            };
            family.tcp.push(endpoint.clone());
            if endpoint.flags & (FLAG_TCPO_ONLY | FLAG_SECRET) == 0 {
                family.http.push(endpoint.clone());
            }
        }
        Some(result)
    }
}
