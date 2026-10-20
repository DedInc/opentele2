//! Session formats of other Telegram libraries, built from tdata accounts.
//!
//! - [`dc`]: the built-in DC table and its first-endpoint choice.
//! - [`telethon`]: Telethon `StringSession` (version `'1'`).
//! - [`mtcute`]: mtcute string session version 3.
//! - [`grammers`]: plain structs shaped like grammers 0.11 `SessionData`,
//!   with no grammers dependency.
//! - [`telethon_file`]: Telethon `SQLiteSession` (version 8) rows and the
//!   `.session` + `.json` pair; the file itself is written and read
//!   only with the optional feature `telethon-sqlite`.
//!
//! Every `from_account` takes the endpoints of the account's stored MTP
//! config ([`crate::tdata::account::Account::mtp_config`]) when the account
//! has config bytes, as `TDesktop` does with performance mode off, and the
//! built-in production table of [`dc`] otherwise, as `TDesktop` does in
//! performance mode (its default, where the stored config is never read).
//! The production default config holds the same endpoints as the table.
//!
//! Every type holds its key as a [`crate::crypto::AuthKey`], whose `Debug`
//! prints the key id only, never key material.

mod codecs;
pub mod telethon_file;

pub use codecs::{grammers, mtcute, telethon};

/// The built-in DC options (`BuiltInDc`) and the endpoint choice of the
/// Telethon conversion.
///
/// The DC options are built from these lists in order, IPv4 then IPv6,
/// every entry a static TCP endpoint. A session takes the first TCP endpoint
/// of the main DC: from the IPv6 list when IPv6 is asked for and the DC has
/// an IPv6 endpoint, else from the IPv4 list.
pub mod dc {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    /// The port of every built-in DC option.
    pub const PORT: u16 = 443;

    const fn v4(id: i32, a: u8, b: u8, c: u8, d: u8) -> (i32, SocketAddr) {
        (
            id,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), PORT)),
        )
    }

    const fn v6(id: i32, s: [u16; 8]) -> (i32, SocketAddr) {
        (
            id,
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
                PORT,
                0,
                0,
            )),
        )
    }

    /// Production IPv4 options as (DC id, address), in table order; DC 2 is
    /// listed twice (`kBuiltInDcs`).
    pub const PRODUCTION_IPV4: [(i32, SocketAddr); 6] = [
        v4(1, 149, 154, 175, 50),
        v4(2, 149, 154, 167, 51),
        v4(2, 95, 161, 76, 100),
        v4(3, 149, 154, 175, 100),
        v4(4, 149, 154, 167, 91),
        v4(5, 149, 154, 171, 5),
    ];

    /// Production IPv6 options as (DC id, address) (`kBuiltInDcsIPv6`).
    pub const PRODUCTION_IPV6: [(i32, SocketAddr); 5] = [
        v6(1, [0x2001, 0x0b28, 0xf23d, 0xf001, 0, 0, 0, 0x000a]),
        v6(2, [0x2001, 0x067c, 0x04e8, 0xf002, 0, 0, 0, 0x000a]),
        v6(3, [0x2001, 0x0b28, 0xf23d, 0xf003, 0, 0, 0, 0x000a]),
        v6(4, [0x2001, 0x067c, 0x04e8, 0xf004, 0, 0, 0, 0x000a]),
        v6(5, [0x2001, 0x0b28, 0xf23f, 0xf005, 0, 0, 0, 0x000a]),
    ];

    /// Test IPv4 options as (DC id, address) (`kBuiltInDcsTest`).
    pub const TEST_IPV4: [(i32, SocketAddr); 3] = [
        v4(1, 149, 154, 175, 10),
        v4(2, 149, 154, 167, 40),
        v4(3, 149, 154, 175, 117),
    ];

    /// Test IPv6 options as (DC id, address) (`kBuiltInDcsIPv6Test`).
    pub const TEST_IPV6: [(i32, SocketAddr); 3] = [
        v6(1, [0x2001, 0x0b28, 0xf23d, 0xf001, 0, 0, 0, 0x000e]),
        v6(2, [0x2001, 0x067c, 0x04e8, 0xf002, 0, 0, 0, 0x000e]),
        v6(3, [0x2001, 0x0b28, 0xf23d, 0xf003, 0, 0, 0, 0x000e]),
    ];

    /// The DC ids of the production table, ascending.
    pub const PRODUCTION_DC_IDS: [i32; 5] = [1, 2, 3, 4, 5];

    fn first(table: &[(i32, SocketAddr)], dc_id: i32) -> Option<SocketAddr> {
        table
            .iter()
            .find(|(id, _)| *id == dc_id)
            .map(|(_, addr)| *addr)
    }

    fn select(
        ipv4: &[(i32, SocketAddr)],
        ipv6: &[(i32, SocketAddr)],
        dc_id: i32,
        use_ipv6: bool,
    ) -> Option<SocketAddr> {
        use_ipv6
            .then(|| first(ipv6, dc_id))
            .flatten()
            .or_else(|| first(ipv4, dc_id))
    }

    /// The first production endpoint of `dc_id`, IPv6 when `ipv6` is set and
    /// the DC has one; `None` for a DC outside the table (the Python binding
    /// raises `TDataDcIdNotFound`).
    #[must_use]
    pub fn production(dc_id: i32, ipv6: bool) -> Option<SocketAddr> {
        select(&PRODUCTION_IPV4, &PRODUCTION_IPV6, dc_id, ipv6)
    }

    /// The first test-server endpoint of `dc_id`, chosen as [`production`].
    #[must_use]
    pub fn test(dc_id: i32, ipv6: bool) -> Option<SocketAddr> {
        select(&TEST_IPV4, &TEST_IPV6, dc_id, ipv6)
    }
}
