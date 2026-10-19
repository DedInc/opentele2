//! The `<folder>/maps` file of one account (`Storage::Account::readMap`).
//!
//! The file is a `TDF$` container (see [`crate::tdf`]) whose payload is three
//! `QByteArray`s, as in 1.5.0 (`src/td/map_data.py`): the legacy salt, the
//! legacy local key wrap, and the map encrypted under the local key. The
//! decrypted map is a stream of entries, each a `u32` key type followed by a
//! payload whose shape the type decides. 1.5.0 stops at the first type it
//! does not know and keeps what it read so far; so does [`MapData::parse`].

use std::path::Path;

use crate::crypto::{self, AuthKey};
use crate::qt::QReader;
use crate::{Error, Result, tdf};

/// Name of the map file inside an account folder; on disk `maps`.
pub const MAP_FILE: &str = "map";

/// `lskDraft`: drafts, as (file key, serialized peer id) pairs.
pub const LSK_DRAFT: u32 = 0x01;
/// `lskDraftPosition`: draft cursors, as (file key, serialized peer id) pairs.
pub const LSK_DRAFT_POSITION: u32 = 0x02;
/// `lskLegacyImages`: legacy image locations.
pub const LSK_LEGACY_IMAGES: u32 = 0x03;
/// `lskLegacyStickerImages`: legacy sticker image locations.
pub const LSK_LEGACY_STICKER_IMAGES: u32 = 0x05;
/// `lskLegacyAudios`: legacy audio locations.
pub const LSK_LEGACY_AUDIOS: u32 = 0x06;
/// `lskSelfSerialized`: the serialized self user.
pub const LSK_SELF_SERIALIZED: u32 = 0x15;
/// `lskWebviewTokens`: the bots and other web view storage tokens.
pub const LSK_WEBVIEW_TOKENS: u32 = 0x19;
/// `lskBotStorages`: bot storages, as (file key, serialized peer id) pairs.
pub const LSK_BOT_STORAGES: u32 = 0x1D;
/// `lskWalletEngineStorages`: wallet engine storages, as (file key, name).
pub const LSK_WALLET_ENGINE_STORAGES: u32 = 0x21;

/// Number of `u64` file keys stored after `kind`, for the key types that hold
/// only file keys (1.5.0's `_LSK_KEY_MAP`, `_LSK_SKIP_TYPES`, and the two
/// legacy wallet keys); `None` for every other type.
#[must_use]
pub fn file_key_count(kind: u32) -> Option<usize> {
    match kind {
        // Locations, recent stickers (old), background (old old), user
        // settings, recent hashtags, stickers (old), saved peers (old),
        // report spam statuses (old), saved gifs (old), saved gifs, trusted
        // bots, faved stickers, export settings, search suggestions, round
        // placeholder, inline bots downloads, media playback positions,
        // prefs, wallet key, wallet engine key. 1.5.0 reads and drops the
        // three old skip types and the two wallet keys.
        0x04 | 0x07..=0x0F | 0x11..=0x13 | 0x18 | 0x1A..=0x1C | 0x1E..=0x20 => Some(1),
        // Background (old): day and night.
        0x14 => Some(2),
        // Stickers keys: installed, featured, recent, archived.
        0x10 => Some(4),
        // Masks keys and custom emoji keys: three each.
        0x16 | 0x17 => Some(3),
        _ => None,
    }
}

/// One entry of the decrypted map, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapEntry {
    /// A key type that holds only file keys (see [`file_key_count`]).
    FileKeys {
        /// The `lsk` key type.
        kind: u32,
        /// The file keys, as many as [`file_key_count`] gives.
        keys: Vec<u64>,
    },
    /// [`LSK_DRAFT`], [`LSK_DRAFT_POSITION`], or [`LSK_BOT_STORAGES`].
    PeerKeys {
        /// The `lsk` key type.
        kind: u32,
        /// (file key, serialized peer id) pairs in file order.
        pairs: Vec<(u64, u64)>,
    },
    /// [`LSK_LEGACY_IMAGES`], [`LSK_LEGACY_STICKER_IMAGES`], or
    /// [`LSK_LEGACY_AUDIOS`]: three `u64` and an `i32` per item, which 1.5.0
    /// reads and drops.
    LegacyLocations {
        /// The `lsk` key type.
        kind: u32,
        /// The raw items in file order.
        items: Vec<(u64, u64, u64, i32)>,
    },
    /// [`LSK_SELF_SERIALIZED`]; `None` for a null array.
    SelfSerialized(Option<Vec<u8>>),
    /// [`LSK_WEBVIEW_TOKENS`]; `None` for a null array.
    WebviewTokens {
        /// Storage token of bot web views.
        bots: Option<Vec<u8>>,
        /// Storage token of other web views.
        other: Option<Vec<u8>>,
    },
    /// [`LSK_WALLET_ENGINE_STORAGES`]: (file key, entry name) pairs; `None`
    /// for a null string.
    WalletEngineStorages(Vec<(u64, Option<String>)>),
}

/// A decoded `maps` file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapData {
    /// Telegram Desktop version stored in the `TDF$` header.
    pub version: u32,
    /// The legacy salt; `None` for a null array.
    pub legacy_salt: Option<Vec<u8>>,
    /// The legacy local key wrap; `None` for a null array.
    pub legacy_key_encrypted: Option<Vec<u8>>,
    /// The decoded entries in file order.
    pub entries: Vec<MapEntry>,
    /// The unknown key type the entries stopped at, if any; 1.5.0 ignores
    /// everything after it.
    pub stopped_at: Option<u32>,
}

impl MapData {
    /// Decodes a decrypted map (the data part of the encrypted blob) into
    /// its entries and the unknown key type they stopped at.
    ///
    /// A key type that cannot be read in full ends the entries like an
    /// unknown one, since 1.5.0 reads a short value as 0 (`lskUserMap`).
    ///
    /// # Errors
    /// [`Error::QDataStreamFailed`] when an entry of a known type is cut
    /// short or holds an invalid string.
    pub fn parse_entries(data: &[u8]) -> Result<(Vec<MapEntry>, Option<u32>)> {
        let mut reader = QReader::new(data);
        let mut entries = Vec::new();
        while !reader.is_empty() {
            let Ok(kind) = reader.read_u32() else {
                return Ok((entries, Some(0)));
            };
            match read_entry(&mut reader, kind)? {
                Some(entry) => entries.push(entry),
                None => return Ok((entries, Some(kind))),
            }
        }
        Ok((entries, None))
    }

    /// Reads and decrypts the `maps` file in the account folder `dir`
    /// (`MapData.read` with a local key).
    ///
    /// # Errors
    /// - [`Error::ReadMapDataFailed`] when the file is missing or invalid, or
    ///   the map does not decrypt under `local_key`.
    /// - [`Error::QDataStreamFailed`] when the three arrays or an entry are
    ///   cut short.
    pub fn read(dir: impl AsRef<Path>, local_key: &AuthKey) -> Result<Self> {
        let file = tdf::read(dir, MAP_FILE).map_err(|_| Error::ReadMapDataFailed)?;
        let mut reader = QReader::new(&file.payload);
        let legacy_salt = reader.read_bytearray()?.map(<[u8]>::to_vec);
        let legacy_key_encrypted = reader.read_bytearray()?.map(<[u8]>::to_vec);
        let encrypted = reader.read_bytearray()?.unwrap_or_default();
        let map =
            crypto::decrypt_local(encrypted, local_key).map_err(|_| Error::ReadMapDataFailed)?;
        let (entries, stopped_at) = Self::parse_entries(&map)?;
        Ok(Self {
            version: file.version,
            legacy_salt,
            legacy_key_encrypted,
            entries,
            stopped_at,
        })
    }
}

/// Reads `count: u32` items with `item`; the count is never preallocated,
/// so a forged count fails at the first short read.
fn read_counted<'a, T>(
    reader: &mut QReader<'a>,
    mut item: impl FnMut(&mut QReader<'a>) -> Result<T>,
) -> Result<Vec<T>> {
    let count = reader.read_u32()?;
    let mut items = Vec::new();
    for _ in 0..count {
        items.push(item(reader)?);
    }
    Ok(items)
}

fn owned(blob: Option<&[u8]>) -> Option<Vec<u8>> {
    blob.map(<[u8]>::to_vec)
}

/// Reads the payload of one entry; `None` for a key type 1.5.0 does not know.
fn read_entry(reader: &mut QReader<'_>, kind: u32) -> Result<Option<MapEntry>> {
    let entry = match kind {
        LSK_DRAFT | LSK_DRAFT_POSITION | LSK_BOT_STORAGES => MapEntry::PeerKeys {
            kind,
            pairs: read_counted(reader, |r| Ok((r.read_u64()?, r.read_u64()?)))?,
        },
        LSK_LEGACY_IMAGES | LSK_LEGACY_STICKER_IMAGES | LSK_LEGACY_AUDIOS => {
            MapEntry::LegacyLocations {
                kind,
                items: read_counted(reader, |r| {
                    Ok((r.read_u64()?, r.read_u64()?, r.read_u64()?, r.read_i32()?))
                })?,
            }
        }
        LSK_SELF_SERIALIZED => MapEntry::SelfSerialized(owned(reader.read_bytearray()?)),
        LSK_WEBVIEW_TOKENS => MapEntry::WebviewTokens {
            bots: owned(reader.read_bytearray()?),
            other: owned(reader.read_bytearray()?),
        },
        LSK_WALLET_ENGINE_STORAGES => MapEntry::WalletEngineStorages(read_counted(reader, |r| {
            Ok((r.read_u64()?, r.read_qstring()?))
        })?),
        _ => {
            let Some(count) = file_key_count(kind) else {
                return Ok(None);
            };
            let mut keys = Vec::with_capacity(count);
            for _ in 0..count {
                keys.push(reader.read_u64()?);
            }
            MapEntry::FileKeys { kind, keys }
        }
    };
    Ok(Some(entry))
}
