//! The `<folder>/maps` file of one account (`Storage::Account::readMap`).
//!
//! The file is a `TDF$` container (see [`crate::tdf`]) whose payload is three
//! `QByteArray`s, as in 1.5.0 (`src/td/map_data.py`): the legacy salt, the
//! legacy local key wrap, and the map encrypted under the local key. The
//! decrypted map is a stream of entries, each a `u32` key type followed by a
//! payload whose shape the type decides. 1.5.0 stops at the first type it
//! does not know and keeps what it read so far; so does [`MapData::parse`].

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::crypto::{self, AuthKey};
use crate::qt::{QReader, QWriter};
use crate::tdata::{APP_VERSION, FillRandom, encrypt, write_tdf};
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
/// `lskUserSettings`: the user settings file key.
pub const LSK_USER_SETTINGS: u32 = 0x09;
/// `lskSelfSerialized`: the serialized self user.
pub const LSK_SELF_SERIALIZED: u32 = 0x15;
/// `lskWebviewTokens`: the bots and other web view storage tokens.
pub const LSK_WEBVIEW_TOKENS: u32 = 0x19;
/// `lskBotStorages`: bot storages, as (file key, serialized peer id) pairs.
pub const LSK_BOT_STORAGES: u32 = 0x1D;
/// `lskWalletEngineStorages`: wallet engine storages, as (file key, name).
pub const LSK_WALLET_ENGINE_STORAGES: u32 = 0x21;

/// User settings file key in the map of a new account
/// (`MapData._HARDCODED_SETTINGS_KEY`).
pub const NEW_ACCOUNT_SETTINGS_KEY: u64 = 1_851_671_142_505_648_812;

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

    /// The map 1.5.0 gives a new account (`MapData.__init__`): only the
    /// [`NEW_ACCOUNT_SETTINGS_KEY`] user settings key, [`APP_VERSION`], and
    /// no legacy arrays.
    #[must_use]
    pub fn new_account() -> Self {
        Self {
            version: APP_VERSION,
            legacy_salt: None,
            legacy_key_encrypted: None,
            entries: vec![MapEntry::FileKeys {
                kind: LSK_USER_SETTINGS,
                keys: vec![NEW_ACCOUNT_SETTINGS_KEY],
            }],
            stopped_at: None,
        }
    }

    /// Encodes the decrypted map the way 1.5.0 writes it
    /// (`MapData._writeMapEntries`), which is not a copy of the entries: they
    /// are first folded into 1.5.0's `MapData` fields.
    ///
    /// - File keys land in their named slots, a later entry overwriting an
    ///   earlier one; `lskStickersOld` fills the installed stickers key and
    ///   `lskBackgroundOldOld` the day background key. The three old skip
    ///   types and the two legacy wallet keys are dropped, and so are legacy
    ///   locations.
    /// - Draft, draft cursor, and bot storage pairs are keyed by peer id
    ///   (`PeerId.FromSerialized`, legacy layouts converted); a repeated peer
    ///   keeps its first position and its last file key. Peers are written
    ///   with the serialized-id flag set (`PeerId.Serialize`).
    /// - The self user, the web view tokens, and the wallet engine storages
    ///   keep the last entry; wallet entries are written sorted by name, a
    ///   null name as an empty one.
    ///
    /// The output follows 1.5.0's fixed type order and writes a key type
    /// only when one of its keys is non-zero, the self user only when it is
    /// non-empty, the web view tokens only when one is non-empty, and the
    /// wallet engine storages only when there is one.
    ///
    /// # Errors
    /// [`Error::QDataStreamFailed`] when a count or blob does not fit a `u32`.
    pub fn encode_entries(&self) -> Result<Vec<u8>> {
        MapState::fold(&self.entries).encode()
    }

    /// Writes the `maps` file into the account folder `dir`
    /// (`StorageAccount._writeMap`): two null arrays, then the encrypted
    /// [`MapData::encode_entries`].
    pub(crate) fn write(
        &self,
        dir: &Path,
        local_key: &AuthKey,
        rng: &mut FillRandom<'_>,
    ) -> Result<()> {
        let entries = self.encode_entries()?;
        if entries.is_empty() {
            // 1.5.0 builds no buffer for an empty map and fails to encrypt.
            return Err(Error::SaveFailed);
        }
        let mut payload = QWriter::new();
        payload.write_bytearray(None)?;
        payload.write_bytearray(None)?;
        payload.write_bytearray(Some(&encrypt(&entries, local_key, rng)?))?;
        write_tdf(dir, MAP_FILE, payload.into_bytes())
    }
}

/// File key slots of 1.5.0's `MapData`, one per `_KEY_TO_ATTR` attribute.
mod slot {
    pub const PREFS: usize = 0;
    pub const LOCATIONS: usize = 1;
    pub const TRUSTED_BOTS: usize = 2;
    pub const RECENT_STICKERS_OLD: usize = 3;
    pub const INSTALLED_STICKERS: usize = 4;
    pub const FEATURED_STICKERS: usize = 5;
    pub const RECENT_STICKERS: usize = 6;
    pub const FAVED_STICKERS: usize = 7;
    pub const ARCHIVED_STICKERS: usize = 8;
    pub const SAVED_GIFS: usize = 9;
    pub const INSTALLED_MASKS: usize = 10;
    pub const RECENT_MASKS: usize = 11;
    pub const ARCHIVED_MASKS: usize = 12;
    pub const INSTALLED_CUSTOM_EMOJI: usize = 13;
    pub const FEATURED_CUSTOM_EMOJI: usize = 14;
    pub const ARCHIVED_CUSTOM_EMOJI: usize = 15;
    pub const SEARCH_SUGGESTIONS: usize = 16;
    pub const BACKGROUND_DAY: usize = 17;
    pub const BACKGROUND_NIGHT: usize = 18;
    pub const USER_SETTINGS: usize = 19;
    pub const RECENT_HASHTAGS: usize = 20;
    pub const EXPORT_SETTINGS: usize = 21;
    pub const ROUND_PLACEHOLDER: usize = 22;
    pub const INLINE_BOTS_DOWNLOADS: usize = 23;
    pub const MEDIA_PLAYBACK_POSITIONS: usize = 24;
    pub const COUNT: usize = 25;
}

/// The slots a file-key type reads into, in stream order (1.5.0's
/// `_LSK_KEY_MAP`); empty for the types 1.5.0 drops.
fn key_slots(kind: u32) -> &'static [usize] {
    match kind {
        0x1E => &[slot::PREFS],
        0x04 => &[slot::LOCATIONS],
        0x11 => &[slot::TRUSTED_BOTS],
        0x07 => &[slot::RECENT_STICKERS_OLD],
        0x08 => &[slot::BACKGROUND_DAY],
        LSK_USER_SETTINGS => &[slot::USER_SETTINGS],
        0x0A => &[slot::RECENT_HASHTAGS],
        0x0B => &[slot::INSTALLED_STICKERS],
        0x12 => &[slot::FAVED_STICKERS],
        0x0F => &[slot::SAVED_GIFS],
        0x13 => &[slot::EXPORT_SETTINGS],
        0x18 => &[slot::SEARCH_SUGGESTIONS],
        0x14 => &[slot::BACKGROUND_DAY, slot::BACKGROUND_NIGHT],
        0x10 => &[
            slot::INSTALLED_STICKERS,
            slot::FEATURED_STICKERS,
            slot::RECENT_STICKERS,
            slot::ARCHIVED_STICKERS,
        ],
        0x16 => &[
            slot::INSTALLED_MASKS,
            slot::RECENT_MASKS,
            slot::ARCHIVED_MASKS,
        ],
        0x17 => &[
            slot::INSTALLED_CUSTOM_EMOJI,
            slot::FEATURED_CUSTOM_EMOJI,
            slot::ARCHIVED_CUSTOM_EMOJI,
        ],
        0x1A => &[slot::ROUND_PLACEHOLDER],
        0x1B => &[slot::INLINE_BOTS_DOWNLOADS],
        0x1C => &[slot::MEDIA_PLAYBACK_POSITIONS],
        _ => &[],
    }
}

/// `UserId::kReservedBit << 48`: set in every modern serialized peer id.
const PEER_SERIALIZED_FLAG: u64 = 0x80 << 48;

/// `PeerId.FromSerialized`: the peer id of a serialized one, converting the
/// legacy layout (type in bits 32..36); an unknown legacy type is peer 0.
fn peer_from_serialized(serialized: u64) -> u64 {
    if serialized & PEER_SERIALIZED_FLAG != 0 {
        return serialized & !PEER_SERIALIZED_FLAG;
    }
    let bare = serialized & 0xFFFF_FFFF;
    match serialized & 0xF_0000_0000 {
        0 => bare,
        0x1_0000_0000 => bare | (1 << 48),
        0x2_0000_0000 => bare | (2 << 48),
        0xF_0000_0000 => bare | (0x7F << 48),
        _ => 0,
    }
}

/// A Python dict from peer id to file key: insertion order, last value wins.
#[derive(Default)]
struct PeerMap {
    pairs: Vec<(u64, u64)>,
    index: HashMap<u64, usize>,
}

impl PeerMap {
    fn insert(&mut self, peer: u64, file_key: u64) {
        if let Some(&at) = self.index.get(&peer) {
            self.pairs[at].1 = file_key;
        } else {
            self.index.insert(peer, self.pairs.len());
            self.pairs.push((peer, file_key));
        }
    }

    fn encode(&self, writer: &mut QWriter, kind: u32) -> Result<()> {
        if self.pairs.is_empty() {
            return Ok(());
        }
        let count = u32::try_from(self.pairs.len()).map_err(|_| Error::QDataStreamFailed)?;
        writer.write_u32(kind);
        writer.write_u32(count);
        for &(peer, file_key) in &self.pairs {
            writer.write_u64(file_key);
            writer.write_u64(peer | PEER_SERIALIZED_FLAG);
        }
        Ok(())
    }
}

/// The fields of 1.5.0's `MapData` after `_parseMapStream`.
struct MapState<'a> {
    keys: [u64; slot::COUNT],
    self_serialized: Option<&'a [u8]>,
    drafts: PeerMap,
    draft_positions: PeerMap,
    bot_storages: PeerMap,
    // Both start null, which is never written.
    webview_bots: Option<&'a [u8]>,
    webview_other: Option<&'a [u8]>,
    wallet: BTreeMap<&'a str, u64>,
}

impl<'a> MapState<'a> {
    fn fold(entries: &'a [MapEntry]) -> Self {
        let mut state = Self {
            keys: [0; slot::COUNT],
            self_serialized: None,
            drafts: PeerMap::default(),
            draft_positions: PeerMap::default(),
            bot_storages: PeerMap::default(),
            webview_bots: None,
            webview_other: None,
            wallet: BTreeMap::new(),
        };
        for entry in entries {
            match entry {
                MapEntry::FileKeys { kind, keys } => {
                    for (&at, &key) in key_slots(*kind).iter().zip(keys) {
                        state.keys[at] = key;
                    }
                }
                MapEntry::PeerKeys { kind, pairs } => {
                    let target = match *kind {
                        LSK_DRAFT => &mut state.drafts,
                        LSK_DRAFT_POSITION => &mut state.draft_positions,
                        LSK_BOT_STORAGES => &mut state.bot_storages,
                        _ => continue,
                    };
                    for &(file_key, peer) in pairs {
                        target.insert(peer_from_serialized(peer), file_key);
                    }
                }
                MapEntry::LegacyLocations { .. } => {}
                MapEntry::SelfSerialized(blob) => state.self_serialized = blob.as_deref(),
                MapEntry::WebviewTokens { bots, other } => {
                    state.webview_bots = bots.as_deref();
                    state.webview_other = other.as_deref();
                }
                MapEntry::WalletEngineStorages(items) => {
                    state.wallet = items
                        .iter()
                        .map(|(file_key, name)| (name.as_deref().unwrap_or_default(), *file_key))
                        .collect();
                }
            }
        }
        state
    }

    /// `_writeKeyIfSet` / `_writeKeyGroupIfAnySet` for `kind`.
    fn encode_keys(&self, writer: &mut QWriter, kind: u32) {
        let slots = key_slots(kind);
        if slots.iter().any(|&at| self.keys[at] != 0) {
            writer.write_u32(kind);
            for &at in slots {
                writer.write_u64(self.keys[at]);
            }
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = QWriter::new();
        if let Some(blob) = self.self_serialized.filter(|blob| !blob.is_empty()) {
            writer.write_u32(LSK_SELF_SERIALIZED);
            writer.write_bytearray(Some(blob))?;
        }
        // Prefs.
        self.encode_keys(&mut writer, 0x1E);
        self.drafts.encode(&mut writer, LSK_DRAFT)?;
        self.draft_positions
            .encode(&mut writer, LSK_DRAFT_POSITION)?;
        self.bot_storages.encode(&mut writer, LSK_BOT_STORAGES)?;
        // Locations, trusted bots, recent stickers (old), stickers keys,
        // faved stickers, saved gifs, user settings, recent hashtags, export
        // settings, masks keys, custom emoji keys, search suggestions.
        for kind in [
            0x04, 0x11, 0x07, 0x10, 0x12, 0x0F, 0x09, 0x0A, 0x13, 0x16, 0x17, 0x18,
        ] {
            self.encode_keys(&mut writer, kind);
        }
        let non_empty = |token: Option<&[u8]>| token.is_some_and(|t| !t.is_empty());
        if non_empty(self.webview_bots) || non_empty(self.webview_other) {
            writer.write_u32(LSK_WEBVIEW_TOKENS);
            writer.write_bytearray(self.webview_bots)?;
            writer.write_bytearray(self.webview_other)?;
        }
        // Round placeholder, inline bots downloads, media playback positions.
        for kind in [0x1A, 0x1B, 0x1C] {
            self.encode_keys(&mut writer, kind);
        }
        if !self.wallet.is_empty() {
            let count = u32::try_from(self.wallet.len()).map_err(|_| Error::QDataStreamFailed)?;
            writer.write_u32(LSK_WALLET_ENGINE_STORAGES);
            writer.write_u32(count);
            for (&name, &file_key) in &self.wallet {
                writer.write_u64(file_key);
                writer.write_qstring(Some(name))?;
            }
        }
        // Background (old): day and night.
        self.encode_keys(&mut writer, 0x14);
        Ok(writer.into_bytes())
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
