//! Device fingerprints picked exactly as opentele2 1.5.0 picks them.
//!
//! 1.5.0 (`src/devices.py`) expands each catalog into a list in which every
//! (model, system version) pair is repeated by its weight, then indexes that
//! list with a hash of the seed. This module keeps one slot per pair with a
//! cumulative weight instead and finds the slot by binary search, which
//! lands on the same pair as the expanded list without materialising it.
//!
//! The catalogs in `data/devices/` are embedded at build time and parsed once,
//! on first use.
//!
//! The web catalogs are 1.5.0's browserforge pool, drawn with the
//! `opentele2-browser` port from a generator seeded by the Chrome and
//! Firefox majors ([`web_catalog_for`]), so a pool is a pure function of the
//! versions; its devices are picked with the same seed hash and cumulative
//! weights as every other catalog.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock, PoisonError};

use opentele2_browser::{
    Browser, Error as BrowserError, HeaderGenerator, HeaderOptions, HeaderOverrides, Rng,
    get_user_agent,
};
use serde::Deserialize;
use sha1::{Digest, Sha1};

use crate::api::Versions;
use crate::{Error, Result};

const ANDROID_JSON: &str = include_str!("../data/devices/android.json");
const DESKTOP_JSON: &str = include_str!("../data/devices/desktop.json");
const IOS_JSON: &str = include_str!("../data/devices/ios.json");
const MAC_JSON: &str = include_str!("../data/devices/mac.json");

/// The fixed part of the web pool generator's seed; the Chrome and Firefox
/// majors are appended to it.
const WEB_POOL_SEED: &str = "opentele2/devices/web-pool/v1";

/// How many majors the browserforge dataset may trail the live release
/// (1.5.0 `_max_dataset_lag`).
const MAX_DATASET_LAG: u32 = 24;

/// Seed hashes are reduced modulo 10^12, as in 1.5.0 `_strtohashid`.
const HASH_MODULUS: u64 = 1_000_000_000_000;

/// The Android API levels 1.5.0 maps to a release (`_SDK_TO_ANDROID`).
const ANDROID_SDKS: std::ops::RangeInclusive<i64> = 29..=37;

/// Android 12L, emitted only for devices that reported it.
const SDK_12L: i64 = 32;

/// A platform whose catalog a device is picked from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    /// Telegram Desktop on Windows.
    Windows,
    /// Telegram Desktop on Linux.
    Linux,
    /// A Mac. `swift` selects the `TelegramSwift` client, which reports the
    /// bare version (`26.7.1`); Telegram Desktop reports `macOS 26.7.1`.
    MacOS {
        /// Whether the client is `TelegramSwift` rather than Telegram Desktop.
        swift: bool,
    },
    /// Telegram Android and Telegram X, which share one catalog.
    Android,
    /// Telegram iOS.
    Ios,
    /// A Telegram web client in a desktop browser: the model is the browser
    /// user agent and the system version the platform string `client` sends.
    Web {
        /// The web client, which decides the platform string.
        client: WebClient,
    },
}

impl Platform {
    /// Every platform a catalog name selects, in the order the bindings list
    /// the names: `windows`, `linux`, `macos`, `android`, `ios`, `web_a`,
    /// `web_k`. `macos` is Telegram Desktop's Mac; the Swift client shares
    /// its catalog.
    pub const NAMED: [Self; 7] = [
        Self::Windows,
        Self::Linux,
        Self::MacOS { swift: false },
        Self::Android,
        Self::Ios,
        Self::Web {
            client: WebClient::A,
        },
        Self::Web {
            client: WebClient::K,
        },
    ];

    /// The catalog name of the platform, as the bindings' `catalog_entries`,
    /// `device_models` and `system_versions` take it.
    ///
    /// Both Mac clients read one catalog, so `MacOS { swift: true }` is also
    /// `macos`, and [`Platform::from_name`] gives it back as
    /// `MacOS { swift: false }`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOS { .. } => "macos",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Web {
                client: WebClient::A,
            } => "web_a",
            Self::Web {
                client: WebClient::K,
            } => "web_k",
        }
    }

    /// The platform of [`Platform::NAMED`] whose [`Platform::name`] is
    /// exactly `name`; `None` for any other text, including other cases.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::NAMED
            .into_iter()
            .find(|platform| platform.name() == name)
    }
}

/// A Telegram web client. Both share one browser pool, so a seed picks the
/// same user agent for either; they differ in the platform string they send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebClient {
    /// Telegram Web A, which sends a platform name: `Windows`, `macOS`,
    /// `Linux` or `ChromeOS` (1.5.0 variant `z`).
    A,
    /// Telegram Web K and Webogram, which send `navigator.platform`: `Win32`,
    /// `MacIntel`, `Linux x86_64` or `Linux aarch64` (1.5.0 variant `k`).
    K,
}

/// A picked device: the `device_model` and `system_version` a client sends.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Device {
    /// The device model, for example `MacBook Air M4`.
    pub model: String,
    /// The system version, for example `macOS 26.7.1` or `SDK 36`.
    pub system_version: String,
}

/// One catalog pair and the number of times 1.5.0 repeats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WeightedDevice<'a> {
    /// The device model.
    pub model: &'a str,
    /// The system version as stored in the catalog. Mac versions are bare;
    /// [`pick`] adds the `macOS ` prefix for Telegram Desktop.
    pub system_version: &'a str,
    /// How many times the pair occurs in 1.5.0's expanded list; never zero.
    pub weight: u64,
}

/// An owned [`WeightedDevice`]: one entry of [`catalog_entries`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CatalogEntry {
    /// The device model.
    pub model: String,
    /// The system version as stored in the catalog; Mac versions are bare,
    /// as in 1.5.0 `macOSDevice.deviceList`.
    pub system_version: String,
    /// How many times the pair occurs in 1.5.0's expanded list; never zero.
    pub weight: u64,
}

/// 1.5.0 `WebBrowserDevice.BROWSER_WEIGHTS`: the share 1.5.0 gave each
/// browserforge browser, in its order: the weight of every user agent of
/// that browser in the web catalogs.
pub const WEB_BROWSER_WEIGHTS: [(&str, u64); 3] = [("chrome", 19), ("edge", 2), ("firefox", 1)];

#[derive(Debug, Clone)]
struct Slot {
    model: usize,
    version: usize,
    weight: u64,
}

/// The weighted pairs of one platform, in 1.5.0's list order.
#[derive(Debug, Clone)]
pub struct Catalog {
    models: Vec<String>,
    versions: Vec<String>,
    slots: Vec<Slot>,
    /// `ends[i]` is the total weight of slots `0..=i`.
    ends: Vec<u64>,
}

impl Catalog {
    fn new(models: Vec<String>, versions: Vec<String>) -> Self {
        Self {
            models,
            versions,
            slots: Vec::new(),
            ends: Vec::new(),
        }
    }

    fn push(
        &mut self,
        model: usize,
        version: usize,
        weight: u64,
    ) -> std::result::Result<(), String> {
        // A zero weight has no copy in the expanded list, so it gets no slot.
        if weight == 0 {
            return Ok(());
        }
        let end = self
            .total_weight()
            .checked_add(weight)
            .ok_or_else(|| "total weight overflows u64".to_owned())?;
        self.slots.push(Slot {
            model,
            version,
            weight,
        });
        self.ends.push(end);
        Ok(())
    }

    fn finish(self, name: &str) -> std::result::Result<Self, String> {
        if self.slots.is_empty() {
            Err(format!("device catalog {name} is empty after filtering"))
        } else {
            Ok(self)
        }
    }

    /// Number of distinct weighted pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the catalog has no pairs; a catalog returned by [`catalog`]
    /// never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Sum of all weights: the length of 1.5.0's expanded list.
    #[must_use]
    pub fn total_weight(&self) -> u64 {
        self.ends.last().copied().unwrap_or(0)
    }

    /// The weighted pairs in 1.5.0's list order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = WeightedDevice<'_>> + '_ {
        self.slots.iter().map(|slot| self.view(slot))
    }

    /// The weighted pairs in 1.5.0's list order, owned, for bindings.
    #[must_use]
    pub fn to_entries(&self) -> Vec<CatalogEntry> {
        self.entries()
            .map(|entry| CatalogEntry {
                model: entry.model.to_owned(),
                system_version: entry.system_version.to_owned(),
                weight: entry.weight,
            })
            .collect()
    }

    /// The catalog's models in file order, before any pair is weighted or
    /// filtered: 1.5.0 `device_models` of the desktop, Mac and iOS classes
    /// (1.5.0's `AndroidDevice` keeps that list empty). Desktop models are
    /// already cleaned, which leaves every embedded one unchanged.
    #[must_use]
    pub fn device_models(&self) -> &[String] {
        &self.models
    }

    /// The catalog's system versions in file order: 1.5.0 `system_versions`
    /// of the desktop, Mac and iOS classes; `SDK 29` to `SDK 37` for
    /// Android, and the client's platform strings for the web.
    #[must_use]
    pub fn system_versions(&self) -> &[String] {
        &self.versions
    }

    fn view(&self, slot: &Slot) -> WeightedDevice<'_> {
        WeightedDevice {
            model: self.models.get(slot.model).map_or("", String::as_str),
            system_version: self.versions.get(slot.version).map_or("", String::as_str),
            weight: slot.weight,
        }
    }

    /// The pair at `hash % total_weight()` of the expanded list.
    fn at(&self, hash: u64) -> Option<WeightedDevice<'_>> {
        let total = self.total_weight();
        if total == 0 {
            return None;
        }
        let index = hash % total;
        let slot = self.ends.partition_point(|&end| end <= index);
        self.slots.get(slot).map(|slot| self.view(slot))
    }
}

/// The 1.5.0 seed hash: the full 160-bit SHA-1 digest of the UTF-8 seed,
/// read as a big-endian integer, modulo 10^12.
///
/// Integer seeds are hashed as their decimal string, as 1.5.0 does.
#[must_use]
pub fn seed_hash(seed: &str) -> u64 {
    digest_hash(seed.as_bytes())
}

fn digest_hash(bytes: &[u8]) -> u64 {
    // The remainder stays below 10^12 < 2^40, so `* 256 + 255` fits in u64.
    Sha1::digest(bytes).iter().fold(0u64, |rem, &byte| {
        (rem * 256 + u64::from(byte)) % HASH_MODULUS
    })
}

/// The hash for `seed`, or for 32 random bytes when there is no seed, as
/// 1.5.0 uses `os.urandom(32)`.
fn hash_for(seed: Option<&str>) -> Result<u64> {
    if let Some(seed) = seed {
        return Ok(seed_hash(seed));
    }
    let mut bytes = [0u8; 32];
    crate::crypto::random_fill(&mut bytes)?;
    Ok(digest_hash(&bytes))
}

/// The platform 1.5.0 `API.TelegramDesktop.Generate` chooses when no system
/// is given: `("windows", "macos", "linux")[hash % 3]`.
///
/// Without a seed the choice is random, drawn independently of the device
/// [`pick`] makes afterwards, as in 1.5.0.
///
/// # Errors
///
/// [`Error::Io`] when no seed is given and the OS random source fails.
pub fn desktop_system(seed: Option<&str>) -> Result<Platform> {
    Ok(match hash_for(seed)? % 3 {
        0 => Platform::Windows,
        1 => Platform::MacOS { swift: false },
        _ => Platform::Linux,
    })
}

/// The device 1.5.0 picks for `platform` and `seed`; without a seed the pick
/// is random.
///
/// # Errors
///
/// [`Error::Io`] when no seed is given and the OS random source fails, or
/// when the embedded catalog is malformed or empty after filtering.
pub fn pick(platform: Platform, seed: Option<&str>) -> Result<Device> {
    pick_from(catalog(platform)?, platform, seed)
}

/// The device 1.5.0 picks from `catalog`, which holds `platform`'s pairs,
/// for `seed`; without a seed the pick is random.
pub(crate) fn pick_from(
    catalog: &Catalog,
    platform: Platform,
    seed: Option<&str>,
) -> Result<Device> {
    let hash = hash_for(seed)?;
    let picked = catalog
        .at(hash)
        .ok_or_else(|| catalog_error("device catalog is empty".to_owned()))?;
    let system_version = match platform {
        Platform::MacOS { swift: false } => format!("macOS {}", picked.system_version),
        _ => picked.system_version.to_owned(),
    };
    Ok(Device {
        model: picked.model.to_owned(),
        system_version,
    })
}

/// The weighted catalog of `platform`. Both [`Platform::MacOS`] variants
/// share one catalog; the [`Platform::Web`] catalogs are the
/// [`web_catalog_for`] pools of [`Versions::offline`].
///
/// # Errors
///
/// [`Error::Io`] when the embedded catalog is malformed or empty after
/// filtering, or the web pool fails to generate.
pub fn catalog(platform: Platform) -> Result<&'static Catalog> {
    static DESKTOP: OnceLock<std::result::Result<DesktopCatalogs, String>> = OnceLock::new();
    static MAC: OnceLock<std::result::Result<Catalog, String>> = OnceLock::new();
    static ANDROID: OnceLock<std::result::Result<Catalog, String>> = OnceLock::new();
    static IOS: OnceLock<std::result::Result<Catalog, String>> = OnceLock::new();
    static WEB_A: OnceLock<std::result::Result<Catalog, String>> = OnceLock::new();
    static WEB_K: OnceLock<std::result::Result<Catalog, String>> = OnceLock::new();

    let built = match platform {
        Platform::Windows | Platform::Linux => {
            let desktop = DESKTOP
                .get_or_init(build_desktop)
                .as_ref()
                .map_err(|message| catalog_error(message.clone()))?;
            if platform == Platform::Windows {
                &desktop.windows
            } else {
                &desktop.linux
            }
        }
        Platform::MacOS { .. } => MAC.get_or_init(build_mac),
        Platform::Android => ANDROID.get_or_init(build_android),
        Platform::Ios => IOS.get_or_init(build_ios),
        Platform::Web {
            client: WebClient::A,
        } => WEB_A.get_or_init(|| offline_web_catalog(WebClient::A)),
        Platform::Web {
            client: WebClient::K,
        } => WEB_K.get_or_init(|| offline_web_catalog(WebClient::K)),
    };
    built
        .as_ref()
        .map_err(|message| catalog_error(message.clone()))
}

/// The weighted pairs of `platform`'s [`catalog`], owned, in 1.5.0's list
/// order; the [`Platform::Web`] catalogs included.
///
/// # Errors
///
/// As [`catalog`].
pub fn catalog_entries(platform: Platform) -> Result<Vec<CatalogEntry>> {
    Ok(catalog(platform)?.to_entries())
}

fn catalog_error(message: String) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

fn one() -> u64 {
    1
}

#[derive(Deserialize)]
struct WeightedModel {
    model: String,
    #[serde(default = "one")]
    weight: u64,
}

#[derive(Deserialize)]
struct WeightedVersion {
    version: String,
    #[serde(default = "one")]
    weight: u64,
}

#[derive(Deserialize)]
struct DesktopFile {
    models: Vec<WeightedModel>,
    windows: Vec<WeightedVersion>,
    linux: Vec<WeightedVersion>,
}

#[derive(Deserialize)]
struct MacModel {
    model: String,
    min_macos: String,
    #[serde(default = "one")]
    weight: u64,
}

#[derive(Deserialize)]
struct MacFile {
    models: Vec<MacModel>,
    versions: Vec<WeightedVersion>,
}

#[derive(Deserialize)]
struct IosModel {
    model: String,
    min_ios: String,
    max_major: i64,
    #[serde(default = "one")]
    weight: u64,
}

#[derive(Deserialize)]
struct IosFile {
    models: Vec<IosModel>,
    versions: Vec<WeightedVersion>,
    #[serde(default)]
    only: HashMap<String, Vec<String>>,
    #[serde(default)]
    except: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct AndroidDevice {
    manufacturer: String,
    model: String,
    min_sdk: i64,
    max_sdk: i64,
    #[serde(default = "one")]
    weight: u64,
    #[serde(default)]
    sdk_32: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct AndroidFile {
    devices: Vec<AndroidDevice>,
}

struct DesktopCatalogs {
    windows: std::result::Result<Catalog, String>,
    linux: std::result::Result<Catalog, String>,
}

fn parse<'a, T: Deserialize<'a>>(name: &str, text: &'a str) -> std::result::Result<T, String> {
    serde_json::from_str(text).map_err(|e| format!("device catalog {name} is malformed: {e}"))
}

/// 1.5.0 `_version_tuple`: dot-separated integers, compared element-wise.
fn version_key(version: &str) -> std::result::Result<Vec<i64>, String> {
    version
        .split('.')
        .map(|part| {
            part.parse::<i64>()
                .map_err(|_| format!("device catalog version {version:?} is not numeric"))
        })
        .collect()
}

/// The entry 1.5.0 reads for `item`'s key: its catalogs index weights and
/// limits by name in a dict, so the last entry with a name wins.
fn last_with<'a, T>(items: &'a [T], item: &'a T, key: impl Fn(&T) -> &str) -> &'a T {
    items
        .iter()
        .rev()
        .find(|other| key(other) == key(item))
        .unwrap_or(item)
}

/// The weight 1.5.0 gives each version: `{version: weight}`, last one wins.
fn version_weights(versions: &[WeightedVersion]) -> Vec<u64> {
    versions
        .iter()
        .map(|v| last_with(versions, v, |e| e.version.as_str()).weight)
        .collect()
}

fn weight_product(model: u64, version: u64) -> std::result::Result<u64, String> {
    model
        .checked_mul(version)
        .ok_or_else(|| "device weight overflows u64".to_owned())
}

/// Python `" ".join(text.split())`. `str.split()` also splits on the
/// separators U+001C..U+001F, which Unicode does not class as white space.
fn clean_and_simplify(text: &str) -> String {
    text.split(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn build_desktop() -> std::result::Result<DesktopCatalogs, String> {
    let file: DesktopFile = parse("desktop.json", DESKTOP_JSON)?;
    // 1.5.0 `_gen_desktop`: models lose underscores and extra spaces; a
    // cleaned name takes the weight of the last model that cleans to it.
    let cleaned: Vec<String> = file
        .models
        .iter()
        .map(|m| clean_and_simplify(&m.model.replace('_', "")))
        .collect();
    let model_weights: Vec<u64> = cleaned
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let last = cleaned.iter().rposition(|other| other == name).unwrap_or(i);
            file.models.get(last).map_or(1, |m| m.weight)
        })
        .collect();
    let build = |name: &str, versions: &[WeightedVersion]| {
        let weights = version_weights(versions);
        let mut catalog = Catalog::new(
            cleaned.clone(),
            versions.iter().map(|v| v.version.clone()).collect(),
        );
        for (model, &model_weight) in model_weights.iter().enumerate() {
            for (version, &version_weight) in weights.iter().enumerate() {
                catalog.push(
                    model,
                    version,
                    weight_product(model_weight, version_weight)?,
                )?;
            }
        }
        catalog.finish(name)
    };
    Ok(DesktopCatalogs {
        windows: build("windows", &file.windows),
        linux: build("linux", &file.linux),
    })
}

fn build_mac() -> std::result::Result<Catalog, String> {
    let file: MacFile = parse("mac.json", MAC_JSON)?;
    let keys = file
        .versions
        .iter()
        .map(|v| version_key(&v.version))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let weights = version_weights(&file.versions);
    let mut catalog = Catalog::new(
        file.models.iter().map(|m| m.model.clone()).collect(),
        file.versions.iter().map(|v| v.version.clone()).collect(),
    );
    for (model, entry) in file.models.iter().enumerate() {
        let entry = last_with(&file.models, entry, |e| e.model.as_str());
        let minimum = version_key(&entry.min_macos)?;
        for (version, (key, &version_weight)) in keys.iter().zip(&weights).enumerate() {
            if *key >= minimum {
                catalog.push(
                    model,
                    version,
                    weight_product(entry.weight, version_weight)?,
                )?;
            }
        }
    }
    catalog.finish("mac")
}

fn build_ios() -> std::result::Result<Catalog, String> {
    let file: IosFile = parse("ios.json", IOS_JSON)?;
    let keys = file
        .versions
        .iter()
        .map(|v| version_key(&v.version))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let weights = version_weights(&file.versions);
    let mut catalog = Catalog::new(
        file.models.iter().map(|m| m.model.clone()).collect(),
        file.versions.iter().map(|v| v.version.clone()).collect(),
    );
    for (model, entry) in file.models.iter().enumerate() {
        let entry = last_with(&file.models, entry, |e| e.model.as_str());
        let minimum = version_key(&entry.min_ios)?;
        for (version, (key, &version_weight)) in keys.iter().zip(&weights).enumerate() {
            let name = file
                .versions
                .get(version)
                .map_or("", |v| v.version.as_str());
            // 1.5.0 `_model_gets_version`.
            let too_old = *key < minimum;
            let too_new = key.first().is_some_and(|&major| major > entry.max_major);
            let not_only = file
                .only
                .get(name)
                .is_some_and(|models| !models.contains(&entry.model));
            let excluded = file
                .except
                .get(name)
                .is_some_and(|models| models.contains(&entry.model));
            if !(too_old || too_new || not_only || excluded) {
                catalog.push(
                    model,
                    version,
                    weight_product(entry.weight, version_weight)?,
                )?;
            }
        }
    }
    catalog.finish("ios")
}

fn build_android() -> std::result::Result<Catalog, String> {
    let file: AndroidFile = parse("android.json", ANDROID_JSON)?;
    let sdk_versions: Vec<String> = ANDROID_SDKS.map(|sdk| format!("SDK {sdk}")).collect();
    let mut catalog = Catalog::new(
        file.devices
            .iter()
            .map(|d| format!("{}{}", d.manufacturer, d.model))
            .collect(),
        sdk_versions,
    );
    for (model, device) in file.devices.iter().enumerate() {
        // `entry.get("sdk_32") is True`: only the JSON literal `true` counts.
        let allow_12l =
            device.sdk_32 == Some(serde_json::Value::Bool(true)) || device.min_sdk == SDK_12L;
        for sdk in device.min_sdk..=device.max_sdk {
            if sdk == SDK_12L && !allow_12l {
                continue;
            }
            if !ANDROID_SDKS.contains(&sdk) {
                continue;
            }
            let version = usize::try_from(sdk - ANDROID_SDKS.start())
                .map_err(|_| format!("Android SDK {sdk} has no version slot"))?;
            catalog.push(model, version, device.weight)?;
        }
    }
    catalog.finish("android")
}

/// One browserforge browser of 1.5.0 `WebBrowserDevice.__gen__`.
struct WebBrowserConfig {
    /// The browserforge browser name.
    name: &'static str,
    /// The live major window, inclusive at both ends.
    min: u32,
    max: u32,
    /// The browserforge operating systems.
    os: &'static [&'static str],
    /// How many user agents are drawn; duplicates are skipped.
    count: usize,
    /// The prefixes whose major is shifted back up after a slide
    /// (1.5.0 `_UA_MAJOR_PATTERNS`).
    major_prefixes: &'static [&'static str],
}

/// The weight 1.5.0 `BROWSER_WEIGHTS.get(name, 1)` gives a browser.
fn web_browser_weight(name: &str) -> u64 {
    WEB_BROWSER_WEIGHTS
        .iter()
        .find(|(browser, _)| *browser == name)
        .map_or(1, |&(_, weight)| weight)
}

/// The major of a dotted version such as `155.0.0.0` or `150.0`.
fn major_of(browser: &str, version: &str) -> Result<u32> {
    version
        .split('.')
        .next()
        .and_then(|major| major.trim().parse().ok())
        .ok_or_else(|| {
            catalog_error(format!(
                "{browser} version {version:?} has no numeric major"
            ))
        })
}

/// One probing `generate()` call of a strict generator.
enum WebProbe {
    /// The generator drew headers.
    Drawn(HeaderGenerator),
    /// The dataset has no sample for the options (`NoHeaders`).
    Empty,
    /// Any other error, which drops the browser as 1.5.0's
    /// `except Exception` does.
    Failed,
}

/// A strict desktop generator for `config`'s browser and operating systems
/// with majors from `min` to `max` (unbounded when `None`), probed with one
/// `generate()` call whose headers are discarded, as 1.5.0 does. The
/// generator is strict, so no option is relaxed into another browser.
fn web_probe(config: &WebBrowserConfig, min: u32, max: Option<u32>, rng: &mut Rng) -> WebProbe {
    let options = HeaderOptions {
        browsers: vec![Browser {
            min_version: Some(min),
            max_version: max,
            ..Browser::new(config.name)
        }],
        os: config.os.iter().map(|&os| os.to_owned()).collect(),
        devices: vec!["desktop".to_owned()],
        strict: true,
        ..HeaderOptions::default()
    };
    let Ok(generator) = HeaderGenerator::new(options) else {
        return WebProbe::Failed;
    };
    match generator.generate(rng, &HeaderOverrides::default()) {
        Ok(_) => WebProbe::Drawn(generator),
        Err(BrowserError::NoHeaders) => WebProbe::Empty,
        Err(_) => WebProbe::Failed,
    }
}

/// How far the dataset trails `config`'s live window:
/// `max(0, config.max - newest)`, where `newest` is the newest major the
/// dataset has for the browser over HTTP/2 on `config`'s desktop operating
/// systems; `None` when that lag exceeds [`MAX_DATASET_LAG`] or the probe
/// fails.
///
/// `opentele2-browser` has no accessor for its helper data, so the lag is
/// the smallest offset at which a generator for majors of at least
/// `config.max - offset` draws. The search is exhaustive, so whether a draw
/// exists does not depend on the generator state; a fixed per-browser seed
/// keeps the probes off the pool's generator.
fn web_dataset_lag(config: &WebBrowserConfig) -> Option<u32> {
    let mut rng = Rng::from_seed(&format!("{WEB_POOL_SEED}/dataset-lag/{}", config.name));
    for offset in 0..=MAX_DATASET_LAG {
        let floor = config.max.checked_sub(offset)?;
        match web_probe(config, floor, None, &mut rng) {
            WebProbe::Drawn(_) => return Some(offset),
            WebProbe::Empty => {}
            WebProbe::Failed => return None,
        }
    }
    None
}

/// 1.5.0 `_header_generator`: a generator for the window slid down so its
/// top is the dataset's newest major, and that offset ([`web_dataset_lag`]).
/// The window keeps its full width, so once the caller shifts the drawn
/// majors back up by the offset the pool spans the whole live window
/// rather than collapsing onto the dataset's newest major: the intent
/// 1.5.0's `_header_generator` docstring states.
///
/// When even the slid window has no sample, this falls back to 1.5.0's
/// loop: the smallest offset (at most [`MAX_DATASET_LAG`]) at which the
/// window has a sample. Any error but `NoHeaders` drops the browser.
fn web_generator(config: &WebBrowserConfig, rng: &mut Rng) -> Option<(HeaderGenerator, u32)> {
    if let Some(offset) = web_dataset_lag(config)
        && let (Some(min), Some(max)) = (
            config.min.checked_sub(offset),
            config.max.checked_sub(offset),
        )
    {
        match web_probe(config, min, Some(max), rng) {
            WebProbe::Drawn(generator) => return Some((generator, offset)),
            WebProbe::Empty => {}
            WebProbe::Failed => return None,
        }
    }
    for offset in 0..=MAX_DATASET_LAG {
        let (Some(min), Some(max)) = (
            config.min.checked_sub(offset),
            config.max.checked_sub(offset),
        ) else {
            break;
        };
        match web_probe(config, min, Some(max), rng) {
            WebProbe::Drawn(generator) => return Some((generator, offset)),
            WebProbe::Empty => {}
            WebProbe::Failed => return None,
        }
    }
    None
}

/// 1.5.0 `_shift_ua_major`: every major following one of `prefixes` is
/// raised by `offset`, prefix by prefix, as `re.sub(r"(prefix)(\d+)")`.
fn shift_majors(user_agent: &str, prefixes: &[&str], offset: u32) -> String {
    let mut shifted = user_agent.to_owned();
    if offset == 0 {
        return shifted;
    }
    for prefix in prefixes {
        let mut out = String::with_capacity(shifted.len());
        let mut rest = shifted.as_str();
        while let Some(at) = rest.find(prefix) {
            let (head, tail) = rest.split_at(at + prefix.len());
            out.push_str(head);
            let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
            let (number, after) = tail.split_at(digits);
            match number.parse::<u64>() {
                Ok(major) => out.push_str(&major.saturating_add(u64::from(offset)).to_string()),
                Err(_) => out.push_str(number),
            }
            rest = after;
        }
        out.push_str(rest);
        shifted = out;
    }
    shifted
}

/// 1.5.0 `_parse_os_from_ua`: the platform name Web A sends.
fn web_a_system(user_agent: &str) -> &'static str {
    let ua = user_agent.to_lowercase();
    if ua.contains("windows") {
        "Windows"
    } else if ua.contains("macintosh") || ua.contains("mac os") {
        "macOS"
    } else if ua.contains("cros") {
        "ChromeOS"
    } else if ua.contains("linux") {
        "Linux"
    } else {
        "Windows"
    }
}

/// 1.5.0 `_parse_platform_from_ua`: the `navigator.platform` Web K sends.
fn web_k_system(user_agent: &str) -> &'static str {
    let ua = user_agent.to_lowercase();
    if ua.contains("win64") || ua.contains("windows") {
        "Win32"
    } else if ua.contains("macintosh") || ua.contains("mac os") {
        "MacIntel"
    } else if ua.contains("linux") {
        if ua.contains("x86_64") || ua.contains("x64") {
            "Linux x86_64"
        } else if ua.contains("aarch64") || ua.contains("arm") {
            "Linux aarch64"
        } else {
            "Linux x86_64"
        }
    } else {
        "Win32"
    }
}

/// 1.5.0 `WebBrowserDevice.__gen__` for live Chrome major `chrome` and
/// Firefox major `firefox`: the distinct user agents in generation order,
/// each with its browser's weight. Every draw comes from one generator
/// seeded by [`WEB_POOL_SEED`] and both majors, so the pool is a pure
/// function of them.
fn web_pool(chrome: u32, firefox: u32) -> std::result::Result<Vec<(String, u64)>, String> {
    let mut rng = Rng::from_seed(&format!(
        "{WEB_POOL_SEED}/chrome/{chrome}/firefox/{firefox}"
    ));
    // 1.5.0 `max_v - random.randint(2, 4)`.
    let spread = 2 + u32::try_from(rng.next_u64() % 3).unwrap_or(0);
    let chrome_min = chrome.saturating_sub(spread);
    let all_os: &[&str] = &["windows", "macos", "linux"];
    let configs = [
        WebBrowserConfig {
            name: "chrome",
            min: chrome_min,
            max: chrome,
            os: all_os,
            count: 60,
            major_prefixes: &["Chrome/"],
        },
        WebBrowserConfig {
            name: "edge",
            min: chrome_min.saturating_sub(2),
            max: chrome,
            os: &["windows", "macos"],
            count: 30,
            major_prefixes: &["Chrome/", "Edg/"],
        },
        WebBrowserConfig {
            name: "firefox",
            min: firefox.saturating_sub(3),
            max: firefox,
            os: all_os,
            count: 20,
            major_prefixes: &["rv:", "Firefox/"],
        },
    ];
    let overrides = HeaderOverrides::default();
    let mut seen = HashSet::new();
    let mut pool = Vec::new();
    for config in &configs {
        let weight = web_browser_weight(config.name);
        let Some((generator, offset)) = web_generator(config, &mut rng) else {
            continue;
        };
        for _ in 0..config.count {
            let headers = match generator.generate(&mut rng, &overrides) {
                Ok(headers) => headers,
                // 1.5.0 skips a draw that raises `ValueError`.
                Err(BrowserError::NoHeaders) => continue,
                Err(e) => return Err(format!("web pool {}: {e}", config.name)),
            };
            let Some(user_agent) = get_user_agent(&headers) else {
                continue;
            };
            let user_agent = shift_majors(user_agent, config.major_prefixes, offset);
            if seen.insert(user_agent.clone()) {
                pool.push((user_agent, weight));
            }
        }
    }
    if pool.is_empty() {
        pool.push((
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36"
            ),
            1,
        ));
    }
    Ok(pool)
}

/// The catalog of `pool` with `system` naming each user agent's platform;
/// the system versions are the distinct names in first-seen order.
fn web_pool_catalog(
    pool: &[(String, u64)],
    system: fn(&str) -> &'static str,
    name: &str,
) -> std::result::Result<Catalog, String> {
    let mut versions: Vec<String> = Vec::new();
    let mut slots = Vec::with_capacity(pool.len());
    for (model, (user_agent, weight)) in pool.iter().enumerate() {
        let platform = system(user_agent);
        let version = versions
            .iter()
            .position(|known| known == platform)
            .unwrap_or_else(|| {
                versions.push(platform.to_owned());
                versions.len() - 1
            });
        slots.push((model, version, *weight));
    }
    let mut catalog = Catalog::new(pool.iter().map(|(ua, _)| ua.clone()).collect(), versions);
    for (model, version, weight) in slots {
        catalog.push(model, version, weight)?;
    }
    catalog.finish(name)
}

/// The web catalog of `client` for `versions`: 1.5.0's browserforge pool of
/// up to 60 Chrome, 30 Edge and 20 Firefox desktop user agents weighted by
/// [`WEB_BROWSER_WEIGHTS`], drawn deterministically for the majors of
/// [`Versions::chrome_version`] and [`Versions::firefox_version`].
///
/// When the dataset trails a live major, the browser's window slides down
/// (by at most 24) until its top is the newest major the dataset has,
/// keeping its width, and the drawn majors are shifted back up, so the
/// spread is kept instead of collapsing to one major, as 1.5.0 intends.
/// Both clients hold the same user agents
/// in the same order and weights, with their own platform strings. Pools
/// are cached per client and pair of majors.
///
/// # Errors
///
/// [`Error::Io`] with [`std::io::ErrorKind::InvalidData`] when either
/// version has no numeric major or the browser dataset fails to generate.
pub fn web_catalog_for(client: WebClient, versions: &Versions) -> Result<Catalog> {
    /// A web client and the Chrome and Firefox majors of its pool.
    type WebKey = (WebClient, u32, u32);
    static CACHE: OnceLock<Mutex<HashMap<WebKey, Catalog>>> = OnceLock::new();

    let chrome = major_of("Chrome", &versions.chrome_version)?;
    let firefox = major_of("Firefox", &versions.firefox_version)?;
    let mut cache = CACHE
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(cached) = cache.get(&(client, chrome, firefox)) {
        return Ok(cached.clone());
    }
    let pool = web_pool(chrome, firefox).map_err(catalog_error)?;
    let a = web_pool_catalog(&pool, web_a_system, "web A").map_err(catalog_error)?;
    let k = web_pool_catalog(&pool, web_k_system, "web K").map_err(catalog_error)?;
    let wanted = match client {
        WebClient::A => a.clone(),
        WebClient::K => k.clone(),
    };
    cache.insert((WebClient::A, chrome, firefox), a);
    cache.insert((WebClient::K, chrome, firefox), k);
    Ok(wanted)
}

/// [`web_catalog_for`] of the [`Versions::offline`] majors, for [`catalog`].
fn offline_web_catalog(client: WebClient) -> std::result::Result<Catalog, String> {
    web_catalog_for(client, &Versions::offline()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{WebBrowserConfig, web_dataset_lag};

    const ALL_OS: &[&str] = &["windows", "macos", "linux"];

    fn config(
        name: &'static str,
        min: u32,
        max: u32,
        os: &'static [&'static str],
    ) -> WebBrowserConfig {
        WebBrowserConfig {
            name,
            min,
            max,
            os,
            count: 1,
            major_prefixes: &[],
        }
    }

    /// The dataset's newest HTTP/2 desktop majors are Chrome 149, Edge 148
    /// and Firefox 151; the lag is how far the window's top is above them.
    #[test]
    fn dataset_lag_is_the_distance_to_the_newest_major() {
        assert_eq!(
            web_dataset_lag(&config("chrome", 152, 155, ALL_OS)),
            Some(6)
        );
        assert_eq!(
            web_dataset_lag(&config("chrome", 146, 149, ALL_OS)),
            Some(0)
        );
        assert_eq!(
            web_dataset_lag(&config("chrome", 140, 143, ALL_OS)),
            Some(0)
        );
        let edge_os: &[&str] = &["windows", "macos"];
        assert_eq!(web_dataset_lag(&config("edge", 150, 155, edge_os)), Some(7));
        assert_eq!(web_dataset_lag(&config("edge", 143, 148, edge_os)), Some(0));
        assert_eq!(
            web_dataset_lag(&config("firefox", 147, 150, ALL_OS)),
            Some(0)
        );
        assert_eq!(
            web_dataset_lag(&config("firefox", 152, 155, ALL_OS)),
            Some(4)
        );
    }

    #[test]
    fn dataset_lag_beyond_the_limit_is_none() {
        assert_eq!(web_dataset_lag(&config("chrome", 200, 200, ALL_OS)), None);
    }
}
