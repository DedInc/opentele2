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
//! The web catalog (`web.json`) replaces 1.5.0's browserforge fingerprints
//! with a curated list of browser releases; its devices are picked with the
//! same seed hash and cumulative weights as every other catalog.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;
use sha1::{Digest, Sha1};

use crate::{Error, Result};

const ANDROID_JSON: &str = include_str!("../data/devices/android.json");
const DESKTOP_JSON: &str = include_str!("../data/devices/desktop.json");
const IOS_JSON: &str = include_str!("../data/devices/ios.json");
const MAC_JSON: &str = include_str!("../data/devices/mac.json");
const WEB_JSON: &str = include_str!("../data/devices/web.json");

/// The only `web.json` schema this parser understands.
const WEB_SCHEMA: u64 = 1;

/// The placeholder a `web.json` user agent template carries for the version.
const WEB_VERSION_PLACEHOLDER: &str = "{version}";

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

/// A Telegram web client. Both share one browser catalog, so a seed picks the
/// same user agent for either; they differ in the platform string they send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebClient {
    /// Telegram Web A, which sends a platform name: `Windows`, `macOS` or
    /// `Linux` (1.5.0 variant `z`).
    A,
    /// Telegram Web K and Webogram, which send `navigator.platform`: `Win32`,
    /// `MacIntel` or `Linux x86_64` (1.5.0 variant `k`).
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
/// browserforge browser, in its order. The web catalog weighs its user
/// agents by the shares `web.json` cites instead; these are kept for
/// bindings that expose the 1.5.0 attribute.
pub const WEB_BROWSER_WEIGHTS: [(&str, u64); 3] = [("chrome", 19), ("edge", 2), ("firefox", 1)];

#[derive(Debug)]
struct Slot {
    model: usize,
    version: usize,
    weight: u64,
}

/// The weighted pairs of one platform, in 1.5.0's list order.
#[derive(Debug)]
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
    getrandom::fill(&mut bytes).map_err(|e| Error::Io(std::io::Error::other(e)))?;
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
    let catalog = catalog(platform)?;
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
/// share one catalog; the [`Platform::Web`] catalogs hold the same user
/// agents in the same order and weights, with each client's platform string.
///
/// # Errors
///
/// [`Error::Io`] when the embedded catalog is malformed or empty after
/// filtering.
pub fn catalog(platform: Platform) -> Result<&'static Catalog> {
    static DESKTOP: OnceLock<std::result::Result<DesktopCatalogs, String>> = OnceLock::new();
    static MAC: OnceLock<std::result::Result<Catalog, String>> = OnceLock::new();
    static ANDROID: OnceLock<std::result::Result<Catalog, String>> = OnceLock::new();
    static IOS: OnceLock<std::result::Result<Catalog, String>> = OnceLock::new();
    static WEB: OnceLock<std::result::Result<WebCatalogs, String>> = OnceLock::new();

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
        Platform::Web { client } => {
            let web = WEB
                .get_or_init(|| build_web(WEB_JSON))
                .as_ref()
                .map_err(|message| catalog_error(message.clone()))?;
            return Ok(web.get(client));
        }
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

/// The web catalog of `client` built from the text of a `web.json`; the
/// embedded one is what [`catalog`] returns for [`Platform::Web`].
///
/// # Errors
///
/// [`Error::Io`] with [`std::io::ErrorKind::InvalidData`] when `text` is not
/// a `web.json` of schema 1, cites no sources, references an unknown OS, has
/// a template without `{version}`, or yields no weighted entry.
pub fn web_catalog(text: &str, client: WebClient) -> Result<Catalog> {
    let built = build_web(text).map_err(catalog_error)?;
    Ok(match client {
        WebClient::A => built.a,
        WebClient::K => built.k,
    })
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

#[derive(Deserialize)]
struct WebSchema {
    schema: u64,
}

#[derive(Deserialize)]
struct WebSource {
    url: String,
    accessed: String,
}

#[derive(Deserialize)]
struct WebPlatform {
    os: String,
    share_bp: u64,
    web_a: String,
    web_k: String,
}

#[derive(Deserialize)]
struct WebUserAgent {
    os: String,
    template: String,
}

#[derive(Deserialize)]
struct WebBrowser {
    browser: String,
    version: String,
    share_bp: u64,
    user_agents: Vec<WebUserAgent>,
}

#[derive(Deserialize)]
struct WebFile {
    sources: Vec<WebSource>,
    platforms: Vec<WebPlatform>,
    browsers: Vec<WebBrowser>,
}

struct WebCatalogs {
    a: Catalog,
    k: Catalog,
}

impl WebCatalogs {
    fn get(&self, client: WebClient) -> &Catalog {
        match client {
            WebClient::A => &self.a,
            WebClient::K => &self.k,
        }
    }
}

/// `round(share * os_share / os_total)`, halves rounded up: a browser's
/// cited share split by the desktop share of the OSes it lists.
fn web_weight(share: u64, os_share: u64, os_total: u64) -> std::result::Result<u64, String> {
    if os_total == 0 {
        return Err("web browser lists only OSes with a zero share".to_owned());
    }
    let total = u128::from(os_total);
    let weight = (u128::from(share) * u128::from(os_share) + total / 2) / total;
    u64::try_from(weight).map_err(|_| "web device weight overflows u64".to_owned())
}

fn build_web(text: &str) -> std::result::Result<WebCatalogs, String> {
    // The schema is read on its own first, so a future schema with other
    // fields is reported as unknown rather than as malformed.
    let WebSchema { schema } = parse("web.json", text)?;
    if schema != WEB_SCHEMA {
        return Err(format!(
            "device catalog web.json has unknown schema {schema}"
        ));
    }
    let file: WebFile = parse("web.json", text)?;
    let cited = !file.sources.is_empty()
        && file
            .sources
            .iter()
            .all(|source| source.url.starts_with("https://") && !source.accessed.is_empty());
    if !cited {
        return Err("device catalog web.json must cite https sources with access dates".to_owned());
    }
    let mut models = Vec::new();
    let mut slots = Vec::new();
    for browser in &file.browsers {
        let mut platforms = Vec::with_capacity(browser.user_agents.len());
        for agent in &browser.user_agents {
            let index = file
                .platforms
                .iter()
                .position(|platform| platform.os == agent.os)
                .ok_or_else(|| {
                    format!(
                        "web browser {} lists unknown OS {:?}",
                        browser.browser, agent.os
                    )
                })?;
            if !agent.template.contains(WEB_VERSION_PLACEHOLDER) {
                return Err(format!(
                    "web browser {} template for {} has no {WEB_VERSION_PLACEHOLDER}",
                    browser.browser, agent.os
                ));
            }
            platforms.push(index);
        }
        let os_total = platforms.iter().try_fold(0u64, |sum, &index| {
            file.platforms
                .get(index)
                .and_then(|platform| sum.checked_add(platform.share_bp))
                .ok_or_else(|| "web OS shares overflow u64".to_owned())
        })?;
        for (agent, &index) in browser.user_agents.iter().zip(&platforms) {
            let os_share = file.platforms.get(index).map_or(0, |p| p.share_bp);
            let weight = web_weight(browser.share_bp, os_share, os_total)?;
            slots.push((models.len(), index, weight));
            models.push(
                agent
                    .template
                    .replace(WEB_VERSION_PLACEHOLDER, &browser.version),
            );
        }
    }
    let build = |name: &str, version: fn(&WebPlatform) -> &String| {
        let mut catalog = Catalog::new(
            models.clone(),
            file.platforms.iter().map(|p| version(p).clone()).collect(),
        );
        for &(model, platform, weight) in &slots {
            catalog.push(model, platform, weight)?;
        }
        catalog.finish(name)
    };
    Ok(WebCatalogs {
        a: build("web A", |platform| &platform.web_a)?,
        k: build("web K", |platform| &platform.web_k)?,
    })
}
