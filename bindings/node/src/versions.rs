//! Current official client versions from the public release feeds
//! (opentele2-versions), fetched as an async task.

use std::time::Duration;

use napi::Task;
use napi::bindgen_prelude::{AsyncTask, Env};
use napi_derive::napi;

use opentele2_versions::{DEFAULT_TIMEOUT, VersionsPatch as CorePatch, fetch_all};

use crate::api::{PlatformVersions, Versions, versions};

/// The `PlatformVersions` fields the release feeds answered; a field no
/// source answered is absent.
#[napi(object)]
pub struct VersionsPatch {
    /// Latest Telegram Desktop release. Reported but never applied: the
    /// desktop version is bound to the version written into tdata.
    pub desktop_app_version: Option<String>,
    /// Telegram Android version.
    pub android_app_version: Option<String>,
    /// Telegram Android version code.
    pub android_app_version_code: Option<u32>,
    /// Telegram X version.
    pub android_x_app_version: Option<String>,
    /// Telegram iOS version.
    pub ios_app_version: Option<String>,
    /// Telegram iOS build number.
    pub ios_build_number: Option<u32>,
    /// Telegram for macOS version.
    pub macos_app_version: Option<String>,
    /// Telegram for macOS build number.
    pub macos_build_number: Option<u32>,
    /// Telegram Web K version, with its ` K` suffix.
    pub web_k_version: Option<String>,
    /// Telegram Web A version, with its ` A` suffix.
    pub web_a_version: Option<String>,
}

impl From<CorePatch> for VersionsPatch {
    fn from(patch: CorePatch) -> Self {
        Self {
            desktop_app_version: patch.desktop_app_version,
            android_app_version: patch.android_app_version,
            android_app_version_code: patch.android_app_version_code,
            android_x_app_version: patch.android_x_app_version,
            ios_app_version: patch.ios_app_version,
            ios_build_number: patch.ios_build_number,
            macos_app_version: patch.macos_app_version,
            macos_build_number: patch.macos_build_number,
            web_k_version: patch.web_k_version,
            web_a_version: patch.web_a_version,
        }
    }
}

impl From<VersionsPatch> for CorePatch {
    fn from(patch: VersionsPatch) -> Self {
        Self {
            desktop_app_version: patch.desktop_app_version,
            android_app_version: patch.android_app_version,
            android_app_version_code: patch.android_app_version_code,
            android_x_app_version: patch.android_x_app_version,
            ios_app_version: patch.ios_app_version,
            ios_build_number: patch.ios_build_number,
            macos_app_version: patch.macos_app_version,
            macos_build_number: patch.macos_build_number,
            web_k_version: patch.web_k_version,
            web_a_version: patch.web_a_version,
            ..CorePatch::default()
        }
    }
}

/// `fetch_all` off the JavaScript thread.
pub struct FetchTask {
    timeout: Duration,
}

#[napi]
impl Task for FetchTask {
    type Output = CorePatch;
    type JsValue = VersionsPatch;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(fetch_all(self.timeout))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<VersionsPatch> {
        Ok(output.into())
    }
}

/// Fetches the current versions from the seven release feeds of 1.5.0
/// `version_fetcher.py` (Telegram Desktop, Android, Telegram X, iOS, macOS,
/// Web K, Web A) in parallel. `timeoutMs` bounds each HTTP request, 10000
/// by default. Never rejects: a source that fails or times out leaves its
/// fields absent, and with no network the patch is empty.
#[napi]
pub fn fetch_versions(timeout_ms: Option<u32>) -> AsyncTask<FetchTask> {
    let timeout = timeout_ms.map_or(DEFAULT_TIMEOUT, |ms| Duration::from_millis(ms.into()));
    AsyncTask::new(FetchTask { timeout })
}

/// `versions` (overrides of the offline `PlatformVersions`, a full
/// `PlatformVersions` included) with every field `patch` sets written onto
/// it, as 1.5.0 `_apply_fetched_versions`: each field lands on the field of
/// the same name, except `desktopAppVersion`, which stays bound to the
/// tdata version.
#[napi]
pub fn apply_versions_patch(versions: Option<Versions>, patch: VersionsPatch) -> PlatformVersions {
    let mut versions = self::versions(versions);
    CorePatch::from(patch).apply(&mut versions);
    versions.into()
}
