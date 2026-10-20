//! Current official client and browser versions from the public release
//! feeds (opentele2-versions), fetched as an async task.
//!
//! A patch crosses the boundary as a plain object converted through the core
//! [`CorePatch::to_map`] and [`CorePatch::from_map`], its `snake_case` keys
//! in camelCase, so every core patch field reaches JavaScript without being
//! listed here.

use std::time::Duration;

use napi::ScopedTask;
use napi::bindgen_prelude::{AsyncTask, Env, Object};
use napi_derive::napi;
use serde_json::{Map, Value};

use opentele2_core::Error;
use opentele2_versions::{DEFAULT_TIMEOUT, VersionsPatch as CorePatch, fetch_all};

use crate::api::{PlatformVersions, Versions, versions};
use crate::error::{Result, core_error, invalid_arg, rejection};

/// The `PlatformVersions` fields the release feeds answered; a field no
/// source answered is absent.
// The TypeScript shape of the objects `fetchVersions` resolves with and
// `applyVersionsPatch` reads. The values never pass through this struct:
// they cross as maps keyed by the camelCase names of `CorePatch::FIELDS`.
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
    /// Stable Chrome version as its user agent reports it, `<major>.0.0.0`;
    /// applying it rebuilds `userAgent` too.
    pub chrome_version: Option<String>,
    /// Stable Firefox version as its user agent reports it, `<major>.0`.
    pub firefox_version: Option<String>,
}

/// The empty [`VersionsPatch`], named field by field, so the declaration
/// stays in step with the core: the literal stops compiling when a field is
/// added to the struct or removed from it, the assertion when the core's
/// field count moves, and `__test__/versions.test.mjs` checks every
/// declared key against the core.
const _: VersionsPatch = {
    assert!(
        CorePatch::FIELDS.len() == 12,
        "VersionsPatch must declare every core patch field"
    );
    VersionsPatch {
        desktop_app_version: None,
        android_app_version: None,
        android_app_version_code: None,
        android_x_app_version: None,
        ios_app_version: None,
        ios_build_number: None,
        macos_app_version: None,
        macos_build_number: None,
        web_k_version: None,
        web_a_version: None,
        chrome_version: None,
        firefox_version: None,
    }
};

/// `field`, a `snake_case` core patch field, in camelCase.
fn camel_case(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut upper = false;
    for ch in field.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            out.push(ch.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// The patch a JavaScript patch object holds. A key that names no core
/// field is ignored, as a napi object ignores extra properties; a `null`
/// value is an absent field; a wrongly typed value throws
/// `ERR_INVALID_ARG_VALUE` naming the camelCase key.
fn to_patch(object: Map<String, Value>) -> Result<CorePatch> {
    let mut patch = CorePatch::default();
    for (key, value) in object {
        let Some(field) = CorePatch::FIELDS
            .iter()
            .find(|field| camel_case(field) == key)
        else {
            continue;
        };
        let single = Map::from_iter([((*field).to_owned(), value)]);
        let answer = CorePatch::from_map(&single).map_err(|reason| {
            invalid_arg(reason.replace(&format!("`{field}`"), &format!("`{key}`")))
        })?;
        patch.merge(answer);
    }
    Ok(patch)
}

/// `patch` as a JavaScript object with camelCase keys, in field order; an
/// absent field is no key.
fn patch_object<'env>(env: &'env Env, patch: &CorePatch) -> napi::Result<Object<'env>> {
    let mut object = Object::new(env)?;
    for (field, value) in patch.to_map() {
        object.set(camel_case(&field), value)?;
    }
    Ok(object)
}

/// `fetch_all` off the JavaScript thread; no timeout is an invalid
/// `timeoutMs`, which rejects instead of fetching.
pub struct FetchTask {
    timeout: Option<Duration>,
}

#[napi]
impl<'task> ScopedTask<'task> for FetchTask {
    type Output = Option<CorePatch>;
    type JsValue = Object<'task>;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(self.timeout.map(fetch_all))
    }

    fn resolve(&mut self, env: &'task Env, output: Self::Output) -> napi::Result<Object<'task>> {
        match output {
            Some(patch) => patch_object(env, &patch),
            None => Err(rejection(
                *env,
                core_error(&Error::InvalidInput {
                    what: "timeoutMs",
                    reason: "must be a positive number of milliseconds".to_owned(),
                }),
            )),
        }
    }
}

/// Fetches the current versions from the nine sources of opentele2-versions
/// (Telegram Desktop, Android, Telegram X, iOS, macOS, Web K, Web A, Chrome,
/// Firefox) in parallel. `timeoutMs` bounds each HTTP request, 10000 by
/// default; a `timeoutMs` that is not a positive number rejects with
/// `OT_INVALID_INPUT`. Never rejects for the network: a source that fails
/// or times out leaves its fields absent, and with no network the patch is
/// empty.
#[napi(ts_return_type = "Promise<VersionsPatch>")]
pub fn fetch_versions(timeout_ms: Option<f64>) -> AsyncTask<FetchTask> {
    let timeout = timeout_ms.map_or(Some(DEFAULT_TIMEOUT), |ms| {
        // NaN, an infinity and a negative number fail the conversion.
        Duration::try_from_secs_f64(ms / 1000.0)
            .ok()
            .filter(|timeout| !timeout.is_zero())
    });
    AsyncTask::new(FetchTask { timeout })
}

/// `versions` (overrides of the offline `PlatformVersions`, a full
/// `PlatformVersions` included) with every field `patch` sets written onto
/// it, as 1.5.0 `_apply_fetched_versions`: each field lands on the field of
/// the same name, except `desktopAppVersion`, which stays bound to the
/// tdata version, and `chromeVersion`, which rebuilds `userAgent` too. A
/// wrongly typed patch value throws `ERR_INVALID_ARG_VALUE`.
#[napi]
pub fn apply_versions_patch(
    versions: Option<Versions>,
    #[napi(ts_arg_type = "VersionsPatch")] patch: Map<String, Value>,
) -> Result<PlatformVersions> {
    let mut versions = self::versions(versions);
    to_patch(patch)?.apply(&mut versions);
    Ok(versions.into())
}
