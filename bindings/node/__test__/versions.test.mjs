// versions.test.mjs: PlatformVersions, LAYER, applyVersionsPatch and
// fetchVersions against crates/opentele2-core/tests/api.rs and
// crates/opentele2-versions/tests/patch.rs. The network is only touched by
// the live test, which runs with OPENTELE2_LIVE=1.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { core } from './helpers.mjs'

const WEB_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36'

const OFFLINE = {
  androidAppVersion: '13.0.3',
  androidAppVersionCode: 7183,
  androidSdkRange: [29, 37],
  androidLatestSdk: 37,
  iosAppVersion: '13.0',
  iosBuildNumber: 35303,
  iosVersionRange: ['18.0', '27.0.1'],
  iosSystemVersion: '27.0.1',
  macosSystemVersion: '27.0.1',
  desktopAppVersion: '7.3.1',
  desktopAppVersionSuffix: 'x64',
  macosAppVersion: '13.0',
  macosBuildNumber: 283305,
  androidXAppVersion: '0.29.1.1817',
  webAVersion: '12.0.47 A',
  webKVersion: '2.2 K',
  chromeVersion: '155.0.0.0',
  userAgent: WEB_USER_AGENT,
}

const FULL_PATCH = {
  desktopAppVersion: '9.9.9',
  androidAppVersion: '14.1.2',
  androidAppVersionCode: 7300,
  androidXAppVersion: '0.30.0.1900',
  iosAppVersion: '14.1',
  iosBuildNumber: 36000,
  macosAppVersion: '14.2',
  macosBuildNumber: 290001,
  webKVersion: '2.3 K',
  webAVersion: '12.1.0 A',
}

test('platformVersions holds every offline field, and LAYER is 230', () => {
  assert.deepEqual(core.platformVersions(), OFFLINE)
  assert.equal(core.LAYER, 230)
  const custom = core.platformVersions({
    androidSdkRange: [21, 40],
    iosVersionRange: ['17.0', '28.0'],
    androidLatestSdk: 40,
    chromeVersion: '160.0.0.0',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/160.0.0.0',
  })
  assert.deepEqual(custom, {
    ...OFFLINE,
    androidSdkRange: [21, 40],
    iosVersionRange: ['17.0', '28.0'],
    androidLatestSdk: 40,
    chromeVersion: '160.0.0.0',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/160.0.0.0',
  })
  // A full PlatformVersions is a valid override set.
  assert.deepEqual(core.platformVersions(custom), custom)
  // The new fields reach the profiles: the web device is the user agent.
  assert.equal(core.profile('TelegramWeb_A', custom).deviceModel, custom.userAgent)
})

test('applyVersionsPatch maps every fetched field but the desktop version', () => {
  const applied = core.applyVersionsPatch(null, FULL_PATCH)
  const { desktopAppVersion, ...applicable } = FULL_PATCH
  assert.deepEqual(applied, { ...OFFLINE, ...applicable })
  assert.equal(desktopAppVersion, '9.9.9')
  assert.equal(applied.desktopAppVersion, '7.3.1')

  assert.deepEqual(core.applyVersionsPatch(undefined, {}), OFFLINE)
  const ios = core.applyVersionsPatch(OFFLINE, { iosAppVersion: '14.1' })
  assert.deepEqual(ios, { ...OFFLINE, iosAppVersion: '14.1' })
  // Overrides are applied before the patch, which wins.
  const both = core.applyVersionsPatch({ iosAppVersion: '12.0', iosBuildNumber: 1 }, { iosAppVersion: '14.1' })
  assert.equal(both.iosAppVersion, '14.1')
  assert.equal(both.iosBuildNumber, 1)
})

test('fetchVersions is typed as a Promise-returning async task', () => {
  assert.equal(typeof core.fetchVersions, 'function')
  const typings = readFileSync(new URL('../index.d.ts', import.meta.url), 'utf8')
  assert.match(
    typings,
    /export declare function fetchVersions\(timeoutMs\?: number \| undefined \| null\): Promise<VersionsPatch>/,
  )
})

test('fetchVersions returns current versions', { skip: process.env.OPENTELE2_LIVE !== '1' && 'needs the network; set OPENTELE2_LIVE=1' }, async () => {
  const pending = core.fetchVersions(10000)
  assert.ok(pending instanceof Promise)
  const patch = await pending
  assert.ok(Object.keys(patch).length > 0, 'no source answered')
  for (const value of Object.values(patch)) {
    assert.notEqual(value, '')
  }
  if (patch.webKVersion !== undefined) assert.match(patch.webKVersion, / K$/)
  if (patch.webAVersion !== undefined) assert.match(patch.webAVersion, / A$/)
  assert.equal(core.applyVersionsPatch(null, patch).desktopAppVersion, OFFLINE.desktopAppVersion)
})
