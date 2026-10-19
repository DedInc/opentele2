// fingerprint.test.mjs: tzOffset, validateInitParams, checkVersions, the
// fingerprint config and the msg id helpers against the 1.5.0 values of
// crates/opentele2-core/tests/fingerprint.rs.

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { core, thrown } from './helpers.mjs'

const PACKS = "Expected one of: ['', 'android', 'ios', 'macos', 'tdesktop']"
const ANDROID_MAJOR = "Android app_version '12.3.0' major does not match latest known '13.0.3'"

const profileOf = (apiId, deviceModel, systemVersion, appVersion, systemLangCode, langPack, langCode) => ({
  apiId,
  apiHash: '',
  deviceModel,
  systemVersion,
  appVersion,
  langCode,
  systemLangCode,
  langPack,
})

/** The Android base case of 1.5.0 tests/test_fingerprints.py. */
const android = (edits = {}) => ({
  ...profileOf(6, 'Samsung SM-S928B', 'SDK 35', '12.3.0', 'en-US', 'android', 'en'),
  ...edits,
})

const messages = (issues) => issues.map((issue) => issue.message)
const unknown = (pack) => `lang_pack '${pack}' is not a known official value. ${PACKS}`

function check(label, profile, loose, strict) {
  for (const [mode, severity] of [
    ['off', 'note'],
    ['warn', 'warning'],
  ]) {
    const issues = core.validateInitParams(profile, null, mode)
    assert.deepEqual(messages(issues), loose, `${label} ${mode}`)
    assert.ok(issues.every((issue) => issue.severity === severity), `${label} ${mode} severity`)
  }
  const issues = core.validateInitParams(profile, null, 'strict')
  assert.deepEqual(messages(issues), strict, `${label} strict`)
  assert.ok(issues.every((issue) => issue.severity === 'error'), `${label} strict severity`)
}

test('tzOffset matches 1.5.0 for fixed offsets and odd zones', () => {
  const cases = [
    [18000, 18000],
    [19800, 19800],
    [20700, 20700],
    [-12600, -12600],
    [50400, 50400],
    [-43200, -43200],
    [0, 0],
    [450, 900],
    [-450, -900],
    [420, 0],
    [449, 0],
    [-449, 0],
    [451, 900],
    [1350, 1800],
    [-1350, -1800],
    [50401, -36000],
    [54000, -32400],
    [86399, 0],
    [-43201, 43200],
    [-86399, 0],
    [-50400, 36000],
    [45900, 45900],
    [-2670, -2700],
    [37800, 37800],
    [-34200, -34200],
  ]
  for (const [offset, expected] of cases) {
    assert.ok(Object.is(core.tzOffset(offset), expected), `offset ${offset}`)
  }
  // 1.5.0: sum(int(tdesktop_tz_offset(at(s))) // 900 * (s + 86400)).
  let total = 0n
  for (let offset = -86399; offset < 86400; offset++) {
    total += BigInt(Math.floor(core.tzOffset(offset) / 900)) * BigInt(offset + 86400)
  }
  assert.equal(total, 32358124800n)
  for (const offset of [-(2 ** 31), 2 ** 31 - 1, -1000000, 1000000]) {
    assert.equal(core.tzOffset(offset), core.tzOffset(offset % 86400), `${offset}`)
  }
})

test('validateInitParams matches 1.5.0 for its own test cases', () => {
  check('android_ok', android(), [], [ANDROID_MAJOR])
  check(
    'desktop_ok',
    profileOf(2040, 'Desktop', 'Windows 11', '5.12.3 x64', 'en-US', 'tdesktop', 'en'),
    [],
    ["Desktop app_version '5.12.3 x64' major does not match latest known '7.3.1'"],
  )
  check('web_ok', profileOf(2496, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Windows', '5.0.0 Z', 'en-US', '', 'en'), [], [])
  check('empty_device', android({ deviceModel: '' }), ['device_model is empty'], ['device_model is empty', ANDROID_MAJOR])
  const allEmpty = [
    unknown('invalid'),
    "lang_code '' looks invalid (too short)",
    'device_model is empty',
    'system_version is empty',
    'app_version is empty',
  ]
  check('all_empty', profileOf(6, '', '', '', '', 'invalid', ''), allEmpty, allEmpty)
  const short = "lang_code 'x' looks invalid (too short)"
  check('short_lang', android({ langCode: 'x' }), [short], [short, ANDROID_MAJOR])
  const oneChar = "lang_code 'é' looks invalid (too short)"
  check('one_char_lang', android({ langCode: 'é' }), [oneChar], [oneChar, ANDROID_MAJOR])
  check('two_char_lang', android({ langCode: 'éé' }), [], [ANDROID_MAJOR])
  check('api_mismatch', android({ apiId: 99999 }), [], [
    "api_id 99999 does not match lang_pack 'android' (expected 6)",
    ANDROID_MAJOR,
  ])
  const region = "system_lang_code 'en' should include a region code (e.g. 'en-US') for android clients"
  check('no_region_android', android({ systemLangCode: 'en' }), [region], [region, ANDROID_MAJOR])
  check('no_region_desktop', profileOf(2040, 'Desktop', 'Windows 11', '7.3.1 x64', 'en', 'tdesktop', 'en'), [], [])
  check('ios_wrong_id', profileOf(6, 'Samsung SM-S928B', '27.0.1', '13.0', 'en-US', 'ios', 'en'), [], [
    "api_id 6 does not match lang_pack 'ios' (expected 10840)",
  ])
  check('macos_old', profileOf(2834, 'MacBook Air', 'macOS 27.0.1', '12.9', 'en-US', 'macos', 'en'), [], [
    "macOS app_version '12.9' major does not match latest known '13.0'",
  ])
  check('startswith_quirk', android({ appVersion: '130.0' }), [], [])
  check('android_current', android({ appVersion: '13.0.3', systemVersion: 'SDK 37' }), [], [])

  const kinds = core
    .validateInitParams(profileOf(1, '', '', '', 'en', 'ios', 'x'), undefined, 'strict')
    .map((issue) => issue.kind)
  assert.deepEqual(kinds, [
    'ShortLangCode',
    'MissingRegion',
    'EmptyDeviceModel',
    'EmptySystemVersion',
    'EmptyAppVersion',
    'ApiIdMismatch',
    'AppVersionMajor',
  ])
  // The default mode is 'warn'.
  assert.deepEqual(core.validateInitParams(android({ deviceModel: '' })), core.validateInitParams(android({ deviceModel: '' }), null, 'warn'))
  assert.equal(thrown(() => core.validateInitParams(android(), null, 'WARN')).code, 'ERR_INVALID_ARG_VALUE')
})

test('checkVersions reads Android SDK levels as 1.5.0 does and follows the versions', () => {
  const sdk = (level, range = '[29, 37]') => `Android SDK ${level} is outside the expected range ${range}`
  const cases = [
    ['SDK 29', null],
    ['SDK 37', null],
    ['SDK 28', '28'],
    ['SDK 38', '38'],
    ['SDK35', null],
    ['SDK -5', '-5'],
    ['SDK 3_8', '38'],
    ['SDK 3__8', null],
    ['SDK ٣٨', '38'],
    ['SDK \u001c40', null],
    ['SDK -0', '0'],
    [`SDK ${'9'.repeat(30)}`, '9'.repeat(30)],
    [`SDK ${'9'.repeat(4301)}`, null],
    ['14 (40)', '40'],
    ['15.0(40)', '40'],
    ['15.0.1 (40)', null],
    ['14 (40)\n', '40'],
    ['14 (40)\n\n', null],
    ['14\u001c(40)', '40'],
    ['14 (４０)', '40'],
    ['sdk 40', null],
  ]
  for (const [systemVersion, level] of cases) {
    const profile = android({ appVersion: '13.0.3', systemVersion })
    const issues = core.checkVersions(profile)
    assert.deepEqual(messages(issues), level === null ? [] : [sdk(level)], JSON.stringify(systemVersion))
    assert.ok(issues.every((issue) => issue.kind === 'AndroidSdkRange' && issue.severity === 'error'))
  }
  const versions = { androidAppVersion: '12.9', androidSdkRange: [21, 40] }
  assert.deepEqual(core.checkVersions(android({ systemVersion: 'SDK 40' }), versions), [])
  assert.deepEqual(messages(core.checkVersions(android({ systemVersion: 'SDK 41' }), versions)), [sdk(41, '[21, 40]')])
})

test('fingerprintConfig has the 1.5.0 defaults and validates as 1.5.0', () => {
  const config = core.fingerprintConfig({ msgIdOffset: 0x1234 })
  assert.deepEqual(config, {
    strictMode: 'warn',
    autoValidate: true,
    preferredTransport: 'obfuscated',
    warnOnLayerMismatch: true,
    randomizeMsgIdOffset: true,
    msgIdOffset: 0x1234,
  })
  assert.equal(core.effectiveLayer(config), core.LAYER)
  assert.equal(core.effectiveLayer({ ...config, layerOverride: 201 }), 201)
  assert.equal(core.fingerprintConfig({ layerOverride: 201 }).layerOverride, 201)
  const drawn = core.fingerprintConfig().msgIdOffset
  assert.ok(Number.isInteger(drawn) && drawn >= 0 && drawn <= 0xffff)
  assert.equal(thrown(() => core.fingerprintConfig({ msgIdOffset: 0x10000 })).code, 'ERR_INVALID_ARG_VALUE')
  assert.equal(thrown(() => core.fingerprintConfig({ strictMode: 'loud' })).code, 'ERR_INVALID_ARG_VALUE')

  const profile = android({ apiId: 1, deviceModel: '' })
  for (const [strictMode, autoValidate] of [
    ['off', true],
    ['off', false],
    ['warn', false],
    ['strict', false],
  ]) {
    const quiet = core.fingerprintConfig({ strictMode, autoValidate, msgIdOffset: 0 })
    assert.deepEqual(core.validateFingerprint(quiet, profile), [], `${strictMode} ${autoValidate}`)
  }
  const warned = core.validateFingerprint(core.fingerprintConfig({ msgIdOffset: 0 }), profile)
  assert.ok(warned.every((issue) => issue.severity === 'warning'))
  assert.equal(core.issuesMessage(warned), 'initConnection fingerprint issues:\n  - device_model is empty')
  const raised = core.validateFingerprint(core.fingerprintConfig({ strictMode: 'strict', msgIdOffset: 0 }), profile)
  assert.ok(raised.every((issue) => issue.severity === 'error'))
  assert.equal(
    core.issuesMessage(raised),
    "initConnection fingerprint issues:\n  - device_model is empty\n  - api_id 1 does not match lang_pack 'android' (expected 6)\n  - Android app_version '12.3.0' major does not match latest known '13.0.3'",
  )
  assert.equal(core.issuesMessage([]), 'initConnection fingerprint issues:')
  assert.equal(thrown(() => core.issuesMessage([{ kind: 'Nope', severity: 'note', message: 'x' }])).code, 'ERR_INVALID_ARG_VALUE')
})

test('msgIdOffset and isValidMsgId match 1.5.0', () => {
  for (let n = 0; n < 32; n++) {
    const offset = core.msgIdOffset()
    assert.ok(Number.isInteger(offset) && offset >= 0 && offset <= 0xffff)
  }
  const NOW = 1760000000
  const cases = [
    [7559142440960000001n, true, true],
    [7559142440960000001n, false, false],
    [7559142440960000000n, true, false],
    [7559142440960000000n, false, true],
    [7559143725155221505n, true, true],
    [7559143729450188801n, true, false],
    [7559141156764778497n, true, true],
    [7559141152469811201n, true, false],
    [7559143729450188799n, true, true],
    [7559141156764778495n, true, false],
    [0n, true, false],
    [0n, false, false],
    [-1n, true, false],
    [-2n, false, false],
    [1n, true, false],
    [2n ** 63n - 1n, true, false],
    [7559142440960000004n, false, true],
  ]
  for (const [msgId, fromClient, expected] of cases) {
    assert.equal(core.isValidMsgId(msgId, fromClient, NOW), expected, `${msgId} ${fromClient}`)
    // time.time() == NOW + 0.9: the fraction is dropped.
    assert.equal(core.isValidMsgId(msgId, fromClient, NOW + 0.9), expected, `${msgId} ${fromClient} +0.9`)
  }
  assert.equal(core.isValidMsgId(1, true, NOW), false)
  assert.equal(thrown(() => core.isValidMsgId(2n ** 63n, true, NOW)).code, 'ERR_INVALID_ARG_VALUE')
  assert.equal(thrown(() => core.isValidMsgId(2 ** 53, true, NOW)).code, 'ERR_INVALID_ARG_VALUE')
})
