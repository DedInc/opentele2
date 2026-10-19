// api.test.mjs: profile and generate against devices.json.

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { CLIENTS, PROFILE_FIELDS, core, loadJson, thrown } from './helpers.mjs'

const fields = (profile) => Object.keys(profile).sort()

test('generate matches a sample of the device vectors', () => {
  const cases = loadJson('devices.json').cases
  assert.equal(cases.length, 2800)
  const sample = cases.filter((_, n) => n % 10 === 0)
  assert.ok(sample.length >= 200)
  assert.deepEqual(new Set(sample.map((c) => c.seed_kind)), new Set(['str', 'int']))
  sample.forEach((c, n) => {
    // An int seed arrives as a bigint when a number cannot hold it.
    const seed = c.seed_kind === 'int' ? BigInt(c.seed) : c.seed
    const profile = core.generate(c.entry_point, seed, c.system)
    assert.deepEqual(fields(profile), PROFILE_FIELDS)
    for (const [field, key] of [
      ['deviceModel', 'device_model'],
      ['systemVersion', 'system_version'],
      ['appVersion', 'app_version'],
      ['langPack', 'lang_pack'],
      ['systemLangCode', 'system_lang_code'],
    ]) {
      assert.equal(profile[field], c[key], `case ${n} ${field}`)
    }
    if (c.seed_kind === 'int' && Number.isSafeInteger(Number(c.seed))) {
      assert.deepEqual(core.generate(c.entry_point, Number(c.seed), c.system), profile, `case ${n} number`)
    }
  })
})

test('profiles of every client, overrides and errors', () => {
  for (const client of CLIENTS) {
    const profile = core.profile(client)
    assert.deepEqual(fields(profile), PROFILE_FIELDS)
    assert.equal(profile.langCode, 'en')
  }
  const desktop = core.profile('TelegramDesktop')
  assert.equal(desktop.apiId, 2040)
  assert.equal(desktop.langPack, 'tdesktop')

  const android = core.profile('TelegramAndroid', { androidAppVersion: '1.2.3', androidAppVersionCode: 9 })
  assert.equal(android.appVersion, '1.2.3 (9)')
  const linux = core.generate('TelegramDesktop', 'opentele2', 'linux')
  assert.equal(linux.appVersion, desktop.appVersion.split(' ')[0])
  const ios = core.generate('TelegramIOS', '7')
  assert.deepEqual(core.generate('TelegramIOS', 7), ios)
  assert.deepEqual(core.generate('TelegramIOS', 7n), ios)
  assert.deepEqual(core.generate('TelegramIOS', -0), core.generate('TelegramIOS', '0'))
  assert.deepEqual(fields(core.generate('TelegramAndroid')), PROFILE_FIELDS)

  assert.equal(thrown(() => core.generate('TelegramWeb_A', 'x')).code, 'OT_IO')
  assert.equal(thrown(() => core.profile('Telegram')).code, 'ERR_INVALID_ARG_VALUE')
  assert.match(thrown(() => core.profile('Telegram')).message, /unknown client/)
  assert.equal(thrown(() => core.generate('TelegramIOS', null, 'linux')).code, 'ERR_INVALID_ARG_VALUE')
  assert.equal(thrown(() => core.generate('TelegramIOS', 1.5)).code, 'ERR_INVALID_ARG_VALUE')
  assert.equal(thrown(() => core.generate('TelegramIOS', 2 ** 53)).code, 'ERR_INVALID_ARG_VALUE')
})
