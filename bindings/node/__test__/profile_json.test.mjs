// profile_json.test.mjs: profileToSessionJson, profileFromSessionJson and
// profilesEqual against the APIData values of
// crates/opentele2-core/tests/api.rs.

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { CLIENTS, core, thrown } from './helpers.mjs'

const ACCOUNT_KEYS =
  '"twoFA":null,"role":"","id":null,"phone":null,"username":null,"date_of_birth":null,"date_of_birth_integrity":null,"is_premium":false,"has_profile_pic":false,"spamblock":null,"register_time":null,"last_check_time":null,"avatar":null,"first_name":"","last_name":"","sex":null,"proxy":null,"ipv6":false,"session_file":""'

/** `json.dumps(API.<X>().to_json(), separators=(",", ":"))`, in CLIENTS order. */
const SESSION_JSON = [
  '{"app_id":2040,"app_hash":"b18441a1ff607e10a989891a5462e627","device":"Desktop","sdk":"Windows 11 x64","app_version":"7.3.1 x64","system_lang_pack":"en-US","system_lang_code":"en-US","lang_pack":"tdesktop","lang_code":"en",',
  '{"app_id":6,"app_hash":"eb06d4abfb49dc3eeb1aeb98ae0f581e","device":"samsungSM-S938B","sdk":"SDK 36","app_version":"13.0.3 (7183)","system_lang_pack":"en-US","system_lang_code":"en-US","lang_pack":"android","lang_code":"en",',
  '{"app_id":21724,"app_hash":"3e0cb5efcd52300aec5994fdfc5bdc16","device":"samsungSM-S938B","sdk":"SDK 36","app_version":"0.29.1.1817","system_lang_pack":"en-US","system_lang_code":"en-US","lang_pack":"android","lang_code":"en",',
  '{"app_id":10840,"app_hash":"33c45224029d59cb3ad0c16134215aeb","device":"iPhone 17 Pro","sdk":"27.0.1","app_version":"13.0 (35303) ","system_lang_pack":"en-US","system_lang_code":"en-US","lang_pack":"ios","lang_code":"en",',
  '{"app_id":2834,"app_hash":"68875f756c9b437a8b916ca3de215815","device":"MacBook Air M4","sdk":"27.0.1","app_version":"13.0 (283305) ","system_lang_pack":"en-US","system_lang_code":"en-US","lang_pack":"macos","lang_code":"en",',
  '{"app_id":2496,"app_hash":"8da85b0d5bfe62527e5b244c209159c3","device":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36","sdk":"Windows","app_version":"12.0.47 A","system_lang_pack":"en-US","system_lang_code":"en-US","lang_pack":"","lang_code":"en",',
  '{"app_id":2496,"app_hash":"8da85b0d5bfe62527e5b244c209159c3","device":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36","sdk":"Win32","app_version":"2.2 K","system_lang_pack":"en-US","system_lang_code":"en-US","lang_pack":"macos","lang_code":"en",',
  '{"app_id":2496,"app_hash":"8da85b0d5bfe62527e5b244c209159c3","device":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36","sdk":"Win32","app_version":"0.7.0","system_lang_pack":"en-US","system_lang_code":"en-US","lang_pack":"","lang_code":"en",',
].map((head) => `${head}${ACCOUNT_KEYS}}`)

test('profileToSessionJson writes the session JSON byte for byte and reads back', () => {
  CLIENTS.forEach((client, n) => {
    const profile = core.profile(client)
    const json = core.profileToSessionJson(profile)
    assert.equal(JSON.stringify(json), SESSION_JSON[n], client)
    assert.equal(JSON.stringify(core.profileToSessionJson(profile, {})), SESSION_JSON[n], `${client} {}`)
    assert.equal(JSON.stringify(core.profileToSessionJson(profile, null)), SESSION_JSON[n], `${client} null`)
    assert.deepEqual(core.profileFromSessionJson(json), profile, `${client} object`)
    assert.deepEqual(core.profileFromSessionJson(SESSION_JSON[n]), profile, `${client} text`)
  })
})

test('the extra keys override in place and append, as to_json(extra)', () => {
  const want =
    '{"app_id":7,"app_hash":"eb06d4abfb49dc3eeb1aeb98ae0f581e","device":"samsungSM-S938B","sdk":"SDK 36","app_version":"13.0.3 (7183)","system_lang_pack":"en-US","system_lang_code":"en-US","lang_pack":"android","lang_code":"en","twoFA":null,"role":"","id":null,"phone":"+100","username":null,"date_of_birth":null,"date_of_birth_integrity":null,"is_premium":false,"has_profile_pic":false,"spamblock":null,"register_time":null,"last_check_time":null,"avatar":null,"first_name":"","last_name":"","sex":null,"proxy":null,"ipv6":true,"session_file":"","zeta":1,"alpha":null}'
  const extra = { zeta: 1, phone: '+100', app_id: 7, ipv6: true, alpha: null }
  assert.equal(JSON.stringify(core.profileToSessionJson(core.profile('TelegramAndroid'), extra)), want)
})

test('profileFromSessionJson applies the defaults and rejects malformed input', () => {
  const base = '"app_id":1,"app_hash":"h","device":"d","sdk":"s","app_version":"v"'
  const cases = [
    [`{${base}}`, ['en', 'en', '']],
    [`{${base},"system_lang_pack":"ru-RU"}`, ['en', 'ru-RU', '']],
    [`{${base},"system_lang_code":"","system_lang_pack":"de-DE","lang_code":"de","lang_pack":"tdesktop"}`, ['de', 'de-DE', 'tdesktop']],
    [`{${base},"system_lang_code":"fr-FR","system_lang_pack":"de-DE"}`, ['en', 'fr-FR', '']],
    [`{${base},"system_lang_code":null,"lang_code":null,"lang_pack":null}`, ['en', 'en', '']],
  ]
  for (const [text, [langCode, systemLangCode, langPack]] of cases) {
    const want = { apiId: 1, apiHash: 'h', deviceModel: 'd', systemVersion: 's', appVersion: 'v', langCode, systemLangCode, langPack }
    assert.deepEqual(core.profileFromSessionJson(text), want, text)
    assert.deepEqual(core.profileFromSessionJson(JSON.parse(text)), want, `${text} object`)
  }

  const rest = '"app_hash":"h","device":"d","sdk":"s","app_version":"v"'
  const rejected = [
    '[]',
    `{${rest}}`,
    `{${rest},"app_id":null}`,
    `{${rest},"app_id":"2040"}`,
    `{${rest},"app_id":4294967296}`,
    `{${rest},"app_id":1.5}`,
    '{"app_id":1,"device":"d","sdk":"s","app_version":"v"}',
    '{"app_id":1,"app_hash":"h","sdk":"s","app_version":"v"}',
    '{"app_id":1,"app_hash":"h","device":"d","app_version":"v"}',
    '{"app_id":1,"app_hash":"h","device":"d","sdk":"s"}',
    `{${rest},"app_id":1,"lang_code":5}`,
    `{${rest},"app_id":1,"system_lang_code":false}`,
    '{not json',
  ]
  for (const text of rejected) {
    assert.equal(thrown(() => core.profileFromSessionJson(text)).code, 'OT_IO', text)
  }
  assert.equal(thrown(() => core.profileFromSessionJson([])).code, 'OT_IO')
})

test('profilesEqual ignores the language fields, as APIData.__eq__', () => {
  const base = core.profile('TelegramDesktop')
  assert.ok(core.profilesEqual(base, { ...base, langCode: 'ru', systemLangCode: 'ru-RU', langPack: 'x' }))
  for (const [field, value] of [
    ['apiId', base.apiId + 1],
    ['apiHash', `${base.apiHash}0`],
    ['deviceModel', `${base.deviceModel}0`],
    ['systemVersion', `${base.systemVersion}0`],
    ['appVersion', `${base.appVersion}0`],
  ]) {
    assert.ok(!core.profilesEqual(base, { ...base, [field]: value }), field)
  }
})
