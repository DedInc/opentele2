// auth.test.mjs: QR login URLs, the SRP check, the sessions table, official
// api ids and the consistency texts against the Telethon 1.45.0 values and
// the values of crates/opentele2-core/tests/auth.rs. Passwords are fixtures and
// SRP outputs are compared with assertSame, so neither reaches the log.

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { assertSame, core, rejection, unhex } from './helpers.mjs'

const P =
  'c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f' +
  '48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37' +
  '20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64' +
  '2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4' +
  'a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754' +
  'fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4' +
  'e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f' +
  '0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b'

const SRP_ONE = {
  srpId: 2479236611711966277n,
  g: 3,
  salt1: '713a69e9a27390a0968da87fbf1a8510a4c5da97ed6f64447cbc4135821f3eeeabd5317c3ca6d03e',
  salt2: '6c2fffb7af6a052438d3305e2f42f538',
  srpB:
    'aabfadc340a660e89e0f964c749c62a91d955fa812f58ea17083c3b6b2ddd8e9' +
    '04a40c3c3300a5cd6216ceea87982328fff1b08959e9587dfb2b2956954b948a' +
    'fb689767e50254d9c732524af2f6e3e25c1db60f99672311669f1b4c50fe8ee0' +
    'f8202dd71faee5864581146e4bdd933b8e043b1f3a84c5c8acae2d31215346a1' +
    'eee0d52dd684ac451af249703afe79ab55bbf9e111ec157619205a8d900ae35a' +
    '5508670b1da74bde487e58464481343d9b40f26bfac6c43b785e7e0853251b6c' +
    '1de9315c25cfc22f474c6803f6eb7879f7198c7e0eed715c236da7a5de2a347b' +
    '4ffc471c0f8982bf908e72ea264bced63a635bc3e148b61f0dd248443c06b39d',
  password: 'hunter2-fixture',
  draws: [
    '5e62ea01ba87e020b0b69300dbef2f1c0b8bd99ad78b1a54c8f29f462be3beda' +
      '8e96b717b5e98c7f0c9c1be816e57afa06f372a2678876dbaee2ad3f5b37d829' +
      'a49bbda90e92eb7bb5ca56defcf971319b8b87c7f1613886bfc067baef17920f' +
      '6318981f3626ecbda3ad3194506e9fecd1fbdaa6eced7b2af8b2878c5a40e3f4' +
      'ef7368d3fb76a170f5303830f4a07d621adf717a26c5a4fb68a308065a3ba5f6' +
      '03b3cac89049642698fbf5ef7bf9455d69bfaae9ab57b7746573f33c54971f6a' +
      '0988bbc32fcf75edb64dd438d7807007f598cc96c5ae3d2afe62f1ed109758a9' +
      '8a37469dcb7f18505bd39d152b9273e48a69b70734b8fbc0dc90d07804483988',
  ],
  a:
    '4379fcb7331c3afd731a3fb183c43f54c0342caff67efb16d31c19d1a79a80d8' +
    '731829fc977c46e2742fae5213d19ecbb1197444e5495e2c4cdb724f61a13475' +
    '4132bdbfe7c4e65578d88a7ec20e915826315c74fdccd4fe4afc6722fe113351' +
    '6ad599e9cefcfa2b85dbeaa9d279da272fd375715aa1967028d4f000cb9d5a10' +
    'a26d4f4041c2f883ab4e025e729fcfa6130f7ea9548968f124ecb237504fde6c' +
    'f34916851ee527d90c7ec540db946095b3cc5447bdacf319509b40dd83577471' +
    'e33095fc69059d60a38d2daea78e1693d91bb59cd85d8bae42df1482ddd721d8' +
    '7c763342f745343ff01f71a1b922b9a4687fff8c0e62567c75fcb918d9a30e79',
  m1: 'f362f25a068ba4dd638905fda4d4e6b541f5dbbebfe7eedfcef23f96ec3eb0e3',
}

/** The first draw is `a = 1`, whose `A = 5` Telethon rejects and redraws. */
const SRP_TWO = {
  srpId: 4363604755476580611n,
  g: 5,
  salt1: '3ced22e9780b49d06180dee243d98f4127df5b5156974a9a0882b42403a53eddb77127d6e8b3dcb3',
  salt2: '8179e37406414367517fdb8145907c60',
  srpB:
    '969f3c63ba009ca87e88de13714892ecd959eb8bb11302a8f264e545c0ab54f0' +
    '632eadde6ad5966d2448e1cde0224d2fd3c5bab9ab5a662b6a26721e5fa52877' +
    '2a3fe2a2ed19ffd1c41a1ea4f26f58e1bf6d5c6082915ca0cefdd01022c50cb4' +
    'a80f92d28e05b26fb87c1757218dde35d2c180739497df9277ff5c6710829a9c' +
    'e13c7742b37e74d9edcf9cbe971f1f37ab6d14fc51cea92b7ac54dab2fa97da4' +
    '9e97cd2361024383569c617871087813d31fa4b273fb5d5e54ac8c584304ab82' +
    'a81dad71ebdf3d74227cc9f778cfee212604c9b12ee3c183d16f37fa36ad6017' +
    'b132e9b09d26b28f17fa5193e3afae73a88a511f9bad86e3e7aeb67c3c9472cc',
  password: 'пароль-fixture',
  draws: [
    '00'.repeat(255) + '01',
    'a64dcceb1a998d1a1c78f98d8f372ca4649d349f0d58fe487a450b3f308f0c6f' +
      'f1dc4c8b85f7c69a42f3379106faa777c643de12ed93123c92c5a6917c5dcbdc' +
      '4c5f7adfa2db439957eb16136d2fb35c872046021cb24d32b50362497c03b2fa' +
      '7749bb9bfb335d14e9aa0e21ab38ac0fc6f62832555a3984dcef9f692415af2e' +
      'e333bf43081178f80793a308460b5495699ac12c36ab6e0a819ba8ff69726deb' +
      'c35ae6238b5bfe5b6fe61339312f89e7ce08c26baf9cd6c396f6ddd5657f18d6' +
      'e14ca683ad4e81d797930d876c2dbdb75ca26d994974c9158bd01823e3a5846c' +
      'e6882fd8907315b379cb1d674cf41611dd55baa4a9a975ff10a60881bcc87b0a',
  ],
  a:
    '53bf5c503f621219caf5d35d1ded97cb807d4a7037ddc0660f8fa32d582b0546' +
    '2843fe09b40922ec724e33e522123990c22cbe773b4550f05a9cefd39808dddb' +
    'd940c91e2e24196a5aaf38584df9377b587d922068c053d853caa00028218ad7' +
    'c0d1db714abb763953ed6e6f621117ac63df534ac353390213bdc507a6fbc4a7' +
    'da1de02d5ef52dd97e9b33f0e94a60782010374f51418a1c719cc4a1296b0a82' +
    '14a9f6c26690176368c7bff6740fba3c2796b08616cddddc480e9bd432c15bc2' +
    '1434ac1d9c55384afbf018c2008a8ffa5db40b061383c6f8cae28057a68e2d9b' +
    '813ce2564376feb78572e4b0cb1669fa2e2f8f8ff2b7b7a9798dfeaa77faaefb',
  m1: 'e3f599856deb285836c4e97b75226e43ca861635d48b72ef0ceed578f2845e49',
}

const params = (fixture, edits = {}) => ({
  srpId: fixture.srpId,
  g: fixture.g,
  p: unhex(P),
  salt1: unhex(fixture.salt1),
  salt2: unhex(fixture.salt2),
  srpB: unhex(fixture.srpB),
  ...edits,
})

test('qrLoginUrl matches Telethon QRLogin.url', () => {
  const cases = [
    ['', 'tg://login?token='],
    ['00', 'tg://login?token=AA'],
    ['fb', 'tg://login?token=-w'],
    ['fbff', 'tg://login?token=-_8'],
    ['fbffbf', 'tg://login?token=-_-_'],
    ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'tg://login?token=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'],
    ['6c6f67696e2d746f6b656efeff', 'tg://login?token=bG9naW4tdG9rZW7-_w'],
  ]
  for (const [token, url] of cases) {
    assert.equal(core.qrLoginUrl(unhex(token)), url, token)
    assert.ok(url.startsWith(core.QR_LOGIN_URL_PREFIX))
  }
})

test('srpCheck matches Telethon compute_check, redraws and refuses alike', async () => {
  for (const fixture of [SRP_ONE, SRP_TWO]) {
    const check = await core.srpCheck(params(fixture), fixture.password, fixture.draws.map(unhex))
    assert.equal(check.srpId, fixture.srpId)
    assertSame(check.a, unhex(fixture.a), 'A')
    assertSame(check.m1, unhex(fixture.m1), 'M1')
  }
  // Without recorded exponents each check draws a fresh A.
  const [first, second] = await Promise.all([
    core.srpCheck(params(SRP_ONE), SRP_ONE.password),
    core.srpCheck(params(SRP_ONE), SRP_ONE.password),
  ])
  assert.equal(first.a.length, core.SRP_NUMBER_SIZE)
  assert.equal(first.m1.length, 32)
  assert.ok(!first.a.equals(second.a), 'fresh exponents give a fresh A')

  const p = unhex(P)
  const refused = async (edits, code) => {
    const error = await rejection(core.srpCheck(params(SRP_ONE, edits), SRP_ONE.password, SRP_ONE.draws.map(unhex)))
    assert.equal(error.code, code, JSON.stringify(Object.keys(edits)))
    return error
  }
  const badG = await refused({ g: 9 }, 'OT_SRP_BAD_PRIME_OR_GENERATOR')
  assert.equal(badG.message, 'bad p/g in password')
  // A refusal that is not a core error repeats its message as legacyMessage.
  assert.equal(badG.legacyMessage, 'bad p/g in password')
  await refused({ p: p.subarray(1) }, 'OT_SRP_BAD_PRIME_OR_GENERATOR')
  assert.equal((await refused({ srpB: Buffer.alloc(0) }, 'OT_SRP_BAD_B')).message, 'bad b in check')
  await refused({ srpB: Buffer.alloc(256) }, 'OT_SRP_BAD_B')
  await refused({ srpB: p }, 'OT_SRP_BAD_B')
  await refused({ srpB: Buffer.concat([Buffer.from([0]), unhex(SRP_ONE.srpB)]) }, 'OT_SRP_BAD_B')

  // SRP_TWO needs its second exponent.
  const short = await rejection(core.srpCheck(params(SRP_TWO), SRP_TWO.password, [unhex(SRP_TWO.draws[0])]))
  assert.equal(short.code, 'ERR_INVALID_ARG_VALUE')
  assert.throws(() => core.srpCheck(params(SRP_ONE), SRP_ONE.password, [Buffer.alloc(255)]), { code: 'ERR_INVALID_ARG_VALUE' })
  assert.throws(() => core.srpCheck(params(SRP_ONE, { srpId: 2n ** 63n }), SRP_ONE.password), { code: 'ERR_INVALID_ARG_VALUE' })
})

const row = (current, officialApp, apiId, [deviceModel, platform, systemVersion, appName, appVersion]) => ({
  current,
  officialApp,
  apiId,
  deviceModel,
  platform,
  systemVersion,
  appName,
  appVersion,
})

test('formatSessions renders the PrintSessions table', () => {
  const rows = [
    row(true, true, 2040, ['Desktop', 'Windows', 'Windows 11 x64', 'Telegram Desktop', '6.1.3 x64']),
    row(false, true, 6, ['samsungSM-S938B', 'android', 'SDK 36', 'Telegram Android', '12.0.1 (61234)']),
    row(false, false, 123456, ['Pixel 8 Прo', '', 'Linux', 'My bot thing', '0.1']),
    // `current` and `official_app` unset.
    row(undefined, undefined, 10840, ['iPhone 17 Pro', 'iOS', '26.0', 'Telegram iOS', '12.1 (32000) ']),
  ]
  assert.equal(
    core.formatSessions(rows),
    [
      '|---------+-----------------+----------+----------------+--------+---------------------------------+--------------|',
      '|         |     Device      | Platform |     System     | API_ID |            App name             | Official App |',
      '|---------+-----------------+----------+----------------+--------+---------------------------------+--------------|',
      '| Current |     Desktop     | Windows  | Windows 11 x64 |  2040  |   Telegram Desktop 6.1.3 x64    |      ✔       |',
      '|---------+-----------------+----------+----------------+--------+---------------------------------+--------------|',
      '|    1    | samsungSM-S938B | android  |     SDK 36     |   6    | Telegram Android 12.0.1 (61234) |      ✔       |',
      '|    2    |   Pixel 8 Прo   |          |     Linux      | 123456 |        My bot thing 0.1         |      ✖       |',
      '|    3    |  iPhone 17 Pro  |   iOS    |      26.0      | 10840  |   Telegram iOS 12.1 (32000)     |      ✖       |',
      '|---------+-----------------+----------+----------------+--------+---------------------------------+--------------|',
    ].join('\n'),
  )
  assert.equal(
    core.formatSessions([row(false, false, 1, ['x', 'y', 'z', 'a', 'b'])]),
    [
      '|---+--------+----------+--------+--------+----------+--------------|',
      '|   | Device | Platform | System | API_ID | App name | Official App |',
      '|---+--------+----------+--------+--------+----------+--------------|',
      '| 0 |   x    |    y     |   z    |   1    |   a b    |      ✖       |',
      '|---+--------+----------+--------+--------+----------+--------------|',
    ].join('\n'),
  )
  const empty = core.formatSessions([]).split('\n')
  assert.equal(empty.length, 4)
  assert.equal(empty[1], '|   | Device | Platform | System | API_ID | App name | Official App |')
  assert.deepEqual(core.SESSION_COLUMNS, [' ', 'Device', 'Platform', 'System', 'API_ID', 'App name', 'Official App'])
})

test('the session admin messages and official api ids', () => {
  assert.equal(
    core.FRESH_RESET_FORBIDDEN,
    "You can't logout other sessions if less than 24 hours have passed since you logged on the current session.",
  )
  assert.equal(core.HASH_INVALID, 'The provided hash is invalid.')
  assert.equal(core.SESSIONS_UNAVAILABLE, "Could not fetch the account's sessions")
  assert.equal(
    core.NO_PASSWORD_PROVIDED,
    'Two-step verification is enabled for this account.\nYou need to provide the `password` to argument',
  )
  assert.deepEqual(core.OFFICIAL_API_IDS, [2040, 6, 21724, 10840, 2834, 2496])
  const ids = [...new Set(['TelegramDesktop', 'TelegramAndroid', 'TelegramAndroidX', 'TelegramIOS', 'TelegramMacOS', 'TelegramWeb_A', 'TelegramWeb_K', 'Webogram'].map((c) => core.profile(c).apiId))]
  assert.deepEqual(ids, core.OFFICIAL_API_IDS)
  for (const id of core.OFFICIAL_API_IDS) assert.ok(core.isOfficialApiId(id))
  assert.ok(!core.isOfficialApiId(123456))
  assert.ok(!core.isOfficialApiId(0))
})

test('consistencyExpectations follow the profile', () => {
  const desktop = core.consistencyExpectations(core.profile('TelegramDesktop'))
  assert.deepEqual(desktop, {
    apiId: 2040,
    officialApiId: true,
    langPack: 'tdesktop',
    langPackSkipped: false,
    advertisedLayer: core.LAYER,
    layerTolerance: 15,
    appVersion: core.profile('TelegramDesktop').appVersion,
    versionIssues: [],
    appVersionCurrent: true,
  })
  assert.equal(core.LAYER_TOLERANCE, 15)
  for (const [client, pack, current] of [
    ['TelegramAndroid', 'android', true],
    ['TelegramAndroidX', 'android', false],
    ['TelegramIOS', 'ios', true],
    ['TelegramMacOS', 'macos', true],
    ['TelegramWeb_A', '', true],
    ['TelegramWeb_K', 'macos', false],
    ['Webogram', '', true],
  ]) {
    const expectations = core.consistencyExpectations(core.profile(client))
    assert.equal(expectations.langPack, pack, client)
    assert.equal(expectations.langPackSkipped, pack === '', client)
    assert.ok(expectations.officialApiId, client)
    assert.equal(expectations.appVersionCurrent, current, client)
  }
  assert.equal(
    core.consistencyExpectations(core.profile('TelegramWeb_K')).versionIssues[0].message,
    "macOS app_version '2.2 K' major does not match latest known '13.0'",
  )
  const custom = core.consistencyExpectations({ ...core.profile('TelegramAndroid'), apiId: 123456, appVersion: '1.0' })
  assert.ok(!custom.officialApiId)
  assert.ok(!custom.appVersionCurrent)
  assert.equal(custom.versionIssues[0].message, "Android app_version '1.0' major does not match latest known '13.0.3'")
  const newer = core.consistencyExpectations({ ...core.profile('TelegramAndroid'), appVersion: '14.0' }, { androidAppVersion: '14.0' })
  assert.ok(newer.appVersionCurrent)
})

test('layerResult tolerates fifteen layers', () => {
  for (const [layer, passes] of [
    [229, true],
    [230, true],
    [215, true],
    [245, true],
    [214, false],
    [246, false],
  ]) {
    assert.equal(core.layerResult(layer).passed, passes, `layer ${layer}`)
  }
  assert.deepEqual(core.layerResult(229), {
    name: 'layer_match',
    passed: true,
    detail: 'Telethon layer=229, advertised schema layer=230, diff=1',
  })
  assert.equal(core.layerResult(250).detail, 'Telethon layer=250, advertised schema layer=230, diff=20')
  assert.equal(core.layerDetail(250), core.layerResult(250).detail)
  assert.equal(core.layerDetail(229, 228), 'Telethon layer=229, advertised schema layer=228, diff=1')
})

test('the consistency check names and report texts', () => {
  assert.deepEqual(core.consistencyChecks(), [
    'get_config',
    'nearest_dc',
    'current_session',
    'layer_match',
    'lang_pack',
    'app_update',
    'terms_of_service',
  ])
  const result = (name, passed, detail) => ({ name, passed, detail })
  const session = row(true, true, 2040, ['Desktop', 'Windows', 'Windows 11 x64', 'Telegram Desktop', '6.1.3 x64'])
  const allOk = [
    result('get_config', true, core.getConfigDetail(2)),
    result('nearest_dc', true, core.nearestDcDetail('NL', 2, 4)),
    result('current_session', true, core.currentSessionDetail(session)),
    core.layerResult(229),
    result('lang_pack', true, core.langPackDetail('tdesktop', 3)),
    result('app_update', true, core.NO_APP_UPDATE),
    result('terms_of_service', true, core.TERMS_OF_SERVICE_OK),
  ]
  assert.equal(
    core.consistencySummary(allOk),
    "Consistency: 7/7 checks passed\n  [OK] get_config: Config OK (DC 2)\n  [OK] nearest_dc: country='NL', this_dc=2, nearest_dc=4\n  [OK] current_session: api_id=2040, official=True, device='Desktop', app='Telegram Desktop 6.1.3 x64'\n  [OK] layer_match: Telethon layer=229, advertised schema layer=230, diff=1\n  [OK] lang_pack: lang_pack 'tdesktop' valid (3 languages)\n  [OK] app_update: No update available (app_version accepted)\n  [OK] terms_of_service: ToS check OK",
  )
  const web = [
    result('get_config', true, core.getConfigDetail(2)),
    result('nearest_dc', true, core.nearestDcDetail('NL', 2, 4)),
    result('current_session', false, core.currentSessionDetail({ ...session, officialApp: false })),
    core.layerResult(229),
    result('lang_pack', true, core.LANG_PACK_EMPTY),
    result('app_update', true, core.appUpdateDetail('6.2.0')),
    result('terms_of_service', true, core.TERMS_OF_SERVICE_OK),
  ]
  assert.equal(
    core.consistencySummary(web),
    "Consistency: 6/7 checks passed\n  [OK] get_config: Config OK (DC 2)\n  [OK] nearest_dc: country='NL', this_dc=2, nearest_dc=4\n  [FAIL] current_session: api_id=2040, official=False, device='Desktop', app='Telegram Desktop 6.1.3 x64'\n  [OK] layer_match: Telethon layer=229, advertised schema layer=230, diff=1\n  [OK] lang_pack: lang_pack is empty (web client mode)\n  [OK] app_update: Update available: v6.2.0 (but request succeeded)\n  [OK] terms_of_service: ToS check OK",
  )
  const failing = [
    result('get_config', false, core.getConfigError('boom GetConfigRequest')),
    result('nearest_dc', false, core.nearestDcError('boom GetNearestDcRequest')),
    result('current_session', false, core.CURRENT_SESSION_MISSING),
    core.layerResult(229),
    result('lang_pack', false, core.langPackError('android', 'LANG_PACK_INVALID')),
    result('app_update', false, core.appUpdateError('boom GetAppUpdateRequest')),
    result('terms_of_service', false, core.checkError('boom GetTermsOfServiceUpdateRequest')),
  ]
  assert.equal(
    core.consistencySummary(failing),
    "Consistency: 1/7 checks passed\n  [FAIL] get_config: Server rejected getConfig: boom GetConfigRequest\n  [FAIL] nearest_dc: Error calling getNearestDc: boom GetNearestDcRequest\n  [FAIL] current_session: Could not retrieve current session\n  [OK] layer_match: Telethon layer=229, advertised schema layer=230, diff=1\n  [FAIL] lang_pack: lang_pack 'android' rejected: LANG_PACK_INVALID\n  [FAIL] app_update: Error calling getAppUpdate: boom GetAppUpdateRequest\n  [FAIL] terms_of_service: Error: boom GetTermsOfServiceUpdateRequest",
  )
  assert.equal(core.checkException('kaput'), 'Exception: kaput')
  assert.equal(core.getConfigDetail(), 'Config OK (DC None)')
  assert.equal(core.getConfigDetail(null), 'Config OK (DC None)')
  assert.equal(core.appUpdateDetail(), 'Update available: v? (but request succeeded)')
  assert.equal(core.CONSISTENCY_WARNING_PREFIX, 'opentele2 consistency check issues:\n')
})
