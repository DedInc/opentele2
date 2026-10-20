// core_data.test.mjs: the data the addon exposes from the core:
// `legacyMessage` on errors, the session JSON tables, formatAppVersion, the
// device catalog listings, formatTable, TDF_MAGIC and drawPlan.
//
// Expected values are the literals of crates/opentele2-core/tests/
// {messages,api,devices,auth,tdata_write}.rs.

import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'

import { VECTORS, core, rejection, thrown } from './helpers.mjs'

const scratch = mkdtempSync(path.join(tmpdir(), 'opentele2-core-data-'))
after(() => rmSync(scratch, { recursive: true, force: true }))

let counter = 0
const freshDir = () => path.join(scratch, `out-${counter++}`)
const vectorDir = (folder) => path.join(VECTORS, ...folder.split('/'))

/** A folder whose key file `key_datas` holds `content`. */
function withKeyFile(content) {
  const dir = freshDir()
  mkdirSync(dir)
  writeFileSync(path.join(dir, 'key_datas'), content)
  return dir
}

// ---------------------------------------------------------------- legacyMessage

test('read file rejections carry their legacyMessage', async () => {
  const missing = await rejection(core.loadTdata(path.join(scratch, 'missing')))
  assert.ok(missing instanceof Error)
  assert.equal(missing.code, 'OT_TFILE_NOT_FOUND')
  assert.equal(missing.message, 'tdata file not found')
  assert.equal(missing.legacyMessage, 'Could not open key_data')
  assert.equal(missing.cause, undefined)

  const cases = [
    [Buffer.from('ABCD', 'latin1'), "Invalid magic b'ABCD' in file key_data"],
    [Buffer.from([0x54, 0x27, 0x00, 0xff]), String.raw`Invalid magic b"T'\x00\xff" in file key_data`],
    [Buffer.from([0x27, 0x22, 0x5c, 0x0a]), String.raw`Invalid magic b'\'"\\\n' in file key_data`],
    [Buffer.from([0x09, 0x0d, 0x7f, 0x7e]), String.raw`Invalid magic b'\t\r\x7f~' in file key_data`],
  ]
  for (const [magic, expected] of cases) {
    const error = await rejection(core.loadTdata(withKeyFile(Buffer.concat([magic, Buffer.alloc(30)]))))
    assert.equal(error.code, 'OT_TDATA_INVALID_MAGIC')
    assert.equal(error.legacyMessage, expected)
  }

  const version = Buffer.alloc(4)
  version.writeUInt32LE(7003001)
  const content = Buffer.concat([Buffer.from('TDF$'), version, Buffer.from('hello world'), Buffer.alloc(16)])
  const checksum = await rejection(core.loadTdata(withKeyFile(content)))
  assert.equal(checksum.code, 'OT_TDATA_INVALID_CHECKSUM')
  assert.equal(checksum.legacyMessage, 'Invalid checksum 78e20993e8b2d57b5f190eb51b1e8d63 in file key_data')
})

test('loadMany errors carry the legacyMessage', async () => {
  const [missing, loaded] = await core.loadMany([path.join(scratch, 'missing'), vectorDir('tdata_plain/performance_on')])
  assert.ok(missing instanceof Error)
  assert.equal(missing.code, 'OT_TFILE_NOT_FOUND')
  assert.equal(missing.legacyMessage, 'Could not open key_data')
  assert.ok(loaded instanceof core.TData)
})

test('a wrong passcode rejects with its legacyMessage', async () => {
  const error = await rejection(core.loadTdata(vectorDir('tdata_plain/performance_on'), 'opentele2'))
  assert.equal(error.code, 'OT_TDATA_BAD_DECRYPT_KEY')
  assert.equal(error.legacyMessage, 'Bad decrypt key, data not decrypted - incorrect password?')
})

test('synchronous throws carry the legacyMessage', async () => {
  const accounts = Array.from({ length: 6 }, (_, index) => ({ index, userId: 1n, mainDc: 2, authKey: Buffer.alloc(256) }))
  const tdata = await core.newTdata(accounts)
  const limit = thrown(() => core.addTdataAccount(tdata, 1n, 2, Buffer.alloc(256)))
  assert.ok(limit instanceof Error)
  assert.equal(limit.code, 'OT_MAX_ACCOUNT_LIMIT')
  assert.equal(limit.legacyMessage, "You can't have more than 6 accounts in one TDesktop client")
  assert.equal(limit.cause, undefined)

  const keyless = thrown(() => core.mtcuteStringSession({ index: 0, userId: 1n, mainDc: 2 }))
  assert.equal(keyless.code, 'OT_TDATA_AUTH_KEY_NOT_FOUND')
  assert.equal(keyless.legacyMessage, 'Could not find the main authKey')

  // Without a legacyMessage of its own, the core's text is given.
  const short = thrown(() => core.aesIgeEncrypt(Buffer.alloc(16), Buffer.alloc(16), Buffer.alloc(32)))
  assert.equal(short.code, 'OT_BAD_LENGTH')
  assert.equal(short.legacyMessage, short.message)

  // Arguments the core never sees carry no legacyMessage.
  const negative = thrown(() => core.addTdataAccount(tdata, -1n, 2, Buffer.alloc(256)))
  assert.equal(negative.code, 'ERR_INVALID_ARG_VALUE')
  assert.equal('legacyMessage' in negative, false)
})

// ---------------------------------------------------------------- session JSON and versions

test('formatAppVersion', () => {
  const cases = [
    [7003001, '7.3.1'],
    [7003000, '7.3'],
    [1000000, '1.0'],
    [0, '0.0'],
    [12345678, '12.345.678'],
    [2 ** 32 - 1, '4294.967.295'],
    [1002003, '1.2.3'],
  ]
  for (const [version, expected] of cases) {
    assert.equal(core.formatAppVersion(version), expected, String(version))
  }
  assert.equal(core.formatAppVersion(7003001), core.platformVersions().desktopAppVersion)
})

test('TDF_MAGIC is TDF$', () => {
  assert.equal(core.TDF_MAGIC, 'TDF$')
  assert.deepEqual(Buffer.from(core.TDF_MAGIC, 'latin1'), Buffer.from([0x54, 0x44, 0x46, 0x24]))
})

test('the session JSON tables', () => {
  const expectedExtra = JSON.parse(
    '[["twoFA", null], ["role", ""], ["id", null], ["phone", null], ["username", null], ' +
      '["date_of_birth", null], ["date_of_birth_integrity", null], ["is_premium", false], ' +
      '["has_profile_pic", false], ["spamblock", null], ["register_time", null], ' +
      '["last_check_time", null], ["avatar", null], ["first_name", ""], ["last_name", ""], ' +
      '["sex", null], ["proxy", null], ["ipv6", false], ["session_file", ""]]',
  )
  assert.deepEqual(core.defaultExtraFields(), expectedExtra)

  assert.deepEqual(core.sessionJsonFields(), [
    { key: 'app_id', attribute: 'api_id', default: null, fallback: null },
    { key: 'app_hash', attribute: 'api_hash', default: null, fallback: null },
    { key: 'device', attribute: 'device_model', default: null, fallback: null },
    { key: 'sdk', attribute: 'system_version', default: null, fallback: null },
    { key: 'app_version', attribute: 'app_version', default: null, fallback: null },
    { key: 'system_lang_pack', attribute: 'system_lang_code', default: 'en', fallback: null },
    { key: 'system_lang_code', attribute: 'system_lang_code', default: null, fallback: 'system_lang_pack' },
    { key: 'lang_pack', attribute: 'lang_pack', default: '', fallback: null },
    { key: 'lang_code', attribute: 'lang_code', default: 'en', fallback: null },
  ])

  // The writer follows the same tables.
  const written = core.profileToSessionJson(core.profile('TelegramDesktop'))
  const keys = [...core.sessionJsonFields().map((field) => field.key), ...core.defaultExtraFields().map(([key]) => key)]
  assert.deepEqual(Object.keys(written), keys)
})

// ---------------------------------------------------------------- device catalogs

/** SHA-1 hex of `lines`, each followed by a newline. */
function linesDigest(lines) {
  const hash = createHash('sha1')
  for (const line of lines) hash.update(`${line}\n`, 'utf8')
  return hash.digest('hex')
}

test('catalogEntries list the device lists', () => {
  const expected = [
    ['windows', 232, 'ad3775a3cc0e8a0a305aac31af80c3f5be39fb89'],
    ['linux', 3944, 'd5f46c6619554458fa5b51b4f3a131086f1fbd86'],
    ['macos', 1349, 'ba1531aa74ba005ed87bd4e69fce7a8bf746a368'],
    ['android', 6850, '3e20af265f8b392de686676d135c80cfa1fe0570'],
    ['ios', 1166, '77c5f221cd8683c02ba0f0a451c427029cab7740'],
  ]
  for (const [platform, runs, digest] of expected) {
    const merged = []
    for (const entry of core.catalogEntries(platform)) {
      assert.ok(entry.weight > 0)
      const last = merged.at(-1)
      if (last !== undefined && last[0] === entry.model && last[1] === entry.systemVersion) {
        last[2] += entry.weight
      } else {
        merged.push([entry.model, entry.systemVersion, entry.weight])
      }
    }
    assert.equal(merged.length, runs, platform)
    assert.equal(linesDigest(merged.map((run) => run.join('\t'))), digest, platform)
  }
})

test('deviceModels and systemVersions', () => {
  const expected = [
    ['windows', [116, '5c52da02e390eac9e3753d929c3360cfabbc705a'], [2, 'e6bb592d547ca159c19720732b2b5cbfd6adb4ba']],
    ['linux', [116, '5c52da02e390eac9e3753d929c3360cfabbc705a'], [34, 'f248aeedf61275d7a4b90fcc3ec72d873d5eaac7']],
    ['macos', [36, 'f4da4ee944ec827dbef2c3a4d60c58d318355fe3'], [42, 'da876c68c841a5aaa2e37e32e847122642a3c28f']],
    ['ios', [33, '4e9dfe139b2110fdaa14f269b0d8a723793885be'], [46, '2c94f86b38782cc48e1d171fe82134039ed3efbd']],
  ]
  for (const [platform, models, versions] of expected) {
    const deviceModels = core.deviceModels(platform)
    const systemVersions = core.systemVersions(platform)
    assert.deepEqual([deviceModels.length, linesDigest(deviceModels)], models, platform)
    assert.deepEqual([systemVersions.length, linesDigest(systemVersions)], versions, platform)
  }
  const sdks = Array.from({ length: 9 }, (_, n) => `SDK ${29 + n}`)
  assert.deepEqual(core.systemVersions('android'), sdks)
})

test('the web catalog entries are listed for both clients', () => {
  const webA = core.catalogEntries('web_a')
  const webK = core.catalogEntries('web_k')
  assert.ok(webA.length > 0)
  for (const [entries, client] of [[webA, 'web_a'], [webK, 'web_k']]) {
    const models = new Set(core.deviceModels(client))
    const versions = new Set(core.systemVersions(client))
    assert.ok(entries.every((entry) => models.has(entry.model) && versions.has(entry.systemVersion)))
  }
  const pairs = (entries) => entries.map((entry) => [entry.model, entry.weight])
  assert.deepEqual(pairs(webA), pairs(webK))
})

test('webBrowserWeights', () => {
  assert.deepEqual(Object.entries(core.webBrowserWeights()), [['chrome', 19], ['edge', 2], ['firefox', 1]])
})

test('an unknown platform is refused', () => {
  for (const fn of [core.catalogEntries, core.deviceModels, core.systemVersions]) {
    const error = thrown(() => fn('symbian'))
    assert.equal(error.code, 'ERR_INVALID_ARG_VALUE')
    assert.match(error.message, /unknown platform/)
  }
})

// ---------------------------------------------------------------- formatTable

test('formatTable renders a PrettyTable', () => {
  assert.equal(
    core.formatTable(['a', 'bb'], [['1', 'x'], ['long value', '']]),
    '|------------+----|\n|     a      | bb |\n|------------+----|\n' +
      '|     1      | x  |\n| long value |    |\n|------------+----|',
  )
  assert.equal(
    core.formatTable(['Name', '#'], [['ok', '✔'], ['Ünïcødé', '12'], ['', '3']], [0, 2]),
    '|---------+----|\n|  Name   | #  |\n|---------+----|\n|---------+----|\n' +
      '|   ok    | ✔  |\n| Ünïcødé | 12 |\n|---------+----|\n|         | 3  |\n' +
      '|---------+----|',
  )
  assert.equal(
    core.formatTable(['Header longer'], [['x']], [1, 5]),
    '|---------------|\n| Header longer |\n|---------------|\n|       x       |\n' + '|---------------|',
  )
  assert.equal(
    core.formatTable(['x', 'y'], [['even', 'odd'], ['ab', 'abc']], [1, 1]),
    '|------+-----|\n|  x   |  y  |\n|------+-----|\n| even | odd |\n' + '|------+-----|\n|  ab  | abc |\n|------+-----|',
  )
  assert.equal(
    core.formatTable(['h1', 'h2'], [['only'], ['a', 'b', 'ignored']]),
    '|------+----|\n|  h1  | h2 |\n|------+----|\n| only |    |\n' + '|  a   | b  |\n|------+----|',
  )
})

// ---------------------------------------------------------------- drawPlan

const replayable = (plan) => plan.map((size) => randomBytes(size))

test('drawPlan of a new folder', () => {
  assert.deepEqual(core.drawPlan('new', { hasPasscode: false, performanceMode: true }), [])
  assert.deepEqual(core.drawPlan('new', { hasPasscode: true, performanceMode: true }), [256, 32, 32, 32, 12])
  assert.deepEqual(core.drawPlan('new', { hasPasscode: false, performanceMode: false }), [256, 32, 32, 12])
  // The defaults are those of newTdata.
  assert.deepEqual(core.drawPlan('new', {}), [])
})

test('drawPlan matches the draws of a save', async () => {
  const loaded = await core.loadTdata(vectorDir('tdata_plain/performance_on'))
  const tdata = await core.newTdata(loaded.accounts)
  core.addTdataAccount(tdata, 7n, 4, Buffer.alloc(256, 3))
  for (const performanceMode of [true, false]) {
    tdata.performanceMode = performanceMode
    const plan = core.drawPlan('save', tdata)
    assert.ok(plan.length > 0)
    assert.ok(plan.every((size) => size > 0))
    // A replay of other sizes, a missing or an unused draw rejects.
    await core.saveTdata(tdata, freshDir(), null, replayable(plan))
    const short = await rejection(core.saveTdata(tdata, freshDir(), null, replayable(plan.slice(0, -1))))
    assert.equal(short.code, 'ERR_INVALID_ARG_VALUE')
  }
})

test('drawPlan matches the draws of a migration', async () => {
  const legacy = await core.loadTdata(vectorDir('tdata_legacy/plain'))
  assert.equal(legacy.legacyKeyFile, true)
  const plan = core.drawPlan('migrate', legacy)
  assert.ok(plan.length > 0)
  // A save of a legacy key file migrates first.
  assert.deepEqual(core.drawPlan('save', legacy).slice(0, plan.length), plan)
  assert.equal(await core.migrateTdata(legacy, replayable(plan)), true)
  assert.deepEqual(core.drawPlan('migrate', legacy), [])
})

test('drawPlan refuses what a save refuses and checks its arguments', async () => {
  const empty = await core.newTdata([])
  const failed = thrown(() => core.drawPlan('save', empty))
  assert.equal(failed.code, 'OT_TDATA_SAVE_FAILED')
  assert.equal(failed.legacyMessage, 'Could not save tdata, something went wrong')

  assert.equal(thrown(() => core.drawPlan('delete', empty)).code, 'ERR_INVALID_ARG_VALUE')
  assert.match(thrown(() => core.drawPlan('save', { hasPasscode: true })).message, /TData/)
  assert.equal(thrown(() => core.drawPlan('new', empty)).code, 'ERR_INVALID_ARG_VALUE')
})
