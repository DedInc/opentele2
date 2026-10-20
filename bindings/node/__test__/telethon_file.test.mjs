// telethon_file.test.mjs: the Telethon .session rows, SQL constants, pair
// paths and JSON companion against crates/opentele2-core/tests/session.rs.

import assert from 'node:assert/strict'
import path from 'node:path'
import { test } from 'node:test'

import { CUSTOM_CONFIG, VECTORS, assertSame, core, loadJson, thrown, unhex } from './helpers.mjs'

/** The address text of the built-in table per production DC, as [IPv4, IPv6]. */
const TABLE_TEXT = {
  1: ['149.154.175.50', '2001:0b28:f23d:f001:0000:0000:0000:000a'],
  2: ['149.154.167.51', '2001:067c:04e8:f002:0000:0000:0000:000a'],
  3: ['149.154.175.100', '2001:0b28:f23d:f003:0000:0000:0000:000a'],
  4: ['149.154.167.91', '2001:067c:04e8:f004:0000:0000:0000:000a'],
  5: ['149.154.171.5', '2001:0b28:f23f:f005:0000:0000:0000:000a'],
}

const key = Buffer.alloc(256, 9)
const withConfig = (mainDc, config) => ({ index: 0, userId: 77n, mainDc, authKey: key, config })

test('the schema and statements of the Telethon file', () => {
  const schema = core.telethonSchema()
  assert.deepEqual(
    schema.map((table) => table.name),
    ['version', 'sessions', 'entities', 'sent_files', 'update_state'],
  )
  assert.deepEqual(schema[0], {
    name: 'version',
    ddl: 'create table version (version integer primary key)',
    columns: ['version'],
  })
  assert.deepEqual(schema[1], {
    name: 'sessions',
    ddl: 'create table sessions (dc_id integer primary key, server_address text, port integer, auth_key blob, takeout_id integer, tmp_auth_key blob)',
    columns: ['dc_id', 'server_address', 'port', 'auth_key', 'takeout_id', 'tmp_auth_key'],
  })
  assert.equal(
    schema[3].ddl,
    'create table sent_files (md5_digest blob, file_size integer, type integer, id integer, hash integer, primary key(md5_digest, file_size, type))',
  )
  for (const table of schema) {
    assert.ok(table.ddl.startsWith(`create table ${table.name} (`), table.name)
  }
  assert.equal(core.TELETHON_SESSION_VERSION, 8)
  assert.equal(core.TELETHON_DELETE_VERSION, 'delete from version')
  assert.equal(core.TELETHON_INSERT_VERSION, 'insert into version values (?)')
  assert.equal(core.TELETHON_DELETE_SESSIONS, 'delete from sessions')
  assert.equal(core.TELETHON_INSERT_SESSION, 'insert into sessions values (?, ?, ?, ?, ?, ?)')
  assert.equal(core.TELETHON_INSERT_SESSION.split('?').length - 1, schema[1].columns.length)
  assert.equal(core.TELETHON_SESSION_SUFFIX, '.session')
  assert.equal(core.TELETHON_JSON_SUFFIX, '.json')
})

test('telethonSessionRows of the vector accounts carry the built-in address text', async () => {
  for (const folder of ['tdata_plain/performance_on', 'tdata_plain/performance_off']) {
    const entry = loadJson('tdata.json').folders[folder]
    const tdata = await core.loadTdata(path.join(VECTORS, ...folder.split('/')))
    tdata.accounts.forEach((account, n) => {
      const want = entry.accounts[n]
      TABLE_TEXT[want.main_dc].forEach((text, family) => {
        const rows = core.telethonSessionRows(account, family === 1)
        assert.equal(rows.dcId, want.main_dc, folder)
        assert.equal(rows.serverAddress, text, `${folder} address`)
        assert.equal(rows.port, 443)
        assert.equal(rows.takeoutId, undefined)
        assertSame(rows.authKey, unhex(want.auth_key), `${folder} rows key`)
      })
      assert.deepEqual(core.telethonSessionRows(account), core.telethonSessionRows(account, false))
    })
  }
})

test('telethonSessionRows keep the stored config text and its errors', () => {
  const config = unhex(CUSTOM_CONFIG)
  for (const [ipv6, text] of [
    [false, '203.0.113.2'],
    [true, '2001:db8::2'],
  ]) {
    const rows = core.telethonSessionRows(withConfig(2, config), ipv6)
    assert.deepEqual([rows.dcId, rows.serverAddress, rows.port], [2, text, 443])
    assertSame(rows.authKey, key, 'rows key')
  }
  assert.equal(core.telethonSessionRows(withConfig(3, config), true).serverAddress, '198.51.100.3')
  assert.equal(thrown(() => core.telethonSessionRows(withConfig(5, config))).code, 'OT_TDATA_BAD_CONFIG_DATA')
  // The string sessions take the stored config's endpoint too.
  assert.notEqual(core.telethonStringSession(withConfig(2, config)), core.telethonStringSession(withConfig(2)))
  assert.equal(
    thrown(() => core.telethonSessionRows({ index: 0, userId: 1n, mainDc: 7, authKey: key })).code,
    'OT_TDATA_BAD_CONFIG_DATA',
  )
  const keyless = { index: 0, userId: 1n, mainDc: 2, keys: [{ dcId: 4, authKey: key }] }
  assert.equal(thrown(() => core.telethonSessionRows(keyless)).code, 'OT_TDATA_AUTH_KEY_NOT_FOUND')
})

test('sessionPairPaths and sessionPath', () => {
  const cases = [
    ['acc', 'acc.session', 'acc.json'],
    ['acc.session', 'acc.session', 'acc.json'],
    ['acc.json', 'acc.session', 'acc.json'],
    ['acc.session.json', 'acc.session.session', 'acc.session.json'],
    ['acc.json.session', 'acc.session', 'acc.json'],
    ['dir/acc.session', 'dir/acc.session', 'dir/acc.json'],
    ['acc.SESSION', 'acc.SESSION.session', 'acc.SESSION.json'],
    ['.session', '.session', '.json'],
    ['acc.sessions', 'acc.sessions.session', 'acc.sessions.json'],
    ['a.session.session', 'a.session.session', 'a.session.json'],
    ['a.json.json', 'a.json.session', 'a.json.json'],
    ['', '.session', '.json'],
    ['dir/', 'dir/.session', 'dir/.json'],
    ['acc.session/', 'acc.session/.session', 'acc.session/.json'],
  ]
  for (const [base, session, json] of cases) {
    assert.deepEqual(core.sessionPairPaths(base), { session, json }, JSON.stringify(base))
  }
  for (const [given, full] of [
    ['acc', 'acc.session'],
    ['acc.session', 'acc.session'],
    ['acc.json', 'acc.json.session'],
    ['acc.SESSION', 'acc.SESSION.session'],
  ]) {
    assert.equal(core.sessionPath(given), full)
  }
})

test('sessionCompanionJson is the session JSON with the extra keys', () => {
  const profile = core.profile('TelegramDesktop')
  const json = core.sessionCompanionJson(profile, { session_file: 'acc', id: 77 })
  assert.deepEqual(json, core.profileToSessionJson(profile, { session_file: 'acc', id: 77 }))
  assert.equal(json.session_file, 'acc')
  assert.equal(json.id, 77)
  assert.deepEqual(Object.keys(json), Object.keys(core.profileToSessionJson(profile)))
  assert.equal(JSON.stringify(core.sessionCompanionJson(profile)), JSON.stringify(core.profileToSessionJson(profile)))
})
