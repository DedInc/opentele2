// telethon_sqlite.test.mjs: `opentele2/telethon` files and pairs over
// node:sqlite against crates/opentele2-core/tests/session.rs (the 1.5.0
// dump and the Telethon-written fixture). Keys are synthetic and never
// printed: dumps mask them and comparisons go through assertSame.

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { assertSame, core, rejection } from './helpers.mjs'
import { loadSessionPair, readSessionFile, saveSessionPair, writeSessionFile } from '../telethon.mjs'

const sqlite = await import('node:sqlite').catch(() => null)
const skip = sqlite === null ? `node:sqlite cannot load on Node ${process.versions.node} (needs >= 22.5)` : false

const FIXTURE = fileURLToPath(
  new URL('../../../crates/opentele2-core/tests/fixtures/telethon_v8.session', import.meta.url),
)

/**
 * V150_DUMP of crates/opentele2-core/tests/session.rs: Python `sqlite3`
 * `iterdump()` of the file 1.5.0 writes with
 * `write_session_file(base, 2, "149.154.167.51", 443, bytes(range(256)))`,
 * the key blob masked as `<KEY>`.
 */
const V150_DUMP = [
  'BEGIN TRANSACTION;',
  'CREATE TABLE entities (id integer primary key, hash integer not null, username text, phone integer, name text, date integer);',
  'CREATE TABLE sent_files (md5_digest blob, file_size integer, type integer, id integer, hash integer, primary key(md5_digest, file_size, type));',
  'CREATE TABLE sessions (dc_id integer primary key, server_address text, port integer, auth_key blob, takeout_id integer, tmp_auth_key blob);',
  `INSERT INTO "sessions" VALUES(2,'149.154.167.51',443,X'<KEY>',NULL,NULL);`,
  'CREATE TABLE update_state (id integer primary key, pts integer, qts integer, date integer, seq integer);',
  'CREATE TABLE version (version integer primary key);',
  'INSERT INTO "version" VALUES(8);',
  'COMMIT;',
]

const IPV6_DC5 = '2001:0b28:f23f:f005:0000:0000:0000:000a'
const IPV6_DC2 = '2001:067c:04e8:f002:0000:0000:0000:000a'

/** A key whose byte `i` is `i + offset` (session.rs `counting_key`). */
const countingKey = (offset) => Buffer.from(Array.from({ length: 256 }, (_, i) => (i + offset) & 0xff))
/** The fixture's key: byte `i` is `255 - i`. */
const fixtureKey = () => Buffer.from(Array.from({ length: 256 }, (_, i) => 255 - i))

const rows = (dcId, serverAddress, authKey, takeoutId) => ({ dcId, serverAddress, port: 443, authKey, takeoutId })

const root = mkdtempSync(path.join(tmpdir(), 'opentele2-telethon-'))
after(() => rmSync(root, { recursive: true, force: true }))
let scratchCount = 0
/** A fresh directory for one test. */
const scratch = () => mkdtempSync(path.join(root, `${scratchCount++}-`))

/** Python `iterdump()` for tables, as session.rs `dump`, with `key`'s blob masked. */
function dump(file, key) {
  const db = new sqlite.DatabaseSync(file)
  try {
    const lines = ['BEGIN TRANSACTION;']
    const tables = db
      .prepare("SELECT name, sql FROM sqlite_master WHERE sql NOT NULL AND type == 'table' ORDER BY name")
      .all()
    for (const { name, sql } of tables) {
      lines.push(`${sql};`)
      const columns = db
        .prepare(`pragma table_info("${name}")`)
        .all()
        .map((row) => row.name)
      const values = columns.map((column) => `'||quote("${column}")||'`).join(',')
      const query = `SELECT 'INSERT INTO "${name}" VALUES(${values})' AS line FROM "${name}"`
      lines.push(...db.prepare(query).all().map((row) => `${row.line};`))
    }
    lines.push('COMMIT;')
    const blob = `X'${Buffer.from(key).toString('hex').toUpperCase()}'`
    assert.ok(
      lines.some((line) => line.includes(blob)),
      'dump holds no blob of the key',
    )
    return lines.map((line) => line.replaceAll(blob, "X'<KEY>'"))
  } finally {
    db.close()
  }
}

const inserts = (lines) => lines.filter((line) => line.startsWith('INSERT'))
const creates = (lines) => lines.filter((line) => line.startsWith('CREATE'))

function checkRows(got, want, label) {
  assert.deepEqual(
    [got.dcId, got.serverAddress, got.port, got.takeoutId],
    [want.dcId, want.serverAddress, want.port, want.takeoutId],
    label,
  )
  assert.ok(Buffer.isBuffer(got.authKey), `${label} key is a Buffer`)
  assertSame(got.authKey, want.authKey, `${label} key`)
}

/** Runs `fn` on the database at `file`. */
function withDb(file, fn) {
  const db = new sqlite.DatabaseSync(file)
  try {
    fn(db)
  } finally {
    db.close()
  }
}

const code = async (promise) => (await rejection(promise)).code

test('a written file dumps as 1.5.0 writes it', { skip }, async () => {
  const dir = scratch()
  const file = await writeSessionFile(path.join(dir, 'v150'), rows(2, '149.154.167.51', countingKey(0)))
  assert.equal(file, path.join(dir, 'v150.session'))
  assert.deepEqual(dump(file, countingKey(0)), V150_DUMP)
})

test('a pre-v8 file is rebuilt as 1.5.0 does', { skip }, async () => {
  const file = path.join(scratch(), 'old.session')
  withDb(file, (db) =>
    db.exec(
      `create table version (version integer primary key);
       insert into version values (7);
       create table sessions (dc_id integer primary key, server_address text, port integer, auth_key blob, takeout_id integer);
       insert into sessions values (1, 'x', 1, x'00', 5);`,
    ),
  )
  await writeSessionFile(file, rows(2, '149.154.167.51', countingKey(0)))
  assert.deepEqual(dump(file, countingKey(0)), V150_DUMP)
})

test('write then read round trips', { skip }, async () => {
  const dir = scratch()
  const first = rows(2, '149.154.167.51', countingKey(0))
  const file = await writeSessionFile(path.join(dir, 'acc.session'), first)
  assert.equal(file, path.join(dir, 'acc.session'))
  checkRows(await readSessionFile(file), first, 'read')
  // Without the suffix the reader finds the same file.
  checkRows(await readSessionFile(path.join(dir, 'acc')), first, 'read without suffix')
  assert.equal('takeoutId' in (await readSessionFile(file)), false)

  // Rewriting a current file replaces its one sessions row.
  const second = rows(5, IPV6_DC5, countingKey(3), -42)
  await writeSessionFile(file, second)
  checkRows(await readSessionFile(file), second, 'reread')
  assert.deepEqual(inserts(dump(file, countingKey(3))), [
    `INSERT INTO "sessions" VALUES(5,'${IPV6_DC5}',443,X'<KEY>',-42,NULL);`,
    'INSERT INTO "version" VALUES(8);',
  ])

  // A 64-bit takeout id outside the safe range stays exact.
  await writeSessionFile(file, rows(5, IPV6_DC5, countingKey(3), -(2n ** 63n)))
  assert.equal((await readSessionFile(file)).takeoutId, -(2n ** 63n))
  // The rows telethonSessionRows builds go straight in.
  const account = { index: 0, userId: 77n, mainDc: 4, authKey: countingKey(1) }
  const native = core.telethonSessionRows(account, true)
  checkRows(await readSessionFile(await writeSessionFile(file, native)), native, 'native rows')
})

test('reads the Telethon-written v8 fixture without changing it', { skip }, async () => {
  const before = readFileSync(FIXTURE)
  checkRows(await readSessionFile(FIXTURE), rows(4, '149.154.167.91', fixtureKey(), 1234567), 'fixture')
  assert.ok(readFileSync(FIXTURE).equals(before), 'fixture modified')
})

test('writing over the fixture keeps its schema as 1.5.0 does', { skip }, async () => {
  const file = path.join(scratch(), 'over.session')
  copyFileSync(FIXTURE, file)
  const telethonSchema = creates(dump(file, fixtureKey()))
  assert.ok(
    telethonSchema.some((line) => line.includes('\n')),
    'Telethon writes multi-line DDL',
  )
  const written = rows(2, IPV6_DC2, countingKey(0))
  await writeSessionFile(file, written)
  const lines = dump(file, countingKey(0))
  assert.deepEqual(creates(lines), telethonSchema, 'schema kept')
  assert.deepEqual(inserts(lines), [
    `INSERT INTO "sessions" VALUES(2,'${IPV6_DC2}',443,X'<KEY>',NULL,NULL);`,
    'INSERT INTO "version" VALUES(8);',
  ])
  checkRows(await readSessionFile(file), written, 'over fixture')
})

test('read errors carry the core codes', { skip }, async () => {
  const dir = scratch()
  assert.equal(await code(readSessionFile(path.join(dir, 'missing'))), 'OT_TFILE_NOT_FOUND')

  const text = path.join(dir, 'text.session')
  writeFileSync(text, 'not a database, just text that is long enough')
  assert.equal(await code(readSessionFile(text)), 'OT_IO')

  const file = path.join(dir, 'empty.session')
  await writeSessionFile(file, rows(2, '149.154.167.51', countingKey(0)))
  const expect = async (sql, want, ...params) => {
    withDb(file, (db) => db.prepare(sql).run(...params))
    assert.equal(await code(readSessionFile(file)), want, sql)
  }
  await expect('delete from sessions', 'OT_TDATA_AUTH_KEY_NOT_FOUND')
  await expect(
    "insert into sessions values (2, '149.154.167.51', 443, x'', null, x'')",
    'OT_TDATA_AUTH_KEY_NOT_FOUND',
  )
  await expect("update sessions set auth_key = x'0102'", 'OT_BAD_LENGTH')
  await expect("update sessions set auth_key = 'text'", 'OT_QDATASTREAM_FAILED')
  await expect('update sessions set auth_key = ?, port = 70000', 'OT_TDATA_BAD_CONFIG_DATA', countingKey(0))
  await expect('update sessions set port = null', 'OT_TDATA_BAD_CONFIG_DATA')
  // Text that does not look numeric keeps the TEXT type in an integer column.
  await expect("update sessions set port = 'port'", 'OT_QDATASTREAM_FAILED')
  await expect('update sessions set port = 443, server_address = null', 'OT_TDATA_BAD_CONFIG_DATA')
  await expect("update sessions set server_address = x'00'", 'OT_QDATASTREAM_FAILED')
  await expect("update sessions set server_address = '149.154.167.51', dc_id = 4294967296", 'OT_TDATA_BAD_CONFIG_DATA')
  await expect("update sessions set dc_id = 2, takeout_id = 'x'", 'OT_QDATASTREAM_FAILED')
  withDb(file, (db) => db.exec('update sessions set takeout_id = null'))
  checkRows(await readSessionFile(file), rows(2, '149.154.167.51', countingKey(0)), 'repaired')
  await expect('update version set version = 7', 'OT_QDATASTREAM_FAILED')
  await expect('delete from version', 'OT_QDATASTREAM_FAILED')
  withDb(file, (db) => db.exec('insert into version values (8)'))
  await expect('alter table sessions drop column tmp_auth_key', 'OT_QDATASTREAM_FAILED')
})

test('bad rows are refused before the file is opened', { skip }, async () => {
  const file = path.join(scratch(), 'bad.session')
  assert.equal(await code(writeSessionFile(file, rows(2, 'x', Buffer.alloc(255)))), 'OT_BAD_LENGTH')
  for (const bad of [
    null,
    { ...rows(2, 'x', countingKey(0)), dcId: 1.5 },
    { ...rows(2, 'x', countingKey(0)), serverAddress: 7 },
    { ...rows(2, 'x', countingKey(0)), port: 65536 },
    { ...rows(2, 'x', countingKey(0)), authKey: 'key' },
    rows(2, 'x', countingKey(0), 2n ** 63n),
    rows(2, 'x', countingKey(0), 2 ** 60),
  ]) {
    assert.equal(await code(writeSessionFile(file, bad)), 'ERR_INVALID_ARG_VALUE')
  }
  assert.equal(existsSync(file), false)
})

const ACCOUNT = { index: 0, userId: 77n, mainDc: 2, authKey: countingKey(0) }
const companion = (extra) => JSON.stringify(core.sessionCompanionJson(core.profile('TelegramDesktop'), extra), null, 2)

test('saveSessionPair writes the 1.5.0 pair at the normalised paths', { skip }, async () => {
  const dir = scratch()
  const profile = core.profile('TelegramDesktop')
  for (const given of ['acc', 'acc.session', 'acc.json', 'acc.json.session']) {
    const paths = await saveSessionPair(path.join(dir, given), ACCOUNT, profile)
    assert.deepEqual(paths, { session: path.join(dir, 'acc.session'), json: path.join(dir, 'acc.json') }, given)
    assert.equal(readFileSync(paths.json, 'utf8'), companion({ session_file: 'acc', id: 77 }), given)
    checkRows(await readSessionFile(paths.session), core.telethonSessionRows(ACCOUNT), given)
    assert.deepEqual(inserts(dump(paths.session, countingKey(0))), inserts(V150_DUMP))
  }
  // Forward slashes are separators everywhere, as for Python's basename.
  const nested = await saveSessionPair(`${dir}/acc.session.json`, ACCOUNT, profile)
  assert.deepEqual(nested, core.sessionPairPaths(`${dir}/acc.session.json`))
  assert.equal(readFileSync(nested.json, 'utf8'), companion({ session_file: 'acc.session', id: 77 }))
})

test('saveSessionPair options, ids and loadSessionPair', { skip }, async () => {
  const dir = scratch()
  const profile = core.profile('TelegramAndroid')
  const base = path.join(dir, 'acc')
  const paths = await saveSessionPair(base, ACCOUNT, profile, { ipv6: true, extra: { id: 5, phone: '15550100' } })
  assert.equal(
    readFileSync(paths.json, 'utf8'),
    JSON.stringify(core.sessionCompanionJson(profile, { session_file: 'acc', id: 5, phone: '15550100' }), null, 2),
  )
  const loaded = await loadSessionPair(`${base}.json`)
  assert.deepEqual(loaded.paths, paths)
  checkRows(loaded.rows, rows(2, IPV6_DC2, countingKey(0)), 'loaded')
  assert.deepEqual(loaded.profile, core.profileFromSessionJson(readFileSync(paths.json, 'utf8')))
  assert.ok(core.profilesEqual(loaded.profile, profile))
  assert.equal(loaded.json.id, 5)
  assert.equal(loaded.json.session_file, 'acc')

  // A zero user id writes no id; a wide one keeps its digits.
  await saveSessionPair(base, { ...ACCOUNT, userId: 0n }, core.profile('TelegramDesktop'))
  assert.equal(readFileSync(paths.json, 'utf8'), companion({ session_file: 'acc' }))
  await saveSessionPair(base, { ...ACCOUNT, userId: 2n ** 60n + 1n }, core.profile('TelegramDesktop'))
  const wide = readFileSync(paths.json, 'utf8')
  assert.equal(wide, companion({ session_file: 'acc', id: 1 }).replace('"id": 1,', '"id": 1152921504606846977,'))

  // Both files must exist, and the companion must be session JSON.
  rmSync(paths.json)
  assert.equal(await code(loadSessionPair(base)), 'OT_TFILE_NOT_FOUND')
  writeFileSync(paths.json, '{"app_id": ')
  assert.equal(await code(loadSessionPair(base)), 'OT_IO')
  writeFileSync(paths.json, '{"app_id": 1}')
  assert.equal(await code(loadSessionPair(base)), 'OT_IO')
  rmSync(paths.session)
  assert.equal(await code(loadSessionPair(base)), 'OT_TFILE_NOT_FOUND')
})

const [major, minor] = process.versions.node.split('.').map(Number)
const flagSkip = major > 22 || (major === 22 && minor >= 13) ? false : 'needs Node >= 22.13 for --no-experimental-sqlite'

test('the file functions reject with OT_NODE_SQLITE_UNAVAILABLE without node:sqlite', { skip: flagSkip }, () => {
  const probe = fileURLToPath(new URL('./sqlite_unavailable.fixture.mjs', import.meta.url))
  const child = spawnSync(process.execPath, ['--no-experimental-sqlite', probe], { encoding: 'utf8' })
  assert.equal(child.status, 0, child.stderr)
  assert.deepEqual(JSON.parse(child.stdout), {
    loaded: true,
    write: 'OT_NODE_SQLITE_UNAVAILABLE',
    read: 'OT_NODE_SQLITE_UNAVAILABLE',
    pair: 'OT_NODE_SQLITE_UNAVAILABLE',
  })
})
