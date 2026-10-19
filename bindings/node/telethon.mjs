// telethon.mjs: the `opentele2/telethon` entry point.
//
// Telethon `SQLiteSession` files (database version 8) and the `.session` +
// `.json` pair, written and read as 1.5.0 `src/tl/session_io.py` does and
// as crates/opentele2-core/src/session/telethon_file.rs mirrors. The SQL is
// the native module's (`telethonSchema()` and the `TELETHON_*` statements),
// so it stays the text 1.5.0 runs.
//
// The database is Node's built-in `node:sqlite`, imported on first use, so
// loading this module works on every supported Node; the file functions
// reject with `OT_NODE_SQLITE_UNAVAILABLE` where `node:sqlite` cannot load
// (below Node 22.5, or 22.5 to 22.12 without `--experimental-sqlite`).

import { readFile, stat, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const native = require('./index.js')

const AUTH_KEY_SIZE = 256

/** An `Error` with `code`, the shape the native module throws. */
function codedError(code, message, cause) {
  const error = new Error(message, cause === undefined ? undefined : { cause })
  error.code = code
  return error
}

let sqliteModule

/** `node:sqlite`, loaded once, or a rejection with `OT_NODE_SQLITE_UNAVAILABLE`. */
async function loadSqlite() {
  if (sqliteModule === undefined) {
    try {
      sqliteModule = await import('node:sqlite')
    } catch (cause) {
      throw codedError(
        'OT_NODE_SQLITE_UNAVAILABLE',
        `opentele2/telethon needs node:sqlite (Node >= 22.5; 22.5 to 22.12 need --experimental-sqlite), and Node ${process.versions.node} cannot load it`,
        cause,
      )
    }
  }
  return sqliteModule
}

/** A SQLite failure as the core's `OT_IO`; coded errors pass through. */
function ioError(cause, file) {
  if (typeof cause?.code === 'string' && cause.code.startsWith('OT_')) {
    return cause
  }
  return codedError('OT_IO', `I/O error: SQLite failed on ${file}: ${cause?.message ?? cause}`, cause)
}

/** Whether `file` is an existing regular file. */
async function isFile(file) {
  try {
    return (await stat(file)).isFile()
  } catch {
    return false
  }
}

/** Whether every table of the schema exists with its version 8 columns (1.5.0 `_schema_is_current`). */
function schemaIsCurrent(db, schema) {
  const present = new Set(
    db
      .prepare("select name from sqlite_master where type='table'")
      .all()
      .map((row) => row.name),
  )
  if (!schema.every((table) => present.has(table.name))) {
    return false
  }
  return schema.every((table) => {
    const columns = db
      .prepare(`pragma table_info(${table.name})`)
      .all()
      .map((row) => row.name)
    return columns.length === table.columns.length && columns.every((name, n) => name === table.columns[n])
  })
}

function invalidRows(message) {
  return codedError('ERR_INVALID_ARG_VALUE', `rows.${message}`)
}

/** The values of `rows` in `TELETHON_INSERT_SESSION` order, checked first. */
function sessionValues(rows) {
  if (rows === null || typeof rows !== 'object') {
    throw codedError('ERR_INVALID_ARG_VALUE', 'rows must be a TelethonSessionRows object')
  }
  const { dcId, serverAddress, port, authKey, takeoutId } = rows
  if (!Number.isInteger(dcId) || dcId < -(2 ** 31) || dcId >= 2 ** 31) {
    throw invalidRows('dcId must be a 32-bit integer')
  }
  if (typeof serverAddress !== 'string') {
    throw invalidRows('serverAddress must be a string')
  }
  if (!Number.isInteger(port) || port < 0 || port > 0xffff) {
    throw invalidRows('port must be an integer in 0..65535')
  }
  if (!(authKey instanceof Uint8Array)) {
    throw invalidRows('authKey must be a Uint8Array')
  }
  if (authKey.length !== AUTH_KEY_SIZE) {
    throw codedError('OT_BAD_LENGTH', `auth key has a bad length: expected ${AUTH_KEY_SIZE}, got ${authKey.length}`)
  }
  let takeout = null
  if (takeoutId !== undefined && takeoutId !== null) {
    const wide = typeof takeoutId === 'bigint' ? takeoutId : Number.isSafeInteger(takeoutId) ? BigInt(takeoutId) : null
    if (wide === null || BigInt.asIntN(64, wide) !== wide) {
      throw invalidRows('takeoutId must be a 64-bit integer')
    }
    takeout = wide
  }
  return [dcId, serverAddress, port, authKey, takeout, null]
}

/**
 * Writes `rows` as 1.5.0 `write_session_file` does and resolves to the file
 * path (`sessionPath(path)`). A schema that is not already the version 8
 * layout is dropped and rebuilt; a current one keeps its tables and their
 * other rows. The version row becomes 8 and the sessions row `rows`, with
 * `tmp_auth_key` NULL, in one transaction.
 */
export async function writeSessionFile(path, rows) {
  const values = sessionValues(rows)
  const { DatabaseSync } = await loadSqlite()
  const file = native.sessionPath(path)
  const schema = native.telethonSchema()
  let db
  try {
    db = new DatabaseSync(file)
    db.exec('begin')
    try {
      if (!schemaIsCurrent(db, schema)) {
        for (const table of schema) {
          db.exec(`drop table if exists ${table.name}`)
        }
        for (const table of schema) {
          db.exec(table.ddl)
        }
      }
      db.prepare(native.TELETHON_DELETE_VERSION).run()
      db.prepare(native.TELETHON_INSERT_VERSION).run(native.TELETHON_SESSION_VERSION)
      db.prepare(native.TELETHON_DELETE_SESSIONS).run()
      db.prepare(native.TELETHON_INSERT_SESSION).run(...values)
      db.exec('commit')
    } catch (error) {
      try {
        db.exec('rollback')
      } catch {
        // The failed statement already ended the transaction.
      }
      throw error
    }
  } catch (error) {
    throw ioError(error, file)
  } finally {
    db?.close()
  }
  return file
}

/** The value of `column` in `row` with the SQLite type the select reported for it. */
function typed(row, column) {
  return { type: row[`${column}_type`], value: row[column] }
}

const qdata = (what) => codedError('OT_QDATASTREAM_FAILED', `QDataStream operation failed: ${what}`)
const badConfig = (what) => codedError('OT_TDATA_BAD_CONFIG_DATA', `tdata config data is bad: ${what}`)

/** The checked rows of the first `sessions` row, in the core's check order. */
function sessionRows(row) {
  const authKey = typed(row, 'auth_key')
  if (authKey.type === 'null' || (authKey.type === 'blob' && authKey.value.length === 0)) {
    throw codedError('OT_TDATA_AUTH_KEY_NOT_FOUND', 'tdata auth key not found: the sessions row has no auth key')
  }
  if (authKey.type !== 'blob') {
    throw qdata('auth_key is not a blob')
  }
  if (authKey.value.length !== AUTH_KEY_SIZE) {
    throw codedError(
      'OT_BAD_LENGTH',
      `auth key has a bad length: expected ${AUTH_KEY_SIZE}, got ${authKey.value.length}`,
    )
  }
  const dcId = typed(row, 'dc_id')
  if (dcId.type === 'null') {
    throw badConfig('dc_id is NULL')
  }
  if (dcId.type !== 'integer') {
    throw qdata('dc_id is not an integer')
  }
  if (BigInt.asIntN(32, dcId.value) !== dcId.value) {
    throw badConfig('dc_id is out of range')
  }
  const address = typed(row, 'server_address')
  if (address.type === 'null') {
    throw badConfig('server_address is NULL')
  }
  if (address.type !== 'text') {
    throw qdata('server_address is not text')
  }
  const port = typed(row, 'port')
  if (port.type === 'null') {
    throw badConfig('port is NULL')
  }
  if (port.type !== 'integer') {
    throw qdata('port is not an integer')
  }
  if (port.value < 0n || port.value > 0xffffn) {
    throw badConfig('port is out of range')
  }
  const takeout = typed(row, 'takeout_id')
  if (takeout.type !== 'null' && takeout.type !== 'integer') {
    throw qdata('takeout_id is not an integer')
  }
  const rows = {
    dcId: Number(dcId.value),
    serverAddress: address.value,
    port: Number(port.value),
    authKey: Buffer.from(authKey.value),
  }
  if (takeout.type === 'integer') {
    const id = takeout.value
    rows.takeoutId = id >= BigInt(Number.MIN_SAFE_INTEGER) && id <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(id) : id
  }
  return rows
}

const SESSION_SELECT =
  'select dc_id, typeof(dc_id) as dc_id_type, server_address, typeof(server_address) as server_address_type, ' +
  'port, typeof(port) as port_type, auth_key, typeof(auth_key) as auth_key_type, ' +
  'takeout_id, typeof(takeout_id) as takeout_id_type from sessions'

/**
 * Reads the sessions row of the version 8 file at `sessionPath(path)`,
 * written by 1.5.0, by `writeSessionFile`, or by Telethon itself. Columns
 * are read by name and `tmp_auth_key` is not read. The file is opened
 * read-only; the error codes are those of the core's `read_session_file`.
 */
export async function readSessionFile(path) {
  const { DatabaseSync } = await loadSqlite()
  const file = native.sessionPath(path)
  if (!(await isFile(file))) {
    throw codedError('OT_TFILE_NOT_FOUND', `tdata file not found: ${file}`)
  }
  let db
  try {
    db = new DatabaseSync(file, { readOnly: true })
    if (!schemaIsCurrent(db, native.telethonSchema())) {
      throw qdata('the tables are not the version 8 layout')
    }
    const version = db.prepare('select version, typeof(version) as version_type from version')
    version.setReadBigInts(true)
    const stamp = version.get()
    if (stamp?.version_type !== 'integer' || stamp.version !== BigInt(native.TELETHON_SESSION_VERSION)) {
      throw qdata(`the version row is not ${native.TELETHON_SESSION_VERSION}`)
    }
    const select = db.prepare(SESSION_SELECT)
    select.setReadBigInts(true)
    const row = select.get()
    if (row === undefined) {
      throw codedError('OT_TDATA_AUTH_KEY_NOT_FOUND', 'tdata auth key not found: the file has no sessions row')
    }
    return sessionRows(row)
  } catch (error) {
    throw ioError(error, file)
  } finally {
    db?.close()
  }
}

/**
 * The last component of `base` as Python's `os.path.basename` gives it:
 * the text after the last separator (`/`, and `\` and a drive on Windows),
 * empty when `base` ends with one.
 */
function pythonBasename(base) {
  let text = base
  if (process.platform === 'win32') {
    text = text.replace(/^[A-Za-z]:/, '')
    return text.slice(Math.max(text.lastIndexOf('/'), text.lastIndexOf('\\')) + 1)
  }
  return text.slice(text.lastIndexOf('/') + 1)
}

/** `json` as JSON text with two-space indentation, a `bigint` as its exact digits. */
function companionText(json) {
  const marks = []
  const text = JSON.stringify(
    json,
    (_key, value) => {
      if (typeof value === 'bigint') {
        marks.push(value.toString())
        return `\u0000bigint${marks.length - 1}\u0000`
      }
      return value
    },
    2,
  )
  return text.replace(/"\\u0000bigint(\d+)\\u0000"/g, (_match, n) => marks[Number(n)])
}

/** A user id as the companion's `id`: a `number` when exact, else the `bigint`. */
function jsonId(userId) {
  const id = BigInt(userId)
  return id <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(id) : id
}

/**
 * Writes the pair 1.5.0 `save_session_json` writes for `account` and
 * `profile`, and resolves to its paths (`sessionPairPaths(base)`): the
 * `.session` file holds `telethonSessionRows(account, ipv6)` and the `.json`
 * companion is `sessionCompanionJson(profile, extra)` with two-space
 * indentation, where `extra` starts with `session_file`, the file name of
 * the pair's base path, then the caller's `extra`, then `id`, the account's
 * user id, when it is not zero and `extra` has none.
 */
export async function saveSessionPair(base, account, profile, options = {}) {
  const { ipv6 = false, extra } = options ?? {}
  const paths = native.sessionPairPaths(base)
  const rows = native.telethonSessionRows(account, ipv6)
  await writeSessionFile(paths.session, rows)
  const stem = paths.session.slice(0, -native.TELETHON_SESSION_SUFFIX.length)
  const fields = { session_file: pythonBasename(stem), ...(extra ?? {}) }
  if (!('id' in fields) && account.userId !== undefined && BigInt(account.userId) !== 0n) {
    fields.id = jsonId(account.userId)
  }
  // The native companion takes JSON values; a bigint id is set afterwards
  // in the key position the native builder gave it.
  const wide = typeof fields.id === 'bigint' ? fields.id : undefined
  const json = native.sessionCompanionJson(profile, wide === undefined ? fields : { ...fields, id: 0 })
  if (wide !== undefined) {
    json.id = wide
  }
  try {
    await writeFile(paths.json, companionText(json), 'utf8')
  } catch (cause) {
    throw codedError('OT_IO', `I/O error: cannot write ${paths.json}: ${cause.message}`, cause)
  }
  return paths
}

/**
 * Reads back the pair at `sessionPairPaths(base)` as 1.5.0
 * `from_session_json` does: both files must exist (`OT_TFILE_NOT_FOUND`),
 * the companion is read with `profileFromSessionJson` (`OT_IO` when it is
 * not valid JSON or lacks a required field), and the session file with
 * `readSessionFile`.
 */
export async function loadSessionPair(base) {
  const paths = native.sessionPairPaths(base)
  for (const file of [paths.session, paths.json]) {
    if (!(await isFile(file))) {
      throw codedError('OT_TFILE_NOT_FOUND', `tdata file not found: ${file}`)
    }
  }
  let text
  let json
  try {
    text = await readFile(paths.json, 'utf8')
    json = JSON.parse(text)
  } catch (cause) {
    throw codedError('OT_IO', `I/O error: invalid JSON file ${paths.json}: ${cause.message}`, cause)
  }
  if (json === null || typeof json !== 'object' || Array.isArray(json)) {
    throw codedError('OT_IO', `I/O error: ${paths.json} does not hold a JSON object`)
  }
  const profile = native.profileFromSessionJson(text)
  const rows = await readSessionFile(paths.session)
  return { paths, rows, profile, json }
}
