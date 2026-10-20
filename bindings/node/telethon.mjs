// telethon.mjs: the `opentele2/telethon` entry point.
//
// Telethon `SQLiteSession` files (database version 8) and the `.session` +
// `.json` pair, written and read as 1.5.0 `src/tl/session_io.py` does. The
// file, the companion text and its reading are the native module's
// (crates/opentele2-core/src/session/telethon_file.rs over a bundled
// SQLite), so this module works on every supported Node.

import { readFile, stat, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const native = require('./index.js')

/** An `Error` with `code`, the shape the native module throws. */
function codedError(code, message, cause) {
  const error = new Error(message, cause === undefined ? undefined : { cause })
  error.code = code
  return error
}

/** Whether `file` is an existing regular file. */
async function isFile(file) {
  try {
    return (await stat(file)).isFile()
  } catch {
    return false
  }
}

function invalidRows(message) {
  return codedError('ERR_INVALID_ARG_VALUE', `rows.${message}`)
}

/** `rows` as the native `TelethonSessionRowsInput`, checked first. */
function sessionInput(rows) {
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
  // The key length (OT_BAD_LENGTH, with its legacyMessage) and the 64-bit
  // range of a bigint takeout id are the native module's checks, in that
  // order, as writeTelethonSessionFile makes them.
  const input = { dcId, serverAddress, port, authKey }
  if (takeoutId !== undefined && takeoutId !== null) {
    const wide = typeof takeoutId === 'bigint' ? takeoutId : Number.isSafeInteger(takeoutId) ? BigInt(takeoutId) : null
    if (wide === null) {
      throw invalidRows('takeoutId must be a 64-bit integer')
    }
    input.takeoutId = wide
  }
  return input
}

/**
 * Writes `rows` as 1.5.0 `write_session_file` does and resolves to the file
 * path (`sessionPath(path)`). A schema that is not already the version 8
 * layout is dropped and rebuilt; a current one keeps its tables and their
 * other rows. The version row becomes 8 and the sessions row `rows`, with
 * `tmp_auth_key` NULL, in one transaction.
 */
export async function writeSessionFile(path, rows) {
  const input = sessionInput(rows)
  return native.writeTelethonSessionFile(path, input)
}

/** A 64-bit id as a `number` when it is a safe integer, else the `bigint`. */
function safeId(id) {
  return id >= BigInt(Number.MIN_SAFE_INTEGER) && id <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(id) : id
}

/**
 * Reads the sessions row of the version 8 file at `sessionPath(path)`,
 * written by 1.5.0, by `writeSessionFile`, or by Telethon itself. Columns
 * are read by name and `tmp_auth_key` is not read. The file is opened
 * read-only; the error codes are those of the core's `read_session_file`.
 */
export async function readSessionFile(path) {
  const read = await native.readTelethonSessionFile(path)
  const rows = {
    dcId: read.dcId,
    serverAddress: read.serverAddress,
    port: read.port,
    authKey: read.authKey,
  }
  if (read.takeoutId !== undefined && read.takeoutId !== null) {
    rows.takeoutId = safeId(read.takeoutId)
  }
  return rows
}

/**
 * Writes the pair 1.5.0 `save_session_json` writes for `account` and
 * `profile`, and resolves to its paths (`sessionPairPaths(base)`): the
 * `.session` file holds `telethonSessionRows(account, ipv6)` and the `.json`
 * companion is `sessionCompanionText(profile, extra)`, where `extra` starts
 * with `session_file`, the file name of the pair's base path, then the
 * caller's `extra`, then `id`, the account's user id, when it is not zero
 * and `extra` has none.
 */
export async function saveSessionPair(base, account, profile, options = {}) {
  const { ipv6 = false, extra } = options ?? {}
  const paths = native.sessionPairPaths(base)
  const rows = native.telethonSessionRows(account, ipv6)
  await writeSessionFile(paths.session, rows)
  const fields = { session_file: native.sessionFileName(base), ...(extra ?? {}) }
  if (!('id' in fields) && account.userId !== undefined && BigInt(account.userId) !== 0n) {
    // A bigint id reaches the companion as its exact JSON integer.
    fields.id = BigInt(account.userId)
  }
  const text = native.sessionCompanionText(profile, fields)
  try {
    await writeFile(paths.json, text, 'utf8')
  } catch (cause) {
    throw codedError('OT_IO', `I/O error: cannot write ${paths.json}: ${cause.message}`, cause)
  }
  return paths
}

/**
 * Reads back the pair at `sessionPairPaths(base)` as 1.5.0
 * `from_session_json` does: both files must exist (`OT_TFILE_NOT_FOUND`),
 * the companion is read with `readSessionCompanion` (`OT_IO` when it is not
 * a valid session JSON; `profile` is `null` when its profile keys are not
 * the strict form, as the Python binding returns no profile), and the
 * session file with `readSessionFile`.
 */
export async function loadSessionPair(base) {
  const paths = native.sessionPairPaths(base)
  for (const file of [paths.session, paths.json]) {
    if (!(await isFile(file))) {
      throw codedError('OT_TFILE_NOT_FOUND', `tdata file not found: ${file}`)
    }
  }
  let companion
  try {
    companion = native.readSessionCompanion(await readFile(paths.json, 'utf8'))
  } catch (cause) {
    // Text that is not a session JSON object is OT_IO here, as before.
    throw codedError('OT_IO', `I/O error: invalid JSON file ${paths.json}: ${cause?.message ?? cause}`, cause)
  }
  const rows = await readSessionFile(paths.session)
  return { paths, rows, profile: companion.profile ?? null, json: companion.json }
}
