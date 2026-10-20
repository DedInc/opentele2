// telethon.d.ts: types of the `opentele2/telethon` entry point (telethon.mjs).

import type { AccountInput, ApiProfile, SessionPairPaths, TelethonSessionRows } from './index.js'

/**
 * The `sessions` row `readSessionFile` returns: `TelethonSessionRows`, with
 * a `takeoutId` outside the safe integer range given as a `bigint`.
 */
export interface ReadSessionRows extends Omit<TelethonSessionRows, 'takeoutId'> {
  /** Takeout session id (`takeout_id`); absent is NULL. */
  takeoutId?: number | bigint
}

/** The rows `writeSessionFile` takes; `takeoutId` may be a 64-bit `bigint`. */
export interface WriteSessionRows extends Omit<TelethonSessionRows, 'authKey' | 'takeoutId'> {
  /** The 256-byte auth key (`auth_key`). */
  authKey: Uint8Array
  /** Takeout session id (`takeout_id`); absent or `null` is NULL. */
  takeoutId?: number | bigint | null
}

/** The options of `saveSessionPair`. */
export interface SaveSessionPairOptions {
  /** Write the main DC's IPv6 endpoint instead of its IPv4 one. */
  ipv6?: boolean
  /**
   * Keys of the `.json` companion after `session_file` (which they may
   * override); `id` defaults to the account's user id when it is not zero.
   */
  extra?: Record<string, unknown>
}

/** The pair `loadSessionPair` read. */
export interface LoadedSessionPair {
  /** The paths read, `sessionPairPaths(base)`. */
  paths: SessionPairPaths
  /** The sessions row of the `.session` file. */
  rows: ReadSessionRows
  /** The profile of the `.json` companion (`profileFromSessionJson`). */
  profile: ApiProfile
  /** The `.json` companion as parsed; an integer outside the safe range is a `bigint`. */
  json: Record<string, unknown>
}

/**
 * Writes `rows` as 1.5.0 `write_session_file` does and resolves to the file
 * path (`sessionPath(path)`): a schema that is not the version 8 layout is
 * rebuilt, then the version and sessions rows are replaced in one
 * transaction, over the native module's bundled SQLite. Rejects with
 * `OT_BAD_LENGTH` for a key that is not 256 bytes, `ERR_INVALID_ARG_VALUE`
 * for other bad rows and `OT_IO` when SQLite fails.
 */
export declare function writeSessionFile(path: string, rows: WriteSessionRows): Promise<string>

/**
 * Reads the sessions row of the version 8 file at `sessionPath(path)`,
 * written by 1.5.0, `writeSessionFile` or Telethon. Rejects with
 * `OT_TFILE_NOT_FOUND` when the file is
 * missing, `OT_IO` when it is not a database, `OT_QDATASTREAM_FAILED` for
 * another layout, version or column type, `OT_TDATA_AUTH_KEY_NOT_FOUND`
 * without a row or key, `OT_BAD_LENGTH` for a key that is not 256 bytes,
 * and `OT_TDATA_BAD_CONFIG_DATA` for a NULL or out-of-range DC, address or
 * port.
 */
export declare function readSessionFile(path: string): Promise<ReadSessionRows>

/**
 * Writes the `.session` + `.json` pair 1.5.0 `save_session_json` writes
 * and resolves to its paths: `telethonSessionRows(account, ipv6)` into the
 * session file and `sessionCompanionText(profile, extra)` (1.5.0's
 * two-space `json.dump` text) into the companion, `extra` starting with
 * `session_file`.
 */
export declare function saveSessionPair(
  base: string,
  account: AccountInput,
  profile: ApiProfile,
  options?: SaveSessionPairOptions,
): Promise<SessionPairPaths>

/**
 * Reads the pair at `sessionPairPaths(base)` back as 1.5.0
 * `from_session_json` does. Rejects with `OT_TFILE_NOT_FOUND` when either
 * file is missing, `OT_IO` when the companion is not a valid session JSON,
 * and the `readSessionFile` errors.
 */
export declare function loadSessionPair(base: string): Promise<LoadedSessionPair>
