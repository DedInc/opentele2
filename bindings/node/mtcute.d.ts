// mtcute.d.ts: types of the `opentele2/mtcute` entry point (mtcute.mjs).

import type { tl } from '@mtcute/core'
import type { ICryptoProvider } from '@mtcute/core/utils.js'

import type { AccountInput, ApiProfile, CheckResult, SessionRow, TData, Versions } from './index.js'

/** The `initConnection` fields mtcute's `initConnectionOptions` accepts. */
export interface InitConnectionOptions {
  deviceModel: string
  systemVersion: string
  appVersion: string
  systemLangCode: string
  langPack: string
  langCode: string
}

/**
 * The mtcute v3 string session of `account`, for `client.importSession()`
 * or the `TelegramClient` constructor's session string.
 */
export declare function toStringSession(account: AccountInput): string

/**
 * The `initConnectionOptions` mtcute's `TelegramClient` takes, from an
 * opentele2 `profile()` or `generate()` result; pass `profile.apiId` and
 * `profile.apiHash` to the client separately.
 */
export declare function initConnectionOptions(profile: ApiProfile): InitConnectionOptions

/**
 * mtcute's default Node crypto provider with only `createAesIge` replaced
 * by the opentele2 core. Rejects with code `ERR_MODULE_NOT_FOUND` when
 * `@mtcute/node` is not installed.
 */
export declare function createCryptoProvider(): Promise<ICryptoProvider>

/**
 * The part of an mtcute `TelegramClient` the flows use. Only `call` is
 * required everywhere; a fake that answers it with canned TL objects
 * drives every flow.
 */
export interface FlowClient {
  /** mtcute's raw TL call: resolves to the answer, rejects with `tl.RpcError`. */
  call(request: { _: string; [field: string]: unknown }): Promise<any>
  /** The primary DC; with `changePrimaryDc`, used to align the new client's DC. */
  getPrimaryDcId?(): Promise<number>
  /** Moves the client to `dcId`; required for a QR login DC migration. */
  changePrimaryDc?(dcId: number): Promise<void>
  /** Told about every login the flows complete. */
  notifyLoggedIn?(authorization: tl.auth.TypeAuthorization): Promise<unknown>
  /** The self user; `users.getUsers([inputUserSelf])` without it. */
  getMe?(): Promise<{ id: number | bigint }>
  /** The mtcute v3 string session; required by `tdataFromClient`. */
  exportSession?(): Promise<string>
  /** Server updates; the QR login waits on it for `updateLoginToken`. */
  onServerUpdate?: {
    add(listener: (update: tl.TypeUpdates) => void): void
    remove(listener: (update: tl.TypeUpdates) => void): void
  }
}

/** How many QR login attempts `qrLoginToNewClient` makes (5). */
export declare const QR_LOGIN_ATTEMPTS: number

/** The 1.5.0 message of the `OT_QR_LOGIN_TIMEOUT` rejection. */
export declare const QR_LOGIN_TIMEOUT: string

/** The 1.5.0 message of the `OT_USER_ID_UNRESOLVED` rejection. */
export declare const USER_ID_UNRESOLVED: string

/**
 * The delay range `[minMs, maxMs]` before each 1.5.0 post-login request,
 * `null` for none, in request order.
 */
export declare const POST_LOGIN_DELAYS_MS: ReadonlyArray<readonly [number, number] | null>

/** Waits before a post-login request; 1.5.0 sleeps a random whole ms in `[minMs, maxMs]`. */
export type PostLoginDelay = (minMs: number, maxMs: number) => Promise<void>

/** Options of `qrLoginToNewClient`. */
export interface QrLoginOptions {
  /** API id sent with `auth.exportLoginToken`; default `profile.apiId`. */
  apiId?: number
  /** API hash sent with `auth.exportLoginToken`; default `profile.apiHash`. */
  apiHash?: string
  /** The 2FA password; without it a 2FA account rejects with `OT_NO_PASSWORD_PROVIDED`. */
  password?: string
  /** The new client's profile; its `langPack` drives the post-login requests. */
  profile?: ApiProfile
  /** Whether to send the 1.5.0 post-login requests; default `true`. */
  postLogin?: boolean
  /** The wait before each post-login request; a random sleep by default. */
  delay?: PostLoginDelay
  /** Receives each exported token's `qrLoginUrl` and expiry before it is accepted. */
  onUrl?: (url: string, expires: Date | null) => void
}

/** What `qrLoginToNewClient` resolves to. */
export interface QrLoginResult<C extends FlowClient = FlowClient> {
  /** The new, now authorised client. */
  client: C
  /** The user id it is logged in as. */
  userId: number
}

/**
 * Logs `fresh`, a client with empty storage, in through the authorised
 * `authorized` by QR login, as 1.5.0 `QRLoginToNewClient`: DC alignment,
 * `auth.exportLoginToken` on `fresh` (following `loginTokenMigrateTo` to
 * `auth.importLoginToken`), `auth.acceptLoginToken` on `authorized`, 2FA
 * through `account.getPassword` and the native `srpCheck`, then the
 * post-login requests.
 *
 * Rejects with code `OT_NO_PASSWORD_PROVIDED`, `OT_PASSWORD_INCORRECT`,
 * `OT_UNSUPPORTED_PASSWORD_ALGORITHM`, `OT_QR_LOGIN_TIMEOUT`,
 * `OT_SIGN_UP_REQUIRED`, `OT_SESSION_EXISTS` (an authorised `fresh` with
 * another api id) or the mtcute `RpcError` (`AUTH_TOKEN_*` included).
 */
export declare function qrLoginToNewClient<C extends FlowClient>(
  authorized: FlowClient,
  fresh: C,
  options: QrLoginOptions,
): Promise<QrLoginResult<C>>

/**
 * 1.5.0 `_run_post_login_requests` on `client`; resolves to how many of
 * the requests failed (failures are ignored).
 */
export declare function postLoginRequests(client: FlowClient, langPack?: string, delay?: PostLoginDelay): Promise<number>

/** Telethon `is_user_authorized`: whether `updates.getState` succeeds. */
export declare function isAuthorized(client: FlowClient): Promise<boolean>

/** The self user id; rejects with `OT_USER_ID_UNRESOLVED` without one. */
export declare function getMeId(client: FlowClient): Promise<number>

/**
 * 1.5.0 `GetSessions` (`account.getAuthorizations`); rejects with
 * `OT_SESSIONS_UNAVAILABLE` when the answer holds no list.
 */
export declare function getSessions(client: FlowClient): Promise<tl.account.RawAuthorizations>

/** 1.5.0 `GetCurrentSession`: the session flagged `current`, else `null`. */
export declare function getCurrentSession(client: FlowClient): Promise<tl.RawAuthorization | null>

/**
 * 1.5.0 `TerminateSession` (`account.resetAuthorization`). Rejects with
 * `OT_FRESH_RESET_FORBIDDEN` (message `FRESH_RESET_FORBIDDEN`) or
 * `OT_HASH_INVALID` (message `HASH_INVALID`), the RPC error as `cause`.
 */
export declare function terminateSession(client: FlowClient, hash: tl.Long): Promise<void>

/**
 * 1.5.0 `TerminateAllSessions`: ends every non-current session in list
 * order and resolves to how many were ended.
 */
export declare function terminateAllSessions(client: FlowClient): Promise<number>

/** The `PrintSessions` fields of an mtcute `authorization`. */
export declare function sessionRow(authorization: tl.RawAuthorization): SessionRow & { current: boolean; officialApp: boolean }

/**
 * The 1.5.0 `PrintSessions` table for a client (its sessions are fetched),
 * an `account.authorizations` answer or a list of `authorization`s.
 */
export declare function formatSessions(
  source: FlowClient | tl.account.RawAuthorizations | tl.RawAuthorization[],
): Promise<string>

/** 1.5.0 `is_official_app`: whether the current session is `officialApp`. */
export declare function isOfficialApp(client: FlowClient): Promise<boolean>

/** Options of `runConsistencyChecks`. */
export interface ConsistencyOptions {
  /** The library layer `layer_match` compares; default @mtcute/core's `tl.LAYER`. */
  layer?: number
  /** Whether a failing check emits the 1.5.0 warning; default `true`. */
  autoWarn?: boolean
}

/**
 * The seven 1.5.0 `ConsistencyChecker.run_all` results for `client` used
 * with `profile`, in `consistencyChecks()` order, with the native details;
 * join them with `consistencySummary`.
 */
export declare function runConsistencyChecks(
  client: FlowClient,
  profile: ApiProfile,
  versions?: Versions | null,
  options?: ConsistencyOptions,
): Promise<CheckResult[]>

/** Options of `tdataFromClient`. */
export interface TdataFromClientOptions {
  /** The local passcode; none by default. */
  passcode?: string | Uint8Array
  /** Whether saves skip the `configs` files; default `true`. */
  performanceMode?: boolean
}

/**
 * A new tdata folder with the session of `client` as its only account:
 * main DC and auth key from `client.exportSession()`, user id from
 * `getMeId` (1.5.0 `FromTelethon` with `UseCurrentSession`).
 */
export declare function tdataFromClient(client: FlowClient, options?: TdataFromClientOptions): Promise<TData>
