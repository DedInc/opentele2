// mtcute.mjs: the `opentele2/mtcute` entry point.
//
// Helpers that hand opentele2 data to mtcute, and the 1.5.0 client flows
// over an mtcute client. Nothing here imports @mtcute/core or @mtcute/node
// at load time; the functions that need them load them on first call, so
// both stay optional peers.
//
// The flows mirror crates/opentele2-grammers/src/client.rs. They use only
// the client's raw `call(tlObject)` and a few public helpers
// (`getPrimaryDcId`, `changePrimaryDc`, `notifyLoggedIn`, `getMe`,
// `exportSession`, `onServerUpdate`), each optional where it can be, so a
// fake object that answers `call` with canned TL objects drives them too.

import { randomInt } from 'node:crypto'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const native = require('./index.js')

/**
 * The mtcute v3 string session of `account`, for `client.importSession()`
 * or the `TelegramClient` constructor's session string.
 */
export function toStringSession(account) {
  return native.mtcuteStringSession(account)
}

/**
 * The `initConnectionOptions` mtcute's `TelegramClient` takes, from an
 * opentele2 `profile()` or `generate()` result. The API id and hash are not
 * part of them; pass `profile.apiId` and `profile.apiHash` to the client.
 */
export function initConnectionOptions(profile) {
  return {
    deviceModel: profile.deviceModel,
    systemVersion: profile.systemVersion,
    appVersion: profile.appVersion,
    systemLangCode: profile.systemLangCode,
    langPack: profile.langPack,
    langCode: profile.langCode,
  }
}

/**
 * mtcute's default Node crypto provider with AES-256-IGE, the per-packet
 * cipher, replaced by the opentele2 core. Every other method, including
 * `initialize`, stays mtcute's own.
 */
export async function createCryptoProvider() {
  const utils = await importPeer('@mtcute/node/utils.js', 'createCryptoProvider', '@mtcute/node')
  const provider = new utils.NodeCryptoProvider()
  provider.createAesIge = (key, iv) => ({
    encrypt: (data) => native.aesIgeEncrypt(data, key, iv),
    decrypt: (data) => native.aesIgeDecrypt(data, key, iv),
  })
  return provider
}

/** Loads the optional peer `specifier`, or rejects with `ERR_MODULE_NOT_FOUND`. */
async function importPeer(specifier, caller, pkg) {
  try {
    return await import(specifier)
  } catch (cause) {
    const error = new Error(`${caller} needs the ${pkg} package`, { cause })
    error.code = 'ERR_MODULE_NOT_FOUND'
    throw error
  }
}

// ---------------------------------------------------------------------------
// Client flows
//
// Gaps against 1.5.0, as in the grammers flows:
// - `qrLoginToNewClient` takes a client the caller built (its storage, its
//   initConnection); an already authorised one with another api_id is
//   refused instead of having its session file deleted and logged in again.
// - Without an `onServerUpdate` emitter on the new client, the QR login
//   exports the token again as soon as `auth.acceptLoginToken` returns
//   instead of waiting for `updateLoginToken`.
// - Error details are mtcute's error messages where 1.5.0 prints Telethon's.

/** How many QR login attempts `qrLoginToNewClient` makes (1.5.0 `_DEFAULT_REQUEST_RETRIES`). */
export const QR_LOGIN_ATTEMPTS = 5

/** The 1.5.0 `TimeoutError` message when no QR login attempt logged in. */
export const QR_LOGIN_TIMEOUT = "Something went wrong, i couldn't perform the QR login"

/** The 1.5.0 `TelethonUnauthorized` message when the self user is unknown. */
export const USER_ID_UNRESOLVED = "Could not resolve the account's user id"

/**
 * The delay range in milliseconds before each 1.5.0 post-login request,
 * `null` for none, in `_POST_LOGIN_STEPS` order.
 */
export const POST_LOGIN_DELAYS_MS = Object.freeze(
  [null, [100, 300], [200, 400], [100, 200], [300, 500], [100, 300], [50, 150]].map((range) =>
    range === null ? null : Object.freeze(range),
  ),
)

// 1.5.0 `_QR_EXPIRE_SAFETY_SECONDS`: how long past its expiry a QR token is
// waited for.
const QR_EXPIRE_SAFETY_MS = 5000

const SRP_ALGO = 'passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow'

/** An error named after the 1.5.0 exception, with an `OT_` code. */
function flowError(name, code, message, cause) {
  const error = new Error(message, cause === undefined ? undefined : { cause })
  error.name = name
  error.code = code
  return error
}

/** Whether `error` is an mtcute `RpcError`: a numeric `code` and a `text`. */
function isRpcError(error) {
  return error instanceof Error && typeof error.code === 'number' && typeof error.text === 'string'
}

function rpcIs(error, text) {
  return isRpcError(error) && error.text === text
}

function errorText(error) {
  return error instanceof Error ? error.message : String(error)
}

// Python's warnings.warn; 1.5.0 warns with UserWarning.
function warn(message) {
  process.emitWarning(message, 'UserWarning')
}

function toBigInt(value) {
  return typeof value === 'bigint' ? value : BigInt(value.toString())
}

/**
 * Whether `client` is authorised, as Telethon `is_user_authorized` asks:
 * `updates.getState` succeeds. Any RPC error is `false`; other failures
 * reject.
 */
export async function isAuthorized(client) {
  try {
    await client.call({ _: 'updates.getState' })
    return true
  } catch (error) {
    if (isRpcError(error)) {
      return false
    }
    throw error
  }
}

/**
 * The self user id of `client`: `client.getMe()`, or
 * `users.getUsers([inputUserSelf])` for a client without it. Rejects with
 * code `OT_USER_ID_UNRESOLVED` when there is no user.
 */
export async function getMeId(client) {
  let id
  if (typeof client.getMe === 'function') {
    id = (await client.getMe())?.id
  } else {
    const users = await client.call({ _: 'users.getUsers', id: [{ _: 'inputUserSelf' }] })
    id = users?.[0]?.id
  }
  if (id === undefined || id === null) {
    throw flowError('TelethonUnauthorized', 'OT_USER_ID_UNRESOLVED', USER_ID_UNRESOLVED)
  }
  return id
}

/** Telethon `_on_login`: hands `authorization` to mtcute and returns the user id. */
async function onLogin(client, authorization) {
  if (authorization?._ !== 'auth.authorization') {
    throw flowError(
      'SignUpRequired',
      'OT_SIGN_UP_REQUIRED',
      'the server asked to sign up instead of logging in',
    )
  }
  if (typeof client.notifyLoggedIn === 'function') {
    await client.notifyLoggedIn(authorization)
  }
  return authorization.user.id
}

/**
 * `auth.exportLoginToken` on `fresh` with no ignored ids, as Telethon
 * `qr_login()` sends it; an `auth.loginTokenMigrateTo` moves `fresh` to its
 * DC and is replaced by `auth.importLoginToken` there (1.5.0 `_switch_dc`,
 * then `ImportLoginTokenRequest`).
 */
async function exportLoginToken(fresh, apiId, apiHash) {
  const response = await fresh.call({ _: 'auth.exportLoginToken', apiId, apiHash, exceptIds: [] })
  if (response._ !== 'auth.loginTokenMigrateTo') {
    return response
  }
  await fresh.changePrimaryDc(response.dcId)
  return fresh.call({ _: 'auth.importLoginToken', token: response.token })
}

/**
 * A waiter for the `updateLoginToken` mtcute delivers on `fresh` once the
 * token is accepted (Telethon `QRLogin.wait`); `null` without an emitter.
 */
function loginTokenWaiter(fresh) {
  const emitter = fresh.onServerUpdate
  if (emitter == null || typeof emitter.add !== 'function' || typeof emitter.remove !== 'function') {
    return null
  }
  let arrived
  const update = new Promise((resolve) => {
    arrived = resolve
  })
  const listener = (incoming) => {
    const inner = incoming?._ === 'updateShort' ? incoming.update : incoming
    if (inner?._ === 'updateLoginToken') {
      arrived(true)
    }
  }
  emitter.add(listener)
  return {
    wait(ms) {
      let timer
      const timeout = new Promise((resolve) => {
        timer = setTimeout(resolve, ms, false)
      })
      return Promise.race([update, timeout]).finally(() => clearTimeout(timer))
    },
    dispose() {
      emitter.remove(listener)
    },
  }
}

/**
 * One 1.5.0 QR login attempt: the `auth.authorization` it ended with, or
 * `null` when the token was not accepted in time.
 */
async function qrLoginAttempt(authorized, fresh, apiId, apiHash, onUrl) {
  const first = await exportLoginToken(fresh, apiId, apiHash)
  if (first._ === 'auth.loginTokenSuccess') {
    return first.authorization
  }
  if (typeof onUrl === 'function') {
    onUrl(native.qrLoginUrl(first.token), typeof first.expires === 'number' ? new Date(first.expires * 1000) : null)
  }
  // Subscribed before the accept, so an update that beats its answer counts.
  const waiter = loginTokenWaiter(fresh)
  try {
    await authorized.call({ _: 'auth.acceptLoginToken', token: first.token })
    if (waiter !== null) {
      const left = typeof first.expires === 'number' ? Math.max(0, first.expires * 1000 - Date.now()) : 0
      if (!(await waiter.wait(left + QR_EXPIRE_SAFETY_MS))) {
        return null
      }
    }
  } finally {
    waiter?.dispose()
  }
  const again = await exportLoginToken(fresh, apiId, apiHash)
  return again._ === 'auth.loginTokenSuccess' ? again.authorization : null
}

/**
 * 1.5.0 `_handle2FA`: `account.getPassword`, then `auth.checkPassword` with
 * the native `srpCheck` of `password`.
 */
async function twoFactor(fresh, password) {
  if (password === undefined || password === null) {
    throw flowError('NoPasswordProvided', 'OT_NO_PASSWORD_PROVIDED', native.NO_PASSWORD_PROVIDED)
  }
  const info = await fresh.call({ _: 'account.getPassword' })
  const algo = info.currentAlgo
  if (algo?._ !== SRP_ALGO || !info.srpB || info.srpId === undefined || info.srpId === null) {
    throw flowError(
      'UnsupportedPasswordAlgorithm',
      'OT_UNSUPPORTED_PASSWORD_ALGORITHM',
      'unsupported password algorithm',
    )
  }
  const check = await native.srpCheck(
    { srpId: toBigInt(info.srpId), g: algo.g, p: algo.p, salt1: algo.salt1, salt2: algo.salt2, srpB: info.srpB },
    password,
  )
  let authorization
  try {
    authorization = await fresh.call({
      _: 'auth.checkPassword',
      // The srpId goes back as the server sent it (an mtcute Long).
      password: { _: 'inputCheckPasswordSRP', srpId: info.srpId, A: check.a, M1: check.m1 },
    })
  } catch (error) {
    if (rpcIs(error, 'PASSWORD_HASH_INVALID')) {
      throw flowError('PasswordIncorrect', 'OT_PASSWORD_INCORRECT', error.message, error)
    }
    throw error
  }
  return onLogin(fresh, authorization)
}

/** 1.5.0 `_performQRLogin` with `_handle2FA`; resolves to the user id. */
async function performQrLogin(authorized, fresh, apiId, apiHash, password, onUrl) {
  for (let attempt = 0; attempt < QR_LOGIN_ATTEMPTS; attempt += 1) {
    let authorization
    try {
      if (attempt > 0 && (await isAuthorized(fresh))) {
        return await getMeId(fresh)
      }
      authorization = await qrLoginAttempt(authorized, fresh, apiId, apiHash, onUrl)
    } catch (error) {
      if (rpcIs(error, 'SESSION_PASSWORD_NEEDED')) {
        return twoFactor(fresh, password)
      }
      // AUTH_TOKEN_ALREADY_ACCEPTED, _EXPIRED and _INVALID are re-raised,
      // as is everything else.
      throw error
    }
    if (authorization !== null) {
      return onLogin(fresh, authorization)
    }
    warn(`\nQRLoginToNewClient attempt ${attempt + 1} failed because TimeoutError`)
    warn(`\nQRLoginToNewClient attempt ${attempt + 1} failed. Retrying..`)
  }
  throw flowError('TimeoutError', 'OT_QR_LOGIN_TIMEOUT', QR_LOGIN_TIMEOUT)
}

/** 1.5.0 `_handleExistingSession` for an already authorised new client. */
async function existingSession(fresh, apiId) {
  const current = await getCurrentSession(fresh)
  if (current !== null) {
    if (current.apiId !== apiId) {
      throw flowError(
        'SessionExists',
        'OT_SESSION_EXISTS',
        `the new client already holds a session of api_id ${current.apiId}, not ${apiId}; give it empty storage`,
      )
    }
    warn('\nCreateNewSession - a session file with the same name is already existed, returning the old session')
  }
  return getMeId(fresh)
}

/** Moves `fresh` to the DC of `authorized` when both report one (1.5.0 `_switch_dc`). */
async function alignDc(authorized, fresh) {
  if (typeof authorized.getPrimaryDcId !== 'function' || typeof fresh.getPrimaryDcId !== 'function') {
    return
  }
  const dcId = await authorized.getPrimaryDcId()
  if ((await fresh.getPrimaryDcId()) !== dcId) {
    await fresh.changePrimaryDc(dcId)
  }
}

/**
 * Logs `fresh`, a client with empty storage, in through the authorised
 * client `authorized` by QR login, as 1.5.0 `QRLoginToNewClient`:
 *
 * 1. `fresh` moves to the DC of `authorized`. When `fresh` is already
 *    authorised with the same api id, it is returned as is.
 * 2. Up to `QR_LOGIN_ATTEMPTS` attempts of `auth.exportLoginToken` on
 *    `fresh` (a `loginTokenMigrateTo` is followed by `changePrimaryDc` and
 *    `auth.importLoginToken`), `auth.acceptLoginToken` on `authorized`, the
 *    wait for `updateLoginToken` and the export again.
 * 3. `SESSION_PASSWORD_NEEDED` runs `account.getPassword` and
 *    `auth.checkPassword` with the native `srpCheck` of `password`.
 * 4. The 1.5.0 post-login requests on `fresh` unless `postLogin` is
 *    `false`, each after `delay(minMs, maxMs)` (a random sleep by default).
 *
 * `apiId` and `apiHash` default to the profile's; `profile.langPack` is
 * the lang pack of the post-login `langpack.getLanguages`. `onUrl`, when
 * given, receives each token's `qrLoginUrl` and expiry before it is
 * accepted.
 */
export async function qrLoginToNewClient(authorized, fresh, options = {}) {
  const { profile, password } = options
  const apiId = options.apiId ?? profile?.apiId
  const apiHash = options.apiHash ?? profile?.apiHash
  if (!Number.isInteger(apiId) || typeof apiHash !== 'string' || apiHash === '') {
    throw new TypeError('qrLoginToNewClient needs apiId and apiHash, or a profile with them')
  }
  await alignDc(authorized, fresh)
  if (await isAuthorized(fresh)) {
    return { client: fresh, userId: await existingSession(fresh, apiId) }
  }
  const userId = await performQrLogin(authorized, fresh, apiId, apiHash, password, options.onUrl)
  if (options.postLogin !== false) {
    await postLoginRequests(fresh, profile?.langPack ?? '', options.delay)
  }
  return { client: fresh, userId }
}

const POST_LOGIN_REQUESTS = [
  () => ({ _: 'help.getConfig' }),
  () => ({ _: 'help.getNearestDc' }),
  () => ({ _: 'account.updateStatus', offline: false }),
  (langPack) => ({ _: 'langpack.getLanguages', langPack }),
  () => ({ _: 'help.getAppUpdate', source: '' }),
  () => ({ _: 'help.getTermsOfServiceUpdate' }),
  () => ({ _: 'help.getCountriesList', langCode: 'en', hash: 0 }),
]

// 1.5.0 sleeps a random whole number of milliseconds in the inclusive range.
function randomDelay(minMs, maxMs) {
  return new Promise((resolve) => setTimeout(resolve, randomInt(minMs, maxMs + 1)))
}

/**
 * 1.5.0 `_run_post_login_requests`: `help.getConfig`, `help.getNearestDc`,
 * `account.updateStatus(offline=false)`, `langpack.getLanguages` (only for
 * a non-empty `langPack`), `help.getAppUpdate(source="")`,
 * `help.getTermsOfServiceUpdate` and `help.getCountriesList("en", 0)`, each
 * after `delay` with its `POST_LOGIN_DELAYS_MS` range. Failures are
 * ignored, as in 1.5.0; resolves to how many requests failed.
 */
export async function postLoginRequests(client, langPack = '', delay = randomDelay) {
  let failed = 0
  for (const [step, request] of POST_LOGIN_REQUESTS.entries()) {
    if (step === 3 && !langPack) {
      continue
    }
    const range = POST_LOGIN_DELAYS_MS[step]
    if (range !== null) {
      await (delay ?? randomDelay)(range[0], range[1])
    }
    try {
      await client.call(request(langPack))
    } catch {
      failed += 1
    }
  }
  return failed
}

/**
 * Every session of the account, 1.5.0 `GetSessions`
 * (`account.getAuthorizations`). Rejects with code
 * `OT_SESSIONS_UNAVAILABLE` when the answer holds no list.
 */
export async function getSessions(client) {
  const sessions = await client.call({ _: 'account.getAuthorizations' })
  if (!Array.isArray(sessions?.authorizations)) {
    throw flowError('OpenTeleException', 'OT_SESSIONS_UNAVAILABLE', native.SESSIONS_UNAVAILABLE)
  }
  return sessions
}

/** The session flagged `current`, 1.5.0 `GetCurrentSession`; `null` without one. */
export async function getCurrentSession(client) {
  const sessions = await getSessions(client)
  return sessions.authorizations.find((authorization) => authorization.current) ?? null
}

/**
 * Ends the session `hash`, 1.5.0 `TerminateSession`
 * (`account.resetAuthorization`). `FRESH_RESET_AUTHORISATION_FORBIDDEN`
 * rejects with code `OT_FRESH_RESET_FORBIDDEN` and `HASH_INVALID` with
 * `OT_HASH_INVALID`, each with the 1.5.0 message and the RPC error as
 * `cause`.
 */
export async function terminateSession(client, hash) {
  try {
    await client.call({ _: 'account.resetAuthorization', hash })
  } catch (error) {
    if (rpcIs(error, 'FRESH_RESET_AUTHORISATION_FORBIDDEN')) {
      throw flowError(
        'FreshResetAuthorisationForbiddenError',
        'OT_FRESH_RESET_FORBIDDEN',
        native.FRESH_RESET_FORBIDDEN,
        error,
      )
    }
    if (rpcIs(error, 'HASH_INVALID')) {
      throw flowError('HashInvalidError', 'OT_HASH_INVALID', native.HASH_INVALID, error)
    }
    throw error
  }
}

/**
 * Ends every session but the current one, in list order, 1.5.0
 * `TerminateAllSessions`, and resolves to how many were ended; the first
 * failure stops the loop.
 */
export async function terminateAllSessions(client) {
  let ended = 0
  for (const authorization of (await getSessions(client)).authorizations) {
    if (!authorization.current) {
      await terminateSession(client, authorization.hash)
      ended += 1
    }
  }
  return ended
}

/** The 1.5.0 `PrintSessions` fields of an mtcute `authorization`. */
export function sessionRow(authorization) {
  return {
    current: Boolean(authorization.current),
    deviceModel: authorization.deviceModel,
    platform: authorization.platform,
    systemVersion: authorization.systemVersion,
    apiId: authorization.apiId,
    appName: authorization.appName,
    appVersion: authorization.appVersion,
    officialApp: Boolean(authorization.officialApp),
  }
}

/**
 * The table 1.5.0 `PrintSessions` prints, for a client (whose sessions are
 * fetched), an `account.authorizations` answer or a list of
 * `authorization`s.
 */
export async function formatSessions(source) {
  let authorizations
  if (Array.isArray(source)) {
    authorizations = source
  } else if (typeof source?.call === 'function') {
    authorizations = (await getSessions(source)).authorizations
  } else if (Array.isArray(source?.authorizations)) {
    authorizations = source.authorizations
  } else {
    throw flowError('OpenTeleException', 'OT_SESSIONS_UNAVAILABLE', native.SESSIONS_UNAVAILABLE)
  }
  return native.formatSessions(authorizations.map(sessionRow))
}

/**
 * Whether the server flags the current session `official_app`, 1.5.0
 * `is_official_app`; `false` without a current session.
 */
export async function isOfficialApp(client) {
  const current = await getCurrentSession(client)
  return current !== null && Boolean(current.officialApp)
}

const checkResult = (name, passed, detail) => ({ name, passed, detail })

async function checkGetConfig(client) {
  let config
  try {
    config = await client.call({ _: 'help.getConfig' })
  } catch (error) {
    return checkResult('get_config', false, native.getConfigError(errorText(error)))
  }
  return checkResult('get_config', true, native.getConfigDetail(config?.thisDc))
}

async function checkNearestDc(client) {
  let nearest
  try {
    nearest = await client.call({ _: 'help.getNearestDc' })
  } catch (error) {
    return checkResult('nearest_dc', false, native.nearestDcError(errorText(error)))
  }
  return checkResult('nearest_dc', true, native.nearestDcDetail(nearest.country, nearest.thisDc, nearest.nearestDc))
}

async function checkCurrentSession(client) {
  let current
  try {
    current = await getCurrentSession(client)
  } catch (error) {
    return checkResult('current_session', false, native.checkError(errorText(error)))
  }
  if (current === null) {
    return checkResult('current_session', false, native.CURRENT_SESSION_MISSING)
  }
  const row = sessionRow(current)
  return checkResult('current_session', row.officialApp, native.currentSessionDetail(row))
}

async function checkLangPack(client, expectations) {
  if (expectations.langPackSkipped) {
    return checkResult('lang_pack', true, native.LANG_PACK_EMPTY)
  }
  const { langPack } = expectations
  let languages
  try {
    languages = await client.call({ _: 'langpack.getLanguages', langPack })
  } catch (error) {
    return checkResult('lang_pack', false, native.langPackError(langPack, errorText(error)))
  }
  return checkResult('lang_pack', true, native.langPackDetail(langPack, languages.length))
}

async function checkAppUpdate(client) {
  let update
  try {
    update = await client.call({ _: 'help.getAppUpdate', source: '' })
  } catch (error) {
    return checkResult('app_update', false, native.appUpdateError(errorText(error)))
  }
  if (update?._ === 'help.noAppUpdate') {
    return checkResult('app_update', true, native.NO_APP_UPDATE)
  }
  return checkResult('app_update', true, native.appUpdateDetail(update?.version))
}

async function checkTermsOfService(client) {
  try {
    await client.call({ _: 'help.getTermsOfServiceUpdate' })
  } catch (error) {
    return checkResult('terms_of_service', false, native.checkError(errorText(error)))
  }
  return checkResult('terms_of_service', true, native.TERMS_OF_SERVICE_OK)
}

/**
 * The seven checks of 1.5.0 `ConsistencyChecker.run_all`, in
 * `consistencyChecks()` order, with the native details:
 *
 * - `get_config`, `nearest_dc`, `app_update` and `terms_of_service` pass
 *   when their request succeeds.
 * - `current_session` passes when the current session is `officialApp`.
 * - `layer_match` is `layerResult` of `options.layer`, by default the
 *   layer of the installed @mtcute/core.
 * - `lang_pack` asks `langpack.getLanguages` about the profile's lang pack
 *   (the one `initConnectionOptions(profile)` sends), and passes without a
 *   request when it is empty.
 *
 * A check that throws out of its own handling fails with the
 * `checkException` detail. With `autoWarn` (default `true`) a failing
 * check emits the 1.5.0 warning: `CONSISTENCY_WARNING_PREFIX` and
 * `consistencySummary`.
 */
export async function runConsistencyChecks(client, profile, versions, options = {}) {
  const expectations = native.consistencyExpectations(profile, versions)
  const layer =
    options.layer ?? (await importPeer('@mtcute/core', 'runConsistencyChecks', '@mtcute/core')).tl.LAYER
  const checks = [
    ['get_config', () => checkGetConfig(client)],
    ['nearest_dc', () => checkNearestDc(client)],
    ['current_session', () => checkCurrentSession(client)],
    ['layer_match', () => native.layerResult(layer)],
    ['lang_pack', () => checkLangPack(client, expectations)],
    ['app_update', () => checkAppUpdate(client)],
    ['terms_of_service', () => checkTermsOfService(client)],
  ]
  const results = []
  for (const [name, run] of checks) {
    try {
      results.push(await run())
    } catch (error) {
      results.push(checkResult(name, false, native.checkException(errorText(error))))
    }
  }
  if (options.autoWarn !== false && !results.every((result) => result.passed)) {
    warn(native.CONSISTENCY_WARNING_PREFIX + native.consistencySummary(results))
  }
  return results
}

/**
 * A new tdata folder holding the session of `client` as its only account
 * (index 0), as 1.5.0 `Account.FromTelethon` with `UseCurrentSession`
 * builds one without an owner: the main DC and its auth key from
 * `client.exportSession()`, the user id from `getMeId`, then `newTdata`
 * with `passcode` and `performanceMode` (default `true`).
 *
 * 1.5.0's `CreateNewSession` flag logs a new session in first; run
 * `qrLoginToNewClient` and pass the new client here.
 */
export async function tdataFromClient(client, options = {}) {
  const { readStringSession } = await importPeer('@mtcute/core/utils.js', 'tdataFromClient', '@mtcute/core')
  const session = readStringSession(await client.exportSession())
  const userId = await getMeId(client)
  const account = {
    index: 0,
    userId: toBigInt(userId),
    mainDc: session.primaryDcs.main.id,
    authKey: session.authKey,
  }
  return native.newTdata([account], options.passcode, options.performanceMode ?? true)
}
