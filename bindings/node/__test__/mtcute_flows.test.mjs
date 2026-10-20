// mtcute_flows.test.mjs: the 1.5.0 client flows of `opentele2/mtcute`
// driven by fake clients whose `call` answers with canned mtcute-shaped TL
// objects; each test checks the exact call sequence. One live test runs
// only with OPENTELE2_LIVE=1.
//
// The 2FA fake plays the server's side of SRP, so the check is verified
// rather than compared. Passwords are fixtures and key bytes are compared
// with assertSame, so neither reaches the log.

import assert from 'node:assert/strict'
import { createHash, pbkdf2Sync, randomBytes } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { test } from 'node:test'

import { Long, tl } from '@mtcute/core'

import {
  POST_LOGIN_DELAYS_MS,
  QR_LOGIN_ATTEMPTS,
  QR_LOGIN_TIMEOUT,
  USER_ID_UNRESOLVED,
  createCryptoProvider,
  formatSessions,
  getCurrentSession,
  getMeId,
  getSessions,
  initConnectionOptions,
  isAuthorized,
  isOfficialApp,
  postLoginRequests,
  qrLoginToNewClient,
  runConsistencyChecks,
  sessionRow,
  tdataFromClient,
  terminateAllSessions,
  terminateSession,
} from 'opentele2/mtcute'

import { FOLDERS, assertSame, core, loadJson, rejection, unhex, vectorAccount } from './helpers.mjs'

// --- fakes -----------------------------------------------------------------

const rpc = (code, text) => () => new tl.RpcError(code, text)
const unauthorized = rpc(401, 'AUTH_KEY_UNREGISTERED')

/**
 * A client whose `call` answers from `handlers[request._]`: a value, a
 * function of the request, or an array of those used one per call. An
 * answer that is an Error is thrown. Every call lands in `log` as
 * `"<name> <method>"`.
 */
class FakeClient {
  constructor(name, log, handlers, { dc, emitter = false, me } = {}) {
    this.name = name
    this.log = log
    this.handlers = handlers
    this.requests = []
    if (dc !== undefined) {
      this.dc = dc
      this.getPrimaryDcId = async () => {
        log.push(`${name} getPrimaryDcId`)
        return this.dc
      }
    }
    if (emitter) {
      this.listeners = new Set()
      this.onServerUpdate = {
        add: (listener) => this.listeners.add(listener),
        remove: (listener) => this.listeners.delete(listener),
      }
    }
    if (me !== undefined) {
      this.getMe = async () => {
        log.push(`${name} getMe`)
        return me
      }
    }
  }

  async changePrimaryDc(dcId) {
    this.log.push(`${this.name} changePrimaryDc ${dcId}`)
    this.dc = dcId
  }

  async notifyLoggedIn(authorization) {
    this.log.push(`${this.name} notifyLoggedIn ${authorization.user.id}`)
  }

  async notifyLoggedOut() {
    this.log.push(`${this.name} notifyLoggedOut`)
  }

  push(update) {
    for (const listener of this.listeners) listener(update)
  }

  async call(request) {
    this.log.push(`${this.name} ${request._}`)
    this.requests.push(request)
    let handler = this.handlers[request._]
    if (Array.isArray(handler)) handler = handler.shift()
    if (handler === undefined) throw new Error(`${this.name}: unexpected ${request._}`)
    const answer = typeof handler === 'function' ? await handler(request, this) : handler
    if (answer instanceof Error) throw answer
    return answer
  }
}

const TOKEN = Buffer.from('6c6f67696e2d746f6b656efeff', 'hex')
const TOKEN_DC4 = Buffer.from('dc4-login-token')
const loginToken = (token = TOKEN) => ({ _: 'auth.loginToken', expires: Math.floor(Date.now() / 1000) + 30, token })
const authorization = (id) => ({ _: 'auth.authorization', user: { _: 'user', id } })
const success = (id) => ({ _: 'auth.loginTokenSuccess', authorization: authorization(id) })

const DESKTOP = core.profile('TelegramDesktop')

const POST_LOGIN_ANSWERS = {
  'help.getConfig': { _: 'config', thisDc: 2 },
  'help.getNearestDc': { _: 'nearestDc', country: 'NL', thisDc: 2, nearestDc: 4 },
  'account.updateStatus': true,
  'langpack.getLanguages': () => [],
  'help.getAppUpdate': { _: 'help.noAppUpdate' },
  'help.getTermsOfServiceUpdate': { _: 'help.termsOfServiceUpdateEmpty', expires: 0 },
  'help.getCountriesList': { _: 'help.countriesListNotModified' },
}

const POST_LOGIN_SEQUENCE = [
  'help.getConfig',
  'help.getNearestDc',
  'account.updateStatus',
  'langpack.getLanguages',
  'help.getAppUpdate',
  'help.getTermsOfServiceUpdate',
  'help.getCountriesList',
]

const noDelay = async () => {}

/** Runs `fn` and resolves to its outcome and the warnings it emitted. */
async function withWarnings(fn) {
  const warnings = []
  const listener = (warning) => warnings.push(warning)
  process.on('warning', listener)
  try {
    let value
    let error
    try {
      value = await fn()
    } catch (caught) {
      error = caught
    }
    // emitWarning dispatches on the next tick.
    await new Promise((resolve) => setImmediate(resolve))
    return { value, error, warnings }
  } finally {
    process.off('warning', listener)
  }
}

// --- the server's side of SRP ------------------------------------------------

const P = unhex(
  'c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f' +
    '48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37' +
    '20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64' +
    '2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4' +
    'a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754' +
    'fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4' +
    'e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f' +
    '0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b',
)
const SALT1 = unhex('713a69e9a27390a0968da87fbf1a8510a4c5da97ed6f64447cbc4135821f3eeeabd5317c3ca6d03e')
const SALT2 = unhex('6c2fffb7af6a052438d3305e2f42f538')
const PASSWORD = 'hunter2-fixture'

const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest()
const toBig = (bytes) => BigInt('0x' + (Buffer.from(bytes).toString('hex') || '0'))
const toBytes = (n) => Buffer.from(n.toString(16).padStart(512, '0'), 'hex')

function modPow(base, exponent, modulus) {
  let result = 1n
  base %= modulus
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus
    base = (base * base) % modulus
    exponent >>= 1n
  }
  return result
}

/**
 * The account side of an SRP password (Telegram's 2FA scheme, g = 3):
 * the `account.password` the server sends, and `verify(A, M1)` as the
 * server checks `auth.checkPassword`.
 */
function srpServer(password) {
  const p = toBig(P)
  const g = 3n
  const gBytes = toBytes(g)
  const sh = (data, salt) => sha256(salt, data, salt)
  const hash1 = sh(sh(Buffer.from(password, 'utf8'), SALT1), SALT2)
  const x = toBig(sh(pbkdf2Sync(hash1, SALT1, 100000, 64, 'sha512'), SALT2))
  const v = modPow(g, x, p)
  const k = toBig(sha256(P, gBytes))
  const b = toBig(randomBytes(256)) % p
  const srpB = toBytes((k * v + modPow(g, b, p)) % p)
  const srpId = Long.fromString('2479236611711966277')
  return {
    srpId,
    password: {
      _: 'account.password',
      hasPassword: true,
      currentAlgo: { _: 'passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow', salt1: SALT1, salt2: SALT2, g: 3, p: P },
      srpB,
      srpId,
      newAlgo: { _: 'passwordKdfAlgoUnknown' },
      newSecureAlgo: { _: 'securePasswordKdfAlgoUnknown' },
      secureRandom: new Uint8Array(0),
    },
    verify(A, M1) {
      const a = toBig(A)
      const u = toBig(sha256(toBytes(a), srpB))
      const s = modPow((a * modPow(v, u, p)) % p, b, p)
      const hp = sha256(P)
      const hg = sha256(gBytes)
      const expected = sha256(
        Buffer.from(hp.map((byte, n) => byte ^ hg[n])),
        sha256(SALT1),
        sha256(SALT2),
        toBytes(a),
        srpB,
        sha256(toBytes(s)),
      )
      return expected.equals(Buffer.from(M1))
    },
  }
}

// --- QR login ------------------------------------------------------------------

test('qrLoginToNewClient: DC alignment, accept, updateLoginToken, success, post-login', async () => {
  const log = []
  let fresh
  const authorized = new FakeClient(
    'authorized',
    log,
    {
      'auth.acceptLoginToken': (request) => {
        assert.ok(Buffer.from(request.token).equals(TOKEN))
        fresh.push({ _: 'updateShort', update: { _: 'updateLoginToken' }, date: 0 })
        return { _: 'authorization', current: false }
      },
    },
    { dc: 2 },
  )
  fresh = new FakeClient(
    'fresh',
    log,
    {
      'updates.getState': unauthorized,
      'auth.exportLoginToken': [loginToken(), success(777)],
      ...POST_LOGIN_ANSWERS,
    },
    { dc: 4, emitter: true },
  )
  const delays = []
  const urls = []
  const result = await qrLoginToNewClient(authorized, fresh, {
    profile: DESKTOP,
    delay: async (min, max) => delays.push([min, max]),
    onUrl: (url, expires) => urls.push([url, expires]),
  })
  assert.equal(result.client, fresh)
  assert.equal(result.userId, 777)
  assert.deepEqual(log, [
    'authorized getPrimaryDcId',
    'fresh getPrimaryDcId',
    'fresh changePrimaryDc 2',
    'fresh updates.getState',
    'fresh auth.exportLoginToken',
    'authorized auth.acceptLoginToken',
    'fresh auth.exportLoginToken',
    'fresh notifyLoggedIn 777',
    ...POST_LOGIN_SEQUENCE.map((method) => `fresh ${method}`),
  ])
  const exports = fresh.requests.filter((request) => request._ === 'auth.exportLoginToken')
  for (const request of exports) {
    assert.deepEqual(request, { _: 'auth.exportLoginToken', apiId: DESKTOP.apiId, apiHash: DESKTOP.apiHash, exceptIds: [] })
  }
  const post = fresh.requests.slice(-7)
  assert.deepEqual(post[2], { _: 'account.updateStatus', offline: false })
  assert.deepEqual(post[3], { _: 'langpack.getLanguages', langPack: 'tdesktop' })
  assert.deepEqual(post[4], { _: 'help.getAppUpdate', source: '' })
  assert.deepEqual(post[6], { _: 'help.getCountriesList', langCode: 'en', hash: 0 })
  assert.deepEqual(delays, POST_LOGIN_DELAYS_MS.filter((range) => range !== null))
  assert.equal(urls.length, 1)
  assert.equal(urls[0][0], core.qrLoginUrl(TOKEN))
  assert.ok(urls[0][1] instanceof Date)
  assert.equal(fresh.listeners.size, 0, 'the updateLoginToken listener is removed')
})

test('qrLoginToNewClient follows loginTokenMigrateTo to importLoginToken', async () => {
  // Migrated on the first export.
  let log = []
  let authorized = new FakeClient('authorized', log, {})
  let fresh = new FakeClient('fresh', log, {
    'updates.getState': unauthorized,
    'auth.exportLoginToken': { _: 'auth.loginTokenMigrateTo', dcId: 4, token: TOKEN_DC4 },
    'auth.importLoginToken': (request) => {
      assert.ok(Buffer.from(request.token).equals(TOKEN_DC4))
      return success(778)
    },
  })
  let result = await qrLoginToNewClient(authorized, fresh, { apiId: 2040, apiHash: DESKTOP.apiHash, postLogin: false })
  assert.equal(result.userId, 778)
  assert.equal(fresh.dc, 4)
  assert.deepEqual(log, [
    'fresh updates.getState',
    'fresh auth.exportLoginToken',
    'fresh changePrimaryDc 4',
    'fresh auth.importLoginToken',
    'fresh notifyLoggedIn 778',
  ])

  // Migrated when the accepted token is exported again, without an emitter.
  log = []
  authorized = new FakeClient('authorized', log, { 'auth.acceptLoginToken': { _: 'authorization' } })
  fresh = new FakeClient('fresh', log, {
    'updates.getState': unauthorized,
    'auth.exportLoginToken': [loginToken(), { _: 'auth.loginTokenMigrateTo', dcId: 5, token: TOKEN_DC4 }],
    'auth.importLoginToken': success(779),
  })
  result = await qrLoginToNewClient(authorized, fresh, { profile: DESKTOP, postLogin: false })
  assert.equal(result.userId, 779)
  assert.deepEqual(log, [
    'fresh updates.getState',
    'fresh auth.exportLoginToken',
    'authorized auth.acceptLoginToken',
    'fresh auth.exportLoginToken',
    'fresh changePrimaryDc 5',
    'fresh auth.importLoginToken',
    'fresh notifyLoggedIn 779',
  ])
})

test('qrLoginToNewClient 2FA: the native SRP check passes the server', async () => {
  const server = srpServer(PASSWORD)
  const log = []
  const authorized = new FakeClient('authorized', log, { 'auth.acceptLoginToken': { _: 'authorization' } })
  const fresh = new FakeClient('fresh', log, {
    'updates.getState': unauthorized,
    'auth.exportLoginToken': [loginToken(), rpc(401, 'SESSION_PASSWORD_NEEDED')],
    'account.getPassword': server.password,
    'auth.checkPassword': ({ password }) => {
      assert.equal(password._, 'inputCheckPasswordSRP')
      assert.equal(password.srpId, server.srpId, 'the srpId goes back as sent')
      assert.equal(password.A.length, core.SRP_NUMBER_SIZE)
      assert.equal(password.M1.length, 32)
      return server.verify(password.A, password.M1) ? authorization(780) : new tl.RpcError(400, 'PASSWORD_HASH_INVALID')
    },
  })
  const result = await qrLoginToNewClient(authorized, fresh, { profile: DESKTOP, password: PASSWORD, postLogin: false })
  assert.equal(result.userId, 780)
  assert.deepEqual(log, [
    'fresh updates.getState',
    'fresh auth.exportLoginToken',
    'authorized auth.acceptLoginToken',
    'fresh auth.exportLoginToken',
    'fresh account.getPassword',
    'fresh auth.checkPassword',
    'fresh notifyLoggedIn 780',
  ])
})

test('qrLoginToNewClient 2FA: wrong, missing and unsupported passwords', async () => {
  const server = srpServer(PASSWORD)
  const scenario = (log, password = server.password) => ({
    authorized: new FakeClient('authorized', log, {}),
    fresh: new FakeClient('fresh', log, {
      'updates.getState': unauthorized,
      'auth.exportLoginToken': rpc(401, 'SESSION_PASSWORD_NEEDED'),
      'account.getPassword': password,
      'auth.checkPassword': ({ password: check }) =>
        server.verify(check.A, check.M1) ? authorization(781) : new tl.RpcError(400, 'PASSWORD_HASH_INVALID'),
    }),
  })

  let log = []
  let { authorized, fresh } = scenario(log)
  const wrong = await rejection(qrLoginToNewClient(authorized, fresh, { profile: DESKTOP, password: 'not-the-fixture', postLogin: false }))
  assert.equal(wrong.code, 'OT_PASSWORD_INCORRECT')
  assert.equal(wrong.name, 'PasswordIncorrect')
  assert.ok(tl.RpcError.is(wrong.cause, 'PASSWORD_HASH_INVALID'))
  assert.equal(wrong.message, wrong.cause.message)
  assert.deepEqual(log, ['fresh updates.getState', 'fresh auth.exportLoginToken', 'fresh account.getPassword', 'fresh auth.checkPassword'])

  log = []
  ;({ authorized, fresh } = scenario(log))
  const missing = await rejection(qrLoginToNewClient(authorized, fresh, { profile: DESKTOP, postLogin: false }))
  assert.equal(missing.code, 'OT_NO_PASSWORD_PROVIDED')
  assert.equal(missing.name, 'NoPasswordProvided')
  assert.equal(missing.message, core.NO_PASSWORD_PROVIDED)
  assert.deepEqual(log, ['fresh updates.getState', 'fresh auth.exportLoginToken'])

  log = []
  ;({ authorized, fresh } = scenario(log, { ...server.password, currentAlgo: { _: 'passwordKdfAlgoUnknown' } }))
  const unsupported = await rejection(qrLoginToNewClient(authorized, fresh, { profile: DESKTOP, password: PASSWORD, postLogin: false }))
  assert.equal(unsupported.code, 'OT_UNSUPPORTED_PASSWORD_ALGORITHM')
  assert.equal(unsupported.name, 'ValueError')
  assert.equal(unsupported.message, 'unsupported password algorithm passwordKdfAlgoUnknown')
  assert.equal(unsupported.message, core.unsupportedPasswordAlgorithm('passwordKdfAlgoUnknown'))
  assert.deepEqual(log, ['fresh updates.getState', 'fresh auth.exportLoginToken', 'fresh account.getPassword'])
})

test('qrLoginToNewClient 2FA without srpId or srpB ends in the core OT_SRP_BAD_B', async () => {
  const server = srpServer(PASSWORD)
  const { srpB: _srpB, ...noB } = server.password
  const { srpId: _srpId, ...noId } = server.password
  for (const password of [noB, noId, { ...server.password, srpB: undefined, srpId: undefined }]) {
    const log = []
    const fresh = new FakeClient('fresh', log, {
      'updates.getState': unauthorized,
      'auth.exportLoginToken': rpc(401, 'SESSION_PASSWORD_NEEDED'),
      'account.getPassword': password,
    })
    const error = await rejection(
      qrLoginToNewClient(new FakeClient('authorized', log, {}), fresh, { profile: DESKTOP, password: PASSWORD, postLogin: false }),
    )
    assert.equal(error.code, 'OT_SRP_BAD_B')
    assert.equal(error.name, 'ValueError')
    // The core rule: without both inputs, id 0 and an empty B, which srpCheck refuses.
    const inputs = core.srpInputs(password.srpId == null ? null : 2479236611711966277n, password.srpB ?? null)
    assert.deepEqual([inputs.srpId, inputs.srpB.length], [0n, 0])
    const refused = await rejection(
      core.srpCheck({ srpId: inputs.srpId, g: 3, p: P, salt1: SALT1, salt2: SALT2, srpB: inputs.srpB }, PASSWORD),
    )
    assert.equal(error.message, refused.message)
    assert.deepEqual(log, ['fresh updates.getState', 'fresh auth.exportLoginToken', 'fresh account.getPassword'])
  }
  const both = core.srpInputs(2479236611711966277n, server.password.srpB)
  assert.equal(both.srpId, 2479236611711966277n)
  assert.ok(Buffer.from(both.srpB).equals(Buffer.from(server.password.srpB)))
  assert.deepEqual([core.srpInputs().srpId, core.srpInputs().srpB.length], [0n, 0])
  assert.throws(() => core.srpInputs(2n ** 64n, null), { code: 'ERR_INVALID_ARG_VALUE' })
})

test('initConnectionOptions sends tz_offset params for tdesktop, as Python does', () => {
  const desktop = initConnectionOptions(DESKTOP)
  const offset = core.tzOffset(Math.round(-new Date().getTimezoneOffset() * 60))
  assert.deepEqual(desktop.params, {
    _: 'jsonObject',
    value: [{ _: 'jsonObjectValue', key: 'tz_offset', value: { _: 'jsonNumber', value: offset } }],
  })
  assert.equal(DESKTOP.langPack, 'tdesktop')
  for (const name of ['TelegramAndroid', 'TelegramWeb_A']) {
    const options = initConnectionOptions(core.profile(name))
    assert.ok(!('params' in options), name)
  }
})

test('the flow RPC names, texts and error classes are the core ones', () => {
  assert.equal(USER_ID_UNRESOLVED, core.USER_ID_UNRESOLVED)
  assert.equal(core.SIGN_UP_REQUIRED, 'the server asked to sign up instead of logging in')
  assert.equal(core.SRP_NUMBER_SIZE, 256)
  assert.deepEqual(
    [
      core.RPC_PASSWORD_HASH_INVALID,
      core.RPC_SESSION_PASSWORD_NEEDED,
      core.RPC_FRESH_RESET_AUTHORISATION_FORBIDDEN,
      core.RPC_HASH_INVALID,
      core.RPC_AUTH_TOKEN_ALREADY_ACCEPTED,
      core.RPC_AUTH_TOKEN_EXPIRED,
      core.RPC_AUTH_TOKEN_INVALID,
    ],
    [
      'PASSWORD_HASH_INVALID',
      'SESSION_PASSWORD_NEEDED',
      'FRESH_RESET_AUTHORISATION_FORBIDDEN',
      'HASH_INVALID',
      'AUTH_TOKEN_ALREADY_ACCEPTED',
      'AUTH_TOKEN_EXPIRED',
      'AUTH_TOKEN_INVALID',
    ],
  )
  assert.deepEqual(core.flowErrorClasses(), {
    OT_NO_PASSWORD_PROVIDED: 'NoPasswordProvided',
    OT_PASSWORD_INCORRECT: 'PasswordIncorrect',
    OT_AUTH_TOKEN_ALREADY_ACCEPTED: 'AuthTokenAlreadyAcceptedError',
    OT_AUTH_TOKEN_EXPIRED: 'AuthTokenExpiredError',
    OT_AUTH_TOKEN_INVALID: 'AuthTokenInvalidError',
    OT_QR_LOGIN_TIMEOUT: 'TimeoutError',
    OT_FRESH_RESET_FORBIDDEN: 'FreshResetAuthorisationForbiddenError',
    OT_HASH_INVALID: 'HashInvalidError',
    OT_UNSUPPORTED_PASSWORD_ALGORITHM: 'ValueError',
    OT_SIGN_UP_REQUIRED: 'SignUpRequired',
    OT_USER_ID_UNRESOLVED: 'TelethonUnauthorized',
    OT_SESSIONS_UNAVAILABLE: 'OpenTeleException',
    OT_SRP_BAD_PRIME_OR_GENERATOR: 'ValueError',
    OT_SRP_BAD_B: 'ValueError',
    OT_SRP_NO_GOOD_RANDOM: 'ValueError',
    OT_SRP_RANDOM_UNAVAILABLE: 'ValueError',
  })
  // The layer rule is the core ConsistencyExpectations one, against an advertised layer.
  assert.deepEqual(core.layerResult(250, 250), { name: 'layer_match', passed: true, detail: core.layerDetail(250, 250) })
  assert.equal(core.layerResult(250, 200).passed, false)
  assert.deepEqual(core.layerResult(229, undefined), core.layerResult(229))
})

test('qrLoginToNewClient retries timed-out attempts, then times out', async () => {
  const log = []
  const authorized = new FakeClient('authorized', log, { 'auth.acceptLoginToken': { _: 'authorization' } })
  const fresh = new FakeClient('fresh', log, {
    'updates.getState': unauthorized,
    'auth.exportLoginToken': () => loginToken(),
  })
  const { error, warnings } = await withWarnings(() => qrLoginToNewClient(authorized, fresh, { profile: DESKTOP }))
  assert.equal(error.code, 'OT_QR_LOGIN_TIMEOUT')
  assert.equal(error.name, 'TimeoutError')
  assert.equal(error.message, QR_LOGIN_TIMEOUT)
  const attempt = ['fresh auth.exportLoginToken', 'authorized auth.acceptLoginToken', 'fresh auth.exportLoginToken']
  const expected = ['fresh updates.getState', ...attempt]
  for (let n = 1; n < QR_LOGIN_ATTEMPTS; n += 1) expected.push('fresh updates.getState', ...attempt)
  assert.deepEqual(log, expected)
  assert.deepEqual(
    warnings.map((warning) => [warning.name, warning.message]),
    Array.from({ length: QR_LOGIN_ATTEMPTS }, (_, n) => [
      // The core text: Python's str(type(e)) of the TimeoutError.
      ['UserWarning', `\nQRLoginToNewClient attempt ${n + 1} failed because <class 'TimeoutError'>`],
      ['UserWarning', `\nQRLoginToNewClient attempt ${n + 1} failed. Retrying..`],
    ]).flat(),
  )
  assert.equal(warnings[0].message, core.qrAttemptTimeoutWarning(1))
  assert.equal(warnings[1].message, core.qrAttemptRetryWarning(1))
})

test('qrLoginToNewClient stops once the new client is authorised', async () => {
  const log = []
  const authorized = new FakeClient('authorized', log, { 'auth.acceptLoginToken': { _: 'authorization' } })
  const fresh = new FakeClient('fresh', log, {
    'updates.getState': [unauthorized, { _: 'updates.state' }],
    'auth.exportLoginToken': () => loginToken(),
    'users.getUsers': [[{ _: 'user', id: 782 }]],
    ...POST_LOGIN_ANSWERS,
  })
  const { value, warnings } = await withWarnings(() =>
    qrLoginToNewClient(authorized, fresh, { profile: core.profile('TelegramWeb_A'), delay: noDelay }),
  )
  assert.equal(value.userId, 782)
  assert.equal(warnings.length, 2)
  assert.deepEqual(log, [
    'fresh updates.getState',
    'fresh auth.exportLoginToken',
    'authorized auth.acceptLoginToken',
    'fresh auth.exportLoginToken',
    'fresh updates.getState',
    'fresh users.getUsers',
    // An empty lang pack skips langpack.getLanguages.
    ...POST_LOGIN_SEQUENCE.filter((method) => method !== 'langpack.getLanguages').map((method) => `fresh ${method}`),
  ])
})

test('qrLoginToNewClient re-raises AUTH_TOKEN_* and other errors without retrying', async () => {
  for (const text of ['AUTH_TOKEN_EXPIRED', 'AUTH_TOKEN_ALREADY_ACCEPTED', 'AUTH_TOKEN_INVALID', 'FLOOD_WAIT_%d']) {
    const log = []
    const authorized = new FakeClient('authorized', log, { 'auth.acceptLoginToken': rpc(400, text) })
    const fresh = new FakeClient('fresh', log, {
      'updates.getState': unauthorized,
      'auth.exportLoginToken': () => loginToken(),
    })
    const error = await rejection(qrLoginToNewClient(authorized, fresh, { profile: DESKTOP }))
    assert.ok(tl.RpcError.is(error, text), text)
    assert.deepEqual(log, ['fresh updates.getState', 'fresh auth.exportLoginToken', 'authorized auth.acceptLoginToken'])
  }
  const signUp = new FakeClient('fresh', [], {
    'updates.getState': unauthorized,
    'auth.exportLoginToken': { _: 'auth.loginTokenSuccess', authorization: { _: 'auth.authorizationSignUpRequired' } },
  })
  const signUpError = await rejection(qrLoginToNewClient(new FakeClient('a', [], {}), signUp, { profile: DESKTOP }))
  assert.equal(signUpError.code, 'OT_SIGN_UP_REQUIRED')
  assert.equal(signUpError.name, 'SignUpRequired')
  assert.equal(signUpError.message, core.SIGN_UP_REQUIRED)
  await assert.rejects(qrLoginToNewClient(new FakeClient('a', [], {}), signUp, {}), TypeError)
})

test('qrLoginToNewClient keeps a session of the same api id and replaces one of another', async () => {
  const sessions = (apiId) => ({
    _: 'account.authorizations',
    authorizationTtlDays: 180,
    authorizations: [{ _: 'authorization', current: true, officialApp: true, apiId, hash: Long.ZERO }],
  })
  let log = []
  let fresh = new FakeClient('fresh', log, { 'updates.getState': { _: 'updates.state' }, 'account.getAuthorizations': sessions(2040) }, { me: { id: 783 } })
  const { value, warnings } = await withWarnings(() => qrLoginToNewClient(new FakeClient('authorized', log, {}), fresh, { profile: DESKTOP }))
  assert.deepEqual(value, { client: fresh, userId: 783 })
  assert.equal(warnings[0].message, '\nCreateNewSession - a session file with the same name is already existed, returning the old session')
  assert.equal(warnings[0].message, core.EXISTING_SESSION_KEPT)
  assert.deepEqual(log, ['fresh updates.getState', 'fresh account.getAuthorizations', 'fresh getMe'])

  // Another api id: 1.5.0 warns, discards the local session file and logs
  // in again; the old authorization is never logged out on the server.
  // The fake answers auth.logOut and has logOut() so that a log-out would
  // show up in the log instead of failing as an unexpected request.
  log = []
  fresh = new FakeClient(
    'fresh',
    log,
    {
      'updates.getState': { _: 'updates.state' },
      'account.getAuthorizations': sessions(6),
      'auth.logOut': { _: 'auth.loggedOut' },
      'auth.exportLoginToken': success(784),
      ...POST_LOGIN_ANSWERS,
    },
    { dc: 2 },
  )
  fresh.logOut = async () => {
    log.push('fresh logOut')
  }
  fresh.disconnect = async () => {
    log.push('fresh disconnect')
  }
  fresh.storage = {
    clear: async (withAuthKeys) => {
      log.push(`fresh storage.clear ${withAuthKeys}`)
    },
  }
  const replaced = await withWarnings(() =>
    qrLoginToNewClient(new FakeClient('authorized', log, {}, { dc: 4 }), fresh, { profile: DESKTOP, delay: noDelay }),
  )
  assert.equal(replaced.error, undefined)
  assert.deepEqual(replaced.value, { client: fresh, userId: 784 })
  assert.deepEqual(
    replaced.warnings.map((warning) => [warning.name, warning.message]),
    [['UserWarning', core.EXISTING_SESSION_REPLACED]],
  )
  assert.match(core.EXISTING_SESSION_REPLACED, /api_id is different from the current one, it will be overwritten$/)
  assert.ok(!log.includes('fresh logOut'), 'logOut() was called')
  assert.ok(!fresh.requests.some((request) => request._ === 'auth.logOut'), 'auth.logOut was sent')
  assert.deepEqual(log, [
    'authorized getPrimaryDcId',
    'fresh getPrimaryDcId',
    'fresh changePrimaryDc 4',
    'fresh updates.getState',
    'fresh account.getAuthorizations',
    'fresh disconnect',
    'fresh storage.clear true',
    // The cleared storage held DC 4; the realignment finds the client there.
    'authorized getPrimaryDcId',
    'fresh getPrimaryDcId',
    'fresh auth.exportLoginToken',
    'fresh notifyLoggedIn 784',
    ...POST_LOGIN_SEQUENCE.map((method) => `fresh ${method}`),
  ])

  // Without disconnect() and storage.clear() the session cannot be
  // discarded locally, and it is not logged out instead.
  log = []
  fresh = new FakeClient('fresh', log, {
    'updates.getState': { _: 'updates.state' },
    'account.getAuthorizations': sessions(6),
    'auth.logOut': { _: 'auth.loggedOut' },
  })
  const bare = await withWarnings(() => qrLoginToNewClient(new FakeClient('authorized', log, {}), fresh, { profile: DESKTOP }))
  assert.ok(bare.error instanceof TypeError, String(bare.error))
  assert.match(bare.error.message, /disconnect\(\) and storage\.clear\(\)/)
  assert.deepEqual(log, ['fresh updates.getState', 'fresh account.getAuthorizations'])
})

test('postLoginRequests ignores failures and counts them', async () => {
  const log = []
  const client = new FakeClient('client', log, { ...POST_LOGIN_ANSWERS, 'help.getNearestDc': rpc(400, 'X'), 'help.getCountriesList': rpc(500, 'Y') })
  assert.equal(await postLoginRequests(client, 'android', noDelay), 2)
  assert.deepEqual(log, POST_LOGIN_SEQUENCE.map((method) => `client ${method}`))
  assert.equal(await isAuthorized(new FakeClient('c', [], { 'updates.getState': rpc(401, 'SESSION_PASSWORD_NEEDED') })), false)
  await assert.rejects(isAuthorized(new FakeClient('c', [], { 'updates.getState': () => new Error('socket closed') })), /socket closed/)
})

test('the flow constants, post-login steps and delays are the core ones', () => {
  assert.equal(QR_LOGIN_ATTEMPTS, core.QR_LOGIN_ATTEMPTS)
  assert.equal(QR_LOGIN_ATTEMPTS, 5)
  assert.equal(QR_LOGIN_TIMEOUT, core.QR_LOGIN_TIMEOUT)
  assert.equal(core.QR_EXPIRE_SAFETY_SECONDS, 5)
  assert.equal(core.SRP_ALGORITHM, 'passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow')
  assert.equal(core.QR_TIMEOUT_ERROR_TYPE, "<class 'TimeoutError'>")
  assert.equal(core.qrAttemptTimeoutWarning(2, 'X'), '\nQRLoginToNewClient attempt 2 failed because X')

  const all = core.postLoginSteps()
  assert.deepEqual(all.map((step) => step.request), POST_LOGIN_SEQUENCE)
  assert.deepEqual(POST_LOGIN_DELAYS_MS, [null, [100, 300], [200, 400], [100, 200], [300, 500], [100, 300], [50, 150]])
  assert.deepEqual(all.map((step) => step.delayMs ?? null), POST_LOGIN_DELAYS_MS)
  assert.ok(Object.isFrozen(POST_LOGIN_DELAYS_MS) && Object.isFrozen(POST_LOGIN_DELAYS_MS[1]))
  assert.deepEqual(core.postLoginSteps('android'), all)
  assert.deepEqual(
    core.postLoginSteps('').map((step) => step.request),
    POST_LOGIN_SEQUENCE.filter((method) => method !== 'langpack.getLanguages'),
  )

  const seen = new Set()
  for (let n = 0; n < 400; n += 1) {
    const delay = core.randomDelayMs(50, 53)
    assert.ok(Number.isInteger(delay) && delay >= 50 && delay <= 53, String(delay))
    seen.add(delay)
  }
  assert.equal(seen.size, 4)
  assert.equal(core.randomDelayMs(7, 7), 7)
  assert.throws(() => core.randomDelayMs(2, 1), { code: 'OT_INVALID_INPUT' })
})

test('consistencyReport names, fails raised checks and builds the warning', () => {
  const finished = core.consistencyChecks().map((name, n) => ({ passed: true, detail: `d${n}` }))
  const ok = core.consistencyReport(finished)
  assert.deepEqual(ok.checks, core.consistencyChecks().map((name, n) => ({ name, passed: true, detail: `d${n}` })))
  assert.equal(ok.allPassed, true)
  assert.equal(ok.summary, core.consistencySummary(ok.checks))
  assert.equal(ok.warning ?? null, null)

  const raised = core.consistencyReport([{ raised: 'boom' }, ...finished.slice(1)])
  assert.deepEqual(raised.checks[0], { name: 'get_config', passed: false, detail: core.checkException('boom') })
  assert.equal(raised.allPassed, false)
  assert.equal(raised.warning, core.CONSISTENCY_WARNING_PREFIX + raised.summary)

  assert.throws(() => core.consistencyReport(finished.slice(1)), { code: 'ERR_INVALID_ARG_VALUE', message: /needs 7 outcomes, got 6/ })
  assert.throws(() => core.consistencyReport([{ passed: true }, ...finished.slice(1)]), { code: 'ERR_INVALID_ARG_VALUE' })
})

// --- session admin -------------------------------------------------------------

const AUTHORIZATIONS = {
  _: 'account.authorizations',
  authorizationTtlDays: 180,
  authorizations: [
    {
      _: 'authorization',
      current: true,
      officialApp: true,
      hash: Long.ZERO,
      deviceModel: 'Desktop',
      platform: 'Windows',
      systemVersion: 'Windows 11 x64',
      apiId: 2040,
      appName: 'Telegram Desktop',
      appVersion: '6.1.3 x64',
      dateCreated: 0,
      dateActive: 0,
      ip: '',
      country: '',
      region: '',
    },
    {
      _: 'authorization',
      hash: Long.fromString('-6153014343128052893'),
      deviceModel: 'samsungSM-S938B',
      platform: 'android',
      systemVersion: 'SDK 36',
      apiId: 6,
      officialApp: true,
      appName: 'Telegram Android',
      appVersion: '12.0.1 (61234)',
      dateCreated: 0,
      dateActive: 0,
      ip: '',
      country: '',
      region: '',
    },
    {
      _: 'authorization',
      hash: Long.fromString('17'),
      deviceModel: 'Pixel 8 Прo',
      platform: '',
      systemVersion: 'Linux',
      apiId: 123456,
      appName: 'My bot thing',
      appVersion: '0.1',
      dateCreated: 0,
      dateActive: 0,
      ip: '',
      country: '',
      region: '',
    },
  ],
}

test('getSessions, getCurrentSession, sessionRow, formatSessions and isOfficialApp', async () => {
  const log = []
  const client = new FakeClient('client', log, { 'account.getAuthorizations': () => AUTHORIZATIONS })
  assert.equal(await getSessions(client), AUTHORIZATIONS)
  assert.equal(await getCurrentSession(client), AUTHORIZATIONS.authorizations[0])
  assert.equal(await isOfficialApp(client), true)
  const rows = AUTHORIZATIONS.authorizations.map(sessionRow)
  assert.deepEqual(rows[2], {
    current: false,
    deviceModel: 'Pixel 8 Прo',
    platform: '',
    systemVersion: 'Linux',
    apiId: 123456,
    appName: 'My bot thing',
    appVersion: '0.1',
    officialApp: false,
  })
  // Absent flags read as false, through the core sessionRow.
  const { current: _current, officialApp: _officialApp, ...flagless } = AUTHORIZATIONS.authorizations[2]
  assert.deepEqual(sessionRow(flagless), rows[2])
  assert.deepEqual(sessionRow(flagless), core.sessionRow(flagless))
  const table = core.formatSessions(rows)
  assert.equal(await formatSessions(client), table)
  assert.equal(await formatSessions(AUTHORIZATIONS), table)
  assert.equal(await formatSessions(AUTHORIZATIONS.authorizations), table)
  assert.equal(table.split('\n')[3], '| Current |     Desktop     | Windows  | Windows 11 x64 |  2040  |   Telegram Desktop 6.1.3 x64    |      ✔       |')
  assert.deepEqual(log, Array(4).fill('client account.getAuthorizations'))

  const others = { ...AUTHORIZATIONS, authorizations: AUTHORIZATIONS.authorizations.slice(1) }
  const noCurrent = new FakeClient('c', [], { 'account.getAuthorizations': others })
  assert.equal(await getCurrentSession(noCurrent), null)
  assert.equal(await isOfficialApp(new FakeClient('c', [], { 'account.getAuthorizations': others })), false)
  const unofficial = { ...AUTHORIZATIONS, authorizations: [{ ...AUTHORIZATIONS.authorizations[0], officialApp: false }] }
  assert.equal(await isOfficialApp(new FakeClient('c', [], { 'account.getAuthorizations': unofficial })), false)

  const broken = await rejection(getSessions(new FakeClient('c', [], { 'account.getAuthorizations': {} })))
  assert.equal(broken.code, 'OT_SESSIONS_UNAVAILABLE')
  assert.equal(broken.message, core.SESSIONS_UNAVAILABLE)
  assert.equal((await rejection(formatSessions(null))).message, core.SESSIONS_UNAVAILABLE)
})

test('terminateSession maps the 1.5.0 errors', async () => {
  const hash = AUTHORIZATIONS.authorizations[1].hash
  const log = []
  const ok = new FakeClient('client', log, { 'account.resetAuthorization': true })
  assert.equal(await terminateSession(ok, hash), undefined)
  assert.equal(ok.requests[0].hash, hash)
  assert.deepEqual(log, ['client account.resetAuthorization'])

  for (const [text, code, name, message] of [
    ['FRESH_RESET_AUTHORISATION_FORBIDDEN', 'OT_FRESH_RESET_FORBIDDEN', 'FreshResetAuthorisationForbiddenError', core.FRESH_RESET_FORBIDDEN],
    ['HASH_INVALID', 'OT_HASH_INVALID', 'HashInvalidError', core.HASH_INVALID],
  ]) {
    const error = await rejection(terminateSession(new FakeClient('c', [], { 'account.resetAuthorization': rpc(400, text) }), hash))
    assert.equal(error.code, code)
    assert.equal(error.name, name)
    assert.equal(error.message, message)
    assert.ok(tl.RpcError.is(error.cause, text))
  }
  const other = await rejection(terminateSession(new FakeClient('c', [], { 'account.resetAuthorization': rpc(420, 'FLOOD_WAIT_%d') }), hash))
  assert.ok(tl.RpcError.is(other, 'FLOOD_WAIT_%d'))
})

test('terminateAllSessions ends every other session in order and stops on failure', async () => {
  const log = []
  const client = new FakeClient('client', log, { 'account.getAuthorizations': AUTHORIZATIONS, 'account.resetAuthorization': () => true })
  assert.equal(await terminateAllSessions(client), 2)
  assert.deepEqual(log, ['client account.getAuthorizations', 'client account.resetAuthorization', 'client account.resetAuthorization'])
  assert.deepEqual(
    client.requests.slice(1).map((request) => request.hash),
    [AUTHORIZATIONS.authorizations[1].hash, AUTHORIZATIONS.authorizations[2].hash],
  )

  const failing = new FakeClient('client', [], {
    'account.getAuthorizations': AUTHORIZATIONS,
    'account.resetAuthorization': [rpc(406, 'FRESH_RESET_AUTHORISATION_FORBIDDEN'), true],
  })
  assert.equal((await rejection(terminateAllSessions(failing))).code, 'OT_FRESH_RESET_FORBIDDEN')
  assert.equal(failing.requests.length, 2)
})

// --- consistency -----------------------------------------------------------------

const CONSISTENT = {
  'help.getConfig': { _: 'config', thisDc: 2 },
  'help.getNearestDc': { _: 'nearestDc', country: 'NL', thisDc: 2, nearestDc: 4 },
  'account.getAuthorizations': AUTHORIZATIONS,
  'langpack.getLanguages': () => [{ _: 'langPackLanguage' }, { _: 'langPackLanguage' }, { _: 'langPackLanguage' }],
  'help.getAppUpdate': { _: 'help.noAppUpdate' },
  'help.getTermsOfServiceUpdate': { _: 'help.termsOfServiceUpdateEmpty', expires: 0 },
}

const CHECK_CALLS = [
  'help.getConfig',
  'help.getNearestDc',
  'account.getAuthorizations',
  'langpack.getLanguages',
  'help.getAppUpdate',
  'help.getTermsOfServiceUpdate',
]

const check = (name, passed, detail) => ({ name, passed, detail })

test('runConsistencyChecks: every check passes', async () => {
  const log = []
  const client = new FakeClient('client', log, CONSISTENT)
  const { value: results, warnings } = await withWarnings(() => runConsistencyChecks(client, DESKTOP))
  assert.deepEqual(results.map((result) => result.name), core.consistencyChecks())
  assert.deepEqual(results, [
    check('get_config', true, core.getConfigDetail(2)),
    check('nearest_dc', true, core.nearestDcDetail('NL', 2, 4)),
    check('current_session', true, core.currentSessionDetail(sessionRow(AUTHORIZATIONS.authorizations[0]))),
    core.layerResult(tl.LAYER),
    check('lang_pack', true, core.langPackDetail('tdesktop', 3)),
    check('app_update', true, core.NO_APP_UPDATE),
    check('terms_of_service', true, core.TERMS_OF_SERVICE_OK),
  ])
  assert.ok(results[3].passed, 'mtcute layer is within tolerance')
  assert.match(core.consistencySummary(results), /^Consistency: 7\/7 checks passed/)
  assert.deepEqual(log, CHECK_CALLS.map((method) => `client ${method}`))
  assert.deepEqual(client.requests[3], { _: 'langpack.getLanguages', langPack: 'tdesktop' })
  assert.deepEqual(client.requests[4], { _: 'help.getAppUpdate', source: '' })
  assert.equal(warnings.length, 0)
})

test('runConsistencyChecks: every check fails, and the 1.5.0 warning', async () => {
  const errors = {}
  const handlers = {}
  for (const method of CHECK_CALLS) {
    errors[method] = new tl.RpcError(400, `BOOM_${method.split('.')[1].toUpperCase()}`)
    handlers[method] = () => errors[method]
  }
  const log = []
  const profile = core.profile('TelegramAndroid')
  const { value: results, warnings } = await withWarnings(() =>
    runConsistencyChecks(new FakeClient('client', log, handlers), profile, undefined, { layer: 300 }),
  )
  const text = (method) => errors[method].message
  assert.deepEqual(results, [
    check('get_config', false, core.getConfigError(text('help.getConfig'))),
    check('nearest_dc', false, core.nearestDcError(text('help.getNearestDc'))),
    check('current_session', false, core.checkError(text('account.getAuthorizations'))),
    core.layerResult(300),
    check('lang_pack', false, core.langPackError('android', text('langpack.getLanguages'))),
    check('app_update', false, core.appUpdateError(text('help.getAppUpdate'))),
    check('terms_of_service', false, core.checkError(text('help.getTermsOfServiceUpdate'))),
  ])
  assert.equal(results[3].passed, false)
  assert.deepEqual(log, CHECK_CALLS.map((method) => `client ${method}`))
  assert.equal(warnings.length, 1)
  assert.equal(warnings[0].name, 'UserWarning')
  assert.equal(warnings[0].message, core.CONSISTENCY_WARNING_PREFIX + core.consistencySummary(results))
  assert.match(warnings[0].message, /Consistency: 0\/7 checks passed/)
})

test('runConsistencyChecks: web profile, unofficial and missing sessions, an update, a raising check', async () => {
  const unofficial = { ...AUTHORIZATIONS, authorizations: [{ ...AUTHORIZATIONS.authorizations[0], officialApp: false }] }
  let log = []
  const web = await runConsistencyChecks(
    new FakeClient('client', log, { ...CONSISTENT, 'account.getAuthorizations': unofficial, 'help.getAppUpdate': { _: 'help.appUpdate', version: '6.2.0' } }),
    core.profile('TelegramWeb_A'),
    null,
    { autoWarn: false },
  )
  assert.deepEqual(web[2], check('current_session', false, core.currentSessionDetail(sessionRow(unofficial.authorizations[0]))))
  assert.deepEqual(web[4], check('lang_pack', true, core.LANG_PACK_EMPTY))
  assert.deepEqual(web[5], check('app_update', true, core.appUpdateDetail('6.2.0')))
  // An empty lang pack asks the server nothing.
  assert.deepEqual(log, CHECK_CALLS.filter((method) => method !== 'langpack.getLanguages').map((method) => `client ${method}`))

  log = []
  const missing = await runConsistencyChecks(
    new FakeClient('client', log, {
      ...CONSISTENT,
      'account.getAuthorizations': { ...AUTHORIZATIONS, authorizations: AUTHORIZATIONS.authorizations.slice(1) },
      // A malformed answer raises out of the check's own handling.
      'help.getNearestDc': null,
    }),
    DESKTOP,
    undefined,
    { autoWarn: false },
  )
  assert.deepEqual(missing[2], check('current_session', false, core.CURRENT_SESSION_MISSING))
  assert.equal(missing[1].name, 'nearest_dc')
  assert.equal(missing[1].passed, false)
  assert.match(missing[1].detail, /^Exception: /)
  assert.equal(missing.length, 7)
})

// --- tdata ------------------------------------------------------------------------

test('tdataFromClient builds a folder from the exported session and getMe', async () => {
  const want = loadJson('tdata.json').folders[FOLDERS[0]].accounts[0]
  const account = vectorAccount(want)
  const session = core.mtcuteStringSession(account)
  const log = []
  const client = new FakeClient('client', log, {}, { me: { id: Number(want.user_id) } })
  client.exportSession = async () => {
    log.push('client exportSession')
    return session
  }
  const tdata = await tdataFromClient(client)
  assert.deepEqual(log, ['client exportSession', 'client getMe'])
  assert.equal(tdata.accounts.length, 1)
  const [made] = tdata.accounts
  assert.equal(made.index, 0)
  assert.equal(made.userId, BigInt(want.user_id))
  assert.equal(made.mainDc, want.main_dc)
  assertSame(made.authKey, unhex(want.auth_key), 'main DC key')
  assert.deepEqual(made.keys.map((key) => key.dcId), [want.main_dc])

  // The passcode reaches the folder: it loads with it and not without.
  const dir = await mkdtemp(path.join(tmpdir(), 'opentele2-mtcute-'))
  try {
    const locked = await tdataFromClient(client, { passcode: 'fixture-passcode', performanceMode: false })
    await core.saveTdata(locked, dir)
    const loaded = await core.loadTdata(dir, 'fixture-passcode')
    assertSame(loaded.mainAccount.authKey, unhex(want.auth_key), 'reloaded key')
    assert.equal((await rejection(core.loadTdata(dir))).code, 'OT_TDATA_BAD_DECRYPT_KEY')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }

  // Without getMe, users.getUsers; without a user, OT_USER_ID_UNRESOLVED.
  const bare = new FakeClient('bare', [], { 'users.getUsers': [[{ _: 'user', id: 784 }], []] })
  bare.exportSession = async () => session
  assert.equal((await tdataFromClient(bare)).accounts[0].userId, 784n)
  const error = await rejection(tdataFromClient(bare))
  assert.equal(error.code, 'OT_USER_ID_UNRESOLVED')
  assert.equal(error.message, USER_ID_UNRESOLVED)
  assert.equal(await getMeId(new FakeClient('c', [], {}, { me: { id: 785 } })), 785)
})

// --- live -------------------------------------------------------------------------

const LIVE = process.env.OPENTELE2_LIVE === '1'

test(
  'live: read-only flows over a real mtcute client',
  { skip: !LIVE && 'set OPENTELE2_LIVE=1 and OPENTELE2_MTCUTE_SESSION to run' },
  async (t) => {
    const session = process.env.OPENTELE2_MTCUTE_SESSION
    if (!session) {
      t.skip('OPENTELE2_MTCUTE_SESSION is not set')
      return
    }
    const { TelegramClient } = await import('@mtcute/node')
    const { MemoryStorage } = await import('@mtcute/core')
    const profile = core.profile(process.env.OPENTELE2_LIVE_CLIENT ?? 'TelegramDesktop')
    const client = new TelegramClient({
      apiId: profile.apiId,
      apiHash: profile.apiHash,
      storage: new MemoryStorage(),
      initConnectionOptions: initConnectionOptions(profile),
      crypto: await createCryptoProvider(),
    })
    try {
      await client.importSession(session)
      assert.ok(await isAuthorized(client))
      assert.ok(Number.isInteger(await getMeId(client)))
      const results = await runConsistencyChecks(client, profile, undefined, { autoWarn: false })
      assert.deepEqual(results.map((result) => result.name), core.consistencyChecks())
      assert.ok((await formatSessions(client)).includes('Official App'))
      assert.equal(typeof (await isOfficialApp(client)), 'boolean')
    } finally {
      await client.destroy()
    }
  },
)
