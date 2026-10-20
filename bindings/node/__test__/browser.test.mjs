// browser.test.mjs: generateHeaders and generateFingerprint, the
// opentele2-browser port of browserforge, against the option semantics of
// bindings/python/python/opentele2/browser.py.

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { core } from './helpers.mjs'

// browserforge's `Fingerprint` fields, in its dump order.
const FINGERPRINT_KEYS = [
  'screen',
  'navigator',
  'headers',
  'videoCodecs',
  'audioCodecs',
  'pluginsData',
  'battery',
  'videoCard',
  'multimediaDevices',
  'fonts',
  'mockWebRTC',
  'slim',
]

// browserforge's `ScreenFingerprint` fields.
const SCREEN_KEYS = [
  'availHeight',
  'availLeft',
  'availTop',
  'availWidth',
  'clientHeight',
  'clientWidth',
  'colorDepth',
  'devicePixelRatio',
  'hasHDR',
  'height',
  'innerHeight',
  'innerWidth',
  'outerHeight',
  'outerWidth',
  'pageXOffset',
  'pageYOffset',
  'pixelDepth',
  'screenX',
  'width',
]

// browserforge's `NavigatorFingerprint` fields.
const NAVIGATOR_KEYS = [
  'appCodeName',
  'appName',
  'appVersion',
  'deviceMemory',
  'doNotTrack',
  'extraProperties',
  'hardwareConcurrency',
  'language',
  'languages',
  'maxTouchPoints',
  'oscpu',
  'platform',
  'product',
  'productSub',
  'userAgent',
  'userAgentData',
  'vendor',
  'vendorSub',
  'webdriver',
]

/** The `User-Agent` of a generated header set. */
const userAgent = (headers) => headers['User-Agent']

/** Asserts that `promise` rejects with `code`; an `OT_` code carries a `legacyMessage`. */
async function rejectsWith(promise, code, pattern) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code, error.message)
    if (pattern) assert.match(error.message, pattern)
    assert.equal('legacyMessage' in error, code.startsWith('OT_'))
    return true
  })
}

test('generateHeaders and generateFingerprint return promises', async () => {
  const headers = core.generateHeaders()
  const fingerprint = core.generateFingerprint()
  assert.ok(headers instanceof Promise)
  assert.ok(fingerprint instanceof Promise)
  assert.equal(typeof userAgent(await headers), 'string')
  assert.equal(typeof (await fingerprint).navigator.userAgent, 'string')
})

test('a seed reproduces the headers in order, as its decimal text', async () => {
  const first = await core.generateHeaders({}, 'node-seed')
  const again = await core.generateHeaders(undefined, 'node-seed')
  assert.deepEqual(Object.entries(again), Object.entries(first))
  for (const value of Object.values(first)) assert.equal(typeof value, 'string')

  const text = Object.entries(await core.generateHeaders(null, '42'))
  assert.deepEqual(Object.entries(await core.generateHeaders(null, 42)), text)
  assert.deepEqual(Object.entries(await core.generateHeaders(null, 42n)), text)
  const negative = Object.entries(await core.generateHeaders(null, '-7'))
  assert.deepEqual(Object.entries(await core.generateHeaders(null, -7n)), negative)
  assert.deepEqual(
    Object.entries(await core.generateHeaders(null, -0)),
    Object.entries(await core.generateHeaders(null, '0')),
  )
})

test('a seed reproduces the fingerprint', async () => {
  const options = { screen: { minWidth: 1024 }, header: { browsers: ['chrome'] } }
  const first = await core.generateFingerprint(options, 'fp-seed')
  const again = await core.generateFingerprint(options, 'fp-seed')
  assert.equal(JSON.stringify(again), JSON.stringify(first))
  const other = await core.generateFingerprint(options, 'fp-other')
  assert.notEqual(JSON.stringify(other), JSON.stringify(first))
})

test('without a seed every call draws anew', async () => {
  const agents = new Set()
  for (let i = 0; i < 16; i += 1) agents.add(JSON.stringify(await core.generateHeaders()))
  assert.ok(agents.size > 1)
  const one = JSON.stringify(await core.generateFingerprint())
  const two = JSON.stringify(await core.generateFingerprint())
  assert.notEqual(one, two)
})

test('browsers, os and devices constrain the headers', async () => {
  for (let i = 0; i < 8; i += 1) {
    const seed = `constraint-${i}`
    const firefox = await core.generateHeaders({ browsers: 'firefox', strict: true }, seed)
    assert.match(userAgent(firefox), /Firefox\//)
    const mac = await core.generateHeaders({ os: ['macos'], strict: true }, seed)
    assert.match(userAgent(mac), /Macintosh/)
    const mobile = await core.generateHeaders({ devices: 'mobile', strict: true }, seed)
    assert.match(userAgent(mobile), /Mobile|Android|iPhone|iPad/)
    const chrome = await core.generateHeaders(
      { browsers: [{ name: 'chrome', minVersion: 120, maxVersion: 999, httpVersion: '2' }], strict: true },
      seed,
    )
    // Chrome on iOS names itself CriOS.
    const major = Number(/(?:Chrome|CriOS)\/(\d+)/.exec(userAgent(chrome))[1])
    assert.ok(major >= 120, `Chrome ${major}`)
    const windows = await core.generateHeaders(
      { browsers: ['chrome', { name: 'edge' }], os: 'windows', devices: ['desktop'], strict: true },
      seed,
    )
    assert.match(userAgent(windows), /Windows NT/)
  }
})

test('locales, userAgent and requestDependentHeaders shape the headers', async () => {
  const german = await core.generateHeaders({ locales: ['de-DE', 'en'], httpVersion: 1 }, 'locales')
  assert.match(german['Accept-Language'], /^de-DE/)

  const agent = userAgent(await core.generateHeaders({}, 'agent'))
  for (let i = 0; i < 4; i += 1) {
    assert.equal(userAgent(await core.generateHeaders({ userAgent: agent }, `pick-${i}`)), agent)
  }
  const pinned = await core.generateHeaders({ userAgent: [agent] }, 'pinned')
  assert.equal(userAgent(pinned), agent)

  const extra = await core.generateHeaders(
    { requestDependentHeaders: { Referer: 'https://example.com/', 'X-Trace': 'abc' } },
    'extra',
  )
  assert.equal(extra.Referer, 'https://example.com/')
  assert.equal(extra['X-Trace'], 'abc')
  assert.equal(Object.keys(extra).at(-1), 'X-Trace')
})

test('the fingerprint follows its screen, flags and header options', async () => {
  for (let i = 0; i < 6; i += 1) {
    const fingerprint = await core.generateFingerprint(
      {
        screen: { minWidth: 1920, maxHeight: 2000 },
        strict: true,
        mockWebRtc: true,
        slim: true,
        header: { browsers: ['firefox'], os: 'linux', locales: ['fr-FR', 'fr'] },
      },
      `screen-${i}`,
    )
    assert.ok(fingerprint.screen.width >= 1920, `width ${fingerprint.screen.width}`)
    assert.ok(fingerprint.screen.height <= 2000, `height ${fingerprint.screen.height}`)
    assert.equal(fingerprint.mockWebRTC, true)
    assert.equal(fingerprint.slim, true)
    assert.match(fingerprint.navigator.userAgent, /Firefox\//)
    assert.match(fingerprint.navigator.userAgent, /Linux/)
    assert.equal(fingerprint.navigator.userAgent, userAgent(fingerprint.headers))
    assert.deepEqual(fingerprint.navigator.languages, ['fr-FR', 'fr'])
    assert.equal(fingerprint.navigator.language, 'fr-FR')
  }
  const plain = await core.generateFingerprint({}, 'plain')
  assert.equal(plain.mockWebRTC, false)
  assert.equal(plain.slim, false)
})

test('the fingerprint carries browserforge keys and JSON values', async () => {
  for (let i = 0; i < 12; i += 1) {
    const fingerprint = await core.generateFingerprint(null, `keys-${i}`)
    assert.deepEqual(Object.keys(fingerprint), FINGERPRINT_KEYS)
    assert.deepEqual(Object.keys(fingerprint.screen).sort(), SCREEN_KEYS)
    assert.deepEqual(Object.keys(fingerprint.navigator).sort(), NAVIGATOR_KEYS)
    for (const key of SCREEN_KEYS) {
      const kind = key === 'hasHDR' ? 'boolean' : 'number'
      assert.equal(typeof fingerprint.screen[key], kind, key)
    }
    const { navigator } = fingerprint
    assert.ok(navigator.languages.every((language) => typeof language === 'string'))
    assert.equal(typeof navigator.hardwareConcurrency, 'number')
    assert.equal(typeof navigator.maxTouchPoints, 'number')
    for (const key of ['doNotTrack', 'oscpu', 'vendor', 'vendorSub']) {
      assert.ok(navigator[key] === null || typeof navigator[key] === 'string', key)
    }
    assert.ok(navigator.deviceMemory === null || typeof navigator.deviceMemory === 'number')
    assert.equal(typeof navigator.extraProperties, 'object')
    assert.ok(Array.isArray(fingerprint.fonts))
    assert.ok(fingerprint.fonts.every((font) => typeof font === 'string'))
    for (const key of ['videoCodecs', 'audioCodecs', 'pluginsData', 'multimediaDevices']) {
      assert.equal(typeof fingerprint[key], 'object', key)
      assert.notEqual(fingerprint[key], null, key)
    }
    assert.ok(fingerprint.battery === null || typeof fingerprint.battery === 'object')
    if (fingerprint.videoCard !== null) {
      assert.deepEqual(Object.keys(fingerprint.videoCard), ['renderer', 'vendor'])
    }
    assert.equal(typeof userAgent(fingerprint.headers), 'string')
    // Plain JSON: no bigint, no undefined, nothing lost on a round trip.
    assert.deepEqual(JSON.parse(JSON.stringify(fingerprint)), fingerprint)
  }
})

test('strict options nothing satisfies reject with OT_INVALID_INPUT', async () => {
  const impossible = { browsers: ['safari'], os: ['windows'] }
  await rejectsWith(
    core.generateHeaders({ ...impossible, strict: true }, 'strict'),
    'OT_INVALID_INPUT',
    /No headers based on this input/,
  )
  // Not strict, the options relax until a sample fits.
  assert.equal(typeof userAgent(await core.generateHeaders(impossible, 'relaxed')), 'string')

  const huge = { screen: { minWidth: 99999 } }
  await rejectsWith(
    core.generateFingerprint({ ...huge, strict: true }, 'strict'),
    'OT_INVALID_INPUT',
    /screen constraints are too restrictive/,
  )
  // Not strict, the screen constraint is dropped.
  assert.equal(typeof (await core.generateFingerprint(huge, 'relaxed')).screen.width, 'number')

  await rejectsWith(
    core.generateHeaders({ userAgent: 'not a browser at all' }, 'agent'),
    'OT_INVALID_INPUT',
  )
})

test('invalid options reject with ERR_INVALID_ARG_VALUE', async () => {
  const invalid = 'ERR_INVALID_ARG_VALUE'
  await rejectsWith(core.generateHeaders({ httpVersion: 3 }), invalid, /httpVersion/)
  await rejectsWith(core.generateHeaders({ httpVersion: '1.0' }), invalid, /httpVersion/)
  await rejectsWith(
    core.generateHeaders({ browsers: [{ name: 'chrome', httpVersion: 1.5 }] }),
    invalid,
    /httpVersion/,
  )
  await rejectsWith(
    core.generateHeaders({ browsers: [{ name: 'chrome', minVersion: 130, maxVersion: 120 }] }),
    invalid,
    /cannot exceed max version/,
  )
  for (const minVersion of [-1, 1.5, Number.NaN, 2 ** 32]) {
    await rejectsWith(
      core.generateHeaders({ browsers: [{ name: 'chrome', minVersion }] }),
      invalid,
      /minVersion/,
    )
  }
  const locales = Array.from({ length: 11 }, (_, i) => `l${i}`)
  await rejectsWith(core.generateHeaders({ locales }), invalid, /at most 10 locales/)
  await rejectsWith(
    core.generateHeaders({ requestDependentHeaders: { 'X-Count': 1 } }),
    invalid,
    /requestDependentHeaders/,
  )
  await rejectsWith(
    core.generateFingerprint({ screen: { minWidth: 2000, maxWidth: 1000 } }),
    invalid,
  )
  await rejectsWith(core.generateFingerprint({ screen: { minHeight: -5 } }), invalid, /minHeight/)
  await rejectsWith(
    core.generateFingerprint({ header: { httpVersion: 0 } }),
    invalid,
    /httpVersion/,
  )
  await rejectsWith(core.generateHeaders({}, 1.5), invalid, /seed/)
  await rejectsWith(core.generateFingerprint({}, 2 ** 53), invalid, /seed/)
})
