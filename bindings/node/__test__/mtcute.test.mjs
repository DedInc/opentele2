// mtcute.test.mjs: `opentele2/mtcute` against the real @mtcute/core and
// @mtcute/node devDependencies.

import assert from 'node:assert/strict'
import { generatePrimeSync, randomBytes, randomInt } from 'node:crypto'
import path from 'node:path'
import { test } from 'node:test'

import { readStringSession } from '@mtcute/core/utils.js'
import { NodeCryptoProvider } from '@mtcute/node/utils.js'

import { createCryptoProvider, initConnectionOptions, toStringSession } from 'opentele2/mtcute'

import { FOLDERS, VECTORS, assertSame, core, loadJson, unhex } from './helpers.mjs'

const manifest = loadJson('tdata.json').folders

test("mtcute's own reader decodes mtcuteStringSession output", async () => {
  for (const folder of FOLDERS) {
    const entry = manifest[folder]
    const tdata = await core.loadTdata(path.join(VECTORS, ...folder.split('/')), entry.passcode)
    tdata.accounts.forEach((account, n) => {
      const want = entry.accounts[n]
      const session = toStringSession(account)
      assert.equal(session, core.mtcuteStringSession(account))
      const data = readStringSession(session)
      assert.equal(data.version, 3)
      assert.equal(data.primaryDcs.main.id, want.main_dc, `${folder} dc`)
      assert.equal(data.primaryDcs.media.id, want.main_dc, `${folder} media dc`)
      assert.equal(data.primaryDcs.main.port, 443)
      assert.equal(data.primaryDcs.main.ipv6 ?? false, false)
      assert.equal(data.self.userId, want.user_id, `${folder} user id`)
      assert.equal(data.self.isBot, false)
      assertSame(data.authKey, unhex(want.auth_key), `${folder} key`)
    })
  }
})

test('initConnectionOptions carries the six initConnection fields', () => {
  const profile = core.generate('TelegramDesktop', 'opentele2', 'windows')
  const { params, ...options } = initConnectionOptions(profile)
  assert.deepEqual(options, {
    deviceModel: profile.deviceModel,
    systemVersion: profile.systemVersion,
    appVersion: profile.appVersion,
    systemLangCode: profile.systemLangCode,
    langPack: profile.langPack,
    langCode: profile.langCode,
  })
  // tdesktop also sends params ({tz_offset}), as 1.5.0 Python does.
  assert.equal(params?._, 'jsonObject')
  assert.ok(!('apiId' in options) && !('apiHash' in options))
})

const PROVIDER_MEMBERS = [
  'initialize',
  'sha1',
  'sha256',
  'pbkdf2',
  'hmacSha256',
  'createAesCtr',
  'createAesIge',
  'factorizePQ',
  'gzip',
  'gunzip',
  'randomFill',
  'randomBytes',
]

/** Our provider and mtcute's NodeCryptoProvider, both initialised. */
async function providers() {
  const ours = await createCryptoProvider()
  const theirs = new NodeCryptoProvider()
  await ours.initialize()
  await theirs.initialize()
  return { ours, theirs }
}

test('the crypto provider is a plain object with every ICryptoProvider member', async () => {
  const promise = createCryptoProvider()
  assert.ok(promise instanceof Promise)
  const ours = await promise
  assert.ok(!(ours instanceof NodeCryptoProvider))
  assert.equal(Object.getPrototypeOf(ours), Object.prototype)
  assert.deepEqual(Object.keys(ours).sort(), [...PROVIDER_MEMBERS].sort())
  for (const name of PROVIDER_MEMBERS) {
    assert.equal(typeof ours[name], 'function', name)
  }
  assert.equal(ours.initialize(), undefined)
})

test("the crypto provider's hashes and HMAC match mtcute's default provider", async () => {
  const { ours, theirs } = await providers()
  for (const size of [0, 1, 64, 65, 4096]) {
    const data = new Uint8Array(randomBytes(size))
    assertSame(ours.sha1(data), theirs.sha1(data), `sha1 ${size}`)
    assertSame(ours.sha256(data), theirs.sha256(data), `sha256 ${size}`)
    const key = new Uint8Array(randomBytes(size % 100))
    assertSame(await ours.hmacSha256(data, key), await theirs.hmacSha256(data, key), `hmac ${size}`)
  }
})

test("the crypto provider's pbkdf2 matches mtcute's default provider", async () => {
  const { ours, theirs } = await providers()
  const password = new Uint8Array(randomBytes(32))
  const salt = new Uint8Array(randomBytes(16))
  // The 2FA call: no keylen or algo, so 64 bytes of sha512.
  const key = await ours.pbkdf2(password, salt, 1000)
  assert.equal(key.length, 64)
  assertSame(key, await theirs.pbkdf2(password, salt, 1000), 'sha512 default')
  for (const [keylen, algo] of [
    [32, 'sha256'],
    [20, 'sha1'],
    [100, 'sha512'],
  ]) {
    assertSame(
      await ours.pbkdf2(password, salt, 777, keylen, algo),
      await theirs.pbkdf2(password, salt, 777, keylen, algo),
      `${algo} ${keylen}`,
    )
  }
})

test("the crypto provider's AES-CTR matches mtcute's default provider streamed in chunks", async () => {
  const { ours, theirs } = await providers()
  const key = new Uint8Array(randomBytes(32))
  const iv = new Uint8Array(randomBytes(16))
  const data = new Uint8Array(randomBytes(10000))
  // The obfuscated transport keeps one encryptor and one decryptor open.
  const encryptor = ours.createAesCtr(key, iv, true)
  const reference = theirs.createAesCtr(key, iv, true)
  const decryptor = ours.createAesCtr(key, iv, false)
  let offset = 0
  for (const size of [64, 1, 15, 16, 17, 333, 4096, 0, 5000]) {
    const chunk = data.subarray(offset, offset + size)
    offset += size
    const encrypted = encryptor.process(chunk)
    assertSame(encrypted, reference.process(chunk), `chunk ending at ${offset}`)
    assertSame(decryptor.process(encrypted), chunk, `decrypted chunk ending at ${offset}`)
  }
  assert.ok(offset < data.length)
  const rest = data.subarray(offset)
  assertSame(encryptor.process(rest), reference.process(rest), 'tail')
})

test("the crypto provider's IGE matches mtcute's default provider", async () => {
  const { ours, theirs } = await providers()
  for (const size of [16, 32, 1024, 65536]) {
    const key = randomBytes(32)
    const iv = randomBytes(32)
    const data = new Uint8Array(randomBytes(size))
    const mine = ours.createAesIge(key, iv)
    const reference = theirs.createAesIge(key, iv)
    const encrypted = mine.encrypt(data)
    assertSame(encrypted, reference.encrypt(data), `encrypt ${size}`)
    assertSame(mine.decrypt(encrypted), data, `round trip ${size}`)
    assertSame(mine.decrypt(data), reference.decrypt(data), `decrypt ${size}`)
    // A scheme is reusable: a second call starts from the same IV.
    assertSame(mine.encrypt(data), encrypted, `reuse ${size}`)
  }
})

test("the crypto provider's factorizePQ matches mtcute's default provider", async () => {
  const { ours, theirs } = await providers()
  const pqs = [unhex('17ed48941a08f981')]
  for (let n = 0; n < 6; n += 1) {
    const product = generatePrimeSync(randomInt(16, 33), { bigint: true }) * generatePrimeSync(32, { bigint: true })
    pqs.push(Buffer.from(product.toString(16).padStart(16, '0'), 'hex'))
  }
  for (const pq of pqs) {
    const mine = await ours.factorizePQ(pq)
    const reference = await theirs.factorizePQ(pq)
    assert.equal(mine.length, 2)
    assertSame(mine[0], reference[0], `p of ${pq.toString('hex')}`)
    assertSame(mine[1], reference[1], `q of ${pq.toString('hex')}`)
  }
})

test("the crypto provider's gzip round trips through mtcute's gunzip and returns null past maxSize", async () => {
  const { ours, theirs } = await providers()
  const text = new Uint8Array(Buffer.from('{"_":"message","text":"opentele2"} '.repeat(400)))
  // session-connection.js gzips with a limit of 90% of the input.
  const packed = ours.gzip(text, Math.floor(text.length * 0.9))
  assert.ok(packed !== null && packed.length < text.length * 0.9)
  assertSame(ours.gunzip(packed), text, 'our round trip')
  assertSame(theirs.gunzip(packed), text, 'mtcute reads our gzip')

  // Random bytes do not compress: both providers give up.
  const noise = new Uint8Array(randomBytes(2048))
  const limit = Math.floor(noise.length * 0.9)
  assert.equal(ours.gzip(noise, limit), null)
  assert.equal(theirs.gzip(noise, limit), null)
})

test("the crypto provider's random source fills buffers mtcute hands it", async () => {
  const { ours } = await providers()
  const buf = new Uint8Array(64)
  assert.equal(ours.randomFill(buf), undefined)
  assert.ok(buf.some((byte) => byte !== 0))
  const bytes = ours.randomBytes(48)
  assert.ok(bytes instanceof Uint8Array)
  assert.equal(bytes.length, 48)
  assert.ok(!Buffer.from(ours.randomBytes(32)).equals(Buffer.from(ours.randomBytes(32))))
})
