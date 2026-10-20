// crypto.test.mjs: AES-IGE and the KDFs against crypto.json; the hashes,
// HMAC, PBKDF2, AES-CTR, pq factorisation, gzip and the random source
// against node:crypto and node:zlib.

import assert from 'node:assert/strict'
import {
  checkPrimeSync,
  createCipheriv,
  createHash,
  createHmac,
  generatePrimeSync,
  pbkdf2Sync,
  randomBytes,
  randomInt,
} from 'node:crypto'
import { test } from 'node:test'
import { gunzipSync, gzipSync } from 'node:zlib'

import { assertSame, core, loadJson, prepareAesOldmtp, rejection, thrown, unhex } from './helpers.mjs'

const vectors = loadJson('crypto.json')

test('the package exports every function and the TData class', () => {
  for (const name of [
    'aesIgeEncrypt',
    'aesIgeDecrypt',
    'createLocalKey',
    'createLegacyLocalKey',
    'argon2id',
    'sha1',
    'sha256',
    'hmacSha256',
    'pbkdf2',
    'factorizePq',
    'randomFill',
    'randomBytes',
    'gzip',
    'gunzip',
    'loadTdata',
    'saveTdata',
    'newTdata',
    'loadMany',
    'telethonStringSession',
    'mtcuteStringSession',
    'profile',
    'generate',
  ]) {
    assert.equal(typeof core[name], 'function', name)
  }
  assert.equal(typeof core.TData, 'function')
  assert.throws(() => new core.TData())
  assert.equal(typeof core.AesCtr, 'function')
})

test('the JS reference of prepareAES_oldmtp matches its vectors', () => {
  const cases = vectors.prepare_aes_oldmtp
  assert.deepEqual(new Set(cases.map((c) => c.send)), new Set([true, false]))
  cases.forEach((c, n) => {
    const { key, iv } = prepareAesOldmtp(unhex(c.auth_key), unhex(c.msg_key), c.send)
    assertSame(key, unhex(c.aes_key), `aes_key case ${n}`)
    assertSame(iv, unhex(c.aes_iv), `aes_iv case ${n}`)
  })
})

test('aesIgeEncrypt and aesIgeDecrypt reproduce the local encryption vectors', () => {
  const cases = vectors.encrypt_local
  assert.ok(cases.length > 0)
  cases.forEach((c, n) => {
    const encrypted = unhex(c.encrypted)
    const { key, iv } = prepareAesOldmtp(unhex(c.local_key), encrypted.subarray(0, 16))
    const body = encrypted.subarray(16)
    const plain = Buffer.concat([unhex(c.decrypted), unhex(c.padding)])
    const decrypted = core.aesIgeDecrypt(body, key, iv)
    assert.ok(Buffer.isBuffer(decrypted))
    assertSame(decrypted, plain, `decrypt ${n}`)
    assertSame(core.aesIgeEncrypt(plain, key, iv), body, `encrypt ${n}`)
    // A plain Uint8Array is accepted as well as a Buffer.
    assertSame(core.aesIgeDecrypt(new Uint8Array(body), new Uint8Array(key), iv), plain, `u8 ${n}`)
  })
})

test('AES-IGE round trips random data and leaves its input alone', () => {
  const key = randomBytes(32)
  const iv = randomBytes(32)
  for (const size of [0, 16, 32, 4096]) {
    const data = randomBytes(size)
    const copy = Buffer.from(data)
    const encrypted = core.aesIgeEncrypt(data, key, iv)
    assert.equal(encrypted.length, size)
    assertSame(data, copy, `input ${size}`)
    assertSame(core.aesIgeDecrypt(encrypted, key, iv), data, `round trip ${size}`)
  }
})

test('AES-IGE throws OT_BAD_LENGTH on bad lengths', () => {
  const key = Buffer.alloc(32, 7)
  const iv = Buffer.alloc(32, 9)
  for (const fn of [core.aesIgeEncrypt, core.aesIgeDecrypt]) {
    for (const [data, k, v] of [
      [Buffer.alloc(15, 1), key, iv],
      [Buffer.alloc(16, 1), key.subarray(0, 31), iv],
      [Buffer.alloc(16, 1), key, Buffer.alloc(33)],
    ]) {
      const error = thrown(() => fn(data, k, v))
      assert.ok(error instanceof Error)
      assert.equal(error.code, 'OT_BAD_LENGTH')
    }
  }
})

test('createLocalKey and createLegacyLocalKey match their vectors', async () => {
  for (const [n, c] of vectors.create_local_key.entries()) {
    const promise = core.createLocalKey(c.passcode, unhex(c.salt))
    assert.ok(promise instanceof Promise)
    const key = await promise
    assert.equal(key.length, 256)
    assertSame(key, unhex(c.key), `local key ${n}`)
    const bytes = await core.createLocalKey(Buffer.from(c.passcode, 'utf8'), unhex(c.salt))
    assertSame(bytes, key, `local key bytes passcode ${n}`)
  }
  for (const [n, c] of vectors.create_legacy_local_key.entries()) {
    const key = await core.createLegacyLocalKey(c.passcode, unhex(c.salt))
    assertSame(key, unhex(c.key), `legacy local key ${n}`)
  }
})

test('argon2id matches the wrap vector and rejects with a code', async () => {
  const c = vectors.argon2id_wrap
  const wrap = await core.argon2id(c.passcode, unhex(c.salt), c.memory_kib, c.time, c.lanes)
  assert.equal(wrap.length, 256)
  assertSame(wrap, unhex(c.wrap_key), 'wrap_key')

  const empty = await rejection(core.argon2id('', unhex(c.salt), 64, 1, 1))
  assert.ok(empty instanceof Error)
  assert.equal(empty.code, 'OT_BAD_LENGTH')
  const zero = await rejection(core.argon2id('x', unhex(c.salt), 64, 0, 1))
  assert.equal(zero.code, 'OT_TDATA_BAD_DECRYPT_KEY')
})

// Sizes around the 64-byte hash block and its padding boundary.
const HASH_SIZES = [0, 1, 55, 56, 63, 64, 65, 1000, 65537]

test('sha1 and sha256 match node:crypto on fixed and random data', () => {
  assertSame(core.sha1(Buffer.from('abc')), unhex('a9993e364706816aba3e25717850c26c9cd0d89d'), 'sha1 abc')
  assertSame(
    core.sha256(Buffer.from('abc')),
    unhex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    'sha256 abc',
  )
  for (const size of [...HASH_SIZES, randomInt(1, 4096)]) {
    const data = new Uint8Array(randomBytes(size))
    const sha1 = core.sha1(data)
    assert.ok(Buffer.isBuffer(sha1))
    assertSame(sha1, createHash('sha1').update(data).digest(), `sha1 ${size}`)
    assertSame(core.sha256(data), createHash('sha256').update(data).digest(), `sha256 ${size}`)
  }
})

test('hmacSha256 takes the key first and matches createHmac for every key length', () => {
  // RFC 4231 test case 2.
  assertSame(
    core.hmacSha256(Buffer.from('Jefe'), Buffer.from('what do ya want for nothing?')),
    unhex('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'),
    'rfc 4231 case 2',
  )
  for (const keySize of [0, 1, 32, 63, 64, 65, 131]) {
    const key = randomBytes(keySize)
    const data = randomBytes(randomInt(0, 2048))
    assertSame(core.hmacSha256(key, data), createHmac('sha256', key).update(data).digest(), `key ${keySize}`)
  }
})

test('pbkdf2 matches pbkdf2Sync, defaults to 64 bytes of sha512, and rejects with a code', async () => {
  const salt = randomBytes(16)
  const password = randomBytes(24)
  const promise = core.pbkdf2(password, salt, 1000)
  assert.ok(promise instanceof Promise)
  const key = await promise
  assert.ok(Buffer.isBuffer(key))
  assertSame(key, pbkdf2Sync(password, salt, 1000, 64, 'sha512'), 'defaults')
  for (const [digest, keyLen] of [
    ['sha1', 20],
    ['sha1', 41],
    ['sha256', 32],
    ['SHA256', 100],
    ['sha512', 1],
    ['sha512', 200],
  ]) {
    const iterations = randomInt(1, 2000)
    assertSame(
      await core.pbkdf2(password, salt, iterations, keyLen, digest),
      pbkdf2Sync(password, salt, iterations, keyLen, digest.toLowerCase()),
      `${digest} ${keyLen}`,
    )
  }
  assertSame(
    await core.pbkdf2('pässword', salt, 10, 32, 'sha256'),
    pbkdf2Sync(Buffer.from('pässword', 'utf8'), salt, 10, 32, 'sha256'),
    'string password',
  )

  const zero = await rejection(core.pbkdf2(password, salt, 0))
  assert.ok(zero instanceof Error)
  assert.equal(zero.code, 'OT_INVALID_INPUT')
  const md5 = await rejection(core.pbkdf2(password, salt, 1, 16, 'md5'))
  assert.equal(md5.code, 'OT_INVALID_INPUT')
})

test('AesCtr matches aes-256-ctr in one call and streamed in uneven chunks', () => {
  // The all-ones IV checks that the 128-bit counter wraps as OpenSSL's does.
  for (const iv of [randomBytes(16), Buffer.alloc(16, 0xff), Buffer.alloc(16)]) {
    const key = randomBytes(32)
    const data = randomBytes(4099)
    const reference = createCipheriv('aes-256-ctr', key, iv).update(data)

    const whole = new core.AesCtr(key, iv).process(data)
    assert.ok(Buffer.isBuffer(whole))
    assertSame(whole, reference, 'one call')
    assertSame(new core.AesCtr(key, iv).process(whole), data, 'decrypt')

    const stream = new core.AesCtr(new Uint8Array(key), new Uint8Array(iv))
    const chunks = []
    let offset = 0
    for (const size of [0, 1, 15, 16, 17, 100, 31, 1024]) {
      chunks.push(stream.process(data.subarray(offset, offset + size)))
      offset += size
    }
    chunks.push(stream.process(data.subarray(offset)))
    assertSame(Buffer.concat(chunks), reference, 'streamed')
  }

  const input = randomBytes(32)
  const copy = Buffer.from(input)
  new core.AesCtr(randomBytes(32), randomBytes(16)).process(input)
  assertSame(input, copy, 'input untouched')
})

test('AesCtr throws OT_BAD_LENGTH on a bad key or iv', () => {
  for (const [key, iv] of [
    [Buffer.alloc(16), Buffer.alloc(16)],
    [Buffer.alloc(31), Buffer.alloc(16)],
    [Buffer.alloc(32), Buffer.alloc(32)],
    [Buffer.alloc(32), Buffer.alloc(15)],
  ]) {
    const error = thrown(() => new core.AesCtr(key, iv))
    assert.ok(error instanceof Error)
    assert.equal(error.code, 'OT_BAD_LENGTH')
  }
})

/** `value` as minimal big-endian bytes. */
function bigBytes(value) {
  const hex = value.toString(16)
  return Buffer.from(hex.length % 2 === 0 ? hex : `0${hex}`, 'hex')
}

test('factorizePq splits fixed and random products of two primes', () => {
  // The pq of the MTProto auth key exchange example.
  const [p, q] = core.factorizePq(unhex('17ed48941a08f981'))
  assertSame(p, unhex('494c553b'), 'example p')
  assertSame(q, unhex('53911073'), 'example q')
  // Leading zeros are allowed; factors come back minimal and p <= q.
  const [two, three] = core.factorizePq(unhex('000006'))
  assertSame(two, unhex('02'), 'small p')
  assertSame(three, unhex('03'), 'small q')
  const [root, again] = core.factorizePq(bigBytes(65521n * 65521n))
  assertSame(root, again, 'square')

  for (let n = 0; n < 8; n += 1) {
    const bits = randomInt(2, 33)
    const a = generatePrimeSync(bits, { bigint: true })
    const b = generatePrimeSync(randomInt(2, 33), { bigint: true })
    const [lo, hi] = a <= b ? [a, b] : [b, a]
    const factors = core.factorizePq(bigBytes(a * b))
    assert.ok(Array.isArray(factors) && factors.length === 2)
    assertSame(factors[0], bigBytes(lo), `p ${a * b}`)
    assertSame(factors[1], bigBytes(hi), `q ${a * b}`)
  }
})

test('factorizePq throws a code on bad lengths, primes, 0 and 1', () => {
  for (const pq of [Buffer.alloc(0), Buffer.alloc(9, 1)]) {
    assert.equal(thrown(() => core.factorizePq(pq)).code, 'OT_BAD_LENGTH')
  }
  const prime = generatePrimeSync(61, { bigint: true })
  assert.ok(checkPrimeSync(prime))
  for (const pq of [unhex('00'), unhex('01'), unhex('07'), bigBytes(prime)]) {
    const error = thrown(() => core.factorizePq(pq))
    assert.ok(error instanceof Error)
    assert.equal(error.code, 'OT_INVALID_INPUT')
  }
})

test('randomFill fills exactly the view it is given and randomBytes returns fresh bytes', () => {
  const backing = new Uint8Array(96)
  const view = backing.subarray(16, 80)
  assert.equal(core.randomFill(view), undefined)
  assert.ok(backing.subarray(0, 16).every((byte) => byte === 0), 'bytes before the view')
  assert.ok(backing.subarray(80).every((byte) => byte === 0), 'bytes after the view')
  assert.ok(view.some((byte) => byte !== 0), 'the view is filled')
  core.randomFill(new Uint8Array(0))
  const buffer = Buffer.alloc(32)
  core.randomFill(buffer)
  assert.ok(!buffer.equals(Buffer.alloc(32)))

  for (const size of [0, 1, 32, 4096]) {
    const bytes = core.randomBytes(size)
    assert.ok(Buffer.isBuffer(bytes))
    assert.equal(bytes.length, size)
  }
  assert.ok(!core.randomBytes(32).equals(core.randomBytes(32)))
  // 4096 random bytes hit every byte value with overwhelming probability.
  assert.equal(new Set(core.randomBytes(4096)).size, 256)
})

test('gzip and gunzip round trip with node:zlib and honour maxSize', () => {
  const text = Buffer.from('opentele2 '.repeat(5000))
  for (const data of [Buffer.alloc(0), text, randomBytes(70000), randomBytes(randomInt(1, 4096))]) {
    const packed = core.gzip(data)
    assert.ok(Buffer.isBuffer(packed))
    assertSame(gunzipSync(packed), data, `zlib reads gzip ${data.length}`)
    assertSame(core.gunzip(packed), data, `round trip ${data.length}`)
    assertSame(core.gunzip(gzipSync(data)), data, `gunzip reads zlib ${data.length}`)
    assertSame(core.gzip(data, packed.length), packed, `limit at the size ${data.length}`)
    assert.equal(core.gzip(data, packed.length - 1), null, `limit under the size ${data.length}`)
  }
  assert.ok(core.gzip(text, 1024).length < 1024)
  assert.equal(core.gzip(randomBytes(1024), 512), null)

  for (const bad of [Buffer.from('not gzip'), gzipSync(text).subarray(0, 40)]) {
    const error = thrown(() => core.gunzip(bad))
    assert.ok(error instanceof Error)
    assert.equal(error.code, 'OT_IO')
  }
})
