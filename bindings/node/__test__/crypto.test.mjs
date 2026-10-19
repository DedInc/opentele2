// crypto.test.mjs: AES-IGE and the KDFs against crypto.json.

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'

import { assertSame, core, loadJson, prepareAesOldmtp, rejection, thrown, unhex } from './helpers.mjs'

const vectors = loadJson('crypto.json')

test('the package exports every function and the TData class', () => {
  for (const name of [
    'aesIgeEncrypt',
    'aesIgeDecrypt',
    'createLocalKey',
    'createLegacyLocalKey',
    'argon2id',
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
