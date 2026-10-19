// mtcute.test.mjs: `opentele2/mtcute` against the real @mtcute/core and
// @mtcute/node devDependencies.

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
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
  const options = initConnectionOptions(profile)
  assert.deepEqual(options, {
    deviceModel: profile.deviceModel,
    systemVersion: profile.systemVersion,
    appVersion: profile.appVersion,
    systemLangCode: profile.systemLangCode,
    langPack: profile.langPack,
    langCode: profile.langCode,
  })
  assert.ok(!('apiId' in options) && !('apiHash' in options))
})

test("the crypto provider's IGE matches mtcute's default provider", async () => {
  const ours = await createCryptoProvider()
  const theirs = new NodeCryptoProvider()
  await ours.initialize?.()
  await theirs.initialize()

  // Only createAesIge is replaced; everything else is mtcute's own.
  assert.ok(ours instanceof NodeCryptoProvider)
  assert.ok(Object.hasOwn(ours, 'createAesIge'))
  assert.deepEqual(Object.keys(ours), ['createAesIge'])
  assert.equal(ours.sha256, NodeCryptoProvider.prototype.sha256)

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
