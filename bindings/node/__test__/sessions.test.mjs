// sessions.test.mjs: telethonStringSession and mtcuteStringSession against
// sessions.json and the vector accounts.

import assert from 'node:assert/strict'
import path from 'node:path'
import { test } from 'node:test'

import {
  MTCUTE_BOOL_FALSE,
  PRODUCTION,
  VECTORS,
  assertSame,
  core,
  decodeTelethon,
  encodeTelethon,
  loadJson,
  packIp,
  thrown,
  unhex,
} from './helpers.mjs'

test('telethonStringSession matches the sessions.json layout', () => {
  const cases = loadJson('sessions.json').cases
  assert.equal(cases.length, 7)
  cases.forEach((c, n) => {
    const key = unhex(c.auth_key)
    const ipv6 = c.ip_version === 6
    // The reference layout reproduces the vector exactly.
    const decoded = decodeTelethon(c.string_session)
    assert.equal(decoded.dcId, c.dc_id)
    assert.ok(decoded.ip.equals(packIp(c.ip)), `ip ${n}`)
    assert.equal(decoded.port, c.port)
    assertSame(decoded.key, key, `vector key ${n}`)
    assert.equal(encodeTelethon(c.dc_id, c.ip, c.port, key), c.string_session)

    // The binding writes the same layout for the production endpoint.
    const account = { index: 0, userId: 1n, mainDc: c.dc_id, authKey: key }
    const session = core.telethonStringSession(account, ipv6)
    const production = PRODUCTION[c.dc_id][ipv6 ? 1 : 0]
    assert.equal(session, encodeTelethon(c.dc_id, production, 443, key))
  })
})

test('both sessions of the vector accounts carry their key', async () => {
  const entry = loadJson('tdata.json').folders['tdata_plain/performance_on']
  const tdata = await core.loadTdata(path.join(VECTORS, 'tdata_plain', 'performance_on'))
  tdata.accounts.forEach((account, n) => {
    const want = entry.accounts[n]
    const key = unhex(want.auth_key)
    for (const ipv6 of [false, true]) {
      const decoded = decodeTelethon(core.telethonStringSession(account, ipv6))
      assert.equal(decoded.dcId, want.main_dc)
      assert.ok(decoded.ip.equals(packIp(PRODUCTION[want.main_dc][ipv6 ? 1 : 0])))
      assert.equal(decoded.port, 443)
      assertSame(decoded.key, key, 'telethon key')
    }
    assert.equal(core.telethonStringSession(account), core.telethonStringSession(account, false))

    const mtcute = core.mtcuteStringSession(account)
    assert.ok(!mtcute.includes('='))
    const raw = Buffer.from(mtcute, 'base64url')
    assert.equal(raw[0], 3)
    assert.equal(raw.readInt32LE(1), 1)
    const self = raw.subarray(raw.length - 272, raw.length - 260)
    assert.equal(self.readBigUInt64LE(0), BigInt(want.user_id))
    assert.equal(self.readUInt32LE(8), MTCUTE_BOOL_FALSE)
    assert.ok(raw.subarray(raw.length - 260, raw.length - 256).equals(Buffer.from([0xfe, 0x00, 0x01, 0x00])))
    assertSame(raw.subarray(raw.length - 256), key, 'mtcute key')
  })
})

test('a DC outside the production table throws OT_TDATA_BAD_CONFIG_DATA', () => {
  const account = { index: 0, userId: 1n, mainDc: 7, keys: [{ dcId: 7, authKey: Buffer.alloc(256) }] }
  assert.equal(thrown(() => core.telethonStringSession(account)).code, 'OT_TDATA_BAD_CONFIG_DATA')
  assert.equal(thrown(() => core.mtcuteStringSession(account)).code, 'OT_TDATA_BAD_CONFIG_DATA')
})
