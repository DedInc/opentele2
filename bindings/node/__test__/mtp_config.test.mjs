// mtp_config.test.mjs: accountMtpConfig and accountEndpoints against
// crates/opentele2-core/tests/tdata_read.rs, and migrateTdata against the
// tdata_legacy vectors of crates/opentele2-core/tests/tdata_write.rs.

import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'

import { CUSTOM_CONFIG, VECTORS, core, loadJson, rejection, unhex } from './helpers.mjs'

const key = Buffer.alloc(256, 9)
const account = (mainDc, config) => ({ index: 0, userId: 77n, mainDc, authKey: key, config })
const ep = (id, flags, ip, port = 443, secret = Buffer.alloc(0)) => ({ id, flags, ip, port, secret })
const {
  MTP_FLAG_CDN: CDN,
  MTP_FLAG_IPV6: IPV6,
  MTP_FLAG_MEDIA_ONLY: MEDIA,
  MTP_FLAG_SECRET: SECRET,
  MTP_FLAG_STATIC: STATIC,
  MTP_FLAG_TCPO_ONLY: TCPO,
} = core

const scratch = mkdtempSync(path.join(tmpdir(), 'opentele2-node-mtp-'))
after(() => rmSync(scratch, { recursive: true, force: true }))
let counter = 0
const freshDir = () => path.join(scratch, `out-${counter++}`)

test('the MTP flags are tdesktop values', () => {
  assert.deepEqual(
    [IPV6, MEDIA, TCPO, CDN, STATIC, core.MTP_FLAG_THIS_PORT_ONLY, SECRET],
    [1, 2, 4, 8, 16, 32, 1024],
  )
})

test('the production default config and its endpoints', async () => {
  const production = core.accountMtpConfig(account(2))
  assert.equal(production.environment, 'production')
  assert.deepEqual(
    production.dcs.map((dc) => dc.dcId),
    [1, 2, 3, 4, 5],
  )
  assert.equal(production.fields.chatSizeMax, 200)
  assert.equal(production.fields.webFileDcId, 4)
  assert.equal(production.fields.txtDomainString, 'apv3.stel.com')
  assert.equal(production.fields.reactionDefaultCustom, 0n)
  assert.deepEqual(production.cdnPublicKeys, [])

  const dc2 = core.accountEndpoints(account(2))
  assert.deepEqual(
    dc2.ipv4.tcp.map((e) => e.ip),
    ['149.154.167.51', '95.161.76.100'],
  )
  assert.deepEqual(dc2.ipv4.http, dc2.ipv4.tcp)
  assert.deepEqual(dc2.ipv6.tcp, [ep(2, STATIC | IPV6, '2001:067c:04e8:f002:0000:0000:0000:000a')])
  assert.deepEqual(dc2.selectedIpv4, dc2.ipv4.tcp[0])
  assert.deepEqual(dc2.selectedIpv6, dc2.ipv6.tcp[0])
  assert.deepEqual(core.accountEndpoints(account(2), 2), dc2)
  assert.equal(core.accountEndpoints(account(2), 6), null)
  assert.equal(core.accountEndpoints(account(2), 0), null)
  // Bytes that do not parse fall back to the production default.
  assert.deepEqual(core.accountMtpConfig(account(2, Buffer.from([0, 0, 0, 1]))), production)

  // The configs files of the vector folders are that same default.
  const tdata = await core.loadTdata(path.join(VECTORS, 'tdata_plain', 'performance_off'))
  for (const loaded of tdata.accounts) {
    assert.ok(Buffer.isBuffer(loaded.config), 'performance_off stores configs')
    assert.deepEqual(core.accountMtpConfig(loaded), production)
  }
  const plain = await core.loadTdata(path.join(VECTORS, 'tdata_plain', 'performance_on'))
  assert.ok(plain.accounts.every((loaded) => loaded.config === undefined))
})

test('no account reads the production default, as Python does', () => {
  const production = core.accountMtpConfig(account(2))
  assert.deepEqual(core.accountMtpConfig(), production)
  assert.deepEqual(core.accountMtpConfig(null), production)
  // The default main DC is 0, a DC no config lists; an explicit DC is read.
  assert.equal(core.accountEndpoints(), null)
  assert.equal(core.accountEndpoints(undefined), null)
  assert.deepEqual(core.accountEndpoints(null, 2), core.accountEndpoints(account(2)))
  assert.deepEqual(core.accountEndpoints(undefined, 4), core.accountEndpoints(account(2), 4))
  assert.equal(core.accountEndpoints(null, 6), null)
})

test('a stored custom config reads back', () => {
  const config = core.accountMtpConfig(account(2, unhex(CUSTOM_CONFIG)))
  assert.equal(config.environment, 'production')
  assert.deepEqual(
    config.dcs.map((dc) => dc.dcId),
    [2, 1, 3],
    'DCs in first-seen order, 1001 not stored',
  )
  assert.deepEqual(config.cdnPublicKeys, [{ dcId: 203, n: Buffer.from([1, 2, 3]), e: Buffer.from([1, 0, 1]) }])
  const fields = config.fields
  assert.equal(fields.chatSizeMax, 321)
  assert.equal(fields.revokePrivateInbox, true)
  assert.equal(fields.txtDomainString, '')
  assert.equal(fields.reactionDefaultEmoji, '❤')
  assert.equal(fields.reactionDefaultCustom, (1n << 63n) + 5n)
  assert.equal(fields.ratingDecay, -7)
  assert.equal(fields.gifSearchUsername, 'gifs')
  assert.equal(fields.venueSearchUsername, 'venues')

  const secret = Buffer.from(Array.from({ length: 16 }, (_, n) => n + 1))
  const dc1 = core.accountEndpoints(account(2, unhex(CUSTOM_CONFIG)), 1)
  const v6 = ep(1, IPV6 | SECRET, '2001:db8::1', 443, Buffer.alloc(32, 0xab))
  assert.deepEqual(dc1.ipv4.tcp, [ep(1, STATIC, '198.51.100.1')])
  assert.deepEqual(dc1.ipv4.http, dc1.ipv4.tcp)
  assert.deepEqual(dc1.ipv6.tcp, [v6])
  assert.deepEqual(dc1.ipv6.http, [])

  const dc2 = core.accountEndpoints(account(2, unhex(CUSTOM_CONFIG)))
  const plain = ep(2, 0, '203.0.113.2')
  const media = ep(2, MEDIA, '203.0.113.4', 80)
  const v6Static = ep(2, IPV6 | STATIC, '2001:db8::22')
  assert.deepEqual(dc2.ipv4.tcp, [plain, ep(2, SECRET, '203.0.113.3', 8443, secret), media])
  assert.deepEqual(dc2.ipv4.http, [plain, media])
  assert.deepEqual(dc2.ipv6.tcp, [ep(2, IPV6 | TCPO, '2001:db8::2'), v6Static])
  assert.deepEqual(dc2.ipv6.http, [v6Static])

  const dc3 = core.accountEndpoints(account(3, unhex(CUSTOM_CONFIG)))
  assert.deepEqual(dc3.ipv4.tcp, [ep(3, CDN, '198.51.100.3')])
  assert.deepEqual(dc3.ipv6, { tcp: [], http: [] })
  assert.equal(dc3.selectedIpv6.ip, '198.51.100.3', 'falls back to IPv4')
  for (const [dc, ip4, ip6] of [
    [1, '198.51.100.1', '2001:db8::1'],
    [2, '203.0.113.2', '2001:db8::2'],
    [3, '198.51.100.3', '198.51.100.3'],
  ]) {
    const endpoints = core.accountEndpoints(account(2, unhex(CUSTOM_CONFIG)), dc)
    assert.deepEqual([endpoints.selectedIpv4.ip, endpoints.selectedIpv6.ip], [ip4, ip6], `DC ${dc}`)
  }
  assert.equal(core.accountEndpoints(account(5, unhex(CUSTOM_CONFIG))), null)
})

/** The salt, open wrap and trailer of a key file: everything a save keeps. */
function keyFileWraps(dir) {
  const file = readFileSync(path.join(dir, 'key_datas'))
  const payload = file.subarray(8, file.length - 16)
  const parts = []
  let at = 0
  for (let n = 0; n < 3; n++) {
    const length = payload.readUInt32BE(at)
    const size = length === 0xffffffff ? 0 : length
    parts.push(payload.subarray(at, at + 4 + size))
    at += 4 + size
  }
  // The accounts info (parts[2]) is encrypted afresh by every save.
  return Buffer.concat([parts[0], parts[1], payload.subarray(at)])
}

for (const name of ['plain', 'passcode']) {
  test(`migrateTdata keeps one migration of tdata_legacy/${name} across saves`, async () => {
    const entry = loadJson('tdata.json').folders[`tdata_legacy/${name}`]
    const source = path.join(VECTORS, 'tdata_legacy', name)
    const legacy = await core.loadTdata(source, entry.passcode)
    assert.equal(legacy.legacyKeyFile, true)

    // Unmigrated, every save writes a fresh wrap.
    const [first, second] = [freshDir(), freshDir()]
    await core.saveTdata(legacy, first)
    await core.saveTdata(legacy, second)
    assert.ok(!keyFileWraps(first).equals(keyFileWraps(second)), 'unmigrated saves share a wrap')
    assert.equal(legacy.legacyKeyFile, true)

    assert.equal(await core.migrateTdata(legacy), true)
    assert.equal(legacy.legacyKeyFile, false)
    assert.equal(await core.migrateTdata(legacy), false, 'a migrated folder migrates again')
    const [third, fourth] = [freshDir(), freshDir()]
    await core.saveTdata(legacy, third)
    await core.saveTdata(legacy, fourth)
    assert.ok(keyFileWraps(third).equals(keyFileWraps(fourth)), 'migrated saves differ in their wrap')

    // The saved folder opens with the same passcode only.
    const reloaded = await core.loadTdata(third, entry.passcode)
    assert.equal(reloaded.legacyKeyFile, false)
    assert.deepEqual(
      reloaded.accounts.map((a) => [a.index, a.userId, a.mainDc]),
      legacy.accounts.map((a) => [a.index, a.userId, a.mainDc]),
    )
    assert.equal(reloaded.mainAccount.index, entry.main_account_index)
    if (entry.passcode !== '') {
      assert.equal((await rejection(core.loadTdata(third))).code, 'OT_TDATA_BAD_DECRYPT_KEY')
    }
  })
}

test('migrateTdata leaves a 7.3 folder alone', async () => {
  const tdata = await core.loadTdata(path.join(VECTORS, 'tdata_plain', 'performance_on'))
  assert.equal(tdata.legacyKeyFile, false)
  assert.equal(await core.migrateTdata(tdata), false)
})
