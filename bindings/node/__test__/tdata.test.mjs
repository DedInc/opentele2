// tdata.test.mjs: loadTdata, saveTdata, newTdata and loadMany against the
// four vector folders of tdata.json.

import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'

import {
  FOLDERS,
  VECTORS,
  assertSame,
  core,
  listedFiles,
  loadJson,
  rejection,
  thrown,
  unhex,
  vectorAccount,
} from './helpers.mjs'

const manifest = loadJson('tdata.json').folders
const scratch = mkdtempSync(path.join(tmpdir(), 'opentele2-node-'))
after(() => rmSync(scratch, { recursive: true, force: true }))

let counter = 0
const freshDir = () => path.join(scratch, `out-${counter++}`)
const vectorDir = (folder) => path.join(VECTORS, ...folder.split('/'))

function checkAccounts(tdata, entry, label) {
  assert.ok(tdata instanceof core.TData, label)
  const wanted = entry.accounts
  const accounts = tdata.accounts
  assert.deepEqual(
    accounts.map((a) => a.index),
    wanted.map((w) => w.index),
    label,
  )
  accounts.forEach((account, n) => {
    const want = wanted[n]
    assert.equal(typeof account.userId, 'bigint', label)
    assert.equal(account.userId, BigInt(want.user_id), label)
    assert.equal(account.mainDc, want.main_dc, label)
    assert.ok(Buffer.isBuffer(account.authKey), label)
    assertSame(account.authKey, unhex(want.auth_key), `${label} authKey`)
    assert.ok(account.keys.some((key) => key.dcId === want.main_dc), label)
    for (const key of account.keys) {
      assert.equal(key.authKey.length, 256, label)
    }
  })
  assert.equal(tdata.mainAccount.index, entry.main_account_index, label)
  assert.ok(!String(tdata).includes(want0Hex(entry)), `${label} toString shows no key`)
}

const want0Hex = (entry) => entry.accounts[0].auth_key.slice(0, 32)

for (const folder of FOLDERS) {
  test(`loadTdata and saveTdata round trip ${folder}`, async () => {
    const entry = manifest[folder]
    const promise = core.loadTdata(vectorDir(folder), entry.passcode, entry.key_file)
    assert.ok(promise instanceof Promise)
    const loaded = await promise
    checkAccounts(loaded, entry, `${folder} load`)
    // Every vector stores -1, so the main account falls back to the first.
    assert.equal(loaded.activeIndex, -1)
    assert.equal(loaded.keyFile, entry.key_file)

    // A loaded folder saves in performance mode, which writes no configs.
    const saved = freshDir()
    assert.equal(await core.saveTdata(loaded, saved), undefined)
    const expected = entry.files.filter((name) => !name.endsWith('/configs')).sort()
    assert.deepEqual(listedFiles(saved), expected)
    const reloaded = await core.loadTdata(saved, Buffer.from(entry.passcode, 'utf8'))
    checkAccounts(reloaded, entry, `${folder} reload`)
  })

  test(`newTdata writes the vector layout of ${folder}`, async () => {
    const entry = manifest[folder]
    const accounts = entry.accounts.map(vectorAccount)
    const created = await core.newTdata(accounts, entry.passcode, entry.performance_mode)
    assert.equal(created.activeIndex, -1)
    const dir = freshDir()
    await core.saveTdata(created, dir)
    assert.deepEqual(listedFiles(dir), [...entry.files].sort())
    const reloaded = await core.loadTdata(dir, entry.passcode)
    assert.deepEqual(
      reloaded.accounts.map((a) => a.userId),
      entry.accounts.map((w) => BigInt(w.user_id)),
    )
    reloaded.accounts.forEach((account, n) => {
      assertSame(account.authKey, unhex(entry.accounts[n].auth_key), `${folder} new authKey`)
    })
  })
}

test('loaded accounts feed newTdata unchanged', async () => {
  const entry = manifest['tdata_plain/performance_off']
  const loaded = await core.loadTdata(vectorDir('tdata_plain/performance_off'))
  const copy = await core.newTdata(loaded.accounts)
  checkAccounts(copy, entry, 'copy')
})

test('tdata failures carry OT_ codes', async () => {
  const plainWrong = await rejection(core.loadTdata(vectorDir('tdata_plain/performance_on'), 'opentele2'))
  assert.ok(plainWrong instanceof Error)
  assert.equal(plainWrong.code, 'OT_TDATA_BAD_DECRYPT_KEY')

  const passcodeWrong = await rejection(
    core.loadTdata(vectorDir('tdata_passcode/performance_on'), Buffer.from('not-the-passcode')),
  )
  assert.ok(passcodeWrong instanceof Error)
  assert.equal(passcodeWrong.code, 'OT_TDATA_BAD_DECRYPT_KEY')
  assert.equal(typeof passcodeWrong.message, 'string')

  const missing = await rejection(core.loadTdata(path.join(scratch, 'missing')))
  assert.ok(missing instanceof Error)
  assert.equal(missing.code, 'OT_TFILE_NOT_FOUND')

  const keyless = thrown(() => core.newTdata([{ index: 0, userId: 1n, mainDc: 2, keys: [{ dcId: 4, authKey: Buffer.alloc(256) }] }]))
  assert.equal(keyless.code, 'OT_TDATA_AUTH_KEY_NOT_FOUND')
  const noKey = thrown(() => core.mtcuteStringSession({ index: 0, userId: 1n, mainDc: 2 }))
  assert.equal(noKey.code, 'OT_TDATA_AUTH_KEY_NOT_FOUND')
  const short = thrown(() => core.newTdata([{ index: 0, userId: 1n, mainDc: 2, authKey: Buffer.alloc(255) }]))
  assert.equal(short.code, 'OT_BAD_LENGTH')
  const negative = thrown(() => core.mtcuteStringSession({ index: 0, userId: -1n, mainDc: 2, authKey: Buffer.alloc(256) }))
  assert.equal(negative.code, 'ERR_INVALID_ARG_VALUE')

  const empty = await core.newTdata([])
  assert.equal(empty.mainAccount, null)
  const saveFailed = await rejection(core.saveTdata(empty, freshDir()))
  assert.equal(saveFailed.code, 'OT_TDATA_SAVE_FAILED')
})

test('loadMany keeps input order and reports each failure', async () => {
  const passcode = manifest['tdata_passcode/performance_on'].passcode
  const requests = [
    vectorDir('tdata_plain/performance_on'),
    path.join(scratch, 'missing'),
    { path: vectorDir('tdata_passcode/performance_on'), passcode },
    { path: vectorDir('tdata_plain/performance_off'), passcode: Buffer.alloc(0), keyFile: 'data' },
    { path: vectorDir('tdata_plain/performance_on'), passcode: 'wrong' },
    { path: vectorDir('tdata_plain/performance_on'), keyFile: 'other' },
  ]
  const results = await core.loadMany(requests, 2)
  assert.equal(results.length, requests.length)
  const [first, missing, passcodeFolder, plainOff, wrong, other] = results
  checkAccounts(first, manifest['tdata_plain/performance_on'], 'loadMany 0')
  assert.ok(missing instanceof Error)
  assert.equal(missing.code, 'OT_TFILE_NOT_FOUND')
  checkAccounts(passcodeFolder, manifest['tdata_passcode/performance_on'], 'loadMany 2')
  checkAccounts(plainOff, manifest['tdata_plain/performance_off'], 'loadMany 3')
  assert.ok(wrong instanceof Error)
  assert.equal(wrong.code, 'OT_TDATA_BAD_DECRYPT_KEY')
  assert.ok(other instanceof Error)
  assert.equal(other.code, 'OT_TFILE_NOT_FOUND')

  // Without a thread cap the order holds too.
  const uncapped = await core.loadMany([path.join(scratch, 'missing'), vectorDir('tdata_plain/performance_on')])
  assert.equal(uncapped[0].code, 'OT_TFILE_NOT_FOUND')
  assert.ok(uncapped[1] instanceof core.TData)

  assert.deepEqual(await core.loadMany([]), [])
  const zero = thrown(() => core.loadMany(requests, 0))
  assert.equal(zero.code, 'ERR_INVALID_ARG_VALUE')
})
