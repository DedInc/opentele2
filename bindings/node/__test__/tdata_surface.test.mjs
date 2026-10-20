// tdata_surface.test.mjs: the TData key, version, performance-mode and
// active-index surface, and the `draws` replay hook of newTdata, saveTdata
// and migrateTdata, against crates/opentele2-core/tests/tdata_write.rs.
//
// Every vector folder is rebuilt byte for byte by replaying the recorded
// `os.urandom` draws of tdata.json. Key material is compared with
// assertSame and differs, which never print the bytes.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'

import { FOLDERS, VECTORS, assertSame, core, listedFiles, loadJson, rejection, thrown, unhex, vectorAccount } from './helpers.mjs'

const manifest = loadJson('tdata.json').folders
const scratch = mkdtempSync(path.join(tmpdir(), 'opentele2-node-surface-'))
after(() => rmSync(scratch, { recursive: true, force: true }))

let counter = 0
const freshDir = () => path.join(scratch, `out-${counter++}`)
const vectorDir = (folder) => path.join(VECTORS, ...folder.split('/'))

const APP_VERSION = 7_003_001
const NEW_FOLDER_ACTIVE_INDEX = -1
const LEGACY = ['plain', 'passcode']
// Draws a migration of a legacy key file takes: the open salt, with a
// passcode the wrap salt, then the wrap padding.
const MIGRATION_DRAWS = { plain: 2, passcode: 3 }

// The fixed performance-mode local and passcode keys, the keys
// crates/opentele2-core/src/tdata/mod.rs writes without a passcode.
const PERF_LOCAL_KEY = unhex(
  'd8745944519e0d2d71309d6c8d272dc64948f5e3eba7685324d5c691ad810c20' +
    '3b31d19d29aed6ac33c014be6e09843293f6fa32dbe42b6a04e00481fae99511' +
    '4caf6342bd98e96d293dd062c458689b3abd23a5cf230c75527c05bf5f90f38c' +
    'd93952cf61aaac1cfeaae4608592e363ded35f8d8c45234def53231decb35592' +
    'afc40d0601bbed11090969f74d9ab0cc97827546f441242d2cfb8e05a0610e97' +
    '669c0da1adccb56e39e10c69e2942387ff4922f8c55dcb8890e345ef318266f4' +
    'b3831430ea210c863c17624c0494cdead81f523430b5f74c15da323d766bd01c' +
    'b5b88b9d2a731f6d853380ad306a8647fa614cc4017f08902c1e1f997ee12e3c',
)
const PERF_PASSCODE_KEY = unhex(
  '273e6483b313c9dbc4acd9173864c0422f172881bfe1c6649ca5538654d0bd6e' +
    'bcfbcc8dabbb669717ce53b41ca8afbf9d15c23fa2b06a6e166cc61f62e99805' +
    '58cd42cf1022e05b466811ea29e9359fc1f94668e5c85155bce638fe7aa42aa8' +
    '80ca83e0d2e534198a0a890139c8f679a57d3ba06d75fe5faa6e250101a58bc6' +
    'e42b9696604de1e34ae40f6bba144a284f3ad8843253ec9b3971863a2c409208' +
    'c2563967b3587e509b42a42a6040d23ff696ad552a240084fa3f950240f499b2' +
    '3cd6d27e7010cbde07daae0667a7df8a5115a60b265c58f5d9291f7a98fc3c60' +
    '1e2a4a32f1881b8218c855239d7b532959609e6ab52e48ad691c2583b566c8f9',
)

/** Fails without showing either value when the two are equal. */
function differs(actual, expected, label) {
  if (Buffer.from(actual).equals(Buffer.from(expected))) {
    throw new Error(`${label} is unchanged`)
  }
}

const drawsOf = (entry) => entry.rng_draws.map(unhex)

/** tdata.json's `bytes(label, n)`: SHA-256 of the label and a counter. */
function labelBytes(label, size) {
  const parts = []
  for (let n = 0; parts.length * 32 < size; n++) {
    const counter = Buffer.alloc(4)
    counter.writeUInt32BE(n)
    parts.push(createHash('sha256').update(Buffer.from(label, 'utf8')).update(counter).digest())
  }
  return Buffer.concat(parts).subarray(0, size)
}

/** Draws newTdata makes: pass, salt, open salt, a wrap salt with a
 *  passcode, and the wrap padding; none for the fixed performance keys. */
function keyGenerationDraws(entry) {
  if (entry.performance_mode && !entry.passcode) {
    return 0
  }
  return entry.passcode ? 5 : 4
}

function assertSameFolder(folder, written) {
  const entry = manifest[folder]
  assert.deepEqual(listedFiles(written), entry.files, `${folder} file list`)
  for (const name of entry.files) {
    assertSame(
      readFileSync(path.join(written, name)),
      readFileSync(path.join(vectorDir(folder), name)),
      `${folder}/${name}`,
    )
  }
}

// ---------------------------------------------------------------- getters

for (const folder of FOLDERS) {
  test(`getters of ${folder}`, async () => {
    const entry = manifest[folder]
    const draws = drawsOf(entry)
    const tdata = await core.loadTdata(vectorDir(folder), entry.passcode)
    assert.equal(tdata.appVersion, APP_VERSION)
    assert.equal(tdata.activeIndex, NEW_FOLDER_ACTIVE_INDEX)
    assert.equal(tdata.performanceMode, true, 'load turns performance mode on')
    assert.ok(Buffer.isBuffer(tdata.localKey))
    assert.equal(tdata.localKey.length, 256)
    assert.equal(tdata.passcodeKey.length, 256)
    if (keyGenerationDraws(entry) === 0) {
      assertSame(tdata.localKey, PERF_LOCAL_KEY, `${folder} localKey`)
      assertSame(tdata.passcodeKey, PERF_PASSCODE_KEY, `${folder} passcodeKey`)
      return
    }
    assertSame(tdata.localKey, await core.createLocalKey(draws[0], draws[1]), `${folder} localKey`)
    if (entry.passcode) {
      differs(tdata.passcodeKey, PERF_PASSCODE_KEY, `${folder} passcodeKey`)
    } else {
      assertSame(tdata.passcodeKey, await core.createLocalKey('', draws[2]), `${folder} passcodeKey`)
    }
  })
}

for (const name of LEGACY) {
  test(`getters of tdata_legacy/${name}`, async () => {
    const source = `tdata_legacy/${name}`
    const entry = manifest[source]
    const tdata = await core.loadTdata(vectorDir(source), entry.passcode)
    assert.equal(tdata.legacyKeyFile, true)
    assert.equal(tdata.appVersion, APP_VERSION)
    assertSame(tdata.localKey, labelBytes(`${source}/local_key`, 256), `${source} localKey`)
    const salt = labelBytes(`${source}/salt`, 32)
    assertSame(tdata.passcodeKey, await core.createLocalKey(entry.passcode, salt), `${source} passcodeKey`)

    const saved = await core.loadTdata(vectorDir(`${source}_saved`), entry.passcode)
    assert.equal(saved.legacyKeyFile, false)
    assertSame(saved.localKey, tdata.localKey, `${source}_saved localKey`)
    if (!entry.passcode) {
      const openSalt = drawsOf(manifest[`${source}_saved`])[0]
      assertSame(saved.passcodeKey, await core.createLocalKey('', openSalt), `${source}_saved passcodeKey`)
    }
  })
}

// ---------------------------------------------------------------- byte-identical replay

for (const folder of FOLDERS) {
  test(`newTdata and saveTdata replay ${folder} byte for byte`, async () => {
    const entry = manifest[folder]
    const draws = drawsOf(entry)
    const split = keyGenerationDraws(entry)
    const created = await core.newTdata(
      entry.accounts.map(vectorAccount),
      entry.passcode,
      entry.performance_mode,
      undefined,
      draws.slice(0, split),
    )
    assert.equal(created.activeIndex, NEW_FOLDER_ACTIVE_INDEX)
    assert.equal(created.appVersion, APP_VERSION)
    assert.equal(created.performanceMode, entry.performance_mode)
    const dir = freshDir()
    await core.saveTdata(created, dir, undefined, draws.slice(split))
    assertSameFolder(folder, dir)

    const vector = await core.loadTdata(vectorDir(folder), entry.passcode)
    assertSame(created.localKey, vector.localKey, `${folder} localKey`)
    assertSame(created.passcodeKey, vector.passcodeKey, `${folder} passcodeKey`)
  })

  for (const how of ['setter', 'argument']) {
    test(`loadTdata and saveTdata (${how}) replay ${folder} byte for byte`, async () => {
      const entry = manifest[folder]
      const draws = drawsOf(entry).slice(keyGenerationDraws(entry))
      const tdata = await core.loadTdata(vectorDir(folder), entry.passcode)
      const dir = freshDir()
      if (how === 'setter') {
        tdata.performanceMode = entry.performance_mode
        assert.equal(tdata.performanceMode, entry.performance_mode)
        await core.saveTdata(tdata, dir, undefined, draws)
      } else {
        await core.saveTdata(tdata, dir, entry.performance_mode, draws)
        assert.equal(tdata.performanceMode, true, 'the argument applies to that save only')
      }
      assertSameFolder(folder, dir)
    })
  }
}

for (const name of LEGACY) {
  const source = `tdata_legacy/${name}`

  test(`saveTdata replays ${source}_saved byte for byte`, async () => {
    const entry = manifest[source]
    const legacy = await core.loadTdata(vectorDir(source), entry.passcode)
    const dir = freshDir()
    await core.saveTdata(legacy, dir, undefined, drawsOf(manifest[`${source}_saved`]))
    assertSameFolder(`${source}_saved`, dir)
    assert.equal(legacy.legacyKeyFile, true, 'save leaves the folder unmigrated')
  })

  test(`migrateTdata then two saves replay ${source}_saved byte for byte`, async () => {
    const entry = manifest[source]
    const draws = drawsOf(manifest[`${source}_saved`])
    const split = MIGRATION_DRAWS[name]
    const tdata = await core.loadTdata(vectorDir(source), entry.passcode)
    const localKey = tdata.localKey
    const oldPasscodeKey = tdata.passcodeKey
    assert.equal(await core.migrateTdata(tdata, draws.slice(0, split)), true)
    assert.equal(tdata.legacyKeyFile, false)
    assertSame(tdata.localKey, localKey, `${source} localKey`)
    differs(tdata.passcodeKey, oldPasscodeKey, `${source} passcodeKey`)
    const saved = await core.loadTdata(vectorDir(`${source}_saved`), entry.passcode)
    assertSame(tdata.passcodeKey, saved.passcodeKey, `${source} new wrap key`)
    for (let round = 0; round < 2; round++) {
      const dir = freshDir()
      await core.saveTdata(tdata, dir, undefined, draws.slice(split))
      assertSameFolder(`${source}_saved`, dir)
    }
  })
}

// ---------------------------------------------------------------- setters

test('performanceMode and activeIndex round trip', async () => {
  const folder = 'tdata_plain/performance_on'
  const tdata = await core.loadTdata(vectorDir(folder))
  const indices = tdata.accounts.map((a) => a.index)
  tdata.performanceMode = false
  tdata.activeIndex = 1
  assert.equal(tdata.performanceMode, false)
  assert.equal(tdata.activeIndex, 1)
  assert.equal(tdata.mainAccount.index, 1)
  assert.deepEqual(
    tdata.accounts.map((a) => a.index),
    indices,
  )
  const off = freshDir()
  await core.saveTdata(tdata, off)
  assert.deepEqual(listedFiles(off), manifest['tdata_plain/performance_off'].files)
  const reloaded = await core.loadTdata(off)
  assert.equal(reloaded.activeIndex, 1)
  assert.equal(reloaded.mainAccount.index, 1)
  assertSame(reloaded.localKey, tdata.localKey, 'reloaded localKey')

  const on = freshDir()
  await core.saveTdata(tdata, on, true)
  assert.deepEqual(listedFiles(on), manifest[folder].files)
  assert.equal(tdata.performanceMode, false)

  // A copied key is a new buffer; changing it leaves the folder alone.
  const copy = tdata.localKey
  copy.fill(0)
  differs(tdata.localKey, copy, 'localKey copy')
  // Module code is strict, so writing a getter-only property throws.
  assert.throws(() => {
    tdata.localKey = Buffer.alloc(256)
  }, TypeError)
})

test('newTdata stores the active index', async () => {
  const accounts = manifest['tdata_plain/performance_on'].accounts.map(vectorAccount)
  const tdata = await core.newTdata(accounts, undefined, undefined, 1)
  assert.equal(tdata.activeIndex, 1)
  const dir = freshDir()
  await core.saveTdata(tdata, dir)
  assert.equal((await core.loadTdata(dir)).activeIndex, 1)
  assert.equal((await core.newTdata(accounts)).activeIndex, NEW_FOLDER_ACTIVE_INDEX)
})

// ---------------------------------------------------------------- replay errors

test('draws of another size, missing or unused reject with ERR_INVALID_ARG_VALUE', async () => {
  const entry = manifest['tdata_plain/performance_off']
  const accounts = entry.accounts.map(vectorAccount)
  const draws = drawsOf(entry).slice(0, 4)
  const cases = [
    [[draws[0].subarray(1), ...draws.slice(1)], false, 'draw 0 has 255 bytes, but 256 were drawn'],
    [draws.slice(0, 3), false, 'draw 3 of 12 bytes was not given'],
    [[...draws, Buffer.alloc(4)], false, '1 of 5 draws were left unused'],
    [[Buffer.alloc(1)], true, '1 of 1 draws were left unused'],
  ]
  for (const [given, performance, message] of cases) {
    const error = await rejection(core.newTdata(accounts, undefined, performance, undefined, given))
    assert.equal(error.code, 'ERR_INVALID_ARG_VALUE', message)
    assert.ok(error.message.includes(message), error.message)
  }
  const plain = draws.map((draw) => new Uint8Array(draw))
  assert.ok((await core.newTdata(accounts, undefined, false, undefined, plain)) instanceof core.TData)
})

test('saveTdata and migrateTdata reject mismatched draws', async () => {
  const source = 'tdata_legacy/plain'
  const draws = drawsOf(manifest[`${source}_saved`])
  const legacy = await core.loadTdata(vectorDir(source))
  const short = await rejection(core.migrateTdata(legacy, draws.slice(0, 1)))
  assert.equal(short.code, 'ERR_INVALID_ARG_VALUE')
  assert.ok(short.message.includes('draw 1 of 12 bytes was not given'), short.message)
  assert.equal(legacy.legacyKeyFile, true, 'a failed replay leaves the folder as it was')
  const extra = await rejection(core.migrateTdata(legacy, draws))
  assert.equal(extra.code, 'ERR_INVALID_ARG_VALUE')
  assert.equal(legacy.legacyKeyFile, true)
  const saved = await rejection(core.saveTdata(legacy, freshDir(), undefined, [...draws, Buffer.alloc(1)]))
  assert.equal(saved.code, 'ERR_INVALID_ARG_VALUE')
  assert.ok(saved.message.includes('left unused'), saved.message)

  const modern = await core.loadTdata(vectorDir('tdata_plain/performance_on'))
  const unused = await rejection(core.migrateTdata(modern, [Buffer.alloc(1)]))
  assert.equal(unused.code, 'ERR_INVALID_ARG_VALUE')
  assert.equal(await core.migrateTdata(modern, []), false)
})

// ---------------------------------------------------------------- addTdataAccount and keyFile

const labelledAccount = (index) => ({
  index,
  userId: 9_000_000_000n + BigInt(index),
  mainDc: 2,
  authKey: labelBytes(`account ${index}`, 256),
})

test('TDATA_MAX_ACCOUNTS is the tdesktop limit', () => {
  assert.equal(core.TDATA_MAX_ACCOUNTS, 6)
})

test('addTdataAccount then save and reload', async () => {
  const folder = 'tdata_plain/performance_on'
  const tdata = await core.loadTdata(vectorDir(folder))
  const before = tdata.accounts
  const active = tdata.activeIndex
  const key = labelBytes('added account', 256)
  assert.equal(core.addTdataAccount(tdata, 9_000_000_123n, 3, new Uint8Array(key)), 2)
  assert.deepEqual(
    before.map((a) => a.index),
    [0, 1],
    'an earlier accounts array is a snapshot',
  )
  assert.deepEqual(
    tdata.accounts.map((a) => a.index),
    [0, 1, 2],
  )
  assert.equal(tdata.activeIndex, active)
  const added = tdata.accounts[2]
  assert.equal(added.userId, 9_000_000_123n)
  assert.equal(added.mainDc, 3)
  assertSame(added.authKey, key, 'added authKey')

  const dir = freshDir()
  await core.saveTdata(tdata, dir)
  assert.equal(listedFiles(dir).length, manifest[folder].files.length + 2)
  const reloaded = await core.loadTdata(dir)
  assert.deepEqual(
    reloaded.accounts.map((a) => [a.index, a.userId, a.mainDc]),
    tdata.accounts.map((a) => [a.index, a.userId, a.mainDc]),
  )
  reloaded.accounts.forEach((a, n) => assertSame(a.authKey, tdata.accounts[n].authKey, `account ${a.index} authKey`))
})

test('addTdataAccount takes the lowest free index', async () => {
  const tdata = await core.newTdata([labelledAccount(0), labelledAccount(2)])
  assert.equal(core.addTdataAccount(tdata, 1n, 1, labelBytes('gap', 256)), 1)
  assert.equal(core.addTdataAccount(tdata, 3n, 1, labelBytes('next', 256)), 3)
  assert.deepEqual(
    tdata.accounts.map((a) => a.index),
    [0, 2, 1, 3],
  )
})

test('addTdataAccount throws OT_MAX_ACCOUNT_LIMIT past TDATA_MAX_ACCOUNTS', async () => {
  const tdata = await core.loadTdata(vectorDir('tdata_plain/performance_on'))
  const added = [0, 1, 2, 3].map((n) => core.addTdataAccount(tdata, BigInt(n), 2, labelBytes(`fill ${n}`, 256)))
  assert.deepEqual(added, [2, 3, 4, 5])
  const error = thrown(() => core.addTdataAccount(tdata, 7n, 2, labelBytes('seventh', 256)))
  assert.equal(error.code, 'OT_MAX_ACCOUNT_LIMIT')
  assert.deepEqual(
    tdata.accounts.map((a) => a.index),
    [0, 1, 2, 3, 4, 5],
    'a refused add changes nothing',
  )

  const full = await core.newTdata([0, 1, 2, 3, 4, 5].map(labelledAccount))
  const again = thrown(() => core.addTdataAccount(full, 7n, 2, labelBytes('seventh', 256)))
  assert.equal(again.code, 'OT_MAX_ACCOUNT_LIMIT')
})

test('addTdataAccount rejects a bad key or user id', async () => {
  const tdata = await core.loadTdata(vectorDir('tdata_plain/performance_on'))
  assert.equal(thrown(() => core.addTdataAccount(tdata, 7n, 2, Buffer.alloc(255))).code, 'OT_BAD_LENGTH')
  assert.ok(thrown(() => core.addTdataAccount(tdata, -1n, 2, labelBytes('negative', 256))) instanceof Error)
  assert.equal(tdata.accounts.length, 2)
})

// What SaveTData writes for tdata_plain/performance_off after
// TDesktop(folder) and accounts.pop(1), with performance mode off and
// os.urandom replaying the first two recorded save draws (after the four
// local key draws): the SHA-256 of every file.
const DROPPED_SAVE = {
  'D877F783D5D3EF8C/configs': '4be29ce6d41a3915545919936d3bbd592e7320be5b3830649b40e50be309d887',
  'D877F783D5D3EF8C/maps': 'b7844ad62ceba501fadec72a0438db4de337b776f5f684b451f88843adf2fc0e',
  'D877F783D5D3EF8Cs': '10d2cbd465efc1d9eafe1a33bd1788e60643af2f7d7f9a243bba8674259ec1d6',
  key_datas: '80833c6e56b542aeb2aeaa0e0bd5e6055c928bb4d5874d9e6f1370149ba86aee',
}

test('setTdataAccounts keeps the local key and saves the recorded files', async () => {
  const folder = 'tdata_plain/performance_off'
  const tdata = await core.loadTdata(vectorDir(folder))
  tdata.performanceMode = false
  const localKey = tdata.localKey
  const passcodeKey = tdata.passcodeKey
  const before = tdata.accounts
  core.setTdataAccounts(tdata, [before[0]])
  assert.equal(before.length, 2, 'an earlier accounts array is a snapshot')
  assert.deepEqual(
    tdata.accounts.map((a) => a.index),
    [0],
  )
  assertSame(tdata.localKey, localKey, 'local key')
  assertSame(tdata.passcodeKey, passcodeKey, 'passcode key')

  const draws = manifest[folder].rng_draws.slice(4, 6).map(unhex)
  const dir = freshDir()
  await core.saveTdata(tdata, dir, undefined, draws)
  assert.deepEqual(listedFiles(dir), Object.keys(DROPPED_SAVE).sort())
  for (const [name, digest] of Object.entries(DROPPED_SAVE)) {
    const written = createHash('sha256').update(readFileSync(path.join(dir, ...name.split('/')))).digest('hex')
    assert.equal(written, digest, `${name} differs from the recorded digest`)
  }
})

test('setTdataAccounts refuses a list the folder cannot hold', async () => {
  const tdata = await core.loadTdata(vectorDir('tdata_plain/performance_on'))
  const tooMany = [0, 1, 2, 3, 4, 5, 6].map(labelledAccount)
  assert.equal(thrown(() => core.setTdataAccounts(tdata, tooMany)).code, 'OT_MAX_ACCOUNT_LIMIT')
  const repeated = thrown(() => core.setTdataAccounts(tdata, [2, 0, 2].map(labelledAccount)))
  assert.equal(repeated.code, 'OT_TDATA_SAVE_FAILED')
  const badKey = thrown(() => core.setTdataAccounts(tdata, [{ ...labelledAccount(0), authKey: Buffer.alloc(255) }]))
  assert.equal(badKey.code, 'OT_BAD_LENGTH')
  assert.deepEqual(
    tdata.accounts.map((a) => a.index),
    [0, 1],
    'a refused list changes nothing',
  )
  core.setTdataAccounts(tdata, [0, 1, 2, 3, 4, 5].map(labelledAccount))
  assert.equal(tdata.accounts.length, core.TDATA_MAX_ACCOUNTS)
})

test('setTdataAccounts keeps a loaded folder of more accounts writable', async () => {
  const dir = freshDir()
  await core.saveTdata(await core.newTdata([0, 1, 2, 3, 4, 5, 6].map(labelledAccount)), dir)
  const tdata = await core.loadTdata(dir)
  const localKey = tdata.localKey
  core.setTdataAccounts(tdata, [6, 5, 4, 3, 2, 1, 0].map(labelledAccount))
  assert.deepEqual(
    tdata.accounts.map((a) => a.index),
    [6, 5, 4, 3, 2, 1, 0],
  )
  assertSame(tdata.localKey, localKey, 'local key')
  const tooMany = thrown(() => core.setTdataAccounts(tdata, [0, 1, 2, 3, 4, 5, 6, 7].map(labelledAccount)))
  assert.equal(tooMany.code, 'OT_MAX_ACCOUNT_LIMIT')
  assert.equal(tdata.accounts.length, 7, 'a refused list changes nothing')
})

test('keyFile rename then save and reload', async () => {
  const folder = 'tdata_plain/performance_on'
  const tdata = await core.loadTdata(vectorDir(folder))
  const other = await core.loadTdata(vectorDir(folder))
  tdata.keyFile = 'custom'
  assert.equal(tdata.keyFile, 'custom')
  assert.equal(other.keyFile, 'data')
  const dir = freshDir()
  await core.saveTdata(tdata, dir)
  const files = listedFiles(dir)
  assert.ok(files.includes('key_customs'), files.join(', '))
  assert.ok(!files.includes('key_datas'))
  assert.equal(files.length, manifest[folder].files.length)
  assert.ok(
    files.every((name) => !manifest[folder].files.includes(name)),
    'account files are renamed with the key file',
  )

  assert.equal((await rejection(core.loadTdata(dir))).code, 'OT_TFILE_NOT_FOUND')
  const reloaded = await core.loadTdata(dir, undefined, 'custom')
  assert.equal(reloaded.keyFile, 'custom')
  assert.deepEqual(
    reloaded.accounts.map((a) => [a.index, a.userId]),
    tdata.accounts.map((a) => [a.index, a.userId]),
  )
  reloaded.accounts.forEach((a, n) => assertSame(a.authKey, tdata.accounts[n].authKey, `account ${a.index} authKey`))
  assertSame(reloaded.localKey, tdata.localKey, 'reloaded localKey')
})

test('keyFile rejects an empty name', async () => {
  const tdata = await core.loadTdata(vectorDir('tdata_plain/performance_on'))
  const error = thrown(() => {
    tdata.keyFile = ''
  })
  assert.equal(error.code, 'OT_TDATA_SAVE_FAILED')
  assert.equal(tdata.keyFile, 'data')
})
