// sqlite_unavailable.fixture.mjs: run by telethon_sqlite.test.mjs under
// `node --no-experimental-sqlite`. Prints, as JSON, whether
// opentele2/telethon loads and the code each file function rejects with.

const telethon = await import('../telethon.mjs')

async function codeOf(promise) {
  try {
    await promise
    return null
  } catch (error) {
    return error.code ?? String(error)
  }
}

const rows = { dcId: 2, serverAddress: '149.154.167.51', port: 443, authKey: new Uint8Array(256) }
const account = { index: 0, userId: 77n, mainDc: 2, authKey: new Uint8Array(256) }
const profile = { apiId: 1, apiHash: 'hash', deviceModel: 'd', systemVersion: 's', appVersion: 'a', langCode: 'en', systemLangCode: 'en', langPack: '' }
// Nothing is written: every call rejects before touching the filesystem.
const base = new URL('./never-written', import.meta.url).pathname

console.log(
  JSON.stringify({
    loaded: typeof telethon.writeSessionFile === 'function',
    write: await codeOf(telethon.writeSessionFile(base, rows)),
    read: await codeOf(telethon.readSessionFile(base)),
    pair: await codeOf(telethon.saveSessionPair(base, account, profile)),
  }),
)
