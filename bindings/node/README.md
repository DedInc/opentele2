<p align="center">
  <img src="https://raw.githubusercontent.com/DedInc/opentele2/main/opentele.png" alt="opentele2 logo" width="160"/>
</p>

<h1 align="center">opentele2</h1>

<p align="center">
  <b>A Telegram client identity toolkit for Node</b>: Telegram Desktop tdata, mtcute and
  Telethon sessions, official API profiles with realistic devices, initConnection fingerprint
  checks and browser fingerprints, on a Rust core.
</p>

## What it does

- **tdata**: reads and writes Telegram Desktop 7.3.1 folders, including passcode-locked ones,
  several accounts per folder and the stored MTP config.
- **mtcute** (`opentele2/mtcute`): string sessions, `initConnection` options for a profile, a
  complete `ICryptoProvider` on the core, QR login with 2FA, session admin, the consistency
  checks and tdata back from a client.
- **Telethon** (`opentele2/telethon`): string sessions and the `.session` + `.json` pair,
  byte-identical to the Python package.
- **Official API profiles**: Telegram Desktop, Android, Telegram X, iOS, macOS, Web A, Web K
  and Webogram, with weighted device catalogs; the same unique id gives the same device in
  Node, Python and Rust.
- **Browser fingerprints**: HTTP headers and full browser fingerprints, deterministic by seed.

## Installation

```bash
npm install opentele2 @mtcute/node
```

Node 18+. Prebuilt addons for Windows, macOS and Linux (glibc and musl), x64 and arm64.
`opentele2/mtcute` needs `@mtcute/node` 0.32 or newer.

## Example

```js
import { TelegramClient } from '@mtcute/node'
import { generateFingerprint, generateHeaders, loadTdata, profile } from 'opentele2'
import { createCryptoProvider, initConnectionOptions, toStringSession } from 'opentele2/mtcute'
import { saveSessionPair } from 'opentele2/telethon'

const tdata = await loadTdata('tdata') // loadTdata('tdata', passcode) for a locked folder
const desktop = profile('TelegramDesktop')

const client = new TelegramClient({
  apiId: desktop.apiId,
  apiHash: desktop.apiHash,
  initConnectionOptions: initConnectionOptions(desktop),
  crypto: await createCryptoProvider(),
})
await client.importSession(toStringSession(tdata.mainAccount))
console.log(await client.getMe())

// Telethon: a .session file and its .json companion.
await saveSessionPair('account', tdata.mainAccount, desktop)

const headers = await generateHeaders({ browsers: 'chrome', os: 'windows' }, 'my-id')
const { navigator } = await generateFingerprint({ screen: { maxWidth: 1920 } }, 42)
```

## Links

- Documentation: [https://opentele2.github.io/](https://opentele2.github.io/)
- Source and the Python and Rust packages: [https://github.com/DedInc/opentele2](https://github.com/DedInc/opentele2)
- Release notes: [CHANGELOG.md](https://github.com/DedInc/opentele2/blob/main/CHANGELOG.md)

## License

MIT. The bundled browser fingerprint data is Apache-2.0
([NOTICE](https://github.com/DedInc/opentele2/blob/main/crates/opentele2-browser/NOTICE)).
