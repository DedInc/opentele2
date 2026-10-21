<p align="center">
  <img src="https://raw.githubusercontent.com/DedInc/opentele2/main/opentele.png" alt="opentele2 logo" width="180"/>
</p>

<h1 align="center">opentele2</h1>

<p align="center">
  <b>A Telegram client identity toolkit</b>: Telegram Desktop tdata, Telethon, mtcute and grammers
  sessions, official API profiles with realistic devices, initConnection fingerprint checks and
  browser fingerprints, on one Rust core for Python, Node and Rust.
</p>

<p align="center">
  <a href="https://pypi.org/project/opentele2/"><img alt="PyPI" src="https://img.shields.io/pypi/v/opentele2?logo=pypi&logoColor=white"/></a>
  <a href="https://www.npmjs.com/package/opentele2"><img alt="npm" src="https://img.shields.io/npm/v/opentele2?logo=npm"/></a>
  <a href="https://crates.io/crates/opentele2-core"><img alt="crates.io" src="https://img.shields.io/crates/v/opentele2-core?logo=rust"/></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/DedInc/opentele2"/></a>
  <a href="https://github.com/DedInc/opentele2/actions/workflows/test.yml"><img alt="test" src="https://github.com/DedInc/opentele2/actions/workflows/test.yml/badge.svg"/></a>
</p>

## What it does

**Telegram Desktop tdata**
- Reads and writes tdata folders of Telegram Desktop 7.3.1, including passcode-locked folders
  (Argon2id and scrypt passcode wraps, PBKDF2 local keys), several accounts per folder and the
  stored MTP config with its DC endpoints. A folder with a legacy key file is migrated on save.

**Sessions**
- Telethon string sessions and `.session` files (SQLite, version 8) with their `.json` companion.
- mtcute string sessions (version 3) and grammers 0.11 `SessionData`.
- tdata back from a logged-in client session, in every ecosystem.

**Official API profiles and devices**
- Profiles of Telegram Desktop, Android, Telegram X, iOS, macOS, Web A, Web K and Webogram.
- Weighted device catalogs for Android, desktop, iOS and macOS; web devices drawn from browser
  fingerprints. The same unique id gives the same device in Python, Node and Rust.
- Live client versions from the Telegram release sources plus stable Chrome and Firefox.

**Fingerprint and consistency checks**
- `initConnection` validation: layer, lang pack, `tz_offset`, msg_id offset, transport
  recommendation (Python) and version consistency.
- Seven consistency checks of a profile against a live session.

**Client flows**
- QR login into a new session with 2FA, listing and terminating sessions, the sessions table.

**Browser fingerprints** (`opentele2-browser`)
- HTTP headers and full browser fingerprints sampled from Bayesian networks, based on
  browserforge and the Apify fingerprint datapoints. Deterministic by seed: the same seed and
  options give byte-identical output in Rust, Python and Node.

**MTProto client crypto on the Rust core**
- AES-256-IGE and -CTR, SHA-1, SHA-256, HMAC, PBKDF2, PQ factorisation, gzip and the OS random
  source. Telethon reaches it through `cryptg` plus a bridge for AES-CTR, PQ, SHA and password
  hashing; mtcute through a complete `ICryptoProvider`; grammers is Rust.
- Measured on one machine: a one-account tdata folder loads in 0.24 ms against 1.08 ms for a
  pure-Python loader (best of 3 x 200 loads); AES-CTR on 1 MiB takes 0.9 ms against
  3.6 s with pyaes.

## Installation

```bash
pip install opentele2             # Python 3.8+ (abi3 wheels), over Telethon
npm install opentele2             # Node 18+; subpaths opentele2/mtcute and opentele2/telethon
cargo add opentele2-core          # Rust core: tdata, crypto, sessions, devices, API profiles
cargo add opentele2-browser       # Rust: browser headers and fingerprints
cargo add opentele2-versions      # Rust: fetch the current official client and browser versions
cargo add opentele2-grammers      # Rust: grammers 0.11 bridge; client flows behind feature `client`
```

`opentele2/mtcute` needs `@mtcute/node` (0.32 or newer) next to `opentele2`. Targets
**Telegram Desktop 7.3.1** tdata and **Telethon 1.45** (schema layer 230).

## Examples

### Python

```python
import asyncio

from opentele2.api import API, UseCurrentSession
from opentele2.browser import FingerprintGenerator, HeaderGenerator, Screen
from opentele2.td import TDesktop


async def main():
    tdesk = TDesktop("tdata")  # TDesktop("tdata", passcode="...") for a locked folder
    client = await tdesk.ToTelethon("telethon.session", UseCurrentSession)
    await client.connect()
    print(await client.get_me())
    # Back to tdata through a new QR-login session with a generated device.
    tdesk2 = await client.ToTDesktop(api=API.TelegramDesktop.Generate("windows", "my-id"))
    tdesk2.SaveTData("tdata_new")


# browserforge's API, reproducible by seed; the same output as Node for the same seed.
headers = HeaderGenerator(browser="chrome", os="windows").generate(seed="my-id")
print(FingerprintGenerator(screen=Screen(max_width=1920)).generate(seed=42).navigator.userAgent)
asyncio.run(main())
```

### Node

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
  crypto: await createCryptoProvider(), // every ICryptoProvider member on the core
})
await client.importSession(toStringSession(tdata.mainAccount))

// Telethon: a .session file and its .json companion (the core's bundled SQLite).
const { session, json } = await saveSessionPair('telethon', tdata.mainAccount, desktop)

// Browser headers and fingerprints, the same as opentele2.browser for the same seed.
const headers = await generateHeaders({ browsers: 'chrome', os: 'windows' }, 'my-id')
const { navigator } = await generateFingerprint({ screen: { maxWidth: 1920 } }, 42)
```

`opentele2/mtcute` also runs the client flows over an mtcute client: `qrLoginToNewClient`
(QR login with 2FA), `getSessions`, `terminateSession`, `terminateAllSessions`, `formatSessions`,
`runConsistencyChecks` and `tdataFromClient`.

### Rust

`client::*` needs `cargo add opentele2-grammers --features client` and `grammers-client`.

```rust
use grammers_client::Client;
use opentele2_browser::{Browser, FingerprintOptions, HeaderOptions, Screen};
use opentele2_core::api::{self, Versions};
use opentele2_core::session::{mtcute, telethon};
use opentele2_core::tdata::TData;
use opentele2_grammers::client::{self, ClientError};

fn convert() -> opentele2_core::Result<()> {
    let tdata = TData::load("tdata", b"", None)?; // passcode bytes, key file name
    let account = tdata.main_account().expect("folder has an account");
    println!("{}", telethon::StringSession::from_account(account, false)?.encode());
    println!("{}", mtcute::StringSession::from_account(account, false)?.encode());
    // grammers 0.11 session data and initConnection params.
    let desktop = api::profile(api::Client::Desktop, &Versions::offline());
    let _session = opentele2_grammers::session_data(account);
    let _params = opentele2_grammers::connection_params(&desktop);
    Ok(())
}

async fn show_sessions(client: &Client) -> Result<(), ClientError> {
    println!("{}", client::sessions_table(client).await?); // the PrintSessions table
    Ok(())
}

fn browser() -> opentele2_browser::Result<()> {
    let options = HeaderOptions { browsers: vec![Browser::new("chrome")], ..HeaderOptions::default() };
    for (name, value) in opentele2_browser::generate_headers(Some("my-id"), &options)?.iter() {
        println!("{name}: {value}");
    }
    let screen = Some(Screen { max_width: Some(1920), ..Screen::default() });
    let options = FingerprintOptions { screen, ..FingerprintOptions::default() };
    let fingerprint = opentele2_browser::generate_fingerprint(Some("42"), &options)?;
    println!("{}", fingerprint.navigator.user_agent);
    Ok(())
}
```

`client::qr_login`, `client::run_consistency_checks` and `client::tdata_from_client` cover QR
login with 2FA, the consistency checks and tdata from a client session. The Telethon `.session`
file is written by the core's `session::telethon_file::write_session_file` with its
default-off feature `telethon-sqlite`, the same writer the Python and Node packages use.

## Documentation

Guides, API reference and examples: **[https://opentele2.github.io/](https://opentele2.github.io/)**

- [Getting started](https://opentele2.github.io/getting-started/)
- [Guides](https://opentele2.github.io/guides/)
- [API reference](https://opentele2.github.io/reference/)

Release notes are in [CHANGELOG.md](CHANGELOG.md); the internals are in
[ARCHITECTURE.md](ARCHITECTURE.md).

## License

MIT ([LICENSE](LICENSE)) for `opentele2-core`, `opentele2-versions`, `opentele2-grammers` and the
Python and Node packages. `opentele2-browser` is Apache-2.0; its
[NOTICE](crates/opentele2-browser/NOTICE) credits browserforge and the Apify fingerprint datapoints.
