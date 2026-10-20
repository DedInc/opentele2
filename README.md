<!-- vim: syntax=Markdown -->

# opentele2

<p align="center">
<img src="https://raw.githubusercontent.com/DedInc/opentele2/main/opentele.png" alt="logo" width="180"/>
<br><br>
<a href="https://pypi.org/project/opentele2/"><img alt="pypi version" src="https://img.shields.io/pypi/v/opentele2?logo=pypi&logoColor=%232d93c1"/></a>
<a href="https://pypi.org/project/opentele2/"><img alt="pypi status" src="https://img.shields.io/pypi/status/opentele2?color=%2331c754&logo=pypi&logoColor=%232d93c1"/></a>
<a href="https://codecov.io/gh/DedInc/opentele2">
<img src="https://img.shields.io/codecov/c/github/DedInc/opentele2?color=%2331c754&label=codecov&logo=codecov&token=H2IWGEJ5LN"/>
</a>
<a href="https://github.com/DedInc/opentele2/issues"><img alt="issues" src="https://img.shields.io/github/issues/DedInc/opentele2?color=%2331c754&logo=github"/></a>
<a href="https://github.com/DedInc/opentele2/commits/main"><img alt="github last commit" src="https://img.shields.io/github/last-commit/DedInc/opentele2?color=%2331c754&logo=github"/></a>
<a href="https://github.com/DedInc/opentele2/commits/main"><img alt="github commits" src="https://img.shields.io/github/commit-activity/m/DedInc/opentele2?logo=github"/></a>
<a href="https://pypi.org/project/opentele2/"><img alt="pypi installs" src="https://img.shields.io/pypi/dm/opentele2?label=installs&logo=docusign&color=%2331c754"/></a>
<a href="https://en.wikipedia.org/wiki/MIT_License"><img alt="pypi license" src="https://img.shields.io/pypi/l/opentele2?color=%2331c754&logo=gitbook&logoColor=white"/></a>
<a href="https://github.com/psf/black"><img alt="code format" src="https://img.shields.io/badge/code%20style-black-000000.svg?logo=python&logoColor=%232d93c1"/></a>
</p>

<br>

A **Telegram API library** for converting between **tdata** and **telethon** sessions, with built-in **official Telegram APIs**, for Python, Node and Rust.

## Installation

```bash
pip install opentele2             # Python 3.8+
npm install opentele2             # Node 18+, every entry point including opentele2/telethon
cargo add opentele2-core          # Rust core: tdata, crypto, sessions, devices, API profiles
cargo add opentele2-browser       # Rust: browser headers and fingerprints, a port of browserforge
cargo add opentele2-versions      # Rust: fetch the current official client and browser versions
cargo add opentele2-grammers      # Rust: grammers 0.11 bridge; client flows behind feature `client`
```

Targets **Telegram Desktop 7.3.1** tdata and **Telethon 1.45** (schema layer 230),
including 7.3 passcode-locked tdata (Argon2id and scrypt key wraps).

## opentele2 2.0.0

2.0.0 moves the tdata formats and crypto into one Rust core, `opentele2-core`, shared by one
package per ecosystem.

- **Rust core**: tdata read and write, PBKDF2, Argon2id and scrypt key derivation, AES-256-IGE
  and -CTR, SHA-1, SHA-256, HMAC, PQ factorisation, gzip, one OS random source, Telethon and
  mtcute string sessions, Telethon `.session` files, device catalogs and fingerprint checks live
  in `crates/opentele2-core`.
- **Faster**: the core loads a real one-account tdata folder in 0.24 ms against 1.08 ms for the
  pure-Python 1.x `TDesktop` loader (best of 3 x 200 loads, one machine), about 4.6x.
- **Client crypto on the core**: `import opentele2` (before `telethon`) registers
  `opentele2._native.cryptg` (AES-IGE) when the real `cryptg` is absent, and always rebinds Telethon's
  AES-CTR (obfuscated, CDN, MTProxy; 1 MiB in 0.9 ms against 3.6 s for pyaes, one machine), PQ
  factorisation, SHA-1/256 and password hashing; DH/RSA `pow` and `os.urandom` stay Telethon's.
  mtcute's `createCryptoProvider()` covers every `ICryptoProvider` member; DH/RSA bigint maths stay mtcute's.
- **Python 3.8+**: the `opentele2` wheel is abi3 for CPython 3.8 and newer.
- **No C crypto dependencies**: `TgCrypto-pyrofork` and `argon2-cffi` are gone; the dependencies are
  `telethon` and, below Python 3.10, `typing_extensions`.
- **Telethon `.session` on every Node**: `opentele2/telethon` uses the core's bundled SQLite (Node 18+).
- **Browser fingerprints without browserforge**: `opentele2-browser` (Apache-2.0) ports browserforge
  to Rust over the embedded `apify_fingerprint_datapoints` 0.15.0 networks with a seeded
  xoshiro256** RNG, and fixes seven browserforge defects (Sec-Fetch values, OS relaxation, HTTP/1
  fallback, Edge detection, user-agent constraint, locale cap, request-dependent headers). Python
  `opentele2.browser` and Node `generateHeaders` / `generateFingerprint` expose it; the same seed and
  options give byte-identical output in Python and Node.
- **Web devices**: the curated web catalog was replaced by 1.5.0's pool drawn from
  `opentele2-browser` (Chrome, Edge, Firefox weighted 19/2/1 around the live majors), deterministic
  per seed and per Chrome/Firefox major; `opentele2-versions` fetches the Chrome and Firefox versions.
- **Full parity**: Python, Node and Rust cover the same conversions, device generation,
  fingerprint checks, QR login with 2FA, session admin and consistency checks, each over its own
  client (Telethon, mtcute, grammers).

The few places where 2.0.0 deliberately behaves differently from 1.5.0 are listed in
[ARCHITECTURE.md, Deliberate differences from 1.5.0](ARCHITECTURE.md#deliberate-differences-from-150).

### Python

The 1.x API is unchanged.

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

// Telethon: the .session + .json pair 1.5.0 writes (the core's bundled SQLite).
const { session, json } = await saveSessionPair('telethon', tdata.mainAccount, desktop)

// Browser headers and fingerprints, the same as opentele2.browser for the same seed.
const headers = await generateHeaders({ browsers: 'chrome', os: 'windows' }, 'my-id')
const { navigator } = await generateFingerprint({ screen: { maxWidth: 1920 } }, 42)
```

`opentele2/mtcute` also has the 1.5.0 client flows over an mtcute client: `qrLoginToNewClient`
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
    println!("{}", client::sessions_table(client).await?); // 1.5.0 PrintSessions
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

For full documentation, guides, API reference, and examples, please visit the official documentation website:

**[https://opentele2.github.io/](https://opentele2.github.io/)**

### Quick Links

- [Getting Started](https://opentele2.github.io/)
- [Documentation & API Reference](https://opentele2.github.io/documentation)
- [Examples & Recipes](https://opentele2.github.io/examples)

## A New Era for opentele

**opentele2** is the rebirth of the original opentele project. The library is actively maintained and continues the original idea with current Telegram Desktop and Telethon support, bug fixes, and new features.

This new era means the project is no longer just a compatibility fork. It focuses on a lighter dependency footprint, a Rust core for tdata formats and crypto (2.0), updated official Telegram API templates, and more realistic device fingerprint generation.

### Key Enhancements

- **PyQt5 Removed**: The **PyQt5** dependency has been removed. Its required functionality was reimplemented without Qt, in pure Python in 1.x and in the Rust core since 2.0, to reduce overhead and avoid installing unnecessary heavy dependencies.
- **New Fingerprints**: Device information generation has been improved. The library now uses a new device database for more realistic client profiles.
