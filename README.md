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

A **Python Telegram API Library** for converting between **tdata** and **telethon** sessions, with built-in **official Telegram APIs**.

## Installation

```bash
pip install --upgrade opentele2
```

Targets **Telegram Desktop 7.3.1** tdata and **Telethon 1.45** (schema layer 230),
including 7.3 passcode-locked tdata (Argon2id and scrypt key wraps).

## opentele2 2.0 (pre-release, branch `2.0.0`)

2.0 moves the tdata formats and crypto into a Rust core, `opentele2-core`, used from Python, Node and Rust.

- **Rust core**: tdata read and write, PBKDF2, Argon2id and scrypt key derivation, AES-256-IGE,
  Telethon and mtcute string sessions, and device fingerprints live in `crates/opentele2-core`.
- **Faster**: the core's `TData.load` reads a real one-account tdata folder in 0.24 ms against
  1.08 ms for the Python `TDesktop` loader (best of 3 x 200 loads, one machine), about 4.6x.
- **Native AES-IGE for Telethon**: when the real `cryptg` is not installed, `import opentele2`
  registers the core's `opentele2_core.cryptg` as `cryptg`, so Telethon uses it. Import
  `opentele2` before `telethon` for this to apply.
- **Python 3.8+**: `opentele2` and the abi3 wheel `opentele2-core` both need Python 3.8 or newer.
- **No C crypto dependencies**: `TgCrypto-pyrofork` and `argon2-cffi` are gone; the dependencies are
  `telethon`, `opentele2-core` and, below Python 3.10, `typing_extensions`.

### Install

The 2.0 versions are pre-releases: `2.0.0a1` on PyPI, `2.0.0-alpha.1` on npm and crates.io.

```bash
pip install --pre opentele2                 # Python: opentele2 plus opentele2-core
npm install opentele2@2.0.0-alpha.1         # Node 18+; mtcute helpers in opentele2/mtcute
cargo add opentele2-core@2.0.0-alpha.1      # Rust core
cargo add opentele2-grammers@2.0.0-alpha.1  # optional grammers 0.11 bridge
```

Releases come from three workflows, `release-python.yml`, `release-node.yml` and `release-crates.yml`, which run only on a bare version tag such as `2.0.0-alpha.1` (PyPI spells it `2.0.0a1`) and publish from the protected environments `pypi`, `npm` and `crates-io`.

### Python

The 1.x API is unchanged.

```python
import asyncio

from opentele2.api import UseCurrentSession
from opentele2.td import TDesktop


async def main():
    tdesk = TDesktop("tdata")  # TDesktop("tdata", passcode="...") for a locked folder
    client = await tdesk.ToTelethon("telethon.session", UseCurrentSession)
    await client.connect()
    print(await client.get_me())


asyncio.run(main())
```

### Node

```js
import { loadTdata, profile } from 'opentele2'
import { initConnectionOptions, toStringSession } from 'opentele2/mtcute'

const tdata = await loadTdata('tdata') // loadTdata('tdata', passcode) for a locked folder
const desktop = profile('TelegramDesktop')

const session = toStringSession(tdata.mainAccount) // for mtcute's client.importSession()
const options = initConnectionOptions(desktop) // pass desktop.apiId and desktop.apiHash separately
```

`createCryptoProvider()` from `opentele2/mtcute` returns mtcute's Node crypto provider with
AES-IGE from the core.

### Rust

```rust
use opentele2_core::session::{mtcute, telethon};
use opentele2_core::tdata::TData;

fn main() -> opentele2_core::Result<()> {
    let tdata = TData::load("tdata", b"", None)?; // passcode bytes, key file name
    let account = tdata.main_account().expect("folder has an account");
    println!("{}", telethon::StringSession::from_account(account, false)?.encode());
    println!("{}", mtcute::StringSession::from_account(account, false)?.encode());
    Ok(())
}
```

`opentele2-grammers` turns the same account into grammers session data with
`opentele2_grammers::session_data(account)`.

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

- **PyQt5 Removed**: The **PyQt5** dependency has been removed. Its required functionality was reimplemented in **pure Python** to reduce overhead and avoid installing unnecessary heavy dependencies.
- **New Fingerprints**: Device information generation has been improved. The library now uses a new device database for more realistic client profiles.
