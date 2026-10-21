<p align="center">
  <img src="https://raw.githubusercontent.com/DedInc/opentele2/main/opentele.png" alt="opentele2 logo" width="160"/>
</p>

<h1 align="center">opentele2</h1>

<p align="center">
  <b>A Telegram client identity toolkit for Python</b>: Telegram Desktop tdata, Telethon
  sessions, official API profiles with realistic devices, initConnection fingerprint checks and
  browser fingerprints, on a Rust core.
</p>

## What it does

- **tdata**: reads and writes Telegram Desktop 7.3.1 folders, including passcode-locked ones,
  several accounts per folder and the stored MTP config.
- **Telethon**: string sessions, `.session` files (SQLite, version 8) with their `.json`
  companion, and tdata back from a logged-in client through QR login with 2FA.
- **Official API profiles**: Telegram Desktop, Android, Telegram X, iOS, macOS, Web A, Web K
  and Webogram, with weighted device catalogs; the same unique id gives the same device in
  Python, Node and Rust.
- **Fingerprint checks**: `initConnection` validation (layer, lang pack, `tz_offset`, msg_id
  offset, transport) and seven consistency checks of a profile against a live session.
- **Browser fingerprints**: `opentele2.browser` generates HTTP headers and full browser
  fingerprints, deterministic by seed.
- **Fast crypto**: AES-IGE and AES-CTR, SHA, PBKDF2 and PQ factorisation run on the Rust core;
  AES-CTR on 1 MiB takes 0.9 ms against 3.6 s with pyaes.

## Installation

```bash
pip install opentele2
```

Python 3.8+ (abi3 wheels for Windows, macOS and Linux, plus free-threaded 3.14t wheels).
Targets **Telegram Desktop 7.3.1** tdata and **Telethon 1.45** (schema layer 230).

## Example

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

    # The .session + .json pair other tools read.
    await client.SaveSessionJson("account", fetch_user_info=True)

    # Back to tdata through a new QR-login session with a generated device.
    tdesk2 = await client.ToTDesktop(api=API.TelegramDesktop.Generate("windows", "my-id"))
    tdesk2.SaveTData("tdata_new")


headers = HeaderGenerator(browser="chrome", os="windows").generate(seed="my-id")
print(FingerprintGenerator(screen=Screen(max_width=1920)).generate(seed=42).navigator.userAgent)
asyncio.run(main())
```

## Links

- Documentation: [https://opentele2.github.io/](https://opentele2.github.io/)
- Source and the Node and Rust packages: [https://github.com/DedInc/opentele2](https://github.com/DedInc/opentele2)
- Release notes: [CHANGELOG.md](https://github.com/DedInc/opentele2/blob/main/CHANGELOG.md)

## License

MIT. The bundled browser fingerprint data is Apache-2.0
([NOTICE](https://github.com/DedInc/opentele2/blob/main/crates/opentele2-browser/NOTICE)).
