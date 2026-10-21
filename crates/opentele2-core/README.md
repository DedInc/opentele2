# opentele2-core

The Rust core of [opentele2](https://github.com/DedInc/opentele2), a Telegram client identity
toolkit. The same core runs the Python package (PyPI `opentele2`) and the Node package (npm
`opentele2`).

- Telegram Desktop 7.3.1 tdata: read and write, passcode-locked folders (Argon2id and scrypt
  wraps), several accounts per folder, the stored MTP config.
- Sessions: Telethon string sessions and `.session` files (feature `telethon-sqlite`), mtcute
  string sessions (version 3).
- Official API profiles and weighted device catalogs for Android, desktop, iOS, macOS and web.
- `initConnection` fingerprint validation and the seven consistency checks.
- MTProto client crypto: AES-256-IGE and -CTR, SHA-1, SHA-256, HMAC, PBKDF2, PQ factorisation,
  gzip and the OS random source.

Synchronous, no network, no `unsafe`.

```rust
use opentele2_core::api::{self, Versions};
use opentele2_core::session::{mtcute, telethon};
use opentele2_core::tdata::TData;

fn main() -> opentele2_core::Result<()> {
    let tdata = TData::load("tdata", b"", None)?; // passcode bytes, key file name
    let account = tdata.main_account().expect("folder has an account");
    println!("{}", telethon::StringSession::from_account(account, false)?.encode());
    println!("{}", mtcute::StringSession::from_account(account, false)?.encode());
    let desktop = api::profile(api::Client::Desktop, &Versions::offline());
    println!("{} {}", desktop.device_model, desktop.app_version);
    Ok(())
}
```

grammers 0.11 sessions are in [`opentele2-grammers`](https://crates.io/crates/opentele2-grammers),
browser fingerprints in [`opentele2-browser`](https://crates.io/crates/opentele2-browser) and live
client versions in [`opentele2-versions`](https://crates.io/crates/opentele2-versions).

Documentation: [https://opentele2.github.io/](https://opentele2.github.io/). License: MIT.
