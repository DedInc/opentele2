# Changelog

All notable changes to opentele2 are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
releases are tagged `X.Y.Z` following [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2.0.0

### Highlights

- One Rust core, `opentele2-core`, holds every tdata format, session format, device catalog,
  API profile, fingerprint rule and the MTProto client crypto, shared by one package per
  ecosystem: PyPI `opentele2` (Python 3.8+, abi3 wheels), npm `opentele2` (Node 18+, subpaths
  `opentele2/mtcute` and `opentele2/telethon`) and the crates `opentele2-core`,
  `opentele2-browser`, `opentele2-versions` and `opentele2-grammers`.
- Telegram Desktop 7.3.1 tdata read and write, including passcode-locked 7.3 folders
  (Argon2id and scrypt passcode wraps), several accounts per folder and the stored MTP config.
- Sessions for Telethon (string, `.session` + `.json`), mtcute (string session v3) and
  grammers 0.11, and tdata back from a client session, in every ecosystem.
- QR login with 2FA, session admin and the seven consistency checks on each ecosystem's own
  client: Telethon in Python, mtcute in Node, grammers in Rust (feature `client`).
- `opentele2-browser` (Apache-2.0): browser HTTP headers and full fingerprints from the Apify
  fingerprint datapoints, based on browserforge, deterministic by seed and byte-identical in
  Rust, Python (`opentele2.browser`) and Node (`generateHeaders`, `generateFingerprint`). It
  fixes seven browserforge defects: Sec-Fetch values, OS relaxation, HTTP/1 fallback, Edge
  detection, the user-agent constraint, the locale cap and request-dependent headers.
- `opentele2-versions` fetches the current Telegram Desktop, Android, Telegram X, iOS, macOS,
  Web K and Web A versions plus stable Chrome and Firefox.
- Client crypto on the core: Telethon gets AES-IGE through `cryptg` (registered when the real
  `cryptg` is absent) and a bridge for AES-CTR, PQ factorisation, SHA-1/256 and password
  hashing; mtcute gets a complete `ICryptoProvider` from `createCryptoProvider()`.
- Measured on one machine: a one-account tdata folder loads in 0.24 ms against 1.08 ms for the
  pure-Python loader of 1.5.0 (best of 3 x 200 loads); AES-CTR on 1 MiB takes 0.9 ms against
  3.6 s with pyaes.

### Breaking changes

Python package:

- `opentele2` is a native wheel built from the Rust core; its extension module is
  `opentele2._native`.
- The dependencies `browserforge`, `selectolax`, `TgCrypto-pyrofork` and `argon2-cffi` are
  dropped; the package depends on `telethon` and, below Python 3.10, `typing_extensions`.
- Web devices come from a pool drawn with `opentele2-browser` instead of a curated catalog,
  and are deterministic per `unique_id` and per Chrome/Firefox major; `opentele2.browser`
  output is deterministic per `seed`.
- msg_id offsets and flow delays come from the OS random source, so `random.seed` no longer
  reproduces them.
- Removed internals: `td.MTP`, `td.MapData`, `td.Serialize`, `td.Storage`,
  `td.StorageAccount`; the modules `qt_compat`, `utils`, `debug` and the public module path
  `version_fetcher`; `Account.MapData`, `Account.prepareToStart`,
  `Account.serializeMtpAuthorization`, `AuthKey.write` and `AuthKey.FromStream`.
- `AuthKey.prepareAES_oldmtp` raises on a bad key or msg_key length.
- DC ids are plain `int`.
- A new account takes the lowest free index; 1.5.0 used the account count, which could
  collide with an existing index.
- Saving refuses duplicate account indices, and more accounts than six or than the folder
  loaded (whichever is larger), with `TDataSaveFailed`.
- Renaming the key file of a multi-account folder writes per-account file names; 1.5.0
  overwrote the accounts with one another.
- `MtpConfigView` endpoint keys are the strings `"ipv4"`, `"ipv6"` and `"tcp"`.
- `deviceList` and the other catalog lists return fresh read-only copies.
- SRP failures carry the core's error text.

Node package:

- When the new mtcute client already holds a session of another `api_id`, that session is
  replaced locally (`EXISTING_SESSION_REPLACED`), as the Python package does.
- A 2FA password without SRP inputs (`srpId`, `srpB`) ends in `OT_SRP_BAD_B`, as in Python.
- `initConnection` sends `params` with `tz_offset` for the Telegram Desktop profile.
- `accountMtpConfig` and `accountEndpoints` return the production default without an account.
- `fetchVersions` rejects a `timeoutMs` that is not a positive number.
- A loosely typed `.json` companion loads with `profile` `null`.

Rust (`opentele2-grammers`):

- `client::run_consistency_checks` returns the core `ConsistencyReport`.
- grammers 0.11 sends an empty `lang_pack` and no `params` or `proxy` in `initConnection`, and
  its QR login does not wait for `updateLoginToken`.
