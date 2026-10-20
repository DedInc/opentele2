# opentele2 2.0.0 Architecture (v2)

Status: implemented. This is the decision record of the stable 2.0.0 release
(commit 3090cbc; version 2.0.0 in Cargo.toml, which every crate inherits,
and in bindings/node/package.json). Version v1 of this file described the pre-release split (a
pure-Python root package over a separate `opentele2-core` wheel); v2 replaced
it with one package per ecosystem over one Rust core, and every phase below
has shipped except the two maintainer steps marked pending. Facts cite
`path:line`. Citations of `src/` and `tests/` refer to the 1.x tree, which is
the same as tag 1.5.0.

## Layout

The tree at 2.0.0. The root holds only workspace, docs, licence and CI
configuration.

```
Cargo.toml, Cargo.lock        workspace: members crates/*, bindings/python, bindings/node; rust-version 1.89
README.md, ARCHITECTURE.md, LICENSE, .gitignore
opentele.png                  README logo; stays at the root (see below)
.github/workflows/            maintainer-owned; agents stage edits in refs/github-workflows/
crates/opentele2-core/        pure core: no async, no network, no FFI, unsafe_code forbidden
  src/                        qt, tdf, crypto (SHA-1/256, HMAC, PBKDF2, AES-IGE/CTR, PQ, random_fill),
                              compress (gzip), kdf, tdata (incl. mtp_config, migrate, add_account,
                              set_accounts), session (incl. telethon_file), devices, api,
                              fingerprint, auth, batch
  data/devices/               android, desktop, ios, mac (JSON); the only catalog copy; the web
                              pool is drawn from opentele2-browser (M2)
  tests/                      Rust tests + fixtures/; no_suppressions.rs bans lint suppressions
  tests/vectors/              frozen 1.5.0 oracle + gen_core_vectors.py (--source <1.5.0 checkout>)
  features                    parallel (default, rayon), telethon-sqlite (default off, rusqlite bundled)
crates/opentele2-browser/     Apache-2.0 Rust port of browserforge over the embedded
                              apify_fingerprint_datapoints 0.15.0 networks, seeded xoshiro256** Rng
crates/opentele2-versions/    network version fetchers (7 Telegram sources + Chrome, Firefox),
                              blocking HTTP (ureq 3.4), no tokio
crates/opentele2-grammers/    grammers 0.11 bridge + client flows behind feature `client`
bindings/python/              the one PyPI package `opentele2` (maturin, mixed layout)
  Cargo.toml, src/            PyO3 0.29 abi3-py38 cdylib, module `opentele2._native`
  pyproject.toml              name opentele2, version from Cargo, requires-python >=3.8, telethon>=1.45.0
  python/opentele2/           _native.pyi, browser.py, facades api, devices, exception, fingerprint,
                              consistency, td/, tl/; private _compat.py, _telethon_crypto.py,
                              _version_fetcher.py
  tests/                      binding + public-API tests (pytest, `live` marker)
bindings/node/                npm `opentele2` 2.0.0, Node-API, engines >=18
  src/, index.js, index.d.ts  native addon `opentele2`
  mtcute.mjs, mtcute.d.ts     `opentele2/mtcute`: session, crypto provider, client flows
  telethon.mjs, telethon.d.ts `opentele2/telethon`: Telethon .session + .json over the core's
                              bundled SQLite
  npm/, __test__/             per-platform packages; node --test suites
src/, tests/ (tracked files)  1.x implementation and tests: removed by the maintainer's `git rm`
                              (P4-02, pending); the agent kernel's untracked tests/ files stay
```

Placement decisions:
- Tests live with the code they test: Rust in `crates/*/tests/`, Python in
  `bindings/python/tests/`, Node in `bindings/node/__test__/`. No root `tests/`
  after P4-02.
- `gen_core_vectors.py` lives in `crates/opentele2-core/tests/vectors/`, next
  to the oracle it writes, and takes `--source <dir>`, a checkout of tag 1.5.0
  (crates/opentele2-core/tests/vectors/gen_core_vectors.py:3-4). The committed
  vectors stay the frozen oracle: they are never regenerated from 2.0 code.
  `tests/vectors` and `tests/fixtures` are excluded from the published crate
  (crates/opentele2-core/Cargo.toml:13).
- `opentele.png` stays at the root: README.md:6 and the long descriptions of
  every published 1.x release load it from `.../main/opentele.png`, so moving
  it breaks old PyPI pages.
- The agent kernel (AGENTS.md, install.py, tools/, .agents/, docs/, and the
  untracked kernel tests under tests/) is not part of the product tree.

## Decisions

Kept from v1: pure core (v1 D1); AES-IGE from `grammers-crypto` 0.11 with
length checks before each call (v1 D1); PyO3 0.29 `abi3-py38` plus `cp314t`
wheels, `gil_used = false`, `py.detach` around work (v1 D2, floor and wheel
rules only); Telethon acceleration through a cryptg-compatible submodule
registered only when real `cryptg` is absent (v1 D3, module path changes);
npm `opentele2` with `opentele2/mtcute`, Node-API 4, `engines >=18` (v1 D4);
grammers bridge kept out of the core (v1 D5); rayon `parallel` feature for
batch only (v1 D6); one `#[non_exhaustive] Error` with stable `code()` (v1 D7);
tooling (v1 D8); tag-only releases from protected environments (v1 D9).

Superseded: v1 D2 (two Python distributions, pydantic/pydantic-core split) by
M1; v1 Compatibility item 3 (web fingerprints stay in Python, outside the
determinism contract) and item 5 (`browserforge` as the `web` extra) by M2;
v1 Known gap "catalogs exist twice" is closed by Removal.

### M1. One PyPI package `opentele2` (maintainer decision, recorded)
- maturin builds it from bindings/python in mixed layout: Rust extension
  `opentele2._native`, Python sources in bindings/python/python/opentele2/
  (bindings/python/pyproject.toml:39-46). It replaced the root hatchling
  package and the pre-release `opentele2-core` distribution.
- Python sources hold only the Telethon integration (TelegramClient, session
  files, consistency checks) and thin facades that keep 1.x names over
  `_native`. Format, crypto, catalog and fingerprint logic is never Python.
- Python >= 3.8; abi3-py38 (bindings/python/Cargo.toml:27) and cp314t wheels.
- cryptg: `import opentele2` registers `opentele2._native.cryptg` as
  `sys.modules["cryptg"]` when no real `cryptg` imports
  (bindings/python/python/opentele2/__init__.py:7-13).
- Telethon crypto bridge: `opentele2/_telethon_crypto.py`, imported by
  `__init__.py`, rebinds Telethon's `AESModeCTR` (obfuscated, CDN and MTProxy
  transports), `Factorization.factorize`, `sha1`/`sha256` and the password
  and MTProxy `hashlib` to the core. AES-CTR on 1 MiB: 0.9 ms against 3.6 s
  for pyaes (one machine). DH and RSA `pow` and `os.urandom` stay Telethon's.
- Errors: `_native` raises one `CoreError(code, message)`; `opentele2.exception`
  maps `code` to the 1.x subclasses through the core's `core_error_classes()`
  table (bindings/python/python/opentele2/exception.py:228).
- Cost accepted: every pure-Python fix ships as a full wheel matrix.

### M2. Deterministic web devices and browser fingerprints (maintainer decision, recorded)
- `crates/opentele2-browser` (Apache-2.0, as the datapoints it embeds;
  crates/opentele2-browser/Cargo.toml:9-11) ports browserforge over the
  embedded `apify_fingerprint_datapoints` 0.15.0 networks. Every draw comes
  from the seeded xoshiro256** `Rng` and set operations keep first-seen
  order, so a seed reproduces its output on any platform
  (crates/opentele2-browser/src/lib.rs:1-9).
- Seven browserforge defects are fixed, each marked `Defect (n)` in
  crates/opentele2-browser/src/headers.rs: Sec-Fetch values, OS relaxation,
  HTTP/1 fallback, Edge before Chrome in User-Agent detection, the
  user-agent constraint, the ten-locale cap, request-dependent headers;
  fingerprint.rs adds trimmed languages and a bounded retry.
- Web devices are 1.5.0's browserforge pool, drawn with `opentele2-browser`
  from a generator seeded by the Chrome and Firefox majors (`web_catalog_for`,
  crates/opentele2-core/src/devices.rs:12-16): 60 Chrome, 30 Edge and 20
  Firefox desktop user agents weighted 19/2/1 around the live majors, the
  version window shifted by the dataset lag (at most `MAX_DATASET_LAG` = 24).
  `devices::generate(Platform::Web, unique_id)` picks from the pool with the
  same seed hash and cumulative weights as the other platforms. The curated
  web catalog of P1-01 was deleted.
- `api::Versions` carries `chrome_version` and `firefox_version`;
  opentele2-versions fetches both (D10).
- Bindings: Python `opentele2.browser` (`HeaderGenerator`,
  `FingerprintGenerator`, `Browser`, `Screen`, browserforge's arguments plus
  `seed=`); Node `generateHeaders(options, seed)` and
  `generateFingerprint(options, seed)`. Both give byte-identical output for
  the same seed and options.

### D10. Network version fetching is a separate crate
- `crates/opentele2-versions` ports the 7 sources of 1.5.0
  `version_fetcher.py` (tdesktop, Android, Telegram X, iOS, macOS, WebK, WebA)
  plus the stable Chrome and Firefox versions 1.5.0 fetched for its web
  fingerprints, and returns a `VersionsPatch` applied to core `api::Versions`
  (`fetch_all`, `apply`, crates/opentele2-versions/src/lib.rs:204,265). The
  bindings convert the patch through its field map (`VersionsPatch::FIELDS`,
  `to_map`, `from_map`). Blocking HTTP with
  rustls (`ureq`), parallel per source, per-call timeout; parsers are pure
  functions tested on stored HTML fixtures, live fetches are `#[ignore]`.
- Rejected: fetching in the core (breaks the no-network rule) and `reqwest`
  (pulls tokio into a sync stack).
- Python keeps the 1.x import-time fetch and the `OPENTELE_NO_FETCH` switch
  (private `opentele2._version_fetcher`); npm (`fetchVersions`) and Rust
  (`fetch_all`) fetch only on an explicit call.

### D11. Client flows per ecosystem on its native client
- Python over Telethon, npm over mtcute (`opentele2/mtcute`), Rust over
  grammers in `opentele2-grammers` (feature `client`). Each flow lives once,
  on the client its users already run.
- Shared pure pieces in core `auth`: QR URL `tg://login?token=<base64url>`;
  2FA SRP over `grammers_crypto::two_factor_auth::calculate_2fa`;
  session-admin row formatting (the PrintSessions table); consistency
  expectations (lang_pack per profile, layer tolerance 15,
  crates/opentele2-core/src/auth.rs:489).
- grammers 0.11 hardcodes `lang_pack: ""`, `proxy: None`, `params: None`.
  Kept as a documented gap (crates/opentele2-grammers/src/lib.rs:22-38) plus
  the upstream change; rejected: a grammers fork (v1 D5).

### D12. Persistent formats stay owned by the core
- MTP config, DcOptions and legacy dbi blocks are parsed in core `tdata`,
  and `session` takes endpoints from the stored config when the account has
  config bytes (crates/opentele2-core/src/session/mod.rs:12-17).
- Saving a folder with a legacy key file migrates it in the core, as 1.5.0
  does, instead of failing.
- Telethon `.session` sqlite v8: the core builds the rows and the `.json`
  companion and writes and reads the file with its default-off feature
  `telethon-sqlite` (bundled SQLite), which Python, npm (every Node >= 18)
  and Rust all use (bindings/python/Cargo.toml:24,
  bindings/node/Cargo.toml:21; Q6).

## Parity

Shared by core, Rust, Python and npm: tdata read/write, KDFs, AES-IGE and
AES-CTR, SHA-1/256, HMAC, PBKDF2, PQ factorisation, gzip, the OS random
source (`crypto::random_fill`, the single entry point), Telethon and mtcute
string sessions, the Telethon `.session` file, grammers SessionData, device
generation (web included), browser headers and fingerprints, API profiles,
batch load. The bindings take name tables, MTP config marshalling, flow
constants and texts, the consistency report, session JSON shaping and error
classes from core items instead of keeping copies. Python registers the
Telethon crypto bridge (M1); mtcute's `createCryptoProvider()` implements
every `ICryptoProvider` member on the core, while mtcute's DH and RSA bigint
maths stay mtcute's. No Rust source holds a lint suppression
(crates/opentele2-core/tests/no_suppressions.rs). Every row of the 1.x
Python-only matrix below has shipped.

| Capability (1.x source) | Core | Rust API | Python | npm |
|---|---|---|---|---|
| Web fingerprints (src/devices.py) | `devices` web pool over opentele2-browser (M2) | core | facade `WebBrowserDevice` | `generate('TelegramWeb_A' / 'TelegramWeb_K')` |
| browserforge headers and fingerprints (1.5.0 dependency) | no (opentele2-browser) | `generate_headers`, `generate_fingerprint` | `opentele2.browser` | `generateHeaders`, `generateFingerprint` |
| Client protocol crypto (Telethon cryptg, pyaes, hashlib; mtcute ICryptoProvider) | `crypto`, `compress` | core | `_native.cryptg` + `_telethon_crypto` (M1) | `createCryptoProvider` (mtcute) |
| Version fetchers, 7 sources + Chrome, Firefox (src/version_fetcher.py) | no (pure patch type only) | opentele2-versions | `_native` + import-time fetch | `fetchVersions()` Promise |
| PlatformVersions extra fields, LAYER (src/fingerprint.py) | `api::Versions`, `api::LAYER` = 230 | core | facade `PlatformVersions` | `platformVersions`, `LAYER` |
| Advertised layer | no (client property) | `grammers_tl_types::LAYER` | Telethon layer | mtcute TL layer |
| tdesktop_tz_offset | `fingerprint` tz offset | core | facade (local offset) | `tzOffset` |
| validate_init_connection_params | `fingerprint` validation | core | facade | `validateInitParams` |
| Version consistency | `fingerprint` version check | core | facade | `checkVersions` |
| StrictMode, FingerprintConfig | data types in `fingerprint` | core | facades keep fields | `fingerprintConfig` |
| TransportRecommendation | no (Telethon classes) | n/a | Python only | n/a |
| msg_id offset/validity | `fingerprint` | core | facade | `msgIdOffset`, `isValidMsgId` |
| APIData from_json/to_json, extra fields, eq/hash (src/api.py) | `api::ApiProfile` session JSON | core | `APIData` facade | `profileFromSessionJson`, `profileToSessionJson`, `profilesEqual` |
| Telethon .session v8 + .json pair (src/tl/session_io.py) | `session::telethon_file` rows, file + JSON companion | feature `telethon-sqlite` | core writer (`_native.write_session_file`) | `opentele2/telethon` over the core writer |
| Legacy dbi, MTP.Config/DcOptions, endpoints from config (src/td/mtp.py) | `tdata::mtp_config`, `session` endpoint choice (D12) | core | facade `MtpConfigView` | `accountMtpConfig`, `accountEndpoints` |
| Legacy key file migration on save (src/td/tdesktop.py) | `TData::save` / `TData::migrate` (D12) | core | facade | `migrateTdata`, `saveTdata` |
| QR login + 2FA, CreateNewSession (src/tl/telethon.py) | `auth` URL + SRP | `client::qr_login` | Telethon | `qrLoginToNewClient` |
| Client session -> tdata (src/tl/telethon.py, src/td/tdesktop.py) | `TData::new` from user id + key | `client::tdata_from_client` | Telethon | `tdataFromClient` |
| Session admin, PrintSessions, is_official_app (src/tl/telethon.py) | `auth` formatting + official api_id set | `client::sessions`, `sessions_table`, `is_official_app` | Telethon | `getSessions`, `formatSessions`, `isOfficialApp` |
| ConsistencyChecker (src/consistency.py) | `auth` expectations | `client::run_consistency_checks` | Telethon | `runConsistencyChecks` |
| initConnection lang_pack/params/proxy | profile carries values | gap in grammers 0.11 (D11) | Telethon sends them | `initConnectionOptions` |

## Removal

Nothing was deleted before its replacement passed its gate (P4 after P3).

| Legacy path | Fate | State at 2.0.0 |
|---|---|---|
| pyproject.toml, MANIFEST.in, mypy.ini, .coveragerc (root) | delete | deleted (P4-03) |
| bindings/python/opentele2_core.pyi | delete | deleted; python/opentele2/_native.pyi |
| PyPI `opentele2-core` | no further releases | `opentele2._native`; only a pre-release ever existed (Q4) |
| src/__init__.py | port | python/opentele2/__init__.py, same cryptg rule |
| src/api.py, src/exception.py, src/devices.py, src/fingerprint.py, src/consistency.py | facade / port | python/opentele2/, same names; catalogs only in crates/opentele2-core/data/devices, the web pool from opentele2-browser |
| src/version_fetcher.py | delete | opentele2-versions via `_native`; private `_version_fetcher.py` |
| src/td/tdesktop.py, account.py, auth.py | facade | `TDesktop`, `Account`, `AuthKey`, `AuthKeyType` over `_native.TData` |
| src/td/storage.py, storage_account.py, map_data.py, mtp.py, key_data.py, configs.py, shared.py | delete | core `tdata`, `kdf`, `crypto`; `td/__init__.py` exports the facades only |
| src/qt_compat.py, src/utils.py, src/debug.py | delete | core `qt`; `BaseObject`/`sharemethod` in private `_compat.py` |
| src/tl/ | port | python/opentele2/tl/, `TelegramClient` keeps names and signatures |
| scripts/gen_core_vectors.py | move | crates/opentele2-core/tests/vectors/, `--source` (P4-01) |
| src/ and the tracked tests/ files | delete | pending: the maintainer's `git rm` (P4-02); ported tests are in bindings/python/tests |

Deliberately not kept as public names: `td.MTP`, `td.MapData`, `td.Serialize`,
`td.Storage`, `td.StorageAccount` and the modules `qt_compat`, `utils`,
`debug`, `version_fetcher` (see Deliberate differences).

## Compatibility

1. Python public API: `TDesktop`, `Account`, `AuthKey`, `AuthKeyType`,
   `TelegramClient`, `API`, `APIData`, `LoginFlag`, `UseCurrentSession`,
   `CreateNewSession` and every 1.5.0 exception class keep import paths,
   names, signatures and hierarchy. Import-time version fetch is kept (D10).
2. Golden vectors: Generate, crypto, TDF, sessions and tdata outputs stay
   byte-identical to the frozen 1.5.0 vectors in crates/opentele2-core/tests/
   vectors; the Python and Node bindings are tested against the same files.
3. tdata: written folders stay readable by 1.5.0 and tdesktop 7.3.1 (version
   7003001, key_data format 2); legacy key files are migrated on save (D12).
4. Sessions: Telethon string, Telethon sqlite v8 and its .json pair, mtcute
   v3 and grammers SessionData unchanged; endpoints come from the stored
   config when the account has one, as in 1.5.0.
5. Every break is listed under Deliberate differences from 1.5.0.

## Deliberate differences from 1.5.0

Recorded by three review passes of bindings/python against 1.5.0.

- Web devices and browser fingerprints are deterministic per seed (M2): a
  web device per `unique_id` and per Chrome/Firefox major, `opentele2.browser`
  and `generateHeaders`/`generateFingerprint` output per `seed`.
- msg_id offsets and flow delays come from the OS random source, so
  `random.seed` no longer reproduces them
  (bindings/python/python/opentele2/fingerprint.py:378-379).
- Dropped dependencies: `browserforge`, `selectolax`, `tgcrypto`
  (`TgCrypto-pyrofork`) and `argon2-cffi`; the package depends on `telethon`
  and, below Python 3.10, `typing_extensions` (bindings/python/pyproject.toml).
- Removed internals: `td.MTP`, `td.MapData`, `td.Serialize`, `td.Storage`,
  `td.StorageAccount`; the modules `qt_compat`, `utils`, `debug` and the
  public module path `version_fetcher`; `Account.MapData`,
  `Account.prepareToStart`, `Account.serializeMtpAuthorization`,
  `AuthKey.write` and `AuthKey.FromStream`.
- `AuthKey.prepareAES_oldmtp` raises on a bad key or msg_key length
  (bindings/python/python/opentele2/td/auth.py:60).
- DC ids are plain `int`.
- A new account takes the lowest free index
  (crates/opentele2-core/src/tdata/mod.rs:485-496); 1.5.0 used the account
  count and could collide with an existing index.
- Saving refuses duplicate account indices and more accounts than were
  loaded (at least 6) with `TDataSaveFailed`
  (crates/opentele2-core/src/tdata/mod.rs:466-473,
  bindings/python/python/opentele2/td/tdesktop.py:227-235).
- Renaming the key file of a multi-account folder writes per-account file
  names (crates/opentele2-core/src/tdata/mod.rs:508-516); 1.5.0 overwrote the
  accounts with one another.
- `MtpConfigView` endpoint keys are the strings `"ipv4"`, `"ipv6"` and
  `"tcp"` (bindings/python/python/opentele2/td/account.py:46).
- `deviceList` and the other catalog lists return fresh read-only copies
  (bindings/python/python/opentele2/devices.py:60).
- SRP failures carry the core's error text.
- Node: when the new mtcute client already holds a session of another
  `api_id`, that session is replaced locally, as 1.5.0 Python does
  (`EXISTING_SESSION_REPLACED`, bindings/node/index.d.ts:535-539).
- Node: a 2FA password without SRP inputs (`srpId`, `srpB`) ends in
  `OT_SRP_BAD_B`, as in Python (bindings/node/mtcute.d.ts:155-159).
- Node: `initConnection` sends `params` with `tz_offset` for the tdesktop
  profile (bindings/node/mtcute.d.ts:18-36).
- Node: `accountMtpConfig` and `accountEndpoints` return the production
  default without an account (bindings/node/index.d.ts:139-140).
- Node: `fetchVersions` rejects a `timeoutMs` that is not a positive number
  (bindings/node/index.d.ts:551-552).
- Node: a loosely typed `.json` companion loads with `profile` `null`
  (bindings/node/telethon.d.ts:40-43).
- grammers: `client::run_consistency_checks` returns the core
  `ConsistencyReport` (crates/opentele2-grammers/src/client.rs:799-802).
- grammers 0.11 sends an empty `lang_pack` and no `params` or `proxy` in
  `initConnection`, and its QR login does not wait for `updateLoginToken`
  (crates/opentele2-grammers/src/client.rs:22-30).

## Known debts

- Telethon's DH and RSA arithmetic (Python `pow`) and its `os.urandom`
  calls stay Telethon's; the bridge covers the rest of its protocol crypto
  (bindings/python/python/opentele2/_telethon_crypto.py:23-24).
- grammers 0.11 sends an empty `lang_pack` and no `params` in
  `initConnection` (D11).
- On its error path the Python session companion reader parses the `.json`
  once more, since the core's `read_companion`
  (crates/opentele2-core/src/session/telethon_file.rs:260) shares one `what`
  across its errors.

## Phases

Rules: each slice touched at most 5 paths in at most 2 top-level areas and had
one gate from the allowlist (cargo, python, node, pnpm, npm), run under
Windows cmd; Python gates used `.venv38\Scripts\python.exe` (the 3.8 floor).
CI changes go only to refs/github-workflows/; the maintainer copies them to
.github/workflows/.

| Id | Title | Shipped |
|---|---|---|
| P1-01 | Web catalog, schema 1, seeded Web generate (catalog replaced by P5-02) | 8fdf1f4 |
| P1-02, P1-03 | Versions extra fields, layer; APIData JSON with extras, Eq/Hash | 69c3cb4 |
| P1-04 | `fingerprint` module | cfe0379 |
| P1-05 | MTP config, DcOptions, legacy dbi; endpoints from config | 98f6aeb |
| P1-06 | Legacy key migration on save, with 1.5.0 vector | 58f4559 |
| P1-07 | `auth`: QR URL, SRP, session rows, expectations | daa6f1d |
| P1-08 | opentele2-versions crate with fixtures | 406358f |
| P1-09 | Telethon v8 rows + .json companion; feature `telethon-sqlite` | 23a8df3 |
| P2-01 | grammers client flows (feature `client`) | e5dbeae |
| P2-02, P2-03 | Node exports of P1 and `fetchVersions` | 2204c62 |
| P2-04 | mtcute flows: QR + 2FA, sessions admin, consistency | b690f48 |
| P2-05 | Telethon .session + .json for Node (writer moved to the core in P5-04) | 14c5818 |
| P3-01 | Mixed layout: `opentele2._native`, name `opentele2`, cryptg rule | 9b626af |
| P3-02 | `_native` exports of P1 and versions | 04df576 |
| P3-03 | Facades: exception, api, devices, fingerprint | 65e575e, 4471f04 |
| P3-04 | Facades: TDesktop, Account, AuthKey; vector byte identity | a151dad, 02b19d9 |
| P3-05 | Telethon: TelegramClient, session_io, consistency; ported tests | 2dd1fdc, 210b85f |
| P4-01 | Move gen_core_vectors.py, add `--source`, exclude from crate | a8a79e9, a7caa43 |
| P4-02 | Delete src/ and tracked tests/ files | pending: maintainer `git rm` |
| P4-03 | Delete root packaging leftovers | 5356d23 |
| P4-04, P4-05 | Version 2.0.0 in Cargo and npm manifests | 3090cbc |
| P4-06 | README and this file for the stable 2.0.0 | OT-209-docs-stable |
| P4-07 | Staged workflows: one maturin package, versions crate, 1.5.0 vector job | open |
| P5-01 | Core crypto: SHA-1/256, HMAC, PBKDF2, AES-CTR, PQ, `random_fill`, gzip | 1f89b8f..d393d81 |
| P5-02 | opentele2-browser; web devices drawn from it; Chrome/Firefox fetch, `firefox_version` | 1f89b8f..d393d81 |
| P5-03 | `opentele2.browser`, `generateHeaders`/`generateFingerprint`; Telethon crypto bridge; mtcute `createCryptoProvider` on the core | 1f89b8f..d393d81 |
| P5-04 | Telethon .session through the core's bundled SQLite in every binding; binding tables and texts from the core; no Rust lint suppressions | 1f89b8f..d393d81 |
| P5-05 | README and this file for the Rust-everywhere core | OT-290-docs-core-everywhere |

## Resolved questions

- Q1. Web devices are 1.5.0's browserforge pool, drawn by opentele2-browser
  from the embedded `apify_fingerprint_datapoints` 0.15.0 networks (M2); the
  curated web catalog of P1-01 was replaced and no hand-kept list remains.
- Q2. P1-06 uses a synthetic legacy (pre-7.3, no trailer) folder written by
  the vector generator from 1.5.0 primitives
  (crates/opentele2-core/tests/vectors/tdata_legacy/); tests/test_profile3.8
  goes with P4-02.
- Q3. The untracked agent-kernel tests stay where they are; tests/ keeps
  untracked files only.
- Q4. Nothing was ever published to PyPI or npm from 2.0.0 before the stable
  release; nothing to yank.
- Q5. `ureq` is 3.4.2 (crates/opentele2-versions/Cargo.toml:15); the
  workspace builds it under rust-version 1.89 (Cargo.toml:8).
- Q6. Full conversion parity for the Telethon sqlite file (D12).
- Q7. P2-01 is written against grammers-client 0.11.0
  (crates/opentele2-grammers/Cargo.toml).
- Q8. gen_core_vectors.py runs against a 1.5.0 checkout through `--source`
  (a7caa43).
- Q9. Python packages are built with `python -m pip install ./bindings/python`
  (PEP 517, maturin as backend); the guard refuses `python -m maturin`.
