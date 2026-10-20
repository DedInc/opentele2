# opentele2 Architecture

opentele2 is one Rust core, three companion crates and one package per
ecosystem over them: PyPI `opentele2` over Telethon, npm `opentele2` over
mtcute, and the Rust crates over grammers. The version is set once in the
workspace `Cargo.toml`, which every crate inherits, and in
`bindings/node/package.json`.

## Layout

```
Cargo.toml, Cargo.lock        workspace: members crates/*, bindings/python, bindings/node;
                              edition 2024, rust-version 1.89
README.md, ARCHITECTURE.md, CHANGELOG.md, LICENSE
opentele.png                  README logo, loaded from .../main/opentele.png
.github/workflows/            test.yml, release-crates.yml, release-python.yml, release-node.yml
crates/opentele2-core/        pure core: no async, no network, no FFI, unsafe_code forbidden
  src/                        qt, tdf, crypto, compress, kdf, tdata, session, devices, api,
                              fingerprint, auth, batch, error
  data/devices/               android, desktop, ios, mac catalogs (JSON)
  tests/                      Rust tests + fixtures/; no_suppressions.rs
  tests/vectors/              golden vectors (JSON) + gen_core_vectors.py
crates/opentele2-browser/     browser headers and fingerprints (Apache-2.0)
  data/                       embedded Apify networks, LICENSE-APIFY.md, SOURCE.md
crates/opentele2-versions/    version fetchers, blocking HTTP (ureq, rustls), no tokio
crates/opentele2-grammers/    grammers 0.11 bridge; client flows behind feature `client`
bindings/python/              PyPI `opentele2` (maturin, mixed layout)
  Cargo.toml, src/            PyO3 abi3-py38 cdylib, module `opentele2._native`
  pyproject.toml              requires-python >=3.8; telethon>=1.45.0
  python/opentele2/           _native.pyi, api, browser, consistency, devices, exception,
                              fingerprint, td/, tl/; private _compat, _telethon_crypto,
                              _version_fetcher
  tests/                      pytest suites (`live` marker for network tests)
bindings/node/                npm `opentele2`, napi-rs Node-API addon, engines >=18
  src/, index.js, index.d.ts  root entry point
  mtcute.mjs, mtcute.d.ts     `opentele2/mtcute`: session, initConnection options, crypto
                              provider, client flows
  telethon.mjs, telethon.d.ts `opentele2/telethon`: Telethon .session + .json
  __test__/                   node --test suites
```

Tests live with the code they test. `tests/vectors` and `tests/fixtures` are
excluded from the published core crate.

## Crates

- **opentele2-core** owns every format and rule. `tdf` is the `TDF$`
  container, `qt` the big-endian `QDataStream` values, `kdf` the PBKDF2 local
  keys and the capped Argon2id / scrypt passcode wraps of `key_data`, `crypto`
  auth keys, AES-256-IGE and -CTR, SHA-1, SHA-256, HMAC-SHA256, PBKDF2, PQ
  factorisation and `random_fill`, `compress` gzip in pure Rust. `tdata` reads
  and writes folders, accounts, the MTP config and DC options and migrates
  legacy key files; `session` holds Telethon string sessions, mtcute v3 string
  sessions, grammers-shaped `SessionData` and `telethon_file` (SQLite v8 rows
  and the `.json` companion). `devices` picks from the catalogs, `api` holds
  the eight profiles (`Client::ALL`), `Versions` and `LAYER` = 230,
  `fingerprint` the `initConnection` helpers, `auth` the QR URL, SRP, session
  rows, flow constants and texts and the consistency expectations and report,
  `batch` many folders at once. Features: `parallel` (default, a dedicated
  rayon pool per call) and `telethon-sqlite` (off by default; bundled SQLite).
- **opentele2-browser** samples the Apify Bayesian networks as browserforge
  does (`generate_headers`, `generate_fingerprint`), with every draw from its
  seeded xoshiro256** `Rng`. Pure Rust, including the zip inflater.
- **opentele2-versions** queries nine sources (Telegram Desktop, Android,
  Telegram X, iOS, macOS, Web K, Web A, Chrome, Firefox) in parallel with
  `fetch_all(timeout)` and returns a `VersionsPatch` for `api::Versions`; a
  source that fails leaves its fields unset. Parsers are pure functions in
  `parse`, tested on stored fixtures; live fetches are `#[ignore]` tests.
- **opentele2-grammers** turns accounts into grammers `SessionData`
  (`session_data`, `account_from_session`) and profiles into
  `ConnectionParams` (`connection_params`). Feature `client` adds the flows
  over grammers-client: `qr_login`, `sessions`, `sessions_table`,
  `terminate_session`, `run_consistency_checks`, `tdata_from_client`. The core
  never depends on grammers.

## Binding contract

Bindings are glue. The core owns the logic, the tables, the texts, the
crypto and the randomness; a binding converts values, calls the core and
adapts the result to its client. Name tables, MTP config marshalling, flow
constants and texts, the consistency report, session JSON shaping and error
classes all come from core items; no binding keeps a copy. The OS random
source has one entry point, `crypto::random_fill`.

- **Python** (`opentele2`): `opentele2._native` (PyO3, abi3-py38 wheels plus
  cp314t wheels) and Python modules that hold only the Telethon integration
  (`TelegramClient`, session files, consistency checks) and thin facades
  (`TDesktop`, `Account`, `AuthKey`, `API`, `APIData`, devices, fingerprint,
  exception, `opentele2.browser`). Format, crypto, catalog and fingerprint
  logic is never Python. Importing `opentele2` fetches the live versions
  unless `OPENTELE_NO_FETCH` is set.
- **Node** (`opentele2`): a napi-rs addon. The root entry point holds tdata,
  sessions, profiles, devices, fingerprint checks, versions (`fetchVersions()`,
  on an explicit call) and browser generation; `opentele2/mtcute` adds the
  session, `initConnectionOptions`, `createCryptoProvider` and the client
  flows over an mtcute client (optional peer `@mtcute/node` >= 0.32.0);
  `opentele2/telethon` writes and reads Telethon `.session` + `.json` pairs.
- **Rust**: the crates themselves; `fetch_all` runs only on an explicit call.

The Telethon `.session` file is written and read by the core's
`session::telethon_file` with feature `telethon-sqlite` in every ecosystem.

| Capability | Core | Rust API | Python | npm |
|---|---|---|---|---|
| Browser headers and fingerprints | no (opentele2-browser) | `generate_headers`, `generate_fingerprint` | `opentele2.browser` | `generateHeaders`, `generateFingerprint` |
| Web devices | `devices` web pool over opentele2-browser | core | facade `WebBrowserDevice` | `generate('TelegramWeb_A' / 'TelegramWeb_K')` |
| Client protocol crypto | `crypto`, `compress` | core | `_native.cryptg` + `_telethon_crypto` | `createCryptoProvider` |
| Live versions | no (pure patch type only) | opentele2-versions | `_native` + import-time fetch | `fetchVersions()` |
| Versions, layer | `api::Versions`, `api::LAYER` = 230 | core | facade `PlatformVersions` | `platformVersions`, `LAYER` |
| tz offset | `fingerprint` | core | facade (local offset) | `tzOffset` |
| initConnection validation | `fingerprint` | core | facade | `validateInitParams` |
| Version consistency | `fingerprint` | core | facade | `checkVersions` |
| StrictMode, FingerprintConfig | `fingerprint` | core | facades | `fingerprintConfig` |
| Transport recommendation | no (Telethon classes) | n/a | `TransportRecommendation` | n/a |
| msg_id offset and validity | `fingerprint` | core | facade | `msgIdOffset`, `isValidMsgId` |
| Profile session JSON | `api::ApiProfile` | core | `APIData` | `profileFromSessionJson`, `profileToSessionJson`, `profilesEqual` |
| Telethon .session + .json | `session::telethon_file` | feature `telethon-sqlite` | `_native.write_session_file` | `opentele2/telethon` |
| MTP config, endpoints | `tdata::mtp_config`, `session` | core | facade `MtpConfigView` | `accountMtpConfig`, `accountEndpoints` |
| Legacy key file migration | `TData::save`, `TData::migrate` | core | facade | `migrateTdata`, `saveTdata` |
| QR login + 2FA | `auth` URL + SRP | `client::qr_login` | `QRLoginToNewClient` | `qrLoginToNewClient` |
| Client session -> tdata | `TData::new` | `client::tdata_from_client` | `ToTDesktop` | `tdataFromClient` |
| Session admin | `auth` rows, table, official api ids | `client::sessions`, `sessions_table`, `is_official_app` | `GetSessions`, `PrintSessions` | `getSessions`, `formatSessions`, `isOfficialApp` |
| Consistency checks | `auth` expectations and report | `client::run_consistency_checks` | `RunConsistencyChecks` | `runConsistencyChecks` |
| initConnection lang_pack, params, proxy | profile carries values | not sent by grammers 0.11 | Telethon sends them | `initConnectionOptions` |

## Crypto boundary per client

| Client | On the core | Stays with the client |
|---|---|---|
| Telethon | `import opentele2` registers `opentele2._native.cryptg` as `cryptg` (AES-IGE) when no real `cryptg` imports; `_telethon_crypto` rebinds AES-CTR (obfuscated, CDN, MTProxy transports), PQ factorisation, SHA-1/256 and the password and MTProxy hashing | DH and RSA `pow`, `os.urandom` |
| mtcute | `createCryptoProvider()` implements every `ICryptoProvider` member | DH and RSA bigint maths |
| grammers | the core's own crypto; grammers runs `grammers-crypto`, which the core also uses for AES-IGE and 2FA SRP | n/a |

AES-IGE wrappers check buffer lengths before each `grammers-crypto` call and
return `Error::BadLength` instead of panicking.

## Determinism

- Devices: `devices::pick(platform, seed)` indexes the cumulative weights of
  a catalog with the seed hash (SHA-1 of the seed modulo 10^12), so a unique
  id gives the same device in every ecosystem; without a seed the pick draws
  from the OS random source.
- Web devices: `devices::web_catalog_for` draws a pool with opentele2-browser
  from a generator seeded by the Chrome and Firefox majors: up to 60 Chrome,
  30 Edge and 20 Firefox desktop user agents weighted 19/2/1, the version
  window shifted by the dataset lag (at most 24). A pool is a pure function
  of the versions, and its devices are picked as above.
- Browser fingerprints: every draw comes from the seeded xoshiro256** `Rng`
  and set operations keep first-seen order, so the same seed and options give
  byte-identical output on any platform, in Rust, Python and Node.
- Not seeded: msg_id offsets and flow delays come from the OS random source.
- Batch: with and without `parallel`, `batch` returns identical results in
  input order.

## Data provenance

- Device catalogs: `crates/opentele2-core/data/devices/` (android, desktop,
  ios, mac), embedded at build time and parsed once; the only copy. The
  Python `deviceList` and the other catalog lists are fresh read-only copies.
- Browser networks: `crates/opentele2-browser/data/` embeds the three
  Bayesian networks of the Python package `apify_fingerprint_datapoints`
  0.15.0, part of Apify fingerprint-suite, licensed Apache-2.0; provenance in
  `data/SOURCE.md`, licence text in `data/LICENSE-APIFY.md`. The crate ports
  browserforge (Apache-2.0) and is itself Apache-2.0; its `NOTICE` credits
  both. The rest of the project is MIT.
- Versions: `api::Versions::offline()` is the built-in set; opentele2-versions
  fetches the live ones from the clients' public release sources.
- Targets: Telegram Desktop 7.3.1 tdata (version 7003001) and schema layer 230.

## Error model

- Core: one `#[non_exhaustive] Error`. `Error::code()` is a stable
  SCREAMING_SNAKE identifier (for example `TDATA_WRONG_PASSCODE`); the
  `Display` text is for humans and may change. `legacy_message()` is the
  stable display text of the matching exception and `legacy_class()` its
  class name. Flow and SRP failures (`auth::FlowFailure`, `auth::SrpError`)
  carry the same `code()` / `legacy_class()` pair.
- Python: `_native` raises `CoreError` with `code`, `message`,
  `legacy_message` and `detail_code`; `opentele2.exception` maps `code` to its
  exception class through `core_error_classes()` and raises it with
  `legacy_message`.
- Node: an `Error` whose `code` is `OT_` plus the core code (for example
  `OT_TDATA_WRONG_PASSCODE`), `message` the core text and `legacyMessage` the
  stable display text; `flowErrorClasses()` maps flow codes to class names.
  Arguments the core never sees fail with `ERR_INVALID_ARG_VALUE`.
- Rust: `opentele2_core::Error`, `opentele2_browser::Error` and the grammers
  client's `ClientError`.

## Testing

- Golden vectors: `crates/opentele2-core/tests/vectors/` holds frozen
  outputs for crypto, devices, sessions, tdata and TDF. Device generation,
  crypto, TDF, session and tdata outputs must stay byte-identical to them,
  and the Rust, Python and Node suites test against the same files. They are
  never regenerated from the current code: the `vectors` job of `test.yml`
  rebuilds them from the reference sources with
  `gen_core_vectors.py --source <checkout> --check` and compares.
- Suites per ecosystem, all in `test.yml` on Linux, Windows and macOS:
  `cargo test --workspace` plus the four pure crates with `--all-features`;
  `pytest bindings/python/tests -m "not live"` on Python 3.8, 3.12 and 3.14;
  `node --test __test__` on Node 22 and a subset on Node 18. At 2.0.0: 392
  Rust tests, 841 Python tests (3.8 and 3.12) and 172 Node tests.
- No suppressions: `crates/opentele2-core/tests/no_suppressions.rs` fails on
  any lint suppression in Rust sources, and
  `bindings/python/tests/test_no_suppressions.py` on `noqa`, `type: ignore`
  and similar markers in the Python package and its tests.
- Lints and types: `cargo fmt --check`, clippy (`all` and `pedantic`) with
  `-D warnings`, an MSRV check on 1.89, ruff and ty for Python, and a
  type check of the Node declarations.
- Network: live tests carry the pytest `live` marker or Rust `#[ignore]` and
  stay out of CI.

## Release flow

A release is one tag, `X.Y.Z` or `X.Y.Z-(alpha|beta|rc).N`, without a `v`.
Each release workflow checks the tag against the package versions and
publishes from a protected environment with required reviewers.

- `release-crates.yml` (environment `crates-io`) publishes in dependency
  order: opentele2-browser, opentele2-core, opentele2-versions,
  opentele2-grammers. The binding crates are not published to crates.io.
- `release-python.yml` (environment `pypi`, trusted publishing) builds abi3
  (cp38-abi3) and cp314t wheels for manylinux, musllinux, Windows and macOS
  plus the sdist, under the PEP 440 spelling of the tag.
- `release-node.yml` (environment `npm`) builds the addon for the eight
  `napi.targets` and publishes `opentele2` and its per-platform packages with
  npm provenance.

## Known debts

- Telethon's DH and RSA arithmetic (Python `pow`) and its `os.urandom`
  calls stay Telethon's; the bridge covers the rest of its protocol crypto.
- mtcute's DH and RSA bigint maths stay mtcute's.
- grammers 0.11 sends an empty `lang_pack` and no `params` in
  `initConnection`, and its QR login does not wait for `updateLoginToken`.
  Closing the gap needs `lang_pack` and `params` fields on grammers-mtsender's
  `ConnectionParams` (crates/opentele2-grammers/src/lib.rs).
- On its error path the Python session companion reader parses the `.json`
  once more, since the core's `read_companion` shares one `what` across its
  errors.
- A web device's user agent carries the live browser major, which can be newer
  than the newest major in the Apify networks; a full browser fingerprint
  cannot then be generated for exactly that user agent ("No headers based on
  this input"). Generate the fingerprint from browser options instead.
