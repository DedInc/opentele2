# opentele2 2.0.0 Architecture (v2)

Status: decision record for the stable 2.0.0 release. Version v1 of this file
described the pre-release split (a pure-Python root package over a separate
`opentele2-core` wheel); v2 replaces it with one package per ecosystem over one
Rust core, and plans the removal of the 1.x Python implementation. Facts cite
`path:line`; anything not established is under Open questions.

## Layout

Final tree. The root holds only workspace, docs, licence and CI configuration.

```
Cargo.toml, Cargo.lock        workspace: members crates/*, bindings/python, bindings/node; rust-version 1.89
README.md, ARCHITECTURE.md, LICENSE, .gitignore
opentele.png                  README logo; stays at the root (see below)
.github/workflows/            maintainer-owned; agents stage edits in refs/github-workflows/
crates/opentele2-core/        pure core: no async, no network, no FFI, unsafe_code forbidden
  src/                        qt, tdf, crypto, kdf, tdata, session, devices, api, batch,
                              + fingerprint (new), auth (new)
  data/devices/               android, desktop, ios, mac, + web.json (new); the only catalog copy
  tests/                      Rust tests
  tests/vectors/              frozen 1.5.0 oracle + gen_core_vectors.py (moved from scripts/)
crates/opentele2-versions/    new: network version fetchers (7 sources), blocking HTTP, no tokio
crates/opentele2-grammers/    grammers 0.11 bridge + client flows behind feature `client`
bindings/python/              the one PyPI package `opentele2` (maturin, mixed layout)
  Cargo.toml, src/            PyO3 cdylib, module `opentele2._native`
  pyproject.toml              name opentele2, version from Cargo, telethon>=1.45.0
  python/opentele2/           Telethon integration + thin public facades only
  tests/                      binding + public-API tests (pytest, `live` marker)
bindings/node/                npm `opentele2` + `opentele2/mtcute` (unchanged shape)
```

Placement decisions:
- Tests live with the code they test: Rust in `crates/*/tests/`, Python in
  `bindings/python/tests/`, Node in `bindings/node/__test__/`. No root `tests/`.
- `scripts/gen_core_vectors.py` moves to `crates/opentele2-core/tests/vectors/`,
  next to the oracle it writes. Today it imports `src.*` from the checkout
  (scripts/gen_core_vectors.py:84-90,164,206-213,322-324,500-501). Once `src/`
  is gone it takes `--source <dir>`, a checkout of tag 1.5.0 (which has the same
  `src/` and `src/td/` module tree), and keeps setting `OPENTELE_NO_FETCH=1`
  (scripts/gen_core_vectors.py:87). The committed vectors stay the frozen
  oracle: they are never regenerated from 2.0 code. `--check` is a CI job
  against the 1.5.0 checkout; the script and fixtures are excluded from the
  published crate (`exclude` in crates/opentele2-core/Cargo.toml).
- `opentele.png` stays at the root: README.md:6 and the long descriptions of
  every published 1.x release load it from `.../main/opentele.png`, so moving
  it breaks old PyPI pages.
- The agent kernel (AGENTS.md, install.py, tools/, .agents/, docs/, and the
  untracked kernel tests under tests/) is not part of the product tree; this
  plan neither moves nor deletes it (see Q3).

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
  `opentele2._native`, Python sources in bindings/python/python/opentele2/.
  It replaces the root hatchling package (pyproject.toml:1-3,59-63) and the
  `opentele2-core` distribution (bindings/python/pyproject.toml:6).
- Python sources hold only the Telethon integration (TelegramClient, session
  files, consistency checks) and thin facades that keep 1.x names over
  `_native`. Format, crypto, catalog and fingerprint logic is never Python.
- Python >= 3.8; abi3-py38 and cp314t wheels as in release-python.yml today.
- cryptg: `import opentele2` registers `opentele2._native.cryptg` as
  `sys.modules["cryptg"]` under the same rule as src/__init__.py:4-10.
- Errors: `_native` raises one `CoreError(code, message)`; `opentele2.exception`
  maps `code` to the 1.x subclasses (src/exception.py:43-196) in one table.
- Cost accepted: every pure-Python fix ships as a full wheel matrix.

### M2. Deterministic web fingerprints (maintainer decision, recorded)
- `crates/opentele2-core/data/devices/web.json` lists browser, version, OS,
  UA template and weights; `devices::generate(Platform::Web, unique_id)` seeds
  like the other platforms (sha1 mod 10^12, JSON-order weight expansion).
- browserforge (src/devices.py:490-520) and the Chrome/Firefox version probes
  (src/devices.py:399-438,530-538) are dropped. The catalog has a top-level
  `"schema": 1`; the parser rejects unknown schema numbers.

### D10. Network version fetching is a separate crate
- Chosen: `crates/opentele2-versions` ports the 7 sources of
  src/version_fetcher.py:86-204 (tdesktop, Android, Telegram X, iOS, macOS,
  WebK, WebA) and returns a patch applied to core `api::Versions`. Blocking
  HTTP with rustls (`ureq`), parallel per source, per-call timeout; parsers are
  pure functions tested on stored HTML fixtures, live fetches are `#[ignore]`.
- Rejected: fetching in the core (breaks the no-network rule,
  crates/opentele2-core/src/lib.rs:11-12) and `reqwest` (pulls tokio into a
  sync stack). Bindings call it under `py.detach` / as an `AsyncTask` (v1 D6).
- Python keeps the 1.x import-time fetch (src/fingerprint.py:122-147) and the
  `OPENTELE_NO_FETCH` switch (src/version_fetcher.py:209); npm and Rust fetch
  only on an explicit call, since they have no 1.x behaviour to keep.

### D11. Client flows per ecosystem on its native client
- Python over Telethon, npm over mtcute, Rust over grammers in
  `opentele2-grammers` (feature `client`). Each flow lives once, on the client
  its users already run; no binding drives another ecosystem's network stack.
- Shared pure pieces in core `auth`: QR URL `tg://login?token=<base64url>`
  (same string as Telethon qrlogin.py:57 and
  refs/mtcute-master/packages/core/src/highlevel/methods/auth/sign-in-qr.ts:133);
  2FA SRP over `grammers_crypto::two_factor_auth::calculate_2fa` (pub in
  grammers-crypto 0.11.0, src/lib.rs:22); session-admin row formatting (the
  PrintSessions table); consistency expectations (lang_pack per profile,
  layer tolerance). Telethon and mtcute keep their own SRP (`compute_check`,
  mtcute `checkPassword`) because they consume live TL objects; core SRP is
  used by Rust and cross-checked against Telethon in a core test.
- grammers 0.11 hardcodes `lang_pack: ""`, `proxy: None`, `params: None`
  (grammers-mtsender 0.11.0 src/sender_pool.rs:440-443). Kept as a documented
  gap (crates/opentele2-grammers/src/lib.rs:16-32) plus the upstream change;
  rejected: a grammers fork (v1 D5).

### D12. Persistent formats stay owned by the core
- MTP config, DcOptions and legacy dbi blocks are parsed in core `tdata`,
  and `session` takes endpoints from the stored config when performance mode
  is off, closing crates/opentele2-core/src/session/mod.rs:9-13.
- Saving a folder with a legacy key file migrates it in the core, as 1.5.0
  does (src/td/tdesktop.py:199-202), instead of `Error::SaveFailed`
  (crates/opentele2-core/src/tdata/mod.rs:252-278).
- Telethon `.session` sqlite v8 (src/tl/session_io.py:69-104) stays a Python
  write over stdlib `sqlite3` from core rows; rejected: SQLite in the core
  (C dependency for one ecosystem's file format).

## Parity

Already shared by core, Rust, Python and npm today: tdata read/write, KDFs,
AES-IGE, Telethon and mtcute string sessions, grammers SessionData, non-web
device generation, API profiles, batch load. Rows below are the Python-only
matrix; every row has a target.

| Capability (1.x source) | Core | Rust API | Python | npm |
|---|---|---|---|---|
| Web fingerprints (src/devices.py:468-639) | `devices` + web.json (M2) | core | facade `WebBrowserDevice` | `generate('TelegramWeb*')` |
| Version fetchers, 7 sources (src/version_fetcher.py:86-204) | no (pure patch type only) | opentele2-versions | `_native` + import-time fetch | `fetchVersions()` Promise |
| PlatformVersions extra fields, LAYER (src/fingerprint.py:53-112) | `api::Versions` gains 5 fields; recommended layer const | core | facade `PlatformVersions` | `Versions` type |
| Advertised layer (src/fingerprint.py:37-64) | no (client property) | `grammers_tl_types::LAYER` | Telethon layer | mtcute TL layer |
| tdesktop_tz_offset (src/fingerprint.py:154-206) | `fingerprint::tz_offset(offset_secs)` | core | facade (local offset) | wrapper (local offset) |
| validate_init_connection_params (src/fingerprint.py:208-261) | `fingerprint::validate` | core | facade | `validateInitConnection` |
| Version consistency (src/fingerprint.py:263-315) | `fingerprint::check_versions` | core | facade | export |
| StrictMode, FingerprintConfig (src/fingerprint.py:317-386) | data types in `fingerprint` | core | facades keep fields | options object |
| TransportRecommendation (src/fingerprint.py:388-426) | no (Telethon classes) | n/a | Python only | n/a |
| msg_id offset/validity (src/fingerprint.py:428-441) | `fingerprint::{msg_id_offset, is_valid_msg_id(now)}` | core | facade | export |
| APIData from_json/to_json, 19 extra fields, eq/hash (src/api.py:109-254) | `api::ApiProfile` serde, extras kept in order, `Eq + Hash` | core | `APIData` facade | `profileFromJson/ToJson` |
| Telethon .session v8 + .json pair (src/tl/session_io.py:69-242) | rows + JSON companion | feature `telethon-sqlite` (Q6) | Python sqlite3 writer | `node:sqlite` writer (Q6) |
| Legacy dbi, MTP.Config/DcOptions, endpoints from config (src/td/storage.py:392-463, src/td/mtp.py:47-387) | `tdata` parse, `session` endpoint choice (D12) | core | facade | via core |
| Legacy key file migration on save (src/td/tdesktop.py:199-202) | `TData::save` migrates (D12) | core | facade | via core |
| QR login + 2FA, CreateNewSession (src/tl/telethon.py:344-523) | `auth` URL + SRP | opentele2-grammers `client` | Telethon | mtcute `signInQr` + check password |
| Client session -> tdata needing get_me (src/tl/telethon.py:525-534, src/td/tdesktop.py:425-445) | `TData::new` from user id + key | grammers `get_me` | Telethon | mtcute `getMe` |
| Session admin, PrintSessions, is_official_app (src/tl/telethon.py:276-335) | `auth` formatting + official api_id set | grammers `invoke` | Telethon | mtcute `client.call` (client.types.ts:101) |
| ConsistencyChecker (src/consistency.py:50-267) | `auth` expectations | grammers | Telethon | mtcute |
| initConnection lang_pack/params/proxy | profile carries values | gap in grammers 0.11 (D11) | Telethon sends them | mtcute `initConnectionOptions` |

## Removal

Nothing is deleted before its replacement passes its gate (Phases P4 after P3).

| Legacy path | Fate | Replacement / how 1.x behaviour is kept |
|---|---|---|
| pyproject.toml (root, hatchling) | delete | bindings/python/pyproject.toml, name `opentele2` (M1) |
| bindings/python/opentele2_core.pyi | delete | python/opentele2/_native.pyi |
| PyPI `opentele2-core` | no further releases | `opentele2._native`; only a pre-release ever shipped (Q4) |
| src/__init__.py | port | python/opentele2/__init__.py, same cryptg rule |
| src/api.py | facade | `API`, `APIData`, `LoginFlag`, `UseCurrentSession`, `CreateNewSession` keep names and signatures over core profiles |
| src/exception.py | move | python/opentele2/exception.py, same hierarchy (`OpenTeleException(BaseException)`, :43) + code table |
| src/devices.py, src/devices/*.json | facade; json deleted | `SystemInfo` and `*Device` classes over core `generate`; catalogs only in crates/opentele2-core/data/devices |
| src/fingerprint.py | facade | names kept over core `fingerprint`; Telethon transport helper stays Python |
| src/version_fetcher.py | delete | opentele2-versions via `_native` (D10) |
| src/consistency.py | port | Telethon `ConsistencyChecker` over core expectations |
| src/td/tdesktop.py, account.py, auth.py | facade | `TDesktop`, `Account`, `AuthKey`, `AuthKeyType` over `_native.TData` |
| src/td/storage.py, storage_account.py, map_data.py, mtp.py, key_data.py, configs.py, shared.py, __init__.py | delete | core `tdata`, `kdf`, `crypto`; `td/__init__.py` re-exports the facades only |
| src/qt_compat.py | delete | core `qt` |
| src/utils.py | delete | `APP_VERSION` from core; `BaseObject`/`sharemethod` move to a private `_compat.py`; PrettyTable to core `auth` formatting |
| src/debug.py | delete | none (internal instrumentation, `OPENTELE_DEBUG`) |
| src/tl/telethon.py, session_io.py, client_kwargs.py, configs.py, shared.py, __init__.py | port | python/opentele2/tl/, `TelegramClient` keeps names and signatures |
| tests/test_tdata_{keydata,localkey,mapdata,mtp,readfile,storage}.py, test_core_bridge.py | delete | core tests + frozen vectors |
| tests/test_api_typing, client_kwargs, init_connection, session_io, version_layer, desktop_version, {android,ios,mac,desktop}_devices.py | port | bindings/python/tests/, against the facades |
| tests/test_fingerprints.py, test_web_devices.py, test_device_catalog_currency.py | split | pure cases to core tests, facade cases to Python |
| tests/test_version_fetcher.py | port | crates/opentele2-versions/tests (fixtures) |
| tests/test_full.py, tdata_test.py (live) | port | public-API subset to bindings/python/tests, `live` marker kept |
| tests/test_no_suppressions.py, test_platform_versions.py | retarget | scan bindings/python/python instead of src/ |
| tests/__init__.py, tests/pytest.ini | delete | `[tool.pytest.ini_options]` with the `live` marker |
| tests/test_profile3.8/ (4 files, used by tdata_test.py:46) | move or delete | core legacy-key fixture if Q2 confirms the layout, else delete |
| scripts/gen_core_vectors.py | move | crates/opentele2-core/tests/vectors/, `--source` (Layout) |
| MANIFEST.in | delete | includes an absent requirements.txt; maturin `include` |
| mypy.ini | delete | `ty` (v1 D8); names tgcrypto, which is gone |
| .coveragerc | delete | omits an absent setup.py; config in bindings/python/pyproject.toml if kept |

Deliberately not kept as public names: `td.MTP`, `td.MapData`, `td.Serialize`,
`td.Storage`, `td.StorageAccount` (src/td/__init__.py:3-11) and the modules
`qt_compat`, `utils`, `debug`, `version_fetcher`. README.md:69-70 documents
only `opentele2.api` and `opentele2.td.TDesktop`.

## Compatibility

1. Python public API: `TDesktop`, `Account`, `AuthKey`, `AuthKeyType`,
   `TelegramClient`, `API`, `APIData`, `LoginFlag`, `UseCurrentSession`,
   `CreateNewSession` and every class in src/exception.py keep import paths,
   names, signatures and hierarchy. Import-time version fetch is kept (D10).
2. Golden vectors: Generate, crypto, TDF, sessions and tdata outputs stay
   byte-identical to the frozen 1.5.0 vectors in crates/opentele2-core/tests/
   vectors; the Python facades are tested against the same files.
3. tdata: written folders stay readable by 1.5.0 and tdesktop 7.3.1 (version
   7003001, key_data format 2); legacy key files are migrated on save (D12).
   Any slice that changes a written format ships its version handling,
   migration path and a backward-compatibility test together, or is blocked.
4. Sessions: Telethon string, Telethon sqlite v8 and its .json pair, mtcute
   v3 and grammers SessionData unchanged; with performance mode off endpoints
   again come from the stored config, as in 1.5.0.
5. Deliberate breaks: web fingerprints are deterministic per `unique_id` and
   no longer browserforge-random; `browserforge`, `selectolax`, `tgcrypto` and
   `argon2-cffi` are gone (none is a dependency of the 2.0.0 package); the
   pre-release module `opentele2_core` becomes `opentele2._native`; the
   internal names listed under Removal disappear.

## Phases

Rules: each slice touches at most 5 paths in at most 2 top-level areas (a
directory is one path; root files form one area) and has one gate from the
allowlist (cargo, python, node, pnpm, npm), run under Windows cmd. Python gates
use `.venv38\Scripts\python.exe` (the 3.8 floor). Build steps before a gate
(`maturin develop`, `pnpm run build`) are not gates. Slice ids are
placeholders until registered in the backlog. CI changes go only to
refs/github-workflows/; the maintainer copies them to .github/workflows/.

Phase 1, pure features into the core (nothing removed; src/ frozen from here):

| Id | Title | Paths | Gate |
|---|---|---|---|
| P1-01 | Web catalog, schema 1, seeded Web generate | crates/opentele2-core/data/devices/web.json, crates/opentele2-core/src/devices.rs, crates/opentele2-core/tests/devices.rs | `cargo test -p opentele2-core --test devices` |
| P1-02 | Versions extra fields, recommended layer | crates/opentele2-core/src/api.rs, crates/opentele2-core/tests/api.rs | `cargo test -p opentele2-core --test api` |
| P1-03 | APIData JSON with extras, Eq/Hash | crates/opentele2-core/src/api.rs, crates/opentele2-core/tests/api.rs | `cargo test -p opentele2-core --test api` |
| P1-04 | `fingerprint` module | crates/opentele2-core/src/fingerprint.rs, crates/opentele2-core/src/lib.rs, crates/opentele2-core/tests/fingerprint.rs | `cargo test -p opentele2-core --test fingerprint` |
| P1-05 | MTP config, DcOptions, legacy dbi; endpoints from config | crates/opentele2-core/src/tdata/, crates/opentele2-core/src/session/, crates/opentele2-core/tests/tdata_read.rs, crates/opentele2-core/tests/session.rs | `cargo test -p opentele2-core` |
| P1-06 | Legacy key migration on save, with 1.5.0 vector | crates/opentele2-core/src/tdata/, crates/opentele2-core/tests/tdata_write.rs, crates/opentele2-core/tests/vectors/, scripts/gen_core_vectors.py | `cargo test -p opentele2-core --test tdata_write` |
| P1-07 | `auth`: QR URL, SRP, session rows, expectations | crates/opentele2-core/src/auth.rs, crates/opentele2-core/src/lib.rs, crates/opentele2-core/tests/auth.rs | `cargo test -p opentele2-core --test auth` |
| P1-08 | opentele2-versions crate with fixtures | crates/opentele2-versions/, Cargo.lock | `cargo test -p opentele2-versions` |
| P1-09 | Telethon v8 rows + .json companion; feature `telethon-sqlite` writer/reader | crates/opentele2-core/Cargo.toml, crates/opentele2-core/src/session/, crates/opentele2-core/tests/session.rs, Cargo.lock | `cargo test -p opentele2-core --all-features --test session` |

Phase 2, Rust API and npm parity:

| Id | Title | Paths | Gate |
|---|---|---|---|
| P2-01 | grammers client flows (feature `client`) | crates/opentele2-grammers/, Cargo.lock | `cargo test -p opentele2-grammers --all-features` |
| P2-02 | Node exports of P1-01..P1-07 | bindings/node/src/, bindings/node/index.d.ts, bindings/node/index.js, bindings/node/__test__/ | `node --test bindings/node/__test__` |
| P2-03 | Node `fetchVersions` | bindings/node/Cargo.toml, bindings/node/src/, bindings/node/index.d.ts, bindings/node/__test__/, Cargo.lock | `node --test bindings/node/__test__` |
| P2-04 | mtcute flows: QR + 2FA, sessions admin, consistency | bindings/node/mtcute.mjs, bindings/node/mtcute.d.ts, bindings/node/__test__/ | `node --test bindings/node/__test__` |
| P2-05 | Telethon .session + .json via `node:sqlite` | bindings/node/telethon.mjs, bindings/node/telethon.d.ts, bindings/node/package.json, bindings/node/__test__/ | `node --test bindings/node/__test__` |

Phase 3, the single Python package beside the old one:

| Id | Title | Paths | Gate |
|---|---|---|---|
| P3-01 | Mixed layout: `opentele2._native`, name `opentele2`, cryptg rule | bindings/python/pyproject.toml, bindings/python/Cargo.toml, bindings/python/src/, bindings/python/python/, bindings/python/tests/ | `.venv38\Scripts\python.exe -m pytest bindings/python/tests -q` |
| P3-02 | `_native` exports of P1 and versions | bindings/python/Cargo.toml, bindings/python/src/, bindings/python/python/, bindings/python/tests/, Cargo.lock | `.venv38\Scripts\python.exe -m pytest bindings/python/tests -q` |
| P3-03 | Facades: exception, api, devices, fingerprint | bindings/python/python/, bindings/python/tests/ | `.venv38\Scripts\python.exe -m pytest bindings/python/tests -q` |
| P3-04 | Facades: TDesktop, Account, AuthKey; vector byte identity | bindings/python/python/, bindings/python/tests/ | `.venv38\Scripts\python.exe -m pytest bindings/python/tests -q` |
| P3-05 | Telethon: TelegramClient, session_io, consistency; ported tests | bindings/python/python/, bindings/python/tests/ | `.venv38\Scripts\python.exe -m pytest bindings/python/tests -q -m "not live"` |

Phase 4, removal and the stable version (only after P3-05 passes):

| Id | Title | Paths | Gate |
|---|---|---|---|
| P4-01 | Move gen_core_vectors.py, add `--source`, exclude from crate | scripts/, crates/opentele2-core/tests/vectors/, crates/opentele2-core/Cargo.toml | `python crates/opentele2-core/tests/vectors/gen_core_vectors.py --check --source .` |
| P4-02 | Delete src/ and tracked tests/ files (kernel tests untouched) | src/, tests/ | `.venv38\Scripts\python.exe -m pytest bindings/python/tests -q -m "not live"` |
| P4-03 | Delete root packaging leftovers | pyproject.toml, MANIFEST.in, mypy.ini, .coveragerc, bindings/python/opentele2_core.pyi | `cargo test --workspace` |
| P4-04 | Version 2.0.0 in Cargo manifests | Cargo.toml, crates/opentele2-grammers/Cargo.toml, crates/opentele2-versions/Cargo.toml, Cargo.lock | `cargo test --workspace` |
| P4-05 | Version 2.0.0 in npm manifests | bindings/node/package.json, bindings/node/npm/ | `node --test bindings/node/__test__` |
| P4-06 | README for one package per ecosystem | README.md | `python -c "import pathlib,sys; t=pathlib.Path('README.md').read_text(encoding='utf-8'); sys.exit(1 if 'opentele2_core' in t or '2.0.0a1' in t else 0)"` |
| P4-07 | Staged workflows: one maturin package, versions crate, 1.5.0 vector job | refs/github-workflows/ | `python -c "import pathlib,sys; t=''.join(p.read_text(encoding='utf-8') for p in pathlib.Path('refs/github-workflows').glob('*.yml')); sys.exit(1 if 'hatch' in t or 'scripts/gen_core_vectors' in t else 0)"` |

P4-01 runs while src/ still exists, so the moved script is proven against the
current tree before P4-02 deletes it; CI then runs it with `--source` pointing
at a checkout of tag 1.5.0 (P4-07).

## Resolved questions (orchestrator, 2026-10-19)

- Q1. web.json is a curated list of real stable Chrome, Edge, Firefox and
  Safari releases current in October 2026 per OS, weighted by market share
  from a cited public source; P1-01 researches and records the sources in the
  catalog's `"sources"` field. browserforge is not used as a source.
- Q2. P1-06 uses a synthetic legacy (pre-7.3, no trailer) folder written by
  the vector generator from 1.5.0 primitives; tests/test_profile3.8 (a v1.0.0
  demo profile holding a third party's authorization) is deleted in P4-02.
- Q3. The untracked agent-kernel tests stay where they are; tests/ may keep
  untracked files only.
- Q4. Nothing was ever published to PyPI or npm from 2.0.0; nothing to yank.
- Q6. Yes, full conversion parity: the core builds the Telethon v8 rows and
  the .json companion; Python writes the file with stdlib `sqlite3`, npm with
  the built-in `node:sqlite` (Node >= 22.5, a clear error below), Rust with an
  optional, default-off core feature `telethon-sqlite` (rusqlite, bundled), so
  the default core stays FFI-free. This amends D12.
- Q9. The guard refuses `python -m maturin`; Python packages are built with
  `python -m pip install ./bindings/python` (PEP 517, maturin as backend).
  Gates spell the 3.8 interpreter `".venv38\Scripts\python.exe"` (quoted, so
  agentctl's POSIX tokenizer keeps the backslashes).

## Open questions
- Q5. The exact `ureq` version and its MSRV against rust-version 1.89.
- Q6. Whether npm and Rust need the Telethon sqlite file (D12 says no).
- Q7. grammers-client 0.11 API for P2-01 (invoke, password check): only the
  0.10 source is in refs/grammers, and grammers-client 0.11 is not yet in the
  local registry.
- Q8. Whether every name gen_core_vectors.py imports exists at tag 1.5.0 (the
  module tree matches; the per-name check was refused by the tool guard).
