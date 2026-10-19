# opentele2 2.0.0 Architecture

Status: implemented on branch `2.0.0` (from tag `1.5.0`) through OT-162 at
version 2.0.0a1 / 2.0.0-alpha.1; CI and release workflows are open (Phases).
This document records the Rust core and binding architecture. Facts cite
`path:line` in this repository or a pinned version number; anything not
established is listed under Open questions rather than assumed.

## Layout

```
Cargo.toml                    workspace root: members crates/*, bindings/python, bindings/node; rust-version 1.89
crates/opentele2-core/        pure core: no async, no network, no FFI, unsafe_code forbidden
  data/devices/*.json         device catalogs, embedded with include_str! (copies of src/devices/)
  tests/vectors/              golden vectors produced by 1.5.0 (OT-141)
crates/opentele2-grammers/    optional: core Account <-> grammers 0.11 SessionData, ConnectionParams
bindings/python/              PyO3 0.29 abi3-py38 cdylib, maturin, PyPI `opentele2-core`, module `opentele2_core`
  opentele2_core.pyi          typed stub, shipped as the package's __init__.pyi
bindings/node/                napi-rs cdylib, npm package `opentele2`: index.js, index.d.ts
  mtcute.mjs, mtcute.d.ts     the `opentele2/mtcute` entry point
  __test__/                   node --test suite
src/                          pure-Python `opentele2` (hatchling, src -> opentele2), depends on opentele2-core
  devices/*.json              catalogs still read by src/devices.py:30 (duplicate, see Known gaps)
scripts/gen_core_vectors.py   writes crates/opentele2-core/tests/vectors/
.github/workflows/            not written yet (OT-163, OT-164)
```

The core crate owns, as modules: `qt` (big-endian QDataStream), `tdf` (TDF$
container and md5 trailer), `crypto` (AES-256-IGE, `prepareAES_oldmtp`, local
encryption), `kdf` (PBKDF2-SHA512 100000/1, legacy PBKDF2-SHA1 4000/4,
Argon2id, scrypt read-only), `tdata` (key_data with the 0x4B443200 v2 trailer,
map, MtpAuthorization, multi-account read and write), `session` (built-in DC
table, Telethon string, mtcute string v3, a plain grammers-shaped
SessionData), `devices` (catalogs and deterministic Generate), `api` (official
client profiles and offline versions), `batch` (`load_many` on a rayon pool)
and the private `error`, whose `Error` and `Result` are re-exported
(crates/opentele2-core/src/lib.rs:23-34).

## Decisions

### D1. Repository layout: one Cargo workspace, one pure core
- Chosen: a root workspace with `crates/opentele2-core` holding every format and
  crypto rule, thin binding crates under `bindings/`, and grammers glue in a
  separate optional crate. Core has no tokio, no sockets, no filesystem walk
  beyond explicit paths given by the caller.
- Rejected: porting tdata logic separately per binding, or depending on
  `hermes-tdata` 0.2.1 / `grammpars` 0.1.0. Per-binding ports violate DRY;
  hermes-tdata is read-only and the core must write 7.3.1 tdata with the v2
  key_data trailer (src/td/key_data.py:51-52).
- Why (SRP, DRY): today every `td` import drags Telethon in through
  src/td/shared.py:7 -> src/td/tdesktop.py:8 although the format code is IO and
  crypto only; the core cuts that edge once for all three languages.
- Catalogs: `crates/opentele2-core/data/devices/*.json` is the single source,
  embedded with `include_str!` and exposed to Python as data. Rejected: keeping
  them in `src/devices/` and including `../../../src/devices` from the crate,
  because `cargo package` cannot ship files outside the crate directory.
- AES-IGE: `grammers-crypto` 0.11 `aes::ige_encrypt`/`ige_decrypt` (in place,
  over `aes` 0.9.3 with runtime AES-NI), as the maintainer requested. Core checks
  `len % 16 == 0` and the 32-byte key/iv before every call and returns
  `Error::BadLength`, so grammers' `assert_eq!` panic is unreachable. Rejected: a
  core-owned IGE or the RustCrypto `ige` crate, which duplicate code grammers
  already maintains and tests (DRY). The cost, core following grammers-crypto
  releases, is accepted.

### D2. Python packaging: the pydantic / pydantic-core split
- Chosen: two distributions. `opentele2` stays pure Python, keeps the `src/`
  layout and hatchling build (pyproject.toml wheel sources `src = opentele2`),
  keeps all Telethon integration, and depends on `opentele2-core==2.0.*`, an
  abi3 wheel exporting the module `opentele2_core`.
- Rejected: one maturin mixed package. It turns every pure-Python fix into a
  full per-platform wheel matrix and replaces the build backend of code that
  has no native part (KISS, SRP).
- Floor of the core wheel: Python 3.8 via PyO3 0.29.x `abi3-py38`. Rejected:
  3.7 via PyO3 0.28.x, because Telethon itself does not run below 3.8 (walrus at
  refs/telethon/telethon/tl/custom/button.py:53), so 3.7 gains no user (YAGNI).
  PyO3 0.30 is rejected for 2.0.0 because it needs Python >= 3.9.
- Floor of the pure package: lowered from `>=3.10` to `>=3.8` to match the core
  wheel and Telethon, as the maintainer requested. Blockers to remove: runtime
  PEP 604 unions (src/qt_compat.py:13), `typing.ParamSpec` (src/utils.py:6, from
  `typing_extensions` below 3.10), runtime `dict[...]` (src/td/map_data.py:23-25),
  `str.removesuffix` and `asyncio.to_thread` (src/tl/session_io.py:33-34,169,240).
  Most of src/td shrinks to core calls first, so the port is done after that.
- Free-threaded: abi3 wheels do not load on free-threaded interpreters, so the
  matrix adds the `cp314t` wheels that `maturin generate-ci` already emits
  (`abi3t` exists only for CPython 3.15+, PyO3 `abi3t-py315`, and is deferred); the
  module declares `gil_used = false`. The core keeps no global mutable state,
  which makes that declaration true by construction.
- GIL: every exported function that does crypto, KDF or file IO copies its
  inputs to owned Rust values and runs inside `py.detach` (formerly
  `allow_threads`). Trivial accessors do not detach.

### D3. Telethon acceleration through a cryptg-compatible surface
- Chosen: `opentele2_core.cryptg` exposes `encrypt_ige(data, key, iv)` and
  `decrypt_ige(data, key, iv)` with cryptg 0.6.0 signatures, raising
  `ValueError` on bad lengths. `src/__init__.py:7-10` registers it as
  `sys.modules["cryptg"]` before its first Telethon import and only when a
  real `cryptg` is not importable. Telethon then selects it at
  refs/telethon/telethon/crypto/aes.py:17-26 and calls it at :40 and :81.
- Rejected: shipping a top-level `cryptg` module inside the wheel. It collides
  file-for-file with the real cryptg distribution and pip would silently let
  the last install win.
- Limit: if the user imports `telethon` before `opentele2`, Telethon keeps its
  own choice. This is documented, not patched. `factorize_pq_pair` is not
  exposed because Telethon does not call it (grep of refs/telethon finds only
  the two IGE calls).

### D4. Node: one npm package with mtcute helpers
- Chosen: npm package `opentele2` with napi-rs prebuilt binaries as
  `optionalDependencies` (`@opentele2/core-<triple>`), plus TypeScript helpers
  under `opentele2/mtcute`: string session v3 encode/decode (format of
  refs/mtcute-master/packages/core/src/highlevel/utils/string-session.ts:23-60),
  `initConnectionOptions` from a generated device (deviceModel, systemVersion,
  appVersion, langPack, params), and a crypto provider that wraps mtcute's
  default provider and overrides only `createAesIge`
  (refs/mtcute-master/packages/core/src/utils/crypto/abstract.ts:36).
  `@mtcute/core` is an optional peer dependency.
- Rejected: a separate `@opentele2/mtcute` package. Two packages for one small
  helper module is premature structure (YAGNI); the optional peer keeps
  non-mtcute users free of it.
- Rejected: routing tdata through `@mtcute/convert`, which refuses tdata
  versions above 5008003 without `ignoreVersion`
  (refs/mtcute-master/packages/convert/src/tdesktop/tdata.ts:18,178) while 1.5.0
  writes 7003001 (src/utils.py:10).
- Node-API level: 4, the @napi-rs/cli 3.10.8 default; `engines.node >=18`.
  Raising the level needs a feature that requires it.
- Initial targets: win32 x64/arm64, darwin x64/arm64, linux gnu and musl
  x64/arm64. ia32, armv7, android, freebsd and wasm32-wasip1-threads from the
  napi-rs template are deferred until a user asks (YAGNI).

### D5. grammers integration
- Chosen: `crates/opentele2-grammers` depends on core and
  `grammers-session`/`grammers-client` 0.11.0, and offers
  `session_data(&Account) -> SessionData` (home_dc plus
  `dc_options[id].auth_key`) and `connection_params(&Device) -> ConnectionParams`
  (device_model, system_version, app_version, system_lang_code, lang_code).
  Core itself keeps a plain grammers-shaped struct so it never depends on
  grammers.
- lang_pack and params: grammers hardcodes `lang_pack: ""` and `params: None`
  (refs/grammers mtsender sender_pool.rs:432-446, 0.10 source). Chosen: a
  documented fingerprint gap in the crate docs plus an upstream pull request
  that adds both fields to ConnectionParams. Rejected: a vendored or forked
  grammers, which makes us the maintainer of a network stack (KISS).

### D6. Parallelism
- Chosen: rayon 1.12 behind a core feature `parallel`, enabled by both
  bindings. It is used only for batch entry points (`load_many`,
  `convert_many`) that iterate independent tdata folders.
- Not parallel: accounts inside one folder. The expensive step is the one
  passcode KDF per folder (Argon2id m=65536 t=8 p=1, PBKDF2 100000); per-account
  MTP blobs are cheap AES. Argon2 runs with p=1, so there is nothing to split.
  The batch pool is capped so that threads x 64 MiB Argon2 memory stays bounded.
- Rule: Python calls run under `py.detach`; Node calls that do KDF or file IO
  are `AsyncTask`s on the libuv pool and return Promises. Per-packet IGE for
  mtcute stays synchronous because `IEncryptionScheme` is synchronous and the
  work is microseconds.

### D7. Errors
- Chosen: one `#[non_exhaustive] enum opentele2_core::Error` with a stable
  `code() -> &'static str` (for example `TDATA_WRONG_PASSCODE`). Variants map
  1:1 to the tdata exceptions in src/exception.py:96-196 (TFileNotFound,
  TDataInvalidMagic, TDataInvalidCheckSum, TDataBadDecryptKey,
  TDataWrongPasscode, TDataBadEncrypted/DecryptedDataSize, TDataBadConfigData,
  QDataStreamFailed, TDataReadMapDataFailed, TDataReadMapDataIncorrectPasscode,
  TDataAuthKeyNotFound, MaxAccountLimit, TDataSaveFailed).
- Python: the binding raises one `opentele2_core.CoreError(code, message)`;
  `opentele2` maps `code` to its `OpenTeleException` subclass in one table.
  Rejected: `create_exception!` classes in Rust, which would duplicate the
  hierarchy rooted at src/exception.py:43 (DRY).
- Node: `Error` objects with `code = "OT_" + code()`, typed as a string union
  in the `.d.ts`.

### D8. Tooling
- Rust: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`. MSRV is 1.89 (required by aes 0.9.3), declared as
  `rust-version` in the workspace and tested by a 1.89 CI job; it moves only when
  a dependency demands it, and only in a minor release.
- Python: `ruff check`, `ruff format --check`, `ty check`, `pytest`.
- Node: `tsc --noEmit` and `biome check`. Rejected: eslint plus prettier, two
  tools and configs for the job of one (KISS).

### D9. CI and release
- `test.yml` on push and pull_request: Rust gates on ubuntu, windows, macos;
  `maturin develop` plus pytest; `napi build` plus node tests; the 1.5.0
  compatibility job from the Compatibility section.
- `release-python.yml` and `release-node.yml` run only on version tags in the
  repository's existing bare form (`1.5.0`, so `[0-9]+.[0-9]+.[0-9]+*`). Build jobs
  use the `maturin generate-ci` matrix (manylinux x86_64/x86/aarch64/armv7/
  s390x/ppc64le, musllinux_1_2, windows x64/x86/arm64, macos-15-intel and
  macos-latest, plus cp314t) and the napi matrix of D4. Windows arm64 builds set
  `RUSTFLAGS=-Ctarget-feature=+aes` so `aes` uses hardware AES.
- Publish jobs are separate, `needs` all build jobs, run in protected
  environments `pypi` and `npm` with required reviewers, and use OIDC trusted
  publishing / npm provenance. No workflow publishes from a branch.

## Compatibility

Contract for 2.0.0 against 1.5.0:

1. Python public API unchanged: `TDesktop`, `TelegramClient`, `API`, `APIData`
   and every exception class in src/exception.py keep names, signatures and
   class hierarchy (`OpenTeleException` stays a `BaseException`, :43).
2. `Generate(unique_id)` is byte-identical to 1.5.0. The hash is
   `int(sha1(str(uid)).hexdigest(), 16) % 10**12` (src/devices.py:105-108), so
   the core reduces the full 160-bit digest modulo 10^12; truncating to u64
   first is a silent break. Weighted lists are expanded in JSON order
   (src/devices.py:131-146), so catalogs are parsed with order preserved.
   `unique_id=None` keeps using OS randomness (src/devices.py:107).
3. The core generates device_model and system_version only. app_version and
   other fields from fetched versions stay host-side: fingerprint.py:147 fetches
   at import and rewrites API fields (src/api.py:454-476). Golden vectors are
   therefore generated with `OPENTELE_NO_FETCH=1` (src/version_fetcher.py:209).
   Web fingerprints (browserforge, src/devices.py:500) stay in Python and are
   out of the determinism contract.
4. tdata written by 2.0 is read by 1.5.0 (CI job installs `opentele2==1.5.0`
   from PyPI and reads 2.0 output) and by tdesktop 7.3.1: version 7003001
   (src/utils.py:10), key_data format 2, Argon2id write defaults unchanged
   (src/td/key_data.py:64-66). tdesktop readability is a manual release check.
5. Dropped dependencies: `TgCrypto-pyrofork` (src/td/storage.py:60,511-522 move
   to core IGE), `argon2-cffi` (src/td/key_data.py:18 moves to core Argon2id),
   `selectolax` (listed in pyproject.toml but imported nowhere under src/).
   `browserforge` stays the optional `web` extra; `telethon>=1.45.0` stays.

## Phases

Each slice touches at most five paths in at most two areas and has one gate.
Slice ids and outcomes are those recorded in docs/state/LEDGER.md.

| Slice | Content | Status | Gate |
|-------|---------|--------|------|
| OT-141 | Golden vectors from 1.5.0: Generate cases, crypto, TDF, sessions, 4 synthetic tdata folders | done | `python scripts/gen_core_vectors.py --check` |
| OT-142 | Workspace scaffold and the stable-coded `Error` enum | done | `cargo clippy --workspace --all-targets -- -D warnings` |
| OT-143 | `qt` stream and `tdf` container | done | `cargo test -p opentele2-core --test primitives` |
| OT-144 | `crypto` (grammers-crypto IGE, prepareAES_oldmtp, local envelope) and `kdf` | done | `cargo test -p opentele2-core --test crypto` |
| OT-145 | key_data, first attempt | blocked, redone as OT-147 | `cargo test -p opentele2-core --test key_data` |
| OT-146 | `TData::load`: accounts, MtpAuthorization, map, configs | done | `cargo test -p opentele2-core --test tdata_read` |
| OT-147 | key_data: legacy and 7.3 v2 trailer, open_local_key, wraps | done | `cargo test -p opentele2-core --test key_data` |
| OT-148 | `TData::new`/`save`, byte-identical to 1.5.0 | done | `cargo test -p opentele2-core --test tdata_write` |
| OT-149 | Session codecs: Telethon string, mtcute v3, grammers-shaped, 1.5.0 DC table | done | `cargo test -p opentele2-core --test session` |
| OT-150 | `devices`: embedded catalogs, deterministic Generate | done | `cargo test -p opentele2-core --test devices` |
| OT-151 | `api`: official client profiles, offline versions | done | `cargo test -p opentele2-core --test api` |
| OT-152 | `batch` on a dedicated rayon pool (`parallel` feature) | done | `cargo test -p opentele2-core --test batch` |
| OT-153 | Dev profile optimises the hashing crates | done | `cargo test --workspace` |
| OT-154 | Python binding `opentele2-core`: crypto, cryptg, TData, load_many, sessions, fingerprints | done | `python -m pytest bindings/python/tests -q` |
| OT-155 | `opentele2` uses the core for IGE and KDFs; cryptg registration | done | library suite (`pytest tests -m "not live"`) |
| OT-156 | Catalog currency test narrowing | done | `python -m pytest tests/test_device_catalog_currency.py -q` |
| OT-157 | Library tests 3.8-safe | done | library suite |
| OT-158 | Pure package floor 3.8, dependency on opentele2-core | partial, settled by OT-160 | library suite on Python 3.8 |
| OT-159 | Remaining 3.8 test failures | partial (gate defect), settled by OT-160 | library suite on Python 3.8 |
| OT-160 | Library suite green on Python 3.8.20 | done | library suite on Python 3.8 |
| OT-161 | Node binding, npm `opentele2`, `opentele2/mtcute` helpers | done | `node --test bindings/node/__test__` |
| OT-162 | `opentele2-grammers` | done | `cargo test -p opentele2-grammers` |
| OT-163 | test.yml with every Rust, Python and Node gate | open: blocked on the maintainer, the kernel protects .github | workflow file check |
| OT-164 | Release workflows with protected environments | open: blocked, after OT-163 | workflow file check |
| none | Python tdata parsing moves from src/td onto the core `TData` | open | none yet |
| none | src/devices/ removed, Python reads the core catalogs | open | none yet |

## Known gaps

- Device catalogs exist twice: crates/opentele2-core/data/devices/ (embedded
  in the core) and src/devices/ (read by src/devices.py:30).
  crates/opentele2-core/tests/devices.rs:188-196 asserts the two are identical
  until src/devices/ goes away.
- Python tdata parsing still runs in Python (src/td) above the core
  primitives: src/td/storage.py:48-49,471,480 and src/td/key_data.py:168 call
  `opentele2_core` for AES-IGE, local keys and Argon2id only.
- Session endpoints always come from the built-in DC table. With performance
  mode off, 1.5.0 reads them from the account's stored MTP config, which the
  core does not parse (crates/opentele2-core/src/session/mod.rs:9-13).
- grammers builds `initConnection` with `lang_pack: ""`, `proxy: None` and
  `params: None` (refs/grammers grammers-mtsender/src/sender_pool.rs:440-443,
  0.10 source); crates/opentele2-grammers/src/lib.rs:16-32 records the
  lang_pack and params gap for 0.11 and the upstream change that closes it.
- .github/workflows/ is not written: D9 is designed, not implemented
  (OT-163, OT-164).

## Open questions

- Q1 (resolved): the pure package floor is 3.8, see D2.
- Q2 (resolved): PyO3 0.29 `abi3t-py315` covers only CPython 3.15+, so cp314t
  wheels stay; see D2.
- Q3 (resolved in OT-162): grammers 0.11 still hardcodes `lang_pack`/`params`;
  see Known gaps and crates/opentele2-grammers/src/lib.rs:16-32.
- Q4. Does grammers-session 0.11.0 pull async dependencies? Irrelevant to core
  (D5 keeps it out), relevant to the optional crate's footprint.
- Q5. Minimum Node version supported by mtcute 0.32.5; `engines >=18` may need
  to rise to match it.
- Q6. Measured gain of the native `createAesIge` over mtcute's default
  provider; if none, the override is dropped (YAGNI). Benchmark in OT-156.
- Q7. Exact RustCrypto versions for pbkdf2, sha1, sha2, md-5, argon2, scrypt
  are pinned in OT-142, not here.
