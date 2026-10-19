# opentele2 2.0.0 Architecture

Status: accepted for branch `2.0.0` (from tag `1.5.0`). This document records
the Rust core and binding architecture. Facts cite `path:line` in this
repository or a pinned version number; anything not established is listed
under Open questions rather than assumed.

## Layout

```
Cargo.toml                    workspace root: members, shared deps, rust-version
crates/opentele2-core/        pure core: no async, no network, no FFI
  data/devices/*.json         device catalogs, single source (moved from src/devices/)
  tests/vectors/              golden vectors produced by 1.5.0 (OT-141)
crates/opentele2-grammers/    optional: core -> grammers SessionData + ConnectionParams
bindings/python/              PyO3 cdylib, maturin, distribution `opentele2-core`
bindings/node/                napi-rs cdylib + TypeScript, npm package `opentele2`
src/                          pure-Python `opentele2` (hatchling, src -> opentele2)
scripts/gen_core_vectors.py   writes crates/opentele2-core/tests/vectors/
.github/workflows/            test.yml, release-python.yml, release-node.yml
```

The core crate owns, as modules: `qt` (big-endian QDataStream), `tdf` (TDF$
container and md5 trailer), `crypto` (AES-256-IGE, `prepareAES_oldmtp`,
PBKDF2-SHA512 100000/1, legacy PBKDF2-SHA1 4000/4, Argon2id, scrypt read-only),
`tdata` (key_data with the 0x4B443200 v2 trailer, map, MtpAuthorization,
multi-account read and write), `session` (Telethon string, mtcute string v3,
a plain grammers-shaped SessionData), `devices` (catalogs and deterministic
Generate) and `error`.

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
  `ValueError` on bad lengths. `src/__init__.py` registers it with
  `sys.modules.setdefault("cryptg", ...)` before its first Telethon import and
  only when a real `cryptg` is not importable. Telethon then selects it at
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

| Slice  | Content | Paths (areas) | Gate |
|--------|---------|---------------|------|
| OT-141 | Golden vectors from 1.5.0: Generate per platform, IGE, KDFs, TDF, key_data, sessions, plus synthetic tdata folders (no passcode, passcode) written by 1.5.0 with a fixed byte source | scripts/gen_core_vectors.py, crates/opentele2-core/tests/vectors/ (scripts, crate) | `python scripts/gen_core_vectors.py --check` (the script sets OPENTELE_NO_FETCH itself) |
| OT-142 | Workspace scaffold, MSRV, rustfmt | Cargo.toml, rustfmt.toml, crates/opentele2-core/{Cargo.toml,src/lib.rs} | `cargo test --workspace` |
| OT-143 | `error` enum and codes | crates/opentele2-core/src/error.rs, lib.rs | `cargo clippy -p opentele2-core -- -D warnings` |
| OT-144 | `qt` stream and `tdf` container | crates/opentele2-core/src/{qt.rs,tdf.rs}, tests/tdf.rs | `cargo test -p opentele2-core` |
| OT-145 | `crypto`: IGE, prepareAES_oldmtp, PBKDF2, Argon2id, scrypt read | crates/opentele2-core/src/crypto/, tests/crypto.rs | `cargo test -p opentele2-core` |
| OT-146 | key_data v2, map, MtpAuthorization read/write | crates/opentele2-core/src/tdata/, tests/tdata.rs | `cargo test -p opentele2-core` |
| OT-147 | Multi-account tdata against the synthetic OT-141 folders (tests/data holds real accounts, is git-ignored and never used by CI) | crates/opentele2-core/src/tdata/domain.rs, tests/domain.rs | `cargo test -p opentele2-core` |
| OT-148 | Session codecs: Telethon string, mtcute v3, grammers-shaped | crates/opentele2-core/src/session/, tests/session.rs | `cargo test -p opentele2-core` |
| OT-149 | Catalog move and deterministic Generate | crates/opentele2-core/{data/devices/,src/devices.rs,tests/devices.rs} | `cargo test -p opentele2-core devices` |
| OT-150 | `parallel` feature, batch load/convert | crates/opentele2-core/{Cargo.toml,src/batch.rs,tests/batch.rs} | `cargo test -p opentele2-core --features parallel` |
| OT-151 | Python binding: abi3-py38, detach, CoreError, cryptg module | bindings/python/{Cargo.toml,pyproject.toml,src/lib.rs,tests/} | `maturin develop -m bindings/python/Cargo.toml && pytest bindings/python/tests` |
| OT-152 | `opentele2` uses core; drop tgcrypto, argon2-cffi, selectolax | src/td/storage.py, src/td/key_data.py, pyproject.toml (src, packaging) | `pytest tests` |
| OT-153 | Exception mapping and cryptg registration | src/exception.py, src/__init__.py, tests/test_core_bridge.py | `pytest tests/test_core_bridge.py` |
| OT-154 | Catalogs read from core; Python Generate matches vectors | src/devices.py, src/devices/ (removed), tests/test_core_vectors.py | `pytest tests/test_core_vectors.py` |
| OT-154b | Pure package floor 3.8: typing_extensions, no runtime 3.9+/3.10+ syntax, CI on 3.8 | src/utils.py, src/qt_compat.py, src/tl/session_io.py, pyproject.toml (src, packaging) | `pytest tests` on Python 3.8 |
| OT-155 | Node binding and npm layout | bindings/node/{Cargo.toml,package.json,src/lib.rs,index.d.ts,test/} | `napi build && node --test bindings/node/test` |
| OT-156 | mtcute helpers | bindings/node/src/mtcute/, bindings/node/test/mtcute.test.ts | `tsc --noEmit && node --test` |
| OT-157 | grammers crate | crates/opentele2-grammers/{Cargo.toml,src/lib.rs,tests/} | `cargo test -p opentele2-grammers` |
| OT-158 | test.yml, including 1.5.0 compatibility job | .github/workflows/test.yml, tests/compat_150.py | workflow green on the PR |
| OT-159 | Release workflows with protected environments | .github/workflows/{release-python.yml,release-node.yml} | dry run on a `v2.0.0-rc1` tag without publish approval |
| OT-160 | Version 2.0.0, README install notes | pyproject.toml, bindings/*/ manifests, README.md | all CI gates on tag `v2.0.0` |

## Open questions

- Q1 (resolved): the pure package floor is 3.8, see D2.
- Q2 (resolved): PyO3 0.29 `abi3t-py315` covers only CPython 3.15+, so cp314t
  wheels stay; see D2.
- Q3. Do grammers 0.11.0 crates still hardcode `lang_pack`/`params` and keep the
  0.10 SessionData shape? refs/grammers is 0.10 source; verify before OT-157.
- Q4. Does grammers-session 0.11.0 pull async dependencies? Irrelevant to core
  (D5 keeps it out), relevant to the optional crate's footprint.
- Q5. Minimum Node version supported by mtcute 0.32.5; `engines >=18` may need
  to rise to match it.
- Q6. Measured gain of the native `createAesIge` over mtcute's default
  provider; if none, the override is dropped (YAGNI). Benchmark in OT-156.
- Q7. Exact RustCrypto versions for pbkdf2, sha1, sha2, md-5, argon2, scrypt
  are pinned in OT-142, not here.
