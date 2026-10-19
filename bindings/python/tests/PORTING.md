# Porting table: 1.5.0 library tests

Every 1.5.0 library test file (`tests/*.py` of the 1.5.0 tree, without the
agent-kernel tests `test_agentctl`, `test_audit_remediation`,
`test_control_plane`, `test_guard_bypasses`, `test_install`,
`test_market_routing` and `test_model_routing`) with the files of
`bindings/python/tests` its public assertions now live in, or the reason it
has none. `test_porting.py` checks the table against the literal list of
1.5.0 files and checks that every file named in the second column exists.

Removal and M2 below refer to the sections of ARCHITECTURE.md.

| 1.5.0 file | Ported to | Notes |
|---|---|---|
| `__init__.py` | none | Empty package marker; this directory is a pytest rootdir with `conftest.py` and needs none (Removal: delete). |
| `tdata_test.py` | `test_td.py`, `test_conversions.py`, `test_tl.py`, `test_api.py` | The debug-mode cases test the `debug` module, which Removal drops; `test_entry_point` needs a real account and keeps the `live` marker in `test_conversions.py`. |
| `test_android_devices.py` | `test_devices.py` | Catalog-file cases (`deviceList`, `__gen__`) are asserted on the devices `RandomDevice` picks; the catalog itself is tested in crates/opentele2-core/tests/devices.rs. |
| `test_api_typing.py` | `test_api.py` | |
| `test_client_kwargs.py` | `test_client_kwargs.py` | |
| `test_core_bridge.py` | `test_core.py`, `test_cryptg_registration.py` | Removal: core tests + frozen vectors; the cryptg registration and the encrypt_local vectors are asserted on `opentele2._native`. |
| `test_desktop_devices.py` | `test_devices.py` | Model x version weights are a catalog property, tested in crates/opentele2-core/tests/devices.rs. |
| `test_desktop_version.py` | `test_configs.py`, `test_api.py`, `test_versions_sync.py` | |
| `test_device_catalog_currency.py` | `test_devices.py` | Removal: split; the pure catalog cases moved to crates/opentele2-core/tests/devices.rs. |
| `test_fingerprints.py` | `test_api.py`, `test_fingerprint.py`, `test_devices.py`, `test_session_io.py`, `test_versions_sync.py` | Web stat-weight and `deviceList` cases inspected browserforge generation, which M2 drops; the cases over the real accounts in 1.5.0 `tests/data` run on the vector folders of crates/opentele2-core/tests/vectors; live fetches keep the `live` marker. |
| `test_full.py` | `test_api.py`, `test_devices.py`, `test_fingerprint.py`, `test_tl.py`, `test_td.py`, `test_conversions.py`, `test_session_io.py`, `test_core.py` | `WebBrowserDevice.BROWSER_WEIGHTS`, `deviceList` and `__gen__` belong to the browserforge generator M2 drops; `TestStorageIgeOnCore` tested the Python `Storage`, which Removal deletes (AES-IGE is asserted in `test_core.py`); the live classes keep the `live` marker. |
| `test_init_connection.py` | `test_init_connection.py`, `test_fingerprint.py`, `test_devices.py` | The Apple-Silicon-only mac catalog check is the `_MAC_MODEL` pattern of `test_devices.py`. |
| `test_ios_devices.py` | `test_devices.py` | |
| `test_mac_devices.py` | `test_devices.py`, `test_api.py` | |
| `test_no_suppressions.py` | `test_no_suppressions.py` | Removal: retarget; scans bindings/python/python and bindings/python/tests. |
| `test_platform_versions.py` | `test_versions_sync.py` | |
| `test_session_io.py` | `test_session_io.py`, `test_conversions.py` | `_select_endpoint_address` was a private helper over `td.MTP`; the endpoint choice is the core's, asserted in `test_conversions.py`. |
| `test_tdata_keydata.py` | `test_core.py`, `test_tdata_surface.py`, `test_td.py` | Removal: delete; `td.key_data` is core `kdf`/`tdata`, tested on the frozen vectors. |
| `test_tdata_localkey.py` | `test_core.py`, `test_tdata_surface.py` | Removal: delete; core `kdf` + frozen vectors. |
| `test_tdata_mapdata.py` | `test_td.py`, `test_tdata_parity.py` | Removal: delete; `td.MapData` is not kept as a public name. |
| `test_tdata_mtp.py` | `test_tdata_parity.py`, `test_conversions.py` | Removal: delete; `td.MTP` is not kept as a public name; MTP config and endpoints come from `_native`. |
| `test_tdata_readfile.py` | `test_core.py`, `test_td.py`, `test_configs.py` | Removal: delete; TDF reading is core `tdf`. |
| `test_tdata_storage.py` | `test_core.py`, `test_td.py` | Removal: delete; `td.Storage` is not kept as a public name. |
| `test_version_fetcher.py` | `test_versions_sync.py` | The HTML parsers moved with the fetchers to crates/opentele2-versions/tests (D10). |
| `test_version_layer.py` | `test_configs.py`, `test_tl.py` | The TDF write/read cases used `td.Storage`; they are asserted on folders `_native` writes. |
| `test_web_devices.py` | `test_devices.py` | The live-window shift of browserforge versions drops with M2. |
