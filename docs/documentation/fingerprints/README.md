<!-- vim: syntax=Markdown -->

# Fingerprints & Consistency

When connecting to Telegram's servers via the [initConnection](https://core.telegram.org/method/initConnection) method, every client sends a set of parameters that identify the device and application. These parameters form the session's **fingerprint**:

| Parameter | Description | Example |
| :--- | :--- | :--- |
| `api_id` | Application identifier | `2496` |
| `api_hash` | Application secret | `"8da85b0d5bfe62527e5b244c209159c3"` |
| `device_model` | Device or User-Agent string | `"Samsung Galaxy S24 Ultra"` |
| `system_version` | OS version | `"SDK 35"` |
| `app_version` | Client version | `"12.3.0"` |
| `system_lang_code` | OS locale | `"en-US"` |
| `lang_code` | Client language | `"en"` |
| `lang_pack` | Language pack identifier | `"android"` |

Telegram uses these values to identify sessions. If the parameters look inconsistent (e.g. an Android `lang_pack` with an iOS `device_model`), the account may be flagged.

**opentele2** provides tools to keep fingerprints realistic and internally consistent.

## Why Fingerprints Matter

According to [Telegram TOS](https://core.telegram.org/api/obtaining_api_id#using-the-api-id), all accounts that sign up or log in using **unofficial** Telegram API clients are automatically put under observation. opentele2 uses official `api_id`/`api_hash` values and the `lang_pack` parameter (which is restricted to official apps) so that sessions are indistinguishable from real official clients.

However, using an official `api_id` alone is not enough. The remaining fingerprint fields must also be realistic:

- **`device_model`** should match real devices for mobile APIs, or a valid User-Agent for web APIs.
- **`system_version`** should correspond to OS versions that the device actually ships with.
- **`app_version`** should match a version the official client has released.
- **`lang_pack`** must match the platform (`"android"`, `"ios"`, `"tdesktop"`, `"macos"`, or `""` for web).

## Generating Realistic Fingerprints

Every API template in opentele2 supports `Generate()` to create randomized but realistic device info.

### Mobile & Desktop

```python
from opentele2.api import API

# Android — random real device model + SDK version
api = API.TelegramAndroid.Generate()
# e.g. device_model="Samsung SM-A750FN", system_version="SDK 24"

# iOS — random iPhone model + iOS version
api = API.TelegramIOS.Generate()
# e.g. device_model="iPhone 16 Pro Max", system_version="18.2"

# Desktop — random desktop hardware + OS version
api = API.TelegramDesktop.Generate()
# e.g. device_model="ASUS All Series", system_version="Windows 11"

# macOS — random Mac model + macOS version
api = API.TelegramMacOS.Generate()
# e.g. device_model="MacBook Pro", system_version="macOS 15.2"
```

### Web Clients (Browser Fingerprints)

Web APIs (`TelegramWeb_Z`, `TelegramWeb_A`, `TelegramWeb_K`, `Webogram`) now support fingerprint generation using the [browserforge](https://github.com/nicegamer7/browserforge) library. This generates realistic browser User-Agent strings as the `device_model`.

???+ info "Install browserforge"
    Browser fingerprint generation requires the `browserforge` package:
    ```
    pip install browserforge
    ```
    Or install opentele2 with the web extra:
    ```
    pip install opentele2[web]
    ```

```python
from opentele2.api import API

# Web Z — random User-Agent + OS name as system_version
api = API.TelegramWeb_Z.Generate()
# e.g. device_model="Mozilla/5.0 (Windows NT 10.0; ...) Chrome/145.0.0.0 Safari/537.36"
#      system_version="Windows"

# Web A — same behavior as Web Z
api = API.TelegramWeb_A.Generate()
# e.g. device_model="Mozilla/5.0 (Macintosh; ...) Chrome/144.0.0.0 Safari/537.36"
#      system_version="macOS"

# Web K — random User-Agent + navigator.platform as system_version
api = API.TelegramWeb_K.Generate()
# e.g. device_model="Mozilla/5.0 (Windows NT 10.0; ...) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"
#      system_version="Win32"

# Webogram (legacy) — same style as Web K
api = API.Webogram.Generate()
```

#### How Web Fingerprints Work

The web client fingerprint system:

1. **Fetches the latest stable Chrome version** from Google's official API to keep browser version ranges current.
2. **Generates diverse User-Agent strings** for Chrome, Edge, and Firefox on Windows and macOS using browserforge.
3. **Derives `system_version`** from the User-Agent:
    - **Web Z / Web A**: Uses the OS name (e.g. `"Windows"`, `"macOS"`, `"Linux"`) — matching how [telegram-tt](https://github.com/AJaxy/telegram-tt) sends it.
    - **Web K / Webogram**: Uses `navigator.platform` (e.g. `"Win32"`, `"MacIntel"`) — matching how [tweb](https://github.com/morethanwords/tweb) sends it.

#### Web Z vs Web A vs Web K

| Client | `system_version` style | `app_version` | `lang_pack` |
| :--- | :--- | :--- | :--- |
| Web Z | OS name (`"Windows"`) | `"5.0.0 Z"` | `""` |
| Web A | OS name (`"macOS"`) | `"5.0.0 A"` | `""` |
| Web K | `navigator.platform` (`"Win32"`) | `"1.4.2 K"` | `"macos"` |
| Webogram | `navigator.platform` (`"Win32"`) | `"0.7.0"` | `""` |

### Deterministic Generation with `unique_id`

All `Generate()` calls accept an optional `unique_id` parameter. When provided, the same `unique_id` always produces the same device data:

```python
# Always produces the same fingerprint for this session
api = API.TelegramWeb_Z.Generate(unique_id="my_session_1")

# Different unique_id = different fingerprint
api2 = API.TelegramWeb_Z.Generate(unique_id="my_session_2")

# No unique_id = random each time
api3 = API.TelegramWeb_Z.Generate()
```

This is useful when you need consistent device info across restarts for the same session.

---

## Fingerprint Validation

opentele2 includes a validation system that checks `initConnection` parameters for consistency issues. This is provided by the `FingerprintConfig` class.

```python
from opentele2.fingerprint import FingerprintConfig, StrictMode, validate_init_connection_params
```

### Manual Validation

You can validate parameters directly:

```python
from opentele2.fingerprint import validate_init_connection_params

issues = validate_init_connection_params(
    api_id=2496,
    device_model="Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
    system_version="Windows",
    app_version="5.0.0 Z",
    system_lang_code="en-US",
    lang_pack="",
    lang_code="en",
)

if issues:
    for issue in issues:
        print(f"  - {issue}")
else:
    print("All checks passed")
```

The validator checks:

- **`lang_pack`** is a known official value (`"android"`, `"ios"`, `"tdesktop"`, `"macos"`, or `""`)
- **`lang_code`** is a valid language tag
- **`system_lang_code`** includes a region for mobile clients (e.g. `"en-US"` not `"en"`)
- **No empty strings** in `device_model`, `system_version`, or `app_version`

With `strict=True`, additional checks are performed:

- `api_id` matches the expected value for the `lang_pack`
- `app_version` major version matches the latest known official release

### Strict Mode Configuration

```python
from opentele2.fingerprint import FingerprintConfig, StrictMode

# Warn on issues (default)
config = FingerprintConfig(strict_mode=StrictMode.WARN)

# Raise exceptions on any inconsistency
config = FingerprintConfig(strict_mode=StrictMode.STRICT)

# Disable all checks
config = FingerprintConfig(strict_mode=StrictMode.OFF)
```

| Mode | Behavior |
| :--- | :--- |
| `StrictMode.OFF` | No checks |
| `StrictMode.WARN` | Emit warnings for issues (default) |
| `StrictMode.STRICT` | Raise `ValueError` for any inconsistency |

---

## TL Layer Tracking

opentele2 tracks the current official Telegram schema layer and compares it with the layer used by the installed Telethon version. If they diverge too far, a warning is emitted.

```python
from opentele2.fingerprint import get_recommended_layer, LAYER

# The latest official schema layer
print(LAYER)  # e.g. 214

# The layer that will be used (from Telethon)
print(get_recommended_layer())
```

If the difference between the Telethon layer and the official schema layer exceeds 15, a warning is emitted suggesting an update.

---

## Post-Login Consistency Checks

After connecting and authenticating, official Telegram clients make several API calls that the server expects. Skipping them can look suspicious. The `ConsistencyChecker` class mimics this behavior.

```python
from opentele2.tl import TelegramClient
from opentele2.api import API
from opentele2.consistency import ConsistencyChecker

api = API.TelegramWeb_Z.Generate()
client = TelegramClient("session.session", api=api)
await client.connect()

checker = ConsistencyChecker(client)
report = await checker.run_all()

print(report.summary)
# Consistency: 6/6 checks passed
#   [OK] get_config: Config OK (DC 2)
#   [OK] current_session: api_id=2496, official=True, ...
#   [OK] layer_match: Telethon layer=198, official schema layer=214, diff=16
#   [OK] lang_pack: lang_pack is empty (web client mode)
#   [OK] app_update: No update available (app_version accepted)
#   [OK] terms_of_service: ToS check OK
```

### What Gets Checked

| Check | What it does |
| :--- | :--- |
| `get_config` | Calls `help.getConfig` — every official client does this on connect |
| `current_session` | Verifies the session is seen as an official app via `account.getAuthorizations` |
| `layer_match` | Checks if the Telethon TL layer is close to the official schema layer |
| `lang_pack` | Calls `langpack.getLanguages` to verify the `lang_pack` value is accepted |
| `app_update` | Calls `help.getAppUpdate` — official clients do this periodically |
| `terms_of_service` | Calls `help.getTermsOfServiceUpdate` — official clients check this |

All checks are **read-only** and safe to call. They are the same requests that official clients make routinely.

### Auto-Warning

By default, `ConsistencyChecker` emits a warning if any check fails:

```python
# Disable auto-warning
checker = ConsistencyChecker(client, auto_warn=False)
report = await checker.run_all()

if not report.all_passed:
    # Handle manually
    for check in report.checks:
        if not check.passed:
            print(f"FAILED: {check.name} - {check.detail}")
```

---

## Transport Recommendations

Official Telegram clients use **obfuscated** transport by default. opentele2 provides helpers to use the recommended transport:

```python
from opentele2.fingerprint import TransportRecommendation

# Get the recommended connection class
ConnectionClass = TransportRecommendation.get_connection_class()

# Use it with TelegramClient
from opentele2.tl import TelegramClient
from opentele2.api import API

api = API.TelegramWeb_Z.Generate()
client = TelegramClient("session.session", api=api, connection=ConnectionClass)
```

Using plain `ConnectionTcpFull` without obfuscation is increasingly distinguishable from official clients.

---

## Platform Version Constants

opentele2 tracks the latest known versions of all official Telegram clients:

```python
from opentele2.fingerprint import get_platform_versions

pv = get_platform_versions()

print(pv.android_app_version)    # "12.3.0"
print(pv.ios_app_version)        # "12.3"
print(pv.desktop_app_version)    # "5.12.3"
print(pv.macos_app_version)      # "12.3"
print(pv.web_z_version)          # "5.0.0 Z"
print(pv.web_a_version)          # "5.0.0 A"
print(pv.web_k_version)          # "1.4.2 K"
print(pv.chrome_version)         # "144.0.0.0"
```

These constants are used by the strict validator and should be updated when Telegram releases new client versions.
