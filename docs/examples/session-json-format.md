# Session JSON Format

The `.session + .json` format is a portable way to store Telegram sessions. The `.session` file contains the Telethon SQLite session (auth keys, DC info), while the `.json` sidecar contains all API and device fingerprint metadata. This format makes sessions easy to transfer, back up, and manage across tools.

opentele2 supports both **importing** (reading `.session + .json` into a working client) and **exporting** (saving any client to `.session + .json`).

## Preparing
- You need both a `.session` file and a matching `.json` file with the same base name.
- We need to import these things:
    ```python
    from opentele2.td import TDesktop
    from opentele2.tl import TelegramClient
    from opentele2.api import API, APIData, UseCurrentSession, CreateNewSession
    import asyncio
    ```
- And we need to put the main code inside an async function:
    ```python
    async def main():
        # PUT EXAMPLE CODE HERE

    asyncio.run(main())
    ```

## JSON file structure

The `.json` file contains API credentials and device fingerprint data:

```json
{
    "app_id": 2040,
    "app_hash": "b18441a1ff607e10a989891a5462e627",
    "device": "Desktop",
    "sdk": "Windows 11",
    "app_version": "5.12.3 x64",
    "system_lang_pack": "en-US",
    "system_lang_code": "en-US",
    "lang_pack": "tdesktop",
    "lang_code": "en",
    "session_file": "my_account",
    "twoFA": null,
    "id": 123456789,
    "phone": "+1234567890",
    "username": "myuser",
    "is_premium": false
}
```

### Field mapping

| JSON field | APIData field | Description |
|---|---|---|
| `app_id` | `api_id` | Telegram API ID |
| `app_hash` | `api_hash` | Telegram API hash |
| `device` | `device_model` | Device name or User-Agent |
| `sdk` | `system_version` | OS / SDK version |
| `app_version` | `app_version` | Application version string |
| `system_lang_pack` | `system_lang_code` | System language with region |
| `lang_pack` | `lang_pack` | Client lang pack identifier |
| `lang_code` | `lang_code` | UI language code |
| `session_file` | — | Base filename (no extension) |

## Importing a session

### Using [TelegramClient][TelegramClient]

```python
# Import from .session + .json (pass path with or without extension)
client = await TelegramClient.FromSessionJson("path/to/my_account")

# The client now has the auth key, DC info, and API fingerprint loaded.
# Connect to Telegram:
await client.connect()
await client.PrintSessions()
```

You can also pass the `.session` extension explicitly:
```python
client = await TelegramClient.FromSessionJson("path/to/my_account.session")
```

Or specify the JSON path separately:
```python
client = await TelegramClient.FromSessionJson(
    "path/to/my_account",
    json_path="path/to/custom_config.json"
)
```

### Using [TDesktop][TDesktop]

```python
# Import as TDesktop (converts internally via TelegramClient)
tdesk = await TDesktop.FromSessionJson("path/to/my_account")
```

## Exporting a session

### From [TelegramClient][TelegramClient]

```python
# Save current session to .session + .json files
session_path, json_path = await client.SaveSessionJson("output/my_account")
# Creates: output/my_account.session + output/my_account.json
```

If the client is connected, you can also fetch live user info:
```python
session_path, json_path = await client.SaveSessionJson(
    "output/my_account",
    fetch_user_info=True  # populates id, phone, username, is_premium
)
```

### From [TDesktop][TDesktop]

```python
# Load from tdata, then export to .session + .json
tdesk = TDesktop(r"C:\Users\<username>\AppData\Roaming\Telegram Desktop\tdata")
session_path, json_path = await tdesk.SaveSessionJson("output/my_account")
```

## Converting between formats

### tdata to .session + .json

```python
from opentele2.td import TDesktop
from opentele2.api import UseCurrentSession
import asyncio

async def main():
    # Load tdata
    tdesk = TDesktop(r"C:\path\to\tdata")
    assert tdesk.isLoaded()

    # Export to .session + .json
    session_path, json_path = await tdesk.SaveSessionJson("output/my_account")
    print(f"Exported: {session_path}, {json_path}")

asyncio.run(main())
```

### .session + .json to tdata

```python
from opentele2.td import TDesktop
from opentele2.tl import TelegramClient
from opentele2.api import UseCurrentSession
import asyncio

async def main():
    # Import from .session + .json
    client = await TelegramClient.FromSessionJson("my_account")

    # Convert to TDesktop and save as tdata
    tdesk = await client.ToTDesktop(flag=UseCurrentSession)
    tdesk.SaveTData("output/tdata")

asyncio.run(main())
```

### .session + .json round-trip

```python
from opentele2.tl import TelegramClient
import asyncio

async def main():
    # Import
    client = await TelegramClient.FromSessionJson("original/my_account")

    # Export to a new location
    await client.SaveSessionJson("backup/my_account")

    # Re-import from backup (auth key and DC preserved exactly)
    client2 = await TelegramClient.FromSessionJson("backup/my_account")

asyncio.run(main())
```

## Using APIData helpers directly

You can also work with the JSON format programmatically:

```python
from opentele2.api import APIData
import json

# Parse JSON into APIData
with open("my_account.json") as f:
    data = json.load(f)

api = APIData.from_json(data)
print(api.api_id, api.device_model, api.lang_pack)

# Serialize APIData back to JSON
exported = api.to_json(extra={"id": 12345, "session_file": "my_account"})
with open("exported.json", "w") as f:
    json.dump(exported, f, indent=2)
```

[TelegramClient]: https://opentele2.readthedocs.io/en/latest/documentation/telethon/telegramclient/#class-telegramclient
[TDesktop]: https://opentele2.readthedocs.io/en/latest/documentation/telegram-desktop/tdesktop/#class-tdesktop
