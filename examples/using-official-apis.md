# Using official APIs
This example will show you how to use Telethon with official APIs.

## Preparing
- We need to import these things:
    ```python
    from opentele2.td import TDesktop
    from opentele2.tl import TelegramClient
    from opentele2.api import API, UseCurrentSession, CreateNewSession
    import asyncio
    ```
- And we need to put the main code inside an async function:
    ```python
    async def main():
        # PUT EXAMPLE CODE HERE

    asyncio.run(main())
    ```

## Creating an [official API][APIDATA]
- Using the default built-in template for [Telegram Android API][AndroidAPI]:
    ```python
    api = API.TelegramAndroid
    ```
- [Randomize][APIGenerate] the API's device data:
    ```python
    # Randomize the device data
    api = API.TelegramAndroid.Generate()
    ```
- [Randomize][APIGenerate] the API's device data with a `unique_id`:
    ```python
    # unique_id can be anything
    # This will be used to ensure that it will generate the same data everytime.
    # If not set then the data will be randomized each time we runs it.
    api = API.TelegramAndroid.Generate(unique_id="telethon.session")
    ```
- All the built-in [API templates][APITemplates] available:
    ```python
    api = API.TelegramDesktop
    api = API.TelegramAndroid
    api = API.TelegramAndroidX
    api = API.TelegramIOS
    api = API.TelegramMacOS
    api = API.TelegramWeb_Z
    api = API.TelegramWeb_A
    api = API.TelegramWeb_K
    api = API.Webogram
    ```

## Creating a [TelegramClient][TelegramClient] using the API
- From an existing session:
    ```python
    client = TelegramClient("telethon.session", api=api)
    await client.connect()
    ```
- From a `tdata` folder:
    ```python
    tdataFolder = r"C:\Users\<username>\AppData\Roaming\Telegram Desktop\tdata"
    tdesk = TDesktop(tdataFolder)
    assert tdesk.isLoaded()

    client = TelegramClient.FromTDesktop(tdesk, session="telethon.session", flag=UseCurrentSession, api=api)

    await client.connect()
    ```

## Final result example
```python
from opentele2.td import TDesktop
from opentele2.tl import TelegramClient
from opentele2.api import API, UseCurrentSession
import asyncio

async def main():

    # Randomize the device data
    api = API.TelegramAndroid.Generate()

    client = TelegramClient("telethon.session", api=api)
    await client.connect()

asyncio.run(main())
```

## Extra: Demonstrate the behavior of unique_id
```python
def PrintAPI(api):
    print("    ", {"device_model": api.device_model, "system_version": api.system_version})

# Randomize using ["opentele", "library", "by", "DedInc"] as unique_ids
unique_string = "opentele library by DedInc"

for unique_id in unique_string.split(" "):
    print(f'\nunique_id = "{unique_id}"')

    for x in range(5):
        PrintAPI(API.TelegramAndroid.Generate(unique_id))

# Randomize without unique_id
print("\nNot using unique_id")
for x in range(5):
    PrintAPI(API.TelegramAndroid.Generate())
```

The result should look like this:
```python
unique_id = "opentele"
    {'device_model': 'Samsung SM-A750FN', 'system_version': 'SDK 24'}
    {'device_model': 'Samsung SM-A750FN', 'system_version': 'SDK 24'}
    {'device_model': 'Samsung SM-A750FN', 'system_version': 'SDK 24'}
    {'device_model': 'Samsung SM-A750FN', 'system_version': 'SDK 24'}
    {'device_model': 'Samsung SM-A750FN', 'system_version': 'SDK 24'}

unique_id = "library"
    {'device_model': 'Samsung SM-J100G', 'system_version': 'SDK 30'}
    {'device_model': 'Samsung SM-J100G', 'system_version': 'SDK 30'}
    {'device_model': 'Samsung SM-J100G', 'system_version': 'SDK 30'}
    {'device_model': 'Samsung SM-J100G', 'system_version': 'SDK 30'}
    {'device_model': 'Samsung SM-J100G', 'system_version': 'SDK 30'}

unique_id = "by"
    {'device_model': 'Samsung GT-S6800', 'system_version': 'SDK 26'}
    {'device_model': 'Samsung GT-S6800', 'system_version': 'SDK 26'}
    {'device_model': 'Samsung GT-S6800', 'system_version': 'SDK 26'}
    {'device_model': 'Samsung GT-S6800', 'system_version': 'SDK 26'}
    {'device_model': 'Samsung GT-S6800', 'system_version': 'SDK 26'}

unique_id = "DedInc"
    {'device_model': 'Samsung SM-N930VL', 'system_version': 'SDK 29'}
    {'device_model': 'Samsung SM-N930VL', 'system_version': 'SDK 29'}
    {'device_model': 'Samsung SM-N930VL', 'system_version': 'SDK 29'}
    {'device_model': 'Samsung SM-N930VL', 'system_version': 'SDK 29'}
    {'device_model': 'Samsung SM-N930VL', 'system_version': 'SDK 29'}

Not using unique_id
    {'device_model': 'Samsung SM-A705FN', 'system_version': 'SDK 29'}
    {'device_model': 'Samsung SM-T330', 'system_version': 'SDK 30'}
    {'device_model': 'Huawei HUAWEI C8860E', 'system_version': 'SDK 23'}
    {'device_model': 'Huawei HUAWEI C8860E', 'system_version': 'SDK 29'}
    {'device_model': 'Huawei HUAWEI Y625-U32', 'system_version': 'SDK 25'}
```

[APIDATA]: https://opentele2.readthedocs.io/en/latest/documentation/authorization/api/#class-apidata
[AndroidAPI]: https://opentele2.readthedocs.io/en/latest/documentation/authorization/api/#class-telegramandroid
[DesktopdAPI]: https://opentele2.readthedocs.io/en/latest/documentation/authorization/api/#class-telegramdesktop
[APITemplates]: https://opentele2.readthedocs.io/en/latest/documentation/authorization/api/#class-api
[APIGenerate]: https://opentele2.readthedocs.io/en/latest/documentation/authorization/api/#generate
[TelegramClient]: https://opentele2.readthedocs.io/en/latest/documentation/telethon/telegramclient/#class-telegramclient
[TDesktop]: https://opentele2.readthedocs.io/en/latest/documentation/telegram-desktop/tdesktop/#class-tdesktop

## Using web client APIs with browser fingerprints

Web client APIs (`TelegramWeb_Z`, `TelegramWeb_A`, `TelegramWeb_K`, `Webogram`) now support `Generate()` to randomize the browser User-Agent sent as `device_model`.

???+ info "Requires browserforge"
    Install with: `pip install browserforge` or `pip install opentele2[web]`

### Basic usage
```python
from opentele2.tl import TelegramClient
from opentele2.api import API
import asyncio

async def main():

    # Generate a random browser fingerprint for Web Z
    api = API.TelegramWeb_Z.Generate()

    client = TelegramClient("telethon.session", api=api)
    await client.connect()

asyncio.run(main())
```

### All web clients
```python
# Web Z — User-Agent as device_model, OS name as system_version
api = API.TelegramWeb_Z.Generate()
print(api.device_model)     # "Mozilla/5.0 (Windows NT 10.0; ...) Chrome/145.0.0.0 Safari/537.36"
print(api.system_version)   # "Windows"

# Web A — same behavior as Web Z
api = API.TelegramWeb_A.Generate()

# Web K — User-Agent as device_model, navigator.platform as system_version
api = API.TelegramWeb_K.Generate()
print(api.system_version)   # "Win32" or "MacIntel"

# Webogram (legacy) — same style as Web K
api = API.Webogram.Generate()
```

### Deterministic fingerprints with `unique_id`
```python
# Same unique_id always produces the same fingerprint
api1 = API.TelegramWeb_Z.Generate(unique_id="session_abc")
api2 = API.TelegramWeb_Z.Generate(unique_id="session_abc")
assert api1.device_model == api2.device_model  # True

# Different unique_id = different fingerprint
api3 = API.TelegramWeb_Z.Generate(unique_id="session_xyz")
# api3.device_model will differ from api1.device_model

# No unique_id = random each time
api4 = API.TelegramWeb_Z.Generate()
```

### Post-login consistency checks
After connecting, you can run consistency checks to verify that the session looks like a real official client:
```python
from opentele2.consistency import ConsistencyChecker

api = API.TelegramWeb_Z.Generate()
client = TelegramClient("telethon.session", api=api)
await client.connect()

checker = ConsistencyChecker(client)
report = await checker.run_all()
print(report.summary)
```

See [Fingerprints & Consistency][Fingerprints] for full documentation.

[Fingerprints]: https://opentele2.readthedocs.io/en/latest/documentation/fingerprints/