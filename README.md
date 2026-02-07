<!-- vim: syntax=Markdown -->

# opentele2

<p align="center">
<img src="https://raw.githubusercontent.com/DedInc/opentele2/main/opentele.png" alt="logo" width="180"/>
<br><br>
<a href="https://pypi.org/project/opentele2/"><img alt="pypi version" src="https://img.shields.io/pypi/v/opentele2?logo=pypi&logoColor=%232d93c1"/></a>
<a href="https://pypi.org/project/opentele2/"><img alt="pypi status" src="https://img.shields.io/pypi/status/opentele2?color=%2331c754&logo=pypi&logoColor=%232d93c1"/></a>
<a href="https://opentele2.readthedocs.io/"><img alt="documentation" src="https://img.shields.io/readthedocs/opentele2.svg?color=%2331c754&logo=readthedocs"/></a>
<a href="https://codecov.io/gh/DedInc/opentele2">
<img src="https://img.shields.io/codecov/c/github/DedInc/opentele2?color=%2331c754&label=codecov&logo=codecov&token=H2IWGEJ5LN"/>
</a>
<a href="https://github.com/DedInc/opentele2/actions/workflows/package.yml"><img alt="workflow tests" src="https://img.shields.io/github/workflow/status/DedInc/opentele2/package?logo=github&color=%2331c754"/></a>
<a href="https://github.com/DedInc/opentele2/issues"><img alt="issues" src="https://img.shields.io/github/issues/DedInc/opentele2?color=%2331c754&logo=github"/></a>
<a href="https://github.com/DedInc/opentele2/commits/main"><img alt="github last commit" src="https://img.shields.io/github/last-commit/DedInc/opentele2?color=%2331c754&logo=github"/></a>
<a href="https://github.com/DedInc/opentele2/commits/main"><img alt="github commits" src="https://img.shields.io/github/commit-activity/m/DedInc/opentele2?logo=github"/></a>
<a href="https://pypi.org/project/opentele2/"><img alt="pypi installs" src="https://img.shields.io/pypi/dm/opentele2?label=installs&logo=docusign&color=%2331c754"/></a>
<a href="https://en.wikipedia.org/wiki/MIT_License"><img alt="pypi license" src="https://img.shields.io/pypi/l/opentele2?color=%2331c754&logo=gitbook&logoColor=white"/></a>
<a href="https://github.com/psf/black"><img alt="code format" src="https://img.shields.io/badge/code%20style-black-000000.svg?logo=python&logoColor=%232d93c1"/></a>
</p>

<br>

A **Python Telegram API Library** for converting between **tdata** and **telethon** sessions, with built-in **official Telegram APIs**. [**Read the documentation**](https://opentele2.readthedocs.io/en/latest/documentation/telegram-desktop/tdesktop/).

# A New Era for opentele
**opentele2** is the rebirth of the original opentele project. The library is now actively maintained and under continued development. We are committed to keeping it up-to-date with the latest versions of Telegram Desktop and Telethon, fixing bugs, and adding new features.
<br>

## Features
- Convert [Telegram Desktop](https://github.com/telegramdesktop/tdesktop) **tdata** sessions to [telethon](https://github.com/LonamiWebs/Telethon) sessions and vice versa.
- Use **telethon** with [official APIs](#authorization) to avoid bot detection.
- Randomize [device info](https://opentele2.readthedocs.io/en/latest/documentation/authorization/api/#generate) using real data that recognized by Telegram server.

## Dependencies

- [telethon](https://github.com/LonamiWebs/Telethon) - Widely used Telegram's API library for Python.
- [tgcrypto](https://github.com/pyrogram/tgcrypto) - AES-256-IGE encryption to works with `tdata`.

## Installation
- Install from [PyPI](https://pypi.org/project/opentele2/):
```pip title="pip"
pip install --upgrade opentele2
```

## First Run
Load TDesktop from tdata folder and convert it to telethon, with a custom API:
```python
from opentele2.td import TDesktop
from opentele2.tl import TelegramClient
from opentele2.api import API, CreateNewSession, UseCurrentSession
import asyncio

async def main():
    
    # Load TDesktop client from tdata folder
    tdataFolder = r"C:\Users\<username>\AppData\Roaming\Telegram Desktop\tdata"
    tdesk = TDesktop(tdataFolder)

    # Using official iOS API with randomly generated device info
    # print(api) to see more
    api = API.TelegramIOS.Generate()

    # Convert TDesktop session to telethon client
    # CreateNewSession flag will use the current existing session to
    # authorize the new client by `Login via QR code`.
    client = await tdesk.ToTelethon("newSession.session", CreateNewSession, api)

    # Although Telegram Desktop doesn't let you authorize other
    # sessions via QR Code (or it doesn't have that feature),
    # it is still available across all platforms (APIs).

    # Connect and print all logged in devices
    await client.connect()
    await client.PrintSessions()

asyncio.run(main())
```

## Authorization
**opentele2** offers the ability to use **official APIs**, which are used by official apps. You can check that out [here](https://opentele2.readthedocs.io/en/latest/documentation/authorization/api/#class-api).
<br>

According to [Telegram TOS](https://core.telegram.org/api/obtaining_api_id#using-the-api-id): *all accounts that sign up or log in using unofficial Telegram API clients are automatically put under observation to avoid violations of the Terms of Service*.
<br>
<br>
It also uses the **[lang_pack](https://core.telegram.org/method/initConnection)** parameter, of which [telethon can't use](https://github.com/LonamiWebs/Telethon/blob/dd51aea4db90fd255a14e27192e221c70b45e105/telethon/_client/telegrambaseclient.py#L197) because it's for official apps only.
<br>
Therefore, **there are no differences** between using opentele2 and official apps, the server can't tell you apart.

## New features
- **PyQt5 Removed**: The **PyQt5** library has been removed. Its functionality has been reimplemented in **pure Python** to eliminate overhead and avoid installing unnecessary heavy dependencies.
- **New Fingerprints**: Some improvements of device information generation. The library now uses a new device database.


## Examples
The best way to learn anything is by looking at the examples. Am I right?

- Example on [readthedocs](https://opentele2.readthedocs.io/en/latest/examples/)
- Example on [github](./examples)

## Documentation [![documentation](https://readthedocs.org/projects/opentele2/badge/?version=latest&style=flat)](https://opentele2.readthedocs.io/)
- Read documentation on [readthedocs](https://opentele2.readthedocs.io/en/latest/documentation/telegram-desktop/tdesktop/)
- Read documentation on [github](https://github.com/DedInc/opentele2/tree/main/docs)
