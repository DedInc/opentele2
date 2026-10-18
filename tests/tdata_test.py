import contextlib
import importlib
import os
import pathlib
import sys

base_dir = pathlib.Path(__file__).parent.parent.absolute().__str__()
sys.path.insert(1, base_dir)

DEBUG_BK_PY = os.path.join(base_dir, "src", "debug_bk.py")

# Enable the library debug instrumentation for this test module *before* any
# src.* module is imported: src.utils wraps methods at class-creation time based
# on debug.IS_DEBUG_MODE. This must never rewrite the shipped source on disk.
os.environ["OPENTELE_DEBUG"] = "1"

from src import debug

if not debug.IS_DEBUG_MODE:
    # src.debug was already imported by another test module before the env var
    # was set; re-import it so the flag and its instrumentation classes exist.
    debug = importlib.reload(debug)


import pytest
from _pytest._io import TerminalWriter

from src.api import API, APIData, UseCurrentSession
from src.exception import OpenTeleException
from src.td import TDesktop
from src.td.account import Account
from src.tl.telethon import TelegramClient

X1 = "!DedInc#opentele"
X2 = "opentele#DedInc!"


def PythonVersion() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def profile_path() -> str:
    return f"tests/test_profile{PythonVersion()}"


def test_debug_mode_does_not_mutate_shipped_source() -> None:
    assert debug.IS_DEBUG_MODE, "this module must exercise debug mode"

    assert not os.path.exists(DEBUG_BK_PY), (
        "importing the test module must not create src/debug_bk.py"
    )

    source = pathlib.Path(base_dir, "src", "debug.py").read_text(encoding="utf-8")
    assert "IS_DEBUG_MODE = False" in source, (
        "the shipped default must stay off; the test run must not rewrite it"
    )
    assert "is_debug_mode_enabled()" in source


def test_debug_mode_defaults_off_without_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENTELE_DEBUG", raising=False)
    assert debug.is_debug_mode_enabled() is False

    for value in ("1", "true", "YES", " on "):
        monkeypatch.setenv("OPENTELE_DEBUG", value)
        assert debug.is_debug_mode_enabled() is True

    monkeypatch.setenv("OPENTELE_DEBUG", "0")
    assert debug.is_debug_mode_enabled() is False


def test_random_api() -> None:
    API_TYPE = APIData | type[APIData]

    def cmp(src: API_TYPE, dst: API_TYPE) -> bool:
        return (
            src.api_id == dst.api_id
            and src.api_hash == dst.api_hash
            and src.device_model == dst.device_model
            and src.system_version == dst.system_version
            and src.app_version == dst.app_version
            and src.lang_code == dst.lang_code
            and src.system_lang_code == dst.system_lang_code
            and src.lang_pack == dst.lang_pack
        )

    apis: list[API_TYPE] = [
        API.TelegramDesktop,
        API.TelegramAndroid,
        API.TelegramAndroidX,
        API.TelegramIOS,
        API.TelegramMacOS,
        API.TelegramWeb_Z,
        API.TelegramWeb_A,
        API.TelegramWeb_K,
        API.Webogram,
    ]
    for api in apis:
        assert cmp(api, api())

        check = False

        for x in range(10):
            check |= not cmp(api.Generate(), api.Generate())

        assert check

    assert cmp(
        API.TelegramDesktop.Generate("windows", "opentele"),
        API.TelegramDesktop.Generate("windows", "opentele"),
    )

    assert not cmp(
        API.TelegramDesktop.Generate("windows", "opentele"),
        API.TelegramDesktop.Generate("linux", "opentele"),
    )

    assert not cmp(
        API.TelegramDesktop.Generate("macos", "opentele"),
        API.TelegramDesktop.Generate("linux", "opentele"),
    )

    assert not cmp(
        API.TelegramDesktop.Generate("windows", "opentele"),
        API.TelegramDesktop.Generate("windows", "opentele2"),
    )


async def tdata_to_telethon() -> None:
    api_ios = API.TelegramIOS.Generate(X1)
    api_android = API.TelegramAndroid.Generate()

    tdesk = TDesktop(profile_path(), api_ios, X1, X2)
    assert tdesk.isLoaded()

    oldClient = await tdesk.ToTelethon(flag=UseCurrentSession, api=api_ios)
    tdesk = await oldClient.ToTDesktop(UseCurrentSession, api=api_ios)

    await oldClient.connect()
    assert await oldClient.is_user_authorized()
    await oldClient.PrintSessions()

    newClient = await oldClient.QRLoginToNewClient(api=api_android, password=X1)

    await newClient.connect()
    assert await newClient.is_user_authorized()
    await newClient.PrintSessions()

    tdesk = await oldClient.ToTDesktop(UseCurrentSession, api=api_ios)
    oldClient = await tdesk.ToTelethon(flag=UseCurrentSession, api=api_ios)

    tdesk = await oldClient.ToTDesktop(UseCurrentSession, api=api_ios)
    tdesk.SaveTData(profile_path(), X1, X2)

    await oldClient.disconnect()
    await newClient.disconnect()
    await oldClient.disconnected
    await newClient.disconnected


async def telethon_from_tdata() -> None:
    api_ios = API.TelegramIOS.Generate(X1)
    api_android = API.TelegramAndroid.Generate()

    tdesk = TDesktop(profile_path(), api_ios, X1, X2)
    assert tdesk.isLoaded()

    oldClient = await TelegramClient.FromTDesktop(
        tdesk, flag=UseCurrentSession, api=api_ios
    )
    tdesk = await TDesktop.FromTelethon(oldClient, UseCurrentSession, api=api_ios)

    await oldClient.connect()
    assert await oldClient.is_user_authorized()
    await oldClient.PrintSessions()

    newClient = await oldClient.QRLoginToNewClient(api=api_android, password=X1)

    await newClient.connect()
    assert await newClient.is_user_authorized()
    await newClient.PrintSessions()

    tdesk = await TDesktop.FromTelethon(oldClient, UseCurrentSession, api=api_ios)
    oldClient = await TelegramClient.FromTDesktop(
        tdesk, flag=UseCurrentSession, api=api_ios
    )

    tdesk = await TDesktop.FromTelethon(oldClient, UseCurrentSession, api=api_ios)
    tdesk.SaveTData(profile_path(), X1, X2)

    await oldClient.disconnect()
    await newClient.disconnect()
    await oldClient.disconnected
    await newClient.disconnected


async def check_telegramclient() -> None:
    api_ios = API.TelegramIOS.Generate(X1)

    tdesk = TDesktop(profile_path(), api_ios, X1, X2)
    assert tdesk.isLoaded()

    assert (
        TelegramClient().api_id == API.TelegramDesktop.api_id
        and TelegramClient().api_hash == API.TelegramDesktop.api_hash
    )
    assert TelegramClient(None, 1234, "opentele").api_id == 1234
    assert TelegramClient(None, None, 1234, "opentele").api_id == 1234

    oldClient = await TelegramClient.FromTDesktop(
        tdesk, flag=UseCurrentSession, api=api_ios
    )

    with contextlib.suppress(Exception, OpenTeleException):
        await oldClient.TerminateSession(0)

    await oldClient.connect()
    assert await oldClient.is_user_authorized()
    assert await oldClient.is_official_app()
    assert await oldClient.GetCurrentSession()

    _account = await Account.FromTelethon(
        oldClient, flag=UseCurrentSession, api=api_ios
    )

    with contextlib.suppress(Exception, OpenTeleException):
        await oldClient.TerminateSession(0)

    assert await oldClient.TerminateAllSessions()

    await oldClient.disconnect()
    await oldClient.disconnected


@pytest.mark.asyncio
async def test_entry_point() -> None:
    import asyncio

    profile = profile_path()
    if not os.path.isdir(profile):
        pytest.skip(f"Test profile directory not found: {profile}")

    loop = asyncio.get_event_loop()
    ter = TerminalWriter(sys.stdout)
    ter.hasmarkup = True
    loop._close = loop.close
    loop.close = lambda: None

    ter.write("\n\n")
    ter.sep("=", f"Begin testing for Python {PythonVersion()}", cyan=True)

    await tdata_to_telethon()
    await telethon_from_tdata()
    await check_telegramclient()
