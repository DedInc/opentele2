"""Pin the arguments opentele2's TelegramClient hands to Telethon's __init__,
ported from 1.5.0 tests/test_client_kwargs.py.

The expected values are the ones 1.5.0 forwarded (23 recorded constructor
cases): a None session arrives as the MemorySession Telethon would build from
it, and api_id as an int.
"""

from __future__ import annotations

import inspect
import warnings

import pytest
import telethon
from telethon.network.connection import ConnectionTcpFull
from telethon.network.connection.tcpobfuscated import ConnectionTcpObfuscated
from telethon.sessions import MemorySession

from opentele2.api import API
from opentele2.tl.telethon import TelegramClient

_TELETHON_INIT = telethon.TelegramClient.__init__
_TELETHON_SIGNATURE = inspect.signature(_TELETHON_INIT)


class _Recorded(Exception):
    """Stops construction once Telethon's __init__ has been reached."""


@pytest.fixture
def record(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    recorded: dict[str, object] = {}

    def fake_init(self: object, *args: object, **kwargs: object) -> None:
        bound = _TELETHON_SIGNATURE.bind(self, *args, **kwargs)
        recorded.update(bound.arguments)
        del recorded["self"]
        raise _Recorded

    monkeypatch.setattr(telethon.TelegramClient, "__init__", fake_init)
    return recorded


def _desktop(**overrides: object) -> dict[str, object]:
    desktop = API.TelegramDesktop()
    expected: dict[str, object] = {
        "session": MemorySession,
        "api_id": desktop.api_id,
        "api_hash": desktop.api_hash,
        "connection": ConnectionTcpObfuscated,
        "device_model": desktop.device_model,
        "system_version": desktop.system_version,
        "app_version": desktop.app_version,
        "lang_code": "en",
        "system_lang_code": desktop.system_lang_code,
    }
    expected.update(overrides)
    return expected


def _custom(api_id: int, api_hash: str, **overrides: object) -> dict[str, object]:
    expected: dict[str, object] = {
        "session": MemorySession,
        "api_id": api_id,
        "api_hash": api_hash,
        "connection": ConnectionTcpObfuscated,
    }
    expected.update(overrides)
    return expected


_SESSION = MemorySession()
_ANDROID = API.TelegramAndroid()
_SEVEN_NONE = dict.fromkeys(
    [
        "proxy",
        "local_addr",
        "device_model",
        "system_version",
        "app_version",
        "loop",
        "base_logger",
    ]
)

CASES = {
    "none_session": ((None,), {}, _desktop()),
    "str_session": (("sess_str",), {}, _desktop(session="sess_str")),
    "session_obj": ((_SESSION,), {}, _desktop(session=_SESSION)),
    "api_class": ((None,), {"api": API.TelegramDesktop}, _desktop()),
    "api_instance": (
        (None,),
        {"api": _ANDROID},
        _desktop(
            api_id=_ANDROID.api_id,
            api_hash=_ANDROID.api_hash,
            device_model=_ANDROID.device_model,
            system_version=_ANDROID.system_version,
            app_version=_ANDROID.app_version,
            system_lang_code=_ANDROID.system_lang_code,
        ),
    ),
    "api_int_only": ((None,), {"api": 12345}, _desktop()),
    "api_str_only": ((None,), {"api": "12345"}, _desktop()),
    "legacy_int": (("s", 12345, "abcdef"), {}, _custom(12345, "abcdef", session="s")),
    "legacy_str": (
        ("s", "12345", "abcdef"),
        {},
        _custom(12345, "abcdef", session="s"),
    ),
    "api_id_hash_kw": ((None,), {"api_id": 1234, "api_hash": "h"}, _custom(1234, "h")),
    # HEAD forwarded the str and Telethon int()-ed it; now it arrives as int.
    "api_id_str_kw": ((None,), {"api_id": "1234", "api_hash": "h"}, _custom(1234, "h")),
    "proxy_none": ((None,), {"proxy": None}, _desktop(proxy=None)),
    "proxy_tuple": (
        (None,),
        {"proxy": ("socks5", "127.0.0.1", 9050)},
        _desktop(proxy=("socks5", "127.0.0.1", 9050)),
    ),
    "device_model": ((None,), {"device_model": "X1"}, _desktop(device_model="X1")),
    "connection": (
        (None,),
        {"connection": ConnectionTcpFull},
        _desktop(connection=ConnectionTcpFull),
    ),
    "catch_up_true": ((None,), {"catch_up": True}, _desktop(catch_up=True)),
    "catch_up_str": ((None,), {"catch_up": "yes"}, _desktop(catch_up="yes")),
    "catch_up_none": ((None,), {"catch_up": None}, _desktop(catch_up=None)),
    "catch_up_one": ((None,), {"catch_up": 1}, _desktop(catch_up=1)),
    "receive_updates_false": (
        (None,),
        {"receive_updates": False},
        _desktop(receive_updates=False),
    ),
    "entity_cache_limit": (
        (None,),
        {"entity_cache_limit": 5000},
        _desktop(entity_cache_limit=5000),
    ),
    "entity_cache_limit_str": (
        (None,),
        {"entity_cache_limit": "5"},
        _desktop(entity_cache_limit="5"),
    ),
    "seven_none": ((None,), _SEVEN_NONE, _desktop(**_SEVEN_NONE)),
    "custom_no_apidata_none_dm": (
        (None,),
        {"api_id": 1, "api_hash": "h", "device_model": None},
        _custom(1, "h", device_model=None),
    ),
}


def _construct(args, kwargs) -> None:
    # Unannotated on purpose: several cases pass values outside the declared
    # types (catch_up="yes", proxy=None) to pin what reaches Telethon at runtime.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        TelegramClient(*args, **kwargs)


@pytest.mark.parametrize(("args", "kwargs", "expected"), CASES.values(), ids=CASES)
def test_arguments_reach_telethon_as_head_forwarded_them(
    record: dict[str, object],
    args: tuple[object, ...],
    kwargs: dict[str, object],
    expected: dict[str, object],
) -> None:
    with pytest.raises(_Recorded):
        _construct(args, kwargs)
    if expected["session"] is MemorySession:
        assert type(record["session"]) is MemorySession
        record["session"] = MemorySession
    assert record == expected


def test_unknown_keyword_is_pythons_binding_error(record: dict[str, object]) -> None:
    with pytest.raises(TypeError, match="unexpected keyword argument 'bogus_kw'"):
        _construct((None,), {"bogus_kw": 1})
    assert record == {}


def test_missing_api_hash_raises_telethons_value_error(
    record: dict[str, object],
) -> None:
    # HEAD forwarded api_hash=None and Telethon raised this; now it is raised
    # before the call, with Telethon's message.
    with pytest.raises(ValueError, match="cannot be empty or None"):
        _construct((None,), {"api_id": 1234})
    assert record == {}


def test_opentele_keywords_are_not_forwarded(record: dict[str, object]) -> None:
    with pytest.raises(_Recorded):
        TelegramClient(None, auto_post_login=False, fingerprint_config=None)
    assert "auto_post_login" not in record
    assert "fingerprint_config" not in record
