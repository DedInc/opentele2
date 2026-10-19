# Type stub of the opentele2._native extension module (bindings/python/src).
# Docstrings live in the extension; this file carries the types only.

import os
from collections.abc import Iterable, Sequence
from typing import Literal, Protocol, TypedDict, final

from typing_extensions import TypeAlias

__version__: str

_Bytes: TypeAlias = bytes | bytearray
_Passcode: TypeAlias = bytes | bytearray | str
_Path: TypeAlias = str | os.PathLike[str]
_LoadRequest: TypeAlias = (
    _Path | tuple[_Path] | tuple[_Path, _Passcode] | tuple[_Path, _Passcode, str | None]
)
_Client: TypeAlias = Literal[
    "TelegramDesktop",
    "TelegramAndroid",
    "TelegramAndroidX",
    "TelegramIOS",
    "TelegramMacOS",
    "TelegramWeb_A",
    "TelegramWeb_K",
    "Webogram",
]
_DesktopSystem: TypeAlias = Literal["windows", "macos", "linux"]

class CoreError(Exception):
    # Stable SCREAMING_SNAKE identifier, for example "TDATA_WRONG_PASSCODE".
    code: str
    # Human-readable text; may change between releases.
    message: str
    def __init__(self, code: str, message: str) -> None: ...

# The values a client sends in initConnection.
class ApiProfile(TypedDict):
    api_id: int
    api_hash: str
    device_model: str
    system_version: str
    app_version: str
    lang_code: str
    system_lang_code: str
    lang_pack: str

# Overrides of the offline PlatformVersions fields.
class Versions(TypedDict, total=False):
    android_app_version: str
    android_app_version_code: int
    ios_app_version: str
    ios_build_number: int
    ios_system_version: str
    macos_system_version: str
    desktop_app_version: str
    desktop_app_version_suffix: str
    macos_app_version: str
    macos_build_number: int
    android_x_app_version: str
    web_a_version: str
    web_k_version: str

# crypto: failures raise CoreError, bad lengths with code "BAD_LENGTH".

def key_id(auth_key: _Bytes) -> int: ...
def prepare_aes_oldmtp(
    auth_key: _Bytes, msg_key: _Bytes, send: bool = False
) -> tuple[bytes, bytes]: ...
def aes_ige_encrypt(data: _Bytes, key: _Bytes, iv: _Bytes) -> bytes: ...
def aes_ige_decrypt(data: _Bytes, key: _Bytes, iv: _Bytes) -> bytes: ...
def encrypt_local(data: _Bytes, local_key: _Bytes) -> bytes: ...
def decrypt_local(encrypted: _Bytes, local_key: _Bytes) -> bytes: ...
def create_local_key(passcode: _Passcode, salt: _Bytes) -> bytes: ...
def create_legacy_local_key(passcode: _Passcode, salt: _Bytes) -> bytes: ...
def argon2id(
    passcode: _Passcode, salt: _Bytes, memory_kib: int, time: int, lanes: int
) -> bytes: ...

# cryptg 0.6.0 interface, raising ValueError on bad lengths; the submodule is
# also importable as opentele2._native.cryptg, and `import opentele2` registers
# it as the top-level cryptg when no real cryptg is installed.
class _Cryptg(Protocol):
    def encrypt_ige(self, data: _Bytes, key: _Bytes, iv: _Bytes) -> bytes: ...
    def decrypt_ige(self, data: _Bytes, key: _Bytes, iv: _Bytes) -> bytes: ...

cryptg: _Cryptg

# tdata: repr() of Account and TData never shows key bytes.

@final
class Account:
    def __new__(
        cls, index: int, user_id: int, main_dc: int, keys: Iterable[tuple[int, _Bytes]]
    ) -> Account: ...
    @property
    def index(self) -> int: ...
    @property
    def user_id(self) -> int: ...
    @property
    def main_dc(self) -> int: ...
    @property
    def auth_key(self) -> bytes: ...
    @property
    def keys(self) -> list[tuple[int, bytes]]: ...

@final
class TData:
    @staticmethod
    def load(path: _Path, passcode: _Passcode = b"", key_file: str | None = None) -> TData: ...
    @staticmethod
    def new(
        accounts: Sequence[Account], passcode: _Passcode = b"", performance_mode: bool = True
    ) -> TData: ...
    def save(self, path: _Path) -> None: ...
    @property
    def accounts(self) -> list[Account]: ...
    @property
    def active_index(self) -> int: ...
    @property
    def main_account(self) -> Account | None: ...

def load_many(
    requests: Iterable[_LoadRequest], threads: int | None = None
) -> list[TData | CoreError]: ...

# sessions

def telethon_string_session(account: Account, ipv6: bool = False) -> str: ...
def mtcute_string_session(account: Account) -> str: ...

# fingerprints

def profile(client: _Client, versions: Versions | None = None) -> ApiProfile: ...
def generate(
    client: _Client,
    seed: str | int | None = None,
    system: _DesktopSystem | None = None,
    versions: Versions | None = None,
) -> ApiProfile: ...
