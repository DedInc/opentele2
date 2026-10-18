from __future__ import annotations

import hashlib
from typing import Any

from src.qt_compat import QByteArray
from src.td.account import Account
from src.td.auth import AuthKey
from src.td.storage import Storage
from src.td.tdesktop import TDesktop


def _private(client: TDesktop, name: str) -> Any:
    """A name-mangled TDesktop internal the test drives directly."""
    return getattr(client, f"_TDesktop__{name}")


def _set_private(client: TDesktop, name: str, value: object) -> None:
    setattr(client, f"_TDesktop__{name}", value)


# refs/tdesktop-dev/Telegram/SourceFiles/config.h:15-17
LOCAL_ENCRYPT_ITER_COUNT = 4000
LOCAL_ENCRYPT_NO_PWD_ITER_COUNT = 4
LOCAL_ENCRYPT_SALT_SIZE = 32

# refs/tdesktop-dev/Telegram/SourceFiles/main/main_domain.h:39-40
K_PREMIUM_MAX_ACCOUNTS = 6


def _expectedLegacyKey(passcode: bytes, salt: bytes) -> bytes:
    """PKCS5_PBKDF2_HMAC_SHA1 as used by CreateLegacyLocalKey in
    storage/details/storage_file_utilities.cpp:324-342."""
    iterations = (
        LOCAL_ENCRYPT_NO_PWD_ITER_COUNT if not passcode else LOCAL_ENCRYPT_ITER_COUNT
    )
    return hashlib.pbkdf2_hmac("sha1", passcode, salt, iterations, AuthKey.kSize)


def test_legacy_local_key_empty_passcode_is_pbkdf2_sha1_4_iterations() -> None:
    salt = bytes(range(LOCAL_ENCRYPT_SALT_SIZE))

    key = Storage.CreateLegacyLocalKey(QByteArray(salt))

    assert key.key == _expectedLegacyKey(b"", salt)
    assert key.key == hashlib.pbkdf2_hmac("sha1", b"", salt, 4, 256)


def test_legacy_local_key_with_passcode_is_pbkdf2_sha1_4000_iterations() -> None:
    salt = bytes(range(LOCAL_ENCRYPT_SALT_SIZE))
    passcode = b"hunter2"

    key = Storage.CreateLegacyLocalKey(QByteArray(salt), QByteArray(passcode))

    assert key.key == _expectedLegacyKey(passcode, salt)
    assert key.key == hashlib.pbkdf2_hmac("sha1", passcode, salt, 4000, 256)


def test_modern_local_key_derivation_is_unchanged() -> None:
    salt = bytes(range(LOCAL_ENCRYPT_SALT_SIZE))
    passcode = b"hunter2"

    hashKey = hashlib.sha512(salt)
    hashKey.update(passcode)
    hashKey.update(salt)
    expected = hashlib.pbkdf2_hmac("sha512", hashKey.digest(), salt, 100000, 256)

    key = Storage.CreateLocalKey(QByteArray(salt), QByteArray(passcode))

    assert key.key == expected
    assert key.key != _expectedLegacyKey(passcode, salt)


def test_six_account_indices_survive_the_cap() -> None:
    assert TDesktop.kMaxAccounts == K_PREMIUM_MAX_ACCOUNTS

    accepted = [i for i in range(8) if 0 <= i < TDesktop.kMaxAccounts]

    assert accepted == [0, 1, 2, 3, 4, 5]


def test_account_limit_message_states_the_real_cap() -> None:
    import inspect

    from src.td import account as account_module

    source = inspect.getsource(account_module)

    assert "more than 6 accounts in one TDesktop client" in source
    assert "more than 3 accounts in one TDesktop client" not in source


def test_performance_mode_key_regeneration_reaches_loaded_accounts() -> None:
    assert TDesktop.kPerformanceMode is True

    client = TDesktop()
    accounts = [Account(client, index=i) for i in range(3)]
    client.accounts.extend(accounts)

    _private(client, "generateLocalKey")()

    assert client.isLoaded()
    assert client.localKey is not None
    for account in accounts:
        assert account.localKey is client.localKey


def test_non_performance_mode_key_regeneration_reaches_loaded_accounts() -> None:
    client = TDesktop(passcode="hunter2")
    accounts = [Account(client, index=i) for i in range(2)]
    client.accounts.extend(accounts)

    _private(client, "generateLocalKey")()

    for account in accounts:
        assert account.localKey is client.localKey


def test_non_ascii_passcode_is_encoded_as_utf8_without_raising() -> None:
    passcode = "пароль-密码"

    client = TDesktop(passcode=passcode)

    assert client.passcode == passcode
    assert _private(client, "passcodeBytes") == passcode.encode("utf-8")

    _private(client, "generateLocalKey")()

    assert client.isLoaded()
    assert client.localKey is not None
