from __future__ import annotations

import pathlib
from typing import Any

import pytest

from src.exception import OpenTeleException, TDataBadDecryptKey
from src.qt_compat import QByteArray
from src.td import key_data as kd
from src.td import shared as td
from src.td.account import Account
from src.td.tdesktop import TDesktop


def _private(client: TDesktop, name: str) -> Any:
    """A name-mangled TDesktop internal the test drives directly."""
    return getattr(client, f"_TDesktop__{name}")


def _client_key(client: TDesktop) -> bytes:
    assert client.localKey is not None
    return client.localKey.key


def _set_private(client: TDesktop, name: str, value: object) -> None:
    setattr(client, f"_TDesktop__{name}", value)


# Cheap but valid parameters; the format stores them per wrap.
_FAST_SCRYPT = kd.PasscodeKdf(kd.KDF_SCRYPT, memory=1024, time=8, parallel=1)
_FAST_ARGON2 = kd.PasscodeKdf(kd.KDF_ARGON2ID, memory=64, time=1, parallel=1)
_PASSCODE = "пароль".encode()


def _salt(fill: int) -> QByteArray:
    return QByteArray(bytes([fill]) * kd.LOCAL_ENCRYPT_SALT_SIZE)


def _localKey() -> td.AuthKey:
    return td.AuthKey(bytes(range(256)))


def _keyFile(
    tmp_path: pathlib.Path, *blobs: QByteArray
) -> td.Storage.FileReadDescriptor:
    writer = td.Storage.FileWriteDescriptor("key_probe", str(tmp_path))
    for blob in blobs:
        writer.writeData(blob)
    writer.finish()
    return td.Storage.ReadFile("key_probe", str(tmp_path))


def _info(localKey: td.AuthKey) -> QByteArray:
    info = td.Storage.EncryptedDescriptor(12)
    info.stream.writeInt32(1)
    info.stream.writeInt32(0)
    info.stream.writeInt32(0)
    return td.Storage.PrepareEncrypted(info, localKey)


def _openWrap(localKey: td.AuthKey, salt: QByteArray) -> QByteArray:
    return kd.wrap_local_key(localKey, td.Storage.CreateLocalKey(salt))


def _passcodeWrap(
    localKey: td.AuthKey, kdf: kd.PasscodeKdf, generation: int
) -> kd.PasscodeWrap:
    wrap = kd.PasscodeWrap(kdf=kdf, generation=generation, salt=_salt(7))
    wrap.keyEncrypted = kd.wrap_local_key(
        localKey, kd.create_passcode_key(_PASSCODE, wrap.salt, kdf)
    )
    return wrap


def test_a_pre_7_3_three_blob_file_reads_as_legacy(tmp_path: pathlib.Path) -> None:
    localKey = _localKey()
    salt = _salt(1)
    wrapKey = td.Storage.CreateLocalKey(salt, QByteArray(_PASSCODE))
    file = _keyFile(
        tmp_path, salt, kd.wrap_local_key(localKey, wrapKey), _info(localKey)
    )

    data, infoEncrypted = kd.read_key_data(file.stream)

    assert data.legacy
    recovered, _ = kd.open_local_key(data, _PASSCODE)
    assert recovered.key == localKey.key
    td.Storage.DecryptLocal(infoEncrypted, recovered)
    with pytest.raises(TDataBadDecryptKey):
        kd.open_local_key(data, b"")


def test_an_open_7_3_file_opens_without_a_passcode(tmp_path: pathlib.Path) -> None:
    localKey = _localKey()
    data = kd.KeyData(openSalt=_salt(2), legacy=False)
    data.openKeyEncrypted = _openWrap(localKey, data.openSalt)
    file = _keyFile(
        tmp_path,
        data.openSalt,
        data.openKeyEncrypted,
        _info(localKey),
        kd.key_data_trailer(data),
    )

    parsed, _ = kd.read_key_data(file.stream)

    assert not parsed.legacy
    assert parsed.committed == 0 and parsed.passcodeWraps == []
    assert kd.open_local_key(parsed, b"")[0].key == localKey.key
    # startModern: a typed passcode needs exactly one live passcode wrap.
    with pytest.raises(TDataBadDecryptKey):
        kd.open_local_key(parsed, _PASSCODE)


@pytest.mark.parametrize(
    "kdf", [_FAST_SCRYPT, _FAST_ARGON2], ids=["scrypt", "argon2id"]
)
def test_an_app_locked_7_3_file_needs_its_passcode(
    tmp_path: pathlib.Path, kdf: kd.PasscodeKdf
) -> None:
    localKey = _localKey()
    data = kd.KeyData(openSalt=_salt(3), legacy=False, committed=1)
    data.passcodeWraps.append(_passcodeWrap(localKey, kdf, generation=1))
    file = _keyFile(
        tmp_path,
        data.openSalt,
        QByteArray(),
        _info(localKey),
        kd.key_data_trailer(data),
    )

    parsed, _ = kd.read_key_data(file.stream)

    assert parsed.openKeyEncrypted.isEmpty()
    assert parsed.passcodeWraps[0].kdf == kdf
    assert kd.open_local_key(parsed, _PASSCODE)[0].key == localKey.key
    with pytest.raises(TDataBadDecryptKey):
        kd.open_local_key(parsed, b"")
    with pytest.raises(TDataBadDecryptKey):
        kd.open_local_key(parsed, b"wrong")


def test_a_wrap_of_another_generation_is_not_live() -> None:
    localKey = _localKey()
    data = kd.KeyData(openSalt=_salt(4), legacy=False, committed=2)
    data.passcodeWraps.append(_passcodeWrap(localKey, _FAST_SCRYPT, generation=1))

    assert data.liveWraps() == []
    with pytest.raises(TDataBadDecryptKey):
        kd.open_local_key(data, _PASSCODE)


def test_argon2id_matches_openssl() -> None:
    argon2 = pytest.importorskip("cryptography.hazmat.primitives.kdf.argon2")
    salt = _salt(5)

    ours = kd.create_passcode_key(_PASSCODE, salt, _FAST_ARGON2)
    reference = argon2.Argon2id(
        salt=bytes(salt),
        length=256,
        iterations=_FAST_ARGON2.time,
        lanes=_FAST_ARGON2.parallel,
        memory_cost=_FAST_ARGON2.memory,
    ).derive(_PASSCODE)

    assert ours.key == reference


@pytest.mark.parametrize(
    ("header", "message"),
    [
        ((0x12345678, 2, 0, 0), "magic"),
        ((kd.KEY_DATA_MAGIC, 2, 0, 3), "wrap count"),
    ],
)
def test_a_bad_trailer_is_rejected(
    tmp_path: pathlib.Path, header: tuple[int, ...], message: str
) -> None:
    trailer = QByteArray(b"".join(v.to_bytes(4, "big") for v in header))
    file = _keyFile(tmp_path, _salt(6), QByteArray(), QByteArray(), trailer)

    with pytest.raises(kd.TDataKeyDataInvalid, match=message):
        kd.read_key_data(file.stream)


class _UnsavedAccount(Account):
    """A real Account whose own files are not written: these tests only read
    back the key file TDesktop writes around them."""

    def _writeData(self, baseGlobalPath: str, keyFile: str | None = None) -> None:
        pass


def _writtenKeyData(
    tmp_path: pathlib.Path, client: TDesktop
) -> tuple[kd.KeyData, QByteArray]:
    client.accounts.extend(
        [_UnsavedAccount(client, index=0), _UnsavedAccount(client, index=2)]
    )
    _private(client, "generateLocalKey")()
    _private(client, "writeAccounts")(str(tmp_path))
    file = td.Storage.ReadFile("key_data", str(tmp_path))
    return kd.read_key_data(file.stream)


def test_saved_tdata_without_passcode_has_an_open_7_3_key_file(
    tmp_path: pathlib.Path,
) -> None:
    client = TDesktop()
    data, infoEncrypted = _writtenKeyData(tmp_path, client)

    assert not data.legacy
    assert data.passcodeWraps == []
    localKey, _ = kd.open_local_key(data, b"")
    assert localKey.key == _client_key(client)
    info = td.Storage.DecryptLocal(infoEncrypted, localKey)
    assert [info.stream.readInt32() for _ in range(3)] == [2, 0, 2]


def test_saved_tdata_with_passcode_locks_the_open_wrap(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("src.td.tdesktop.default_passcode_kdf", lambda: _FAST_SCRYPT)
    client = TDesktop(passcode="пароль")
    data, _ = _writtenKeyData(tmp_path, client)

    assert data.openKeyEncrypted.isEmpty()
    assert data.openSalt.size() == kd.LOCAL_ENCRYPT_SALT_SIZE
    assert data.committed == 1
    assert [w.generation for w in data.passcodeWraps] == [1]
    assert kd.open_local_key(data, _PASSCODE)[0].key == _client_key(client)
    with pytest.raises(TDataBadDecryptKey):
        kd.open_local_key(data, b"")


def test_saving_a_loaded_legacy_key_file_migrates_it_to_7_3(
    tmp_path: pathlib.Path,
) -> None:
    client = TDesktop()
    client.accounts.append(_UnsavedAccount(client, index=0))
    _private(client, "generateLocalKey")()
    localKey = client.localKey
    assert localKey is not None
    _private(client, "keyData").legacy = True

    client.SaveTData(str(tmp_path))

    file = td.Storage.ReadFile("key_data", str(tmp_path))
    data, _ = kd.read_key_data(file.stream)
    assert not data.legacy
    assert client.localKey is localKey
    assert kd.open_local_key(data, b"")[0].key == localKey.key


def test_a_scrypt_wrap_over_the_memory_cap_is_a_wrong_passcode() -> None:
    # 128 * r * N = 256 MiB, above tdesktop's 192 MiB scrypt ceiling.
    greedy = kd.PasscodeKdf(kd.KDF_SCRYPT, memory=1 << 18, time=8, parallel=1)

    with pytest.raises(TDataBadDecryptKey):
        kd.create_passcode_key(_PASSCODE, _salt(8), greedy)


def test_an_argon2_wrap_over_the_cost_ceiling_is_rejected_before_deriving() -> None:
    greedy = kd.PasscodeKdf(kd.KDF_ARGON2ID, memory=1 << 20, time=1, parallel=1)

    with pytest.raises(kd.TDataKeyDataInvalid):
        kd.create_passcode_key(_PASSCODE, _salt(8), greedy)


def _trailerWith(*wraps: kd.PasscodeWrap, committed: int = 1) -> QByteArray:
    return kd.key_data_trailer(
        kd.KeyData(legacy=False, committed=committed, passcodeWraps=list(wraps))
    )


def test_a_pbkdf2_kind_passcode_wrap_fails_the_file(tmp_path: pathlib.Path) -> None:
    wrap = kd.PasscodeWrap(
        kdf=kd.PasscodeKdf(kd.KDF_PBKDF2, 0, 1, 1), generation=1, salt=_salt(9)
    )
    file = _keyFile(tmp_path, _salt(9), QByteArray(), QByteArray(), _trailerWith(wrap))

    with pytest.raises(kd.TDataKeyDataInvalid, match="KDF family"):
        kd.read_key_data(file.stream)


def test_a_crafted_scrypt_cost_never_runs(tmp_path: pathlib.Path) -> None:
    # Under the memory cap, but about a day of CPU for p=520000.
    crafted = kd.PasscodeKdf(kd.KDF_SCRYPT, memory=1 << 18, time=2, parallel=520000)
    wrap = kd.PasscodeWrap(kdf=crafted, generation=1, salt=_salt(10))
    file = _keyFile(tmp_path, _salt(10), QByteArray(), QByteArray(), _trailerWith(wrap))

    parsed, _ = kd.read_key_data(file.stream)

    assert parsed.unsupportedCost
    for passcode in (b"", _PASSCODE):
        with pytest.raises(TDataBadDecryptKey):
            kd.open_local_key(parsed, passcode)
    with pytest.raises(kd.TDataKeyDataInvalid):
        kd.create_passcode_key(_PASSCODE, _salt(10), crafted)


def test_an_unreadable_accounts_info_is_not_reported_as_a_passcode(
    tmp_path: pathlib.Path,
) -> None:
    localKey = _localKey()
    data = kd.KeyData(openSalt=_salt(11), legacy=False)
    data.openKeyEncrypted = _openWrap(localKey, data.openSalt)
    writer = td.Storage.FileWriteDescriptor("key_data", str(tmp_path))
    for blob in (
        data.openSalt,
        data.openKeyEncrypted,
        _info(td.AuthKey(bytes(256))),
        kd.key_data_trailer(data),
    ):
        writer.writeData(blob)
    writer.finish()

    with pytest.raises(kd.TDataKeyDataInvalid, match="accounts info"):
        TDesktop(str(tmp_path))


def test_loading_drops_wraps_of_other_generations(tmp_path: pathlib.Path) -> None:
    localKey = _localKey()
    data = kd.KeyData(openSalt=_salt(12), legacy=False, committed=1)
    data.openKeyEncrypted = _openWrap(localKey, data.openSalt)
    data.passcodeWraps = [
        _passcodeWrap(localKey, _FAST_SCRYPT, generation=1),
        _passcodeWrap(localKey, _FAST_SCRYPT, generation=2),
    ]
    writer = td.Storage.FileWriteDescriptor("key_data", str(tmp_path))
    for blob in (
        data.openSalt,
        data.openKeyEncrypted,
        _info(localKey),
        kd.key_data_trailer(data),
    ):
        writer.writeData(blob)
    writer.finish()

    client = TDesktop()
    _set_private(client, "basePath", str(tmp_path))
    with pytest.raises(OpenTeleException, match="No account has been loaded"):
        # No account files exist; the key file itself must still parse.
        _private(client, "loadFromTData")()

    kept = _private(client, "keyData").passcodeWraps
    assert [w.generation for w in kept] == [1]


def test_a_newer_key_data_format_is_read_by_its_known_prefix(
    tmp_path: pathlib.Path,
) -> None:
    localKey = _localKey()
    wrap = _passcodeWrap(localKey, _FAST_SCRYPT, generation=1)
    known = bytes(_trailerWith(wrap))
    # Format 3 with a field appended after the wraps.
    newer = known[:4] + (3).to_bytes(4, "big") + known[8:] + b"\x00\x00\x00\x2a"
    file = _keyFile(
        tmp_path, _salt(13), QByteArray(), _info(localKey), QByteArray(newer)
    )

    parsed, _ = kd.read_key_data(file.stream)

    assert [w.generation for w in parsed.passcodeWraps] == [1]
    assert kd.open_local_key(parsed, _PASSCODE)[0].key == localKey.key


def test_a_file_stamped_by_a_newer_tdesktop_still_reads(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("src.td.storage.APP_VERSION", 8001002)
    writer = td.Storage.FileWriteDescriptor("future", str(tmp_path))
    writer.writeData(QByteArray(b"payload"))
    writer.finish()

    result = td.Storage.ReadFile("future", str(tmp_path))

    assert result.version == 8001002


def test_more_accounts_than_7_3_1_allows_are_not_rejected(
    tmp_path: pathlib.Path,
) -> None:
    localKey = _localKey()
    data = kd.KeyData(openSalt=_salt(14), legacy=False)
    data.openKeyEncrypted = _openWrap(localKey, data.openSalt)
    info = td.Storage.EncryptedDescriptor(4 * 9)
    info.stream.writeInt32(7)
    for index in range(7):
        info.stream.writeInt32(index)
    info.stream.writeInt32(0)
    writer = td.Storage.FileWriteDescriptor("key_data", str(tmp_path))
    for blob in (
        data.openSalt,
        data.openKeyEncrypted,
        td.Storage.PrepareEncrypted(info, localKey),
        kd.key_data_trailer(data),
    ):
        writer.writeData(blob)
    writer.finish()

    # Gets past the count check; only the absent account files stop it.
    with pytest.raises(OpenTeleException, match="No account has been loaded"):
        TDesktop(str(tmp_path))
