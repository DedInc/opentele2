from __future__ import annotations

import pathlib

import pytest

from src.exception import TDataBadDecryptKey
from src.qt_compat import QByteArray
from src.td import key_data as kd
from src.td import shared as td
from src.td.tdesktop import TDesktop

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
    assert kd.open_local_key(parsed, _PASSCODE)[0].key == localKey.key


@pytest.mark.parametrize(
    "kdf", [_FAST_SCRYPT, _FAST_ARGON2], ids=["scrypt", "argon2id"]
)
def test_an_app_locked_7_3_file_needs_its_passcode(
    tmp_path: pathlib.Path, kdf: kd.PasscodeKdf
) -> None:
    if kdf.kind == kd.KDF_ARGON2ID:
        pytest.importorskip("argon2")
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
    pytest.importorskip("argon2")
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
        ((kd.KEY_DATA_MAGIC, 3, 0, 0), "format"),
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


class _FakeAccount:
    def __init__(self, index: int) -> None:
        self.index = index
        self.localKey: td.AuthKey | None = None

    def _writeData(self, basePath: str, keyFile: str | None = None) -> None:
        pass


def _writtenKeyData(
    tmp_path: pathlib.Path, client: TDesktop
) -> tuple[kd.KeyData, QByteArray]:
    client.accounts.extend([_FakeAccount(0), _FakeAccount(2)])  # type: ignore[list-item]
    client._TDesktop__generateLocalKey()  # type: ignore[attr-defined]
    client._TDesktop__writeAccounts(str(tmp_path))  # type: ignore[attr-defined]
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
    assert localKey.key == client.localKey.key
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
    assert kd.open_local_key(data, _PASSCODE)[0].key == client.localKey.key
    with pytest.raises(TDataBadDecryptKey):
        kd.open_local_key(data, b"")
