"""The ``key_<dataName>`` file of Telegram Desktop 7.3.

Up to 7.2 the file held three blobs: the open salt, the local key wrapped with
a key derived from that salt and the passcode, and the encrypted accounts
list. 7.3 appends a fourth blob, a trailer that carries passcode wraps
(PBKDF2, Argon2id or scrypt). The open blobs stay first so older builds keep
reading the file; with the app lock on, the open wrap is an empty blob.

Mirrors ``Storage::Domain`` in tdesktop ``storage/storage_domain.cpp``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..exception import (
    Expects,
    ExpectStreamStatus,
    OpenTeleException,
    TDataBadDecryptKey,
)
from ..qt_compat import QBuffer, QByteArray, QDataStream, QIODevice
from . import shared as td

__all__ = [
    "KEY_DATA_MAGIC",
    "KEY_DATA_FORMAT_VERSION",
    "KDF_PBKDF2",
    "KDF_ARGON2ID",
    "KDF_SCRYPT",
    "PasscodeKdf",
    "PasscodeWrap",
    "KeyData",
    "TDataKeyDataInvalid",
    "TDataPasscodeKdfUnavailable",
    "read_key_data",
    "key_data_trailer",
    "create_passcode_key",
    "default_passcode_kdf",
    "wrap_local_key",
    "unwrap_local_key",
    "open_local_key",
]

KEY_DATA_MAGIC = 0x4B443200
KEY_DATA_FORMAT_VERSION = 2
MAX_WRAP_COUNT = 2
LOCAL_ENCRYPT_SALT_SIZE = 32
PASSCODE_SALT_MIN_SIZE = 8

KDF_PBKDF2 = 0
KDF_ARGON2ID = 1
KDF_SCRYPT = 2

# Write defaults and read ceilings from storage_file_utilities.cpp.
_ARGON2_MEMORY_KIB = 65536
_ARGON2_TIME = 8
_ARGON2_LANES = 1
_ARGON2_MAX_MEMORY_KIB = 262144
_ARGON2_MAX_TIME = 64
_ARGON2_MAX_LANES = 16
_SCRYPT_N = 131072
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAX_MEM = 192 * 1024 * 1024


class TDataKeyDataInvalid(OpenTeleException):
    """The key file is malformed or uses a newer format than supported."""


class TDataPasscodeKdfUnavailable(OpenTeleException):
    """The passcode wrap needs a key derivation that is not installed."""


@dataclass
class PasscodeKdf:
    kind: int = KDF_PBKDF2
    memory: int = 0
    time: int = 0
    parallel: int = 0

    def valid(self) -> bool:
        if not self.time or not self.parallel:
            return False
        if self.kind == KDF_ARGON2ID:
            return self.memory >= 8 * self.parallel
        if self.kind == KDF_SCRYPT:
            return self.memory >= 2 and not (self.memory & (self.memory - 1))
        return False

    def costWithinLimits(self) -> bool:
        return self.kind != KDF_ARGON2ID or (
            self.memory <= _ARGON2_MAX_MEMORY_KIB
            and self.time <= _ARGON2_MAX_TIME
            and self.parallel <= _ARGON2_MAX_LANES
        )


@dataclass
class PasscodeWrap:
    kdf: PasscodeKdf = field(default_factory=PasscodeKdf)
    generation: int = 0
    salt: QByteArray = field(default_factory=QByteArray)
    keyEncrypted: QByteArray = field(default_factory=QByteArray)


@dataclass
class KeyData:
    openSalt: QByteArray = field(default_factory=QByteArray)
    openKeyEncrypted: QByteArray = field(default_factory=QByteArray)
    # True for the three-blob layout written before 7.3.
    legacy: bool = True
    committed: int = 0
    passcodeWraps: list[PasscodeWrap] = field(default_factory=list)

    def liveWraps(self) -> list[PasscodeWrap]:
        """Wraps of the committed generation; others are crash leftovers."""
        return [w for w in self.passcodeWraps if w.generation == self.committed]


def _argon2_available() -> bool:
    try:
        import argon2.low_level  # noqa: F401
    except ImportError:
        return False
    return True


def default_passcode_kdf() -> PasscodeKdf:
    """Argon2id when available, else scrypt, like ``DefaultPasscodeKdf``."""
    if _argon2_available():
        return PasscodeKdf(
            KDF_ARGON2ID, _ARGON2_MEMORY_KIB, _ARGON2_TIME, _ARGON2_LANES
        )
    return PasscodeKdf(KDF_SCRYPT, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)


def create_passcode_key(
    passcode: bytes, salt: QByteArray, kdf: PasscodeKdf
) -> td.AuthKey:
    """The wrap key for one passcode wrap (``CreatePasscodeKey`` plus kind 0)."""
    if kdf.kind == KDF_PBKDF2:
        return td.Storage.CreateLocalKey(salt, QByteArray(passcode))

    Expects(
        bool(passcode)
        and salt.size() >= PASSCODE_SALT_MIN_SIZE
        and kdf.costWithinLimits()
        and kdf.valid(),
        TDataKeyDataInvalid(f"Unusable passcode wrap parameters: {kdf}"),
    )

    if kdf.kind == KDF_ARGON2ID:
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError as e:
            raise TDataPasscodeKdfUnavailable(
                "This tdata passcode is protected with Argon2id; "
                "install it with: pip install opentele2[argon2]"
            ) from e
        # OpenSSL's ARGON2ID is version 0x13 with one thread.
        raw = hash_secret_raw(
            secret=passcode,
            salt=bytes(salt),
            time_cost=kdf.time,
            memory_cost=kdf.memory,
            parallelism=kdf.parallel,
            hash_len=td.AuthKey.kSize,
            type=Type.ID,
            version=0x13,
        )
    else:
        raw = hashlib.scrypt(
            passcode,
            salt=bytes(salt),
            n=kdf.memory,
            r=kdf.time,
            p=kdf.parallel,
            maxmem=_SCRYPT_MAX_MEM,
            dklen=td.AuthKey.kSize,
        )
    return td.AuthKey(raw)


def wrap_local_key(localKey: td.AuthKey, wrapKey: td.AuthKey) -> QByteArray:
    data = td.Storage.EncryptedDescriptor(td.AuthKey.kSize)
    localKey.write(data.stream)
    return td.Storage.PrepareEncrypted(data, wrapKey)


def unwrap_local_key(keyEncrypted: QByteArray, wrapKey: td.AuthKey) -> td.AuthKey:
    """Decrypt a wrapped local key; any failure is a wrong passcode."""
    try:
        inner = td.Storage.DecryptLocal(keyEncrypted, wrapKey)
    except OpenTeleException as e:
        raise TDataBadDecryptKey("Could not decrypt the local key") from e
    raw = inner.stream.readRawData(td.AuthKey.kSize)
    Expects(
        len(raw) == td.AuthKey.kSize and inner.stream.atEnd(),
        TDataBadDecryptKey("The decrypted local key has the wrong size"),
    )
    return td.AuthKey(raw)


def read_key_data(stream: QDataStream) -> tuple[KeyData, QByteArray]:
    """Parse a key file stream into its key data and encrypted accounts info."""
    data = KeyData()
    infoEncrypted = QByteArray()
    stream >> data.openSalt >> data.openKeyEncrypted >> infoEncrypted
    ExpectStreamStatus(stream, "Could not stream the key data")
    Expects(
        data.openSalt.size() == LOCAL_ENCRYPT_SALT_SIZE,
        TDataKeyDataInvalid(f"Bad salt in key data, size: {data.openSalt.size()}"),
    )

    if stream.atEnd():
        return data, infoEncrypted

    trailer = QByteArray()
    stream >> trailer
    ExpectStreamStatus(stream, "Could not stream the key data trailer")

    buffer = QBuffer()
    buffer.setBuffer(trailer)
    buffer.open(QIODevice.OpenModeFlag.ReadOnly)
    inner = QDataStream()
    inner.setDevice(buffer)
    inner.setVersion(QDataStream.Version.Qt_5_1)

    magic = inner.readUInt32()
    formatVersion = inner.readUInt32()
    data.committed = inner.readUInt32()
    wrapCount = inner.readUInt32()
    ExpectStreamStatus(inner, "Could not stream the key data trailer header")
    Expects(magic == KEY_DATA_MAGIC, TDataKeyDataInvalid("Bad key data trailer magic"))
    Expects(
        formatVersion <= KEY_DATA_FORMAT_VERSION,
        TDataKeyDataInvalid(f"Too new key data format: {formatVersion}"),
    )
    Expects(
        wrapCount <= MAX_WRAP_COUNT,
        TDataKeyDataInvalid(f"Bad key data wrap count: {wrapCount}"),
    )

    for _ in range(wrapCount):
        wrap = PasscodeWrap()
        wrap.kdf.kind = inner.readUInt32()
        wrap.generation = inner.readUInt32()
        wrap.kdf.memory = inner.readUInt32()
        wrap.kdf.time = inner.readUInt32()
        wrap.kdf.parallel = inner.readUInt32()
        inner >> wrap.salt >> wrap.keyEncrypted
        ExpectStreamStatus(inner, "Could not stream a key data wrap")
        Expects(
            wrap.salt.size() >= PASSCODE_SALT_MIN_SIZE,
            TDataKeyDataInvalid(f"Bad key data wrap salt size: {wrap.salt.size()}"),
        )
        Expects(
            all(w.generation != wrap.generation for w in data.passcodeWraps),
            TDataKeyDataInvalid(
                f"Duplicate key data wrap generation: {wrap.generation}"
            ),
        )
        data.passcodeWraps.append(wrap)

    data.legacy = False
    return data, infoEncrypted


def key_data_trailer(data: KeyData) -> QByteArray:
    """The fourth blob of a 7.3 key file (``WriteKeyData``)."""
    trailer = QByteArray()
    buffer = QBuffer()
    buffer.setBuffer(trailer)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    stream = QDataStream()
    stream.setDevice(buffer)
    stream.setVersion(QDataStream.Version.Qt_5_1)
    stream.writeUInt32(KEY_DATA_MAGIC)
    stream.writeUInt32(KEY_DATA_FORMAT_VERSION)
    stream.writeUInt32(data.committed)
    stream.writeUInt32(len(data.passcodeWraps))
    for wrap in data.passcodeWraps:
        stream.writeUInt32(wrap.kdf.kind)
        stream.writeUInt32(wrap.generation)
        stream.writeUInt32(wrap.kdf.memory)
        stream.writeUInt32(wrap.kdf.time)
        stream.writeUInt32(wrap.kdf.parallel)
        stream << wrap.salt << wrap.keyEncrypted
    buffer.close()
    return trailer


def open_local_key(data: KeyData, passcode: bytes) -> tuple[td.AuthKey, td.AuthKey]:
    """Recover ``(localKey, wrapKey)`` the way ``Domain::startModern`` does."""
    if data.legacy:
        wrapKey = td.Storage.CreateLocalKey(data.openSalt, QByteArray(passcode))
        return unwrap_local_key(data.openKeyEncrypted, wrapKey), wrapKey

    live = data.liveWraps()
    hasOpenWrap = not data.openKeyEncrypted.isEmpty()

    if passcode and len(live) == 1:
        wrap = live[0]
        wrapKey = create_passcode_key(passcode, wrap.salt, wrap.kdf)
        return unwrap_local_key(wrap.keyEncrypted, wrapKey), wrapKey

    if not hasOpenWrap:
        raise TDataBadDecryptKey(
            "The app lock is on, a passcode is needed"
            if not passcode
            else "No passcode wrap to open the local key with"
        )

    # A passcode typed for a tdata whose app lock is off still opens it.
    wrapKey = td.Storage.CreateLocalKey(data.openSalt, QByteArray())
    return unwrap_local_key(data.openKeyEncrypted, wrapKey), wrapKey
