from __future__ import annotations

import hashlib
import os
from ctypes import c_uint32 as uint32
from ctypes import sizeof
from typing import ClassVar

import tgcrypto

from ..exception import (
    Expects,
    ExpectStreamStatus,
    OpenTeleException,
    TDataBadDecryptedDataSize,
    TDataBadDecryptKey,
    TDataBadEncryptedDataSize,
    TDataInvalidCheckSum,
    TDataInvalidMagic,
    TFileNotFound,
)
from ..qt_compat import (
    QBuffer,
    QByteArray,
    QDataStream,
    QDir,
    QFile,
    QIODevice,
    QSysInfo,
)
from ..utils import APP_VERSION, TDF_MAGIC, BaseObject
from . import shared as td
from .configs import DcId, FileKey, ShiftedDcId, dbi

_AES_BLOCK_SIZE = 0x10
_AES_BLOCK_MASK = 0x0F
_PBKDF2_ITERATIONS = 100000
_PBKDF2_ITERATIONS_EMPTY = 1
_LEGACY_PBKDF2_ITERATIONS = 4000
_LEGACY_PBKDF2_ITERATIONS_EMPTY = 4
_TDF_FILE_SUFFIXES = ("s", "1", "0")


class Serialize(BaseObject):
    @staticmethod
    def bytearraySize(arr: QByteArray) -> int:
        return sizeof(uint32) + arr.size()

    @staticmethod
    def bytesSize(arr: bytes) -> int:
        return sizeof(uint32) + len(arr)

    @staticmethod
    def stringSize(arr: str) -> int:
        # QDataStream writes a QString as a byte length plus UTF-16 code units.
        return sizeof(uint32) + len(arr.encode("utf-16-be"))


class Storage(BaseObject):
    class ReadSettingsContext(BaseObject):
        def __init__(self) -> None:
            self.fallbackConfigLegacyDcOptions = td.MTP.DcOptions(
                td.MTP.Environment.Production
            )
            self.fallbackConfigLegacyChatSizeMax = 0
            self.fallbackConfigLegacySavedGifsLimit = 0
            self.fallbackConfigLegacyStickersRecentLimit = 0
            self.fallbackConfigLegacyStickersFavedLimit = 0
            self.fallbackConfigLegacyMegagroupSizeMax = 0
            self.fallbackConfigLegacyTxtDomainString = ""
            self.fallbackConfig = QByteArray()

            self.cacheTotalSizeLimit = 0
            self.cacheTotalTimeLimit = 0
            self.cacheBigFileTotalSizeLimit = 0
            self.cacheBigFileTotalTimeLimit = 0

            self.themeKeyLegacy = FileKey(0)
            self.themeKeyDay = FileKey(0)
            self.themeKeyNight = FileKey(0)
            self.backgroundKeyDay = FileKey(0)
            self.backgroundKeyNight = FileKey(0)

            self.backgroundKeysRead = False
            self.tileDay = False
            self.tileNight = True
            self.tileRead = False

            self.langPackKey = FileKey(0)
            self.languagesKey = FileKey(0)

            self.mtpAuthorization = QByteArray()
            self.mtpLegacyKeys: list[td.AuthKey] = []

            self.mtpLegacyMainDcId = 0
            self.mtpLegacyUserId = 0
            self.legacyRead = False

    class FileReadDescriptor(BaseObject):
        def __init__(self) -> None:
            self.__version = 0
            self.__data = QByteArray()
            self.__buffer = QBuffer()
            self.__stream = QDataStream()

        @property
        def data(self) -> QByteArray:
            return self.__data

        @data.setter
        def data(self, value: QByteArray) -> None:
            self.__data = value

        @property
        def version(self) -> int:
            return self.__version

        @version.setter
        def version(self, value: int) -> None:
            self.__version = value

        @property
        def buffer(self) -> QBuffer:
            return self.__buffer

        @property
        def stream(self) -> QDataStream:
            return self.__stream

    class EncryptedDescriptor(BaseObject):
        def __init__(self, size: int | None = None) -> None:
            self.__data = QByteArray()
            self.__buffer = QBuffer()
            self.__stream = QDataStream()

            if size:
                fullSize = Storage._pad_to_block(4 + size)
                self.__data.reserve(fullSize)
                self.__data.resize(4)
                self.__buffer.setBuffer(self.__data)
                self.__buffer.open(QIODevice.OpenModeFlag.WriteOnly)
                self.__buffer.seek(4)
                self.__stream.setDevice(self.__buffer)
                self.__stream.setVersion(QDataStream.Version.Qt_5_1)

        def finish(self) -> None:
            if self.__stream.device():
                self.__stream.setDevice(None)
            if self.__buffer.isOpen():
                self.__buffer.close()
            self.__buffer.setBuffer(None)

        @property
        def data(self) -> QByteArray:
            return self.__data

        @data.setter
        def data(self, value: QByteArray) -> None:
            self.__data = value

        @property
        def buffer(self) -> QBuffer:
            return self.__buffer

        @property
        def stream(self) -> QDataStream:
            return self.__stream

    class FileWriteDescriptor(BaseObject):
        def __init__(self, fileName: str, basePath: str, sync: bool = False) -> None:
            self.fileName = fileName
            self.basePath = basePath
            self.sync = sync
            self._init(fileName)

        def _init(self, fileName: str) -> None:
            self.base = Storage.PathJoin(self.basePath, fileName)
            self.safeData = QByteArray()
            self.buffer = QBuffer()
            self.buffer.setBuffer(self.safeData)

            result = self.buffer.open(QIODevice.OpenModeFlag.WriteOnly)
            Expects(result, "Can not open buffer, something went wrong")

            self.stream = QDataStream()
            self.stream.setDevice(self.buffer)

            self.md5 = b""
            self.fullSize = 0

        def writeData(self, data: QByteArray) -> None:
            Expects(self.stream.device() is not None, "stream.device is missing")

            self.stream << data
            length = 0xFFFFFFFF if data.isNull() else data.size()

            if QSysInfo.Endian.ByteOrder != QSysInfo.Endian.BigEndian:
                length = (
                    ((length & 0x000000FF) << 24)
                    | ((length & 0x0000FF00) << 8)
                    | ((length & 0x00FF0000) >> 8)
                    | ((length & 0xFF000000) >> 24)
                )

            self.md5 += length.to_bytes(4, "little")
            self.md5 += data.data()
            self.fullSize += 4 + data.size()

        def writeEncrypted(
            self, data: Storage.EncryptedDescriptor, key: td.AuthKey
        ) -> None:
            self.writeData(Storage.PrepareEncrypted(data, key))

        def finish(self) -> None:
            if not self.stream.device():
                return
            self.stream.setDevice(None)

            self.md5 += self.fullSize.to_bytes(4, "little")
            self.md5 += APP_VERSION.to_bytes(4, "little")
            self.md5 += TDF_MAGIC
            self.md5 = hashlib.md5(self.md5).digest()

            self.buffer.close()

            finalData: bytes = self.safeData.data() + self.md5
            Storage.WriteFile(self.fileName, self.basePath, finalData)

    @staticmethod
    def _pad_to_block(size: int) -> int:
        if size & _AES_BLOCK_MASK:
            size += _AES_BLOCK_SIZE - (size & _AES_BLOCK_MASK)
        return size

    @staticmethod
    def PrepareEncrypted(data: EncryptedDescriptor, key: td.AuthKey) -> QByteArray:
        data.finish()

        toEncrypt = QByteArray(data.data)

        size = toEncrypt.size()
        fullSize = Storage._pad_to_block(size)
        if fullSize != size:
            # tdesktop fills the padding with random bytes, not zeros.
            toEncrypt += os.urandom(fullSize - size)

        toEncrypt = QByteArray(size.to_bytes(4, "little")) + toEncrypt[4:]

        hashData = hashlib.sha1(bytes(toEncrypt))
        encrypted = QByteArray(hashData.digest())

        encrypted.resize(_AES_BLOCK_SIZE + fullSize)

        encrypted = encrypted[:_AES_BLOCK_SIZE] + Storage.aesEncryptLocal(
            toEncrypt, key, encrypted
        )

        return encrypted

    @staticmethod
    def WriteFile(fileName: str, basePath: str, data: bytes) -> bool:
        dir = QDir(basePath)
        if not dir.exists():
            dir.mkpath(basePath)

        file = QFile(Storage.PathJoin(basePath, fileName + "s"))
        if file.open(QIODevice.OpenModeFlag.WriteOnly):
            file.write(TDF_MAGIC)
            file.write(APP_VERSION.to_bytes(4, "little"))
            file.write(data)
            file.close()
            return True

        raise OpenTeleException("Failed to write file to disk")

    @staticmethod
    def ReadFile(fileName: str, basePath: str) -> FileReadDescriptor:
        tries_exception: OpenTeleException | None = None
        for suffix in _TDF_FILE_SUFFIXES:
            try:
                file = QFile(Storage.PathJoin(basePath, fileName + suffix))
                if not file.open(QIODevice.OpenModeFlag.ReadOnly):
                    # An absent sibling suffix must not mask an integrity
                    # failure already seen on a file that does exist.
                    if tries_exception is None:
                        tries_exception = TFileNotFound(f"Could not open {fileName}")
                    continue

                magic = file.read(4)
                if magic != TDF_MAGIC:
                    tries_exception = TDataInvalidMagic(
                        f"Invalid magic {magic!r} in file {fileName}"
                    )
                    file.close()
                    continue

                version = int.from_bytes(file.read(4), "little")
                bytesdata = QByteArray(file.read(file.size()))
                dataSize = bytesdata.size() - 16

                check_md5_data = bytesdata.data()[:dataSize]
                check_md5_data += int(dataSize).to_bytes(4, "little")
                check_md5_data += int(version).to_bytes(4, "little")
                check_md5_data += magic
                check_md5_hash = hashlib.md5(check_md5_data)

                md5 = bytesdata.data()[dataSize:]

                if check_md5_hash.hexdigest() != md5.hex():
                    tries_exception = TDataInvalidCheckSum(
                        "Invalid checksum "
                        f"{check_md5_hash.hexdigest()} in file {fileName}"
                    )
                    file.close()
                    continue

                result = Storage.FileReadDescriptor()
                result.version = version

                bytesdata.resize(dataSize)
                result.data = bytesdata

                result.buffer.setBuffer(result.data)
                result.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
                result.stream.setDevice(result.buffer)
                result.stream.setVersion(QDataStream.Version.Qt_5_1)

                file.close()
                return result
            except OSError:
                pass

        raise (
            tries_exception
            if tries_exception
            else TFileNotFound(f"Could not open {fileName}")
        )

    @staticmethod
    def _resetDescriptor(result: FileReadDescriptor) -> None:
        result.stream.setDevice(None)
        if result.buffer.isOpen():
            result.buffer.close()
        result.buffer.setBuffer(None)

    @staticmethod
    def ReadEncryptedFile(
        fileName: str, basePath: str, authKey: td.AuthKey
    ) -> FileReadDescriptor:
        result = Storage.ReadFile(fileName, basePath)
        encrypted = QByteArray()
        result.stream >> encrypted

        try:
            data = Storage.DecryptLocal(encrypted, authKey)
        except OpenTeleException:
            Storage._resetDescriptor(result)
            result.data = QByteArray()
            result.version = 0
            raise

        Storage._resetDescriptor(result)
        result.data = data.data

        result.buffer.setBuffer(result.data)
        result.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
        result.buffer.seek(data.buffer.pos())
        result.stream.setDevice(result.buffer)
        result.stream.setVersion(QDataStream.Version.Qt_5_1)

        return result

    _LEGACY_INT32_SETTINGS: ClassVar[dict[int, str]] = {
        dbi.ChatSizeMaxOld: "fallbackConfigLegacyChatSizeMax",
        dbi.SavedGifsLimitOld: "fallbackConfigLegacySavedGifsLimit",
        dbi.StickersRecentLimitOld: "fallbackConfigLegacyStickersRecentLimit",
        dbi.StickersFavedLimitOld: "fallbackConfigLegacyStickersFavedLimit",
        dbi.MegagroupSizeMaxOld: "fallbackConfigLegacyMegagroupSizeMax",
    }

    @staticmethod
    def ReadSetting(
        blockId: int, stream: QDataStream, _version: int, context: ReadSettingsContext
    ) -> bool:
        if blockId == dbi.DcOptionOldOld:
            dcId = DcId(stream.readUInt32())
            stream.readQString()
            ip = stream.readQString()
            port = stream.readUInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyDcOptions.constructAddOne(
                dcId, td.MTP.DcOptions.Flag(0), ip, port, b""
            )
            context.legacyRead = True

        elif blockId == dbi.DcOptionOld:
            dcIdWithShift = ShiftedDcId(stream.readUInt32())
            flags = td.MTP.DcOptions.Flag(stream.readInt32())
            ip = stream.readQString()
            port = stream.readUInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyDcOptions.constructAddOne(
                dcIdWithShift, flags, ip, port, b""
            )
            context.legacyRead = True

        elif blockId == dbi.DcOptionsOld:
            serialized = QByteArray()
            stream >> serialized
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyDcOptions.constructFromSerialized(serialized)
            context.legacyRead = True

        elif blockId == dbi.ApplicationSettings:
            serialized = QByteArray()
            stream >> serialized
            ExpectStreamStatus(stream)

        elif blockId in Storage._LEGACY_INT32_SETTINGS:
            value = stream.readInt32()
            ExpectStreamStatus(stream)

            setattr(context, Storage._LEGACY_INT32_SETTINGS[blockId], value)
            context.legacyRead = True

        elif blockId == dbi.User:
            userId = stream.readInt32()
            dcId = DcId(stream.readUInt32())
            ExpectStreamStatus(stream)

            context.mtpLegacyMainDcId = dcId
            context.mtpLegacyUserId = userId

        elif blockId == dbi.Key:
            dcId = DcId(stream.readInt32())
            key = stream.readRawData(256)
            ExpectStreamStatus(stream)

            context.mtpLegacyKeys.append(
                td.AuthKey(key, td.AuthKeyType.ReadFromFile, dcId)
            )

        elif blockId == dbi.MtpAuthorization:
            serialized = QByteArray()
            stream >> serialized
            ExpectStreamStatus(stream)

            context.mtpAuthorization = serialized

        return True

    @staticmethod
    def CreateLocalKey(
        salt: QByteArray, passcode: QByteArray | None = None
    ) -> td.AuthKey:
        if passcode is None:
            passcode = QByteArray()
        hashKey = hashlib.sha512(bytes(salt))
        hashKey.update(bytes(passcode))
        hashKey.update(bytes(salt))

        iterationsCount = (
            _PBKDF2_ITERATIONS_EMPTY if passcode.isEmpty() else _PBKDF2_ITERATIONS
        )
        return td.AuthKey(
            hashlib.pbkdf2_hmac(
                "sha512", hashKey.digest(), bytes(salt), iterationsCount, 256
            )
        )

    @staticmethod
    def CreateLegacyLocalKey(
        salt: QByteArray, passcode: QByteArray | None = None
    ) -> td.AuthKey:
        if passcode is None:
            passcode = QByteArray()
        iterationsCount = (
            _LEGACY_PBKDF2_ITERATIONS_EMPTY
            if passcode.isEmpty()
            else _LEGACY_PBKDF2_ITERATIONS
        )
        return td.AuthKey(
            hashlib.pbkdf2_hmac(
                "sha1", passcode.data(), salt.data(), iterationsCount, 256
            )
        )

    @staticmethod
    def aesEncryptLocal(
        src: QByteArray, authKey: td.AuthKey, key128: QByteArray
    ) -> QByteArray:
        aesKey, aesIv = authKey.prepareAES_oldmtp(bytes(key128), False)
        return QByteArray(tgcrypto.ige256_encrypt(bytes(src), aesKey, aesIv))

    @staticmethod
    def aesDecryptLocal(
        src: QByteArray, authKey: td.AuthKey, key128: QByteArray
    ) -> QByteArray:
        aesKey, aesIv = authKey.prepareAES_oldmtp(bytes(key128), False)
        return QByteArray(tgcrypto.ige256_decrypt(bytes(src), aesKey, aesIv))

    @staticmethod
    def DecryptLocal(encrypted: QByteArray, authKey: td.AuthKey) -> EncryptedDescriptor:
        encryptedSize = encrypted.size()
        if (encryptedSize <= _AES_BLOCK_SIZE) or (encryptedSize & _AES_BLOCK_MASK):
            raise TDataBadEncryptedDataSize(f"Bad encrypted part size: {encryptedSize}")

        encryptedKey = encrypted[:_AES_BLOCK_SIZE]
        encryptedData = encrypted[_AES_BLOCK_SIZE:]

        decrypted = Storage.aesDecryptLocal(encryptedData, authKey, encryptedKey)
        checkHash = hashlib.sha1(bytes(decrypted)).digest()[:_AES_BLOCK_SIZE]
        if checkHash != encryptedKey:
            raise TDataBadDecryptKey(
                "Bad decrypt key, data not decrypted - incorrect password?"
            )

        fullLen = encryptedSize - _AES_BLOCK_SIZE
        dataLen = int.from_bytes(bytes(decrypted[:4]), "little")
        if (
            (dataLen > decrypted.size())
            or (dataLen <= fullLen - _AES_BLOCK_SIZE)
            or (dataLen < 4)
        ):
            raise TDataBadDecryptedDataSize(
                "Bad decrypted part size: "
                f"{encryptedSize}, fullLen: {fullLen}, "
                f"decrypted size: {len(decrypted)}"
            )

        decrypted.resize(dataLen)
        result = Storage.EncryptedDescriptor()
        result.data = decrypted

        result.buffer.setBuffer(result.data)
        result.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
        result.buffer.seek(4)
        result.stream.setDevice(result.buffer)
        result.stream.setVersion(QDataStream.Version.Qt_5_1)

        return result

    @staticmethod
    def ComposeDataString(dataName: str, index: int) -> str:
        result = dataName.replace("#", "")
        if index > 0:
            result += f"#{index + 1}"
        return result

    @staticmethod
    def ComputeDataNameKey(dataName: str) -> int:
        md5 = hashlib.md5(dataName.encode("utf-8")).digest()
        return int.from_bytes(md5, "little")

    @staticmethod
    def ToFilePart(val: int) -> str:
        result = ""
        for i in range(0x10):
            v = val & 0xF
            if v < 0x0A:
                result += chr(ord("0") + v)
            else:
                result += chr(ord("A") + (v - 0x0A))
            val >>= 4
        return result

    @staticmethod
    def RandomGenerate(size: int) -> QByteArray:
        return QByteArray(os.urandom(size))

    @staticmethod
    def GetAbsolutePath(path: str | None = None) -> str:
        if path is None or path == "":
            path = os.getcwd()
        return os.path.abspath(path)

    @staticmethod
    def PathJoin(path: str, filename: str) -> str:
        return os.path.join(path, filename)
