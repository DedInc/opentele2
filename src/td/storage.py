from __future__ import annotations

from ..utils import APP_VERSION, BaseObject, TDF_MAGIC
from ..exception import (
    Expects,
    ExpectStreamStatus,
    OpenTeleException,
    TDataBadDecryptKey,
    TDataBadDecryptedDataSize,
    TDataBadEncryptedDataSize,
    TDataInvalidCheckSum,
    TDataInvalidMagic,
    TFileNotFound,
)
from .configs import DcId, FileKey, ShiftedDcId, dbi
from . import shared as td
from ctypes import sizeof, c_uint32 as uint32, c_ushort as ushort
from ..qt_compat import (
    QBuffer,
    QByteArray,
    QDataStream,
    QDir,
    QFile,
    QIODevice,
    QSysInfo,
)
import typing

import hashlib
import os
import tgcrypto

_AES_BLOCK_SIZE = 0x10
_AES_BLOCK_MASK = 0x0F
_PBKDF2_ITERATIONS = 100000
_PBKDF2_ITERATIONS_EMPTY = 1
_TDF_FILE_SUFFIXES = ("s", "1", "0")


class Serialize(BaseObject):
    @staticmethod
    def bytearraySize(arr: QByteArray):
        return sizeof(uint32) + arr.size()

    @staticmethod
    def bytesSize(arr: bytes):
        return sizeof(uint32) + len(arr)

    @staticmethod
    def stringSize(arr: str):
        return sizeof(uint32) + len(arr) + sizeof(ushort)


class Storage(BaseObject):
    class ReadSettingsContext(BaseObject):  # pragma: no cover
        def __init__(self) -> None:
            self.fallbackConfigLegacyDcOptions = td.MTP.DcOptions(
                td.MTP.Environment.Production
            )
            self.fallbackConfigLegacyChatSizeMax = 0
            self.fallbackConfigLegacySavedGifsLimit = 0
            self.fallbackConfigLegacyStickersRecentLimit = 0
            self.fallbackConfigLegacyStickersFavedLimit = 0
            self.fallbackConfigLegacyMegagroupSizeMax = 0
            self.fallbackConfigLegacyTxtDomainString = str()
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
            self.mtpLegacyKeys: typing.List[td.AuthKey] = []

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
        def data(self, value):
            self.__data = value

        @property
        def version(self) -> int:
            return self.__version

        @version.setter
        def version(self, value):
            self.__version = value

        @property
        def buffer(self) -> QBuffer:
            return self.__buffer

        @property
        def stream(self) -> QDataStream:
            return self.__stream

    class EncryptedDescriptor(BaseObject):
        def __init__(self, size: int = None) -> None:
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
                self.__stream.setDevice(None)  # type: ignore
            if self.__buffer.isOpen():
                self.__buffer.close()
            self.__buffer.setBuffer(None)  # type: ignore

        @property
        def data(self) -> QByteArray:
            return self.__data

        @data.setter
        def data(self, value):
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

        def _init(self, fileName: str):
            self.base = Storage.PathJoin(self.basePath, fileName)
            self.safeData = QByteArray()
            self.buffer = QBuffer()
            self.buffer.setBuffer(self.safeData)

            result = self.buffer.open(QIODevice.OpenModeFlag.WriteOnly)
            Expects(result, "Can not open buffer, something went wrong")

            self.stream = QDataStream()
            self.stream.setDevice(self.buffer)

            self.md5 = bytes()
            self.fullSize = 0

        def writeData(self, data: QByteArray):
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

        def writeEncrypted(self, data: Storage.EncryptedDescriptor, key: td.AuthKey):
            self.writeData(Storage.PrepareEncrypted(data, key))

        def finish(self):
            if not self.stream.device():
                return
            self.stream.setDevice(None)  # type: ignore

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
            toEncrypt.resize(fullSize)

        toEncrypt = QByteArray(size.to_bytes(4, "little")) + toEncrypt[4:]

        hashData = hashlib.sha1(bytes(toEncrypt))
        encrypted = QByteArray(hashData.digest())

        encrypted.resize(_AES_BLOCK_SIZE + fullSize)

        encrypted = encrypted[:_AES_BLOCK_SIZE] + Storage.aesEncryptLocal(
            toEncrypt, key, encrypted
        )

        return encrypted

    @staticmethod
    def WriteFile(fileName: str, basePath: str, data: bytes):
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
        tries_exception = None
        for suffix in _TDF_FILE_SUFFIXES:
            try:
                file = QFile(Storage.PathJoin(basePath, fileName + suffix))
                if not file.open(QIODevice.OpenModeFlag.ReadOnly):
                    tries_exception = TFileNotFound(f"Could not open {fileName}")
                    continue

                magic = file.read(4)
                if magic != TDF_MAGIC:
                    tries_exception = TDataInvalidMagic(
                        f"Invalid magic {magic} in file {fileName}"
                    )
                    file.close()
                    continue

                version = int.from_bytes(file.read(4), "little")
                bytesdata = QByteArray(file.read(file.size()))
                dataSize = bytesdata.size() - 16

                check_md5 = bytesdata.data()[:dataSize]
                check_md5 += int(dataSize).to_bytes(4, "little")
                check_md5 += int(version).to_bytes(4, "little")
                check_md5 += magic
                check_md5 = hashlib.md5(check_md5)

                md5 = bytesdata.data()[dataSize:]

                if check_md5.hexdigest() != md5.hex():
                    tries_exception = TDataInvalidCheckSum(
                        f"Invalid checksum {check_md5.hexdigest()} in file {fileName}"
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
            except IOError:
                pass

        raise (
            tries_exception
            if tries_exception
            else TFileNotFound(f"Could not open {fileName}")
        )

    @staticmethod
    def _resetDescriptor(result: FileReadDescriptor) -> None:
        """Reset a FileReadDescriptor's stream/buffer state."""
        result.stream.setDevice(None)  # type: ignore
        if result.buffer.isOpen():
            result.buffer.close()
        result.buffer.setBuffer(None)  # type: ignore

    @staticmethod
    def ReadEncryptedFile(
        fileName: str, basePath: str, authKey: td.AuthKey
    ) -> FileReadDescriptor:
        result = Storage.ReadFile(fileName, basePath)
        encrypted = QByteArray()
        result.stream >> encrypted

        try:
            data = Storage.DecryptLocal(encrypted, authKey)
        except OpenTeleException as e:
            Storage._resetDescriptor(result)
            result.data = QByteArray()
            result.version = 0
            raise e

        Storage._resetDescriptor(result)
        result.data = data.data

        result.buffer.setBuffer(result.data)
        result.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
        result.buffer.seek(data.buffer.pos())
        result.stream.setDevice(result.buffer)
        result.stream.setVersion(QDataStream.Version.Qt_5_1)

        return result

    # Mapping of legacy int32-read settings to their context attribute names
    _LEGACY_INT32_SETTINGS = {
        dbi.ChatSizeMaxOld: "fallbackConfigLegacyChatSizeMax",
        dbi.SavedGifsLimitOld: "fallbackConfigLegacySavedGifsLimit",
        dbi.StickersRecentLimitOld: "fallbackConfigLegacyStickersRecentLimit",
        dbi.StickersFavedLimitOld: "fallbackConfigLegacyStickersFavedLimit",
        dbi.MegagroupSizeMaxOld: "fallbackConfigLegacyMegagroupSizeMax",
    }

    @staticmethod
    def ReadSetting(
        blockId: int, stream: QDataStream, version: int, context: ReadSettingsContext
    ) -> bool:  # pragma: no cover
        if blockId == dbi.DcOptionOldOld:
            dcId = DcId(stream.readUInt32())
            stream.readQString()  # host (unused)
            ip = stream.readQString()
            port = stream.readUInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyDcOptions.constructAddOne(
                dcId, td.MTP.DcOptions.Flag(0), ip, port, bytes()
            )
            context.legacyRead = True

        elif blockId == dbi.DcOptionOld:
            dcIdWithShift = ShiftedDcId(stream.readUInt32())
            flags = td.MTP.DcOptions.Flag(stream.readInt32())
            ip = stream.readQString()
            port = stream.readUInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyDcOptions.constructAddOne(
                dcIdWithShift, flags, ip, port, bytes()
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
            dcId = stream.readUInt32()
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
        salt: QByteArray, passcode: QByteArray = QByteArray()
    ) -> td.AuthKey:
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
        salt: QByteArray, passcode: QByteArray = QByteArray()
    ) -> td.AuthKey:
        iterationsCount = (
            _PBKDF2_ITERATIONS_EMPTY if passcode.isEmpty() else _PBKDF2_ITERATIONS
        )
        return td.AuthKey(
            hashlib.pbkdf2_hmac(
                "sha512", passcode.data(), salt.data(), iterationsCount, 256
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
                f"Bad decrypted part size: {encryptedSize}, fullLen: {fullLen}, decrypted size: {len(decrypted)}"
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
    def ComposeDataString(dataName: str, index: int):
        result = dataName.replace("#", "")
        if index > 0:
            result += f"#{index + 1}"
        return result

    @staticmethod
    def ComputeDataNameKey(dataName: str) -> int:
        md5 = hashlib.md5(dataName.encode("utf-8")).digest()
        return int.from_bytes(md5, "little")

    @staticmethod
    def ToFilePart(val: int):
        result = str()
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
    def GetAbsolutePath(path: str = None) -> str:
        if path is None or path == "":
            path = os.getcwd()
        return os.path.abspath(path)

    @staticmethod
    def PathJoin(path: str, filename: str) -> str:
        return os.path.join(path, filename)
