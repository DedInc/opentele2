"""
Pure Python replacements for PyQt5.QtCore classes used for binary serialization.

Replaces: QByteArray, QDataStream, QBuffer, QIODevice, QFile, QDir, QSysInfo
"""

from __future__ import annotations

import builtins
import os
import struct
import sys
import typing


class QIODevice:
    class OpenModeFlag:
        NotOpen = 0
        ReadOnly = 1
        WriteOnly = 2
        ReadWrite = 3

    class OpenMode:
        pass


class QByteArray:
    """Pure Python replacement for Qt's QByteArray.

    Wraps a bytearray internally with a _null flag to distinguish
    QByteArray() (null) from QByteArray(b"") (empty but non-null).
    """

    __slots__ = ("_data", "_null")

    def __init__(self, data=None):
        if data is None:
            self._data = bytearray()
            self._null = True
        elif isinstance(data, QByteArray):
            self._data = bytearray(data._data)
            self._null = data._null
        elif isinstance(data, (bytes, bytearray, memoryview)):
            self._data = bytearray(data)
            self._null = False
        elif isinstance(data, int):
            self._data = bytearray(data)
            self._null = False
        else:
            self._data = bytearray(data)
            self._null = False

    def size(self) -> int:
        return len(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def data(self) -> bytes:
        return bytes(self._data)

    def isEmpty(self) -> bool:
        return len(self._data) == 0

    def isNull(self) -> bool:
        return self._null

    def resize(self, size: int) -> None:
        cur = len(self._data)
        if size < cur:
            del self._data[size:]
        elif size > cur:
            self._data.extend(b"\x00" * (size - cur))
        self._null = False

    def reserve(self, size: int) -> None:
        pass  # no-op in pure Python

    def clear(self) -> None:
        self._data.clear()
        self._null = True

    def __getitem__(self, key):
        result = self._data[key]
        if isinstance(key, slice):
            return QByteArray(result)
        return result

    def __add__(self, other) -> QByteArray:
        if isinstance(other, QByteArray):
            return QByteArray(self._data + other._data)
        if isinstance(other, (bytes, bytearray)):
            return QByteArray(self._data + other)
        return NotImplemented

    def __radd__(self, other) -> QByteArray:
        if isinstance(other, (bytes, bytearray)):
            return QByteArray(other + self._data)
        return NotImplemented

    def __iadd__(self, other) -> QByteArray:
        if isinstance(other, QByteArray):
            self._data.extend(other._data)
        elif isinstance(other, (bytes, bytearray)):
            self._data.extend(other)
        else:
            return NotImplemented
        self._null = False
        return self

    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def __bool__(self) -> bool:
        return len(self._data) > 0

    def __eq__(self, other) -> bool:
        if isinstance(other, QByteArray):
            return self._data == other._data
        if isinstance(other, (bytes, bytearray)):
            return bytes(self._data) == bytes(other)
        return NotImplemented

    def __ne__(self, other) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self) -> int:
        return hash(bytes(self._data))

    def __repr__(self) -> str:
        return f"QByteArray({bytes(self._data)!r})"

    # Python 3.12+ buffer protocol support
    if sys.version_info >= (3, 12):

        def __buffer__(self, flags):
            return memoryview(self._data)


class QBuffer:
    """Pure Python replacement for Qt's QBuffer.

    In-memory seekable I/O device operating directly on a QByteArray's
    internal bytearray.
    """

    def __init__(self):
        self._buffer: typing.Optional[QByteArray] = None
        self._pos: int = 0
        self._open: bool = False
        self._mode = QIODevice.OpenModeFlag.NotOpen

    def setBuffer(self, buf: typing.Optional[QByteArray]) -> None:
        self._buffer = buf
        self._pos = 0

    def open(self, mode) -> bool:
        if self._buffer is None:
            return False
        self._open = True
        self._mode = mode
        self._pos = 0
        return True

    def close(self) -> None:
        self._open = False

    def isOpen(self) -> bool:
        return self._open

    def seek(self, pos: int) -> bool:
        self._pos = pos
        return True

    def pos(self) -> int:
        return self._pos

    def atEnd(self) -> bool:
        if self._buffer is None:
            return True
        return self._pos >= len(self._buffer._data)

    def size(self) -> int:
        if self._buffer is None:
            return 0
        return len(self._buffer._data)

    def read(self, n: int) -> bytes:
        if self._buffer is None:
            return b""
        data = bytes(self._buffer._data[self._pos : self._pos + n])
        self._pos += len(data)
        return data

    def write(self, data) -> int:
        if self._buffer is None:
            return -1
        if isinstance(data, QByteArray):
            raw = data._data
        elif isinstance(data, (bytes, bytearray)):
            raw = data
        else:
            raw = bytes(data)
        end = self._pos + len(raw)
        # Extend buffer if writing past end
        if end > len(self._buffer._data):
            self._buffer._data.extend(b"\x00" * (end - len(self._buffer._data)))
        self._buffer._data[self._pos : self._pos + len(raw)] = raw
        self._pos = end
        self._buffer._null = False
        return len(raw)


class QDataStream:
    """Pure Python replacement for Qt's QDataStream.

    Binary serialization stream using big-endian byte order (matching Qt's default).
    Reads/writes through a QBuffer device or directly from/to a QByteArray.
    """

    class FloatingPointPrecision:
        SinglePrecision = 0
        DoublePrecision = 1

    class Status:
        Ok = 0
        ReadPastEnd = 1
        ReadCorruptData = 2
        WriteFailed = 3

    class ByteOrder:
        BigEndian = 0
        LittleEndian = 1

    class Version:
        Qt_5_1 = 16

    def __init__(self, data=None, mode=None):
        self._device: typing.Optional[QBuffer] = None
        self._status: int = QDataStream.Status.Ok
        self._version: int = 0
        self._internal_buffer: typing.Optional[QBuffer] = None

        if data is not None and isinstance(data, QByteArray):
            self._internal_buffer = QBuffer()
            self._internal_buffer.setBuffer(data)
            if mode is not None:
                self._internal_buffer.open(mode)
            else:
                self._internal_buffer.open(QIODevice.OpenModeFlag.ReadOnly)
            self._device = self._internal_buffer
        elif data is not None and isinstance(data, QBuffer):
            self._device = data

    def setDevice(self, device: typing.Optional[QBuffer]) -> None:
        self._device = device

    def device(self) -> typing.Optional[QBuffer]:
        return self._device

    def setVersion(self, v: int) -> None:
        self._version = v

    def version(self) -> int:
        return self._version

    def status(self) -> int:
        return self._status

    def setStatus(self, status: int) -> None:
        self._status = status

    def resetStatus(self) -> None:
        self._status = QDataStream.Status.Ok

    def atEnd(self) -> bool:
        if self._device is None:
            return True
        return self._device.atEnd()

    def _read(self, n: int) -> bytes:
        if self._device is None:
            self._status = QDataStream.Status.ReadPastEnd
            return b""
        data = self._device.read(n)
        if len(data) < n:
            self._status = QDataStream.Status.ReadPastEnd
        return data

    def _write(self, data: bytes) -> int:
        if self._device is None:
            self._status = QDataStream.Status.WriteFailed
            return 0
        result = self._device.write(data)
        if result != len(data):
            self._status = QDataStream.Status.WriteFailed
        return result

    # --- Integer read/write ---

    def readInt8(self) -> int:
        data = self._read(1)
        if len(data) < 1:
            return 0
        return struct.unpack(">b", data)[0]

    def writeInt8(self, i: int) -> None:
        self._write(struct.pack(">b", i))

    def readUInt8(self) -> int:
        data = self._read(1)
        if len(data) < 1:
            return 0
        return struct.unpack(">B", data)[0]

    def writeUInt8(self, i: int) -> None:
        self._write(struct.pack(">B", i))

    def readInt16(self) -> int:
        data = self._read(2)
        if len(data) < 2:
            return 0
        return struct.unpack(">h", data)[0]

    def writeInt16(self, i: int) -> None:
        self._write(struct.pack(">h", i))

    def readUInt16(self) -> int:
        data = self._read(2)
        if len(data) < 2:
            return 0
        return struct.unpack(">H", data)[0]

    def writeUInt16(self, i: int) -> None:
        self._write(struct.pack(">H", i))

    def readInt32(self) -> int:
        data = self._read(4)
        if len(data) < 4:
            return 0
        return struct.unpack(">i", data)[0]

    def writeInt32(self, i: int) -> None:
        self._write(struct.pack(">i", i))

    def readUInt32(self) -> int:
        data = self._read(4)
        if len(data) < 4:
            return 0
        return struct.unpack(">I", data)[0]

    def writeUInt32(self, i: int) -> None:
        self._write(struct.pack(">I", i))

    def readInt64(self) -> int:
        data = self._read(8)
        if len(data) < 8:
            return 0
        return struct.unpack(">q", data)[0]

    def writeInt64(self, i: int) -> None:
        self._write(struct.pack(">q", i))

    def readUInt64(self) -> int:
        data = self._read(8)
        if len(data) < 8:
            return 0
        return struct.unpack(">Q", data)[0]

    def writeUInt64(self, i: int) -> None:
        self._write(struct.pack(">Q", i))

    def readInt(self) -> int:
        return self.readInt32()

    def writeInt(self, i: int) -> None:
        self.writeInt32(i)

    # --- Float read/write ---

    def readFloat(self) -> float:
        data = self._read(4)
        if len(data) < 4:
            return 0.0
        return struct.unpack(">f", data)[0]

    def writeFloat(self, f: float) -> None:
        self._write(struct.pack(">f", f))

    def readDouble(self) -> float:
        data = self._read(8)
        if len(data) < 8:
            return 0.0
        return struct.unpack(">d", data)[0]

    def writeDouble(self, f: float) -> None:
        self._write(struct.pack(">d", f))

    def readBool(self) -> bool:
        data = self._read(1)
        if len(data) < 1:
            return False
        return data[0] != 0

    def writeBool(self, b: bool) -> None:
        self._write(b"\x01" if b else b"\x00")

    # --- Raw data ---

    def readRawData(self, length: int) -> bytes:
        return self._read(length)

    def writeRawData(self, data) -> int:
        if isinstance(data, QByteArray):
            raw = bytes(data._data)
        elif isinstance(data, (bytes, bytearray, memoryview)):
            raw = bytes(data)
        else:
            raw = bytes(data)
        return self._write(raw)

    # --- QString ---

    def readQString(self) -> str:
        length_data = self._read(4)
        if len(length_data) < 4:
            return ""
        length = struct.unpack(">I", length_data)[0]
        if length == 0xFFFFFFFF:
            return ""
        raw = self._read(length)
        return raw.decode("utf-16-be")

    def writeQString(self, s: typing.Optional[str]) -> None:
        if s is None:
            self._write(struct.pack(">I", 0xFFFFFFFF))
            return
        encoded = s.encode("utf-16-be")
        self._write(struct.pack(">I", len(encoded)))
        self._write(encoded)

    # --- QByteArray serialization via << and >> operators ---

    def __lshift__(self, other: QByteArray) -> QDataStream:
        """Write QByteArray to stream: stream << qba"""
        if not isinstance(other, QByteArray):
            return NotImplemented
        if other.isNull():
            self._write(struct.pack(">I", 0xFFFFFFFF))
        else:
            self._write(struct.pack(">I", other.size()))
            if other.size() > 0:
                self._write(bytes(other._data))
        return self

    def __rshift__(self, other: QByteArray) -> QDataStream:
        """Read QByteArray from stream: stream >> qba (modifies qba in-place)"""
        if not isinstance(other, QByteArray):
            return NotImplemented
        length_data = self._read(4)
        if len(length_data) < 4:
            return self
        length = struct.unpack(">I", length_data)[0]
        if length == 0xFFFFFFFF:
            other._data.clear()
            other._null = True
        else:
            data = self._read(length)
            other._data = bytearray(data)
            other._null = False
        return self

    # --- Skip ---

    def skipRawData(self, length: int) -> int:
        data = self._read(length)
        return len(data)


class QFile:
    """Pure Python replacement for Qt's QFile.

    Thin wrapper around Python's built-in file I/O.
    """

    def __init__(self, path: str):
        self._path = path
        self._file = None

    def open(self, mode) -> bool:
        try:
            if mode == QIODevice.OpenModeFlag.ReadOnly:
                self._file = builtins.open(self._path, "rb")
            elif mode == QIODevice.OpenModeFlag.WriteOnly:
                self._file = builtins.open(self._path, "wb")
            else:
                self._file = builtins.open(self._path, "r+b")
            return True
        except (IOError, OSError):
            return False

    def read(self, n: int) -> bytes:
        if self._file is None:
            return b""
        return self._file.read(n)

    def write(self, data) -> int:
        if self._file is None:
            return -1
        if isinstance(data, QByteArray):
            raw = data.data()
        elif isinstance(data, (bytes, bytearray)):
            raw = data
        else:
            raw = bytes(data)
        return self._file.write(raw)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def size(self) -> int:
        if self._file is not None:
            pos = self._file.tell()
            self._file.seek(0, 2)
            sz = self._file.tell()
            self._file.seek(pos)
            return sz
        try:
            return os.path.getsize(self._path)
        except OSError:
            return 0


class QDir:
    """Pure Python replacement for Qt's QDir."""

    def __init__(self, path: str):
        self._path = path

    def exists(self) -> bool:
        return os.path.isdir(self._path)

    def mkpath(self, path: str) -> bool:
        os.makedirs(path, exist_ok=True)
        return True


class QSysInfo:
    """Pure Python replacement for Qt's QSysInfo."""

    class Endian:
        BigEndian = "big"
        LittleEndian = "little"
        ByteOrder = sys.byteorder
