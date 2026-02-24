from __future__ import annotations

from ..utils import BaseObject
from .configs import DcId
from enum import IntEnum
from ..qt_compat import QDataStream

import hashlib
import typing


class AuthKeyType(IntEnum):
    Generated = 0
    Temporary = 1
    ReadFromFile = 2
    Local = 3


class AuthKey(BaseObject):
    kSize = 256

    def __init__(
        self,
        key: bytes = bytes(),
        type: AuthKeyType = AuthKeyType.Generated,
        dcId: DcId = DcId.Invalid,
    ) -> None:
        self.__type = type
        self.__dcId = dcId
        self.__key = key
        self.__countKeyId()

    @property
    def dcId(self) -> DcId:
        return self.__dcId

    @property
    def type(self) -> AuthKeyType:
        return self.__type

    @property
    def key(self) -> bytes:
        return self.__key

    def write(self, to: QDataStream) -> None:
        to.writeRawData(self.key)

    def __countKeyId(self) -> None:
        hash = hashlib.sha1(self.__key).digest()
        self.__keyId = int.from_bytes(hash[12 : 12 + 8], "little")

    def prepareAES_oldmtp(
        self, msgKey: bytes, send: bool
    ) -> typing.Tuple[bytes, bytes]:
        x = 0 if send else 8
        sha1_a = hashlib.sha1(msgKey[:16] + self.__key[x : x + 32]).digest()

        sha1_b = hashlib.sha1(
            self.__key[x + 32 : x + 32 + 16]
            + msgKey[:16]
            + self.__key[x + 48 : x + 48 + 16]
        ).digest()

        sha1_c = hashlib.sha1(self.__key[x + 64 : x + 64 + 32] + msgKey[:16]).digest()
        sha1_d = hashlib.sha1(msgKey[:16] + self.__key[x + 96 : x + 96 + 32]).digest()

        aesKey = sha1_a[:8] + sha1_b[8 : 8 + 12] + sha1_c[4 : 4 + 12]
        aesIv = sha1_a[8 : 8 + 12] + sha1_b[:8] + sha1_c[16 : 16 + 4] + sha1_d[:8]

        return aesKey, aesIv

    @staticmethod
    def FromStream(
        stream: QDataStream,
        type: AuthKeyType = AuthKeyType.ReadFromFile,
        dcId: DcId = DcId(0),
    ) -> AuthKey:
        keyData = stream.readRawData(AuthKey.kSize)
        return AuthKey(keyData, type, dcId)
