"""An MTProto auth key, its id and its old-MTP
AES key derivation, computed by :mod:`opentele2._native`."""

from __future__ import annotations

from enum import IntEnum

from .. import _native
from .._compat import BaseObject
from .._native import CoreError
from ..exception import raise_core_error

__all__ = ["AuthKey", "AuthKeyType"]

# The invalid DC id: the DC of a key that belongs to none.
_INVALID_DC_ID = 0


class AuthKeyType(IntEnum):
    Generated = 0
    Temporary = 1
    ReadFromFile = 2
    Local = 3


class AuthKey(BaseObject):
    kSize = 256

    def __init__(
        self,
        key: bytes = b"",
        type: AuthKeyType = AuthKeyType.Generated,
        dcId: int = _INVALID_DC_ID,
    ) -> None:
        self.__type = type
        self.__dcId = dcId
        self.__key = key

    @property
    def dcId(self) -> int:
        return self.__dcId

    @property
    def type(self) -> AuthKeyType:
        return self.__type

    @property
    def key(self) -> bytes:
        return self.__key

    @property
    def keyId(self) -> int:
        """The low 64 bits of SHA-1 of the key, little endian; a key of
        another size than :attr:`kSize` raises ``ValueError``."""
        try:
            return _native.key_id(self.__key)
        except CoreError as error:
            raise_core_error(error)

    def prepareAES_oldmtp(self, msgKey: bytes, send: bool) -> tuple[bytes, bytes]:
        """The AES key and IV of MTProto 1.0 for the first 16 bytes of
        ``msgKey``; ``send`` picks the client-to-server half of the key."""
        try:
            return _native.prepare_aes_oldmtp(self.__key, msgKey[:16], send)
        except CoreError as error:
            raise_core_error(error)
