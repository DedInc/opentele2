from __future__ import annotations

from enum import IntEnum
from typing import ClassVar

from ..exception import (
    Expects,
    ExpectStreamStatus,
    OpenTeleException,
    TDataBadConfigData,
)
from ..qt_compat import QByteArray, QDataStream, QIODevice
from ..utils import BaseObject
from .configs import BuiltInDc, DcId

_MAX_IP_SIZE = 45
_MAX_SECRET_SIZE = 32
_MAX_SERIALIZED_DC_ID = 1000


class TDataDcIdNotFound(OpenTeleException):
    def __init__(self, dcId: int, stack_index: int = 2) -> None:
        super().__init__(f"No endpoints for dc id {int(dcId)}", stack_index)
        self.dcId = dcId


def _qt_stream(data: QByteArray, write: bool = False) -> QDataStream:
    if write:
        stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
    else:
        stream = QDataStream(data)
    stream.setVersion(QDataStream.Version.Qt_5_1)
    return stream


class MTP(BaseObject):  # nocov
    class Environment(IntEnum):
        Production = 0
        Test = 1

    class RSAPublicKey(BaseObject):
        def __init__(self, dcId: int = 0, n: bytes = b"", e: bytes = b"") -> None:
            self.dcId = dcId
            self.n = n
            self.e = e

    class DcOptions(BaseObject):
        kVersion = 2

        def __init__(self, enviroment: MTP.Environment) -> None:
            self._enviroment = enviroment
            self._data: dict[DcId, list[MTP.DcOptions.Endpoint]] = {}
            self._cdnPublicKeys: list[MTP.RSAPublicKey] = []

            self.constructFromBuiltIn()

        def isTestMode(self) -> bool:
            return self._enviroment != MTP.Environment.Production

        def constructAddOne(
            self, id: DcId, flags: MTP.DcOptions.Flag, ip: str, port: int, secret: bytes
        ) -> None:
            self.applyOneGuarded(DcId.BareDcId(id), flags, ip, port, secret)

        def applyOneGuarded(
            self,
            id: DcId,
            flags: MTP.DcOptions.Flag,
            ip: str,
            port: int,
            secret: bytes,
        ) -> None:
            if id not in self._data:
                self._data[id] = []
            else:
                for endpoint in self._data[id]:
                    if (endpoint.ip == ip) and (endpoint.port == port):
                        return

            endpoint = MTP.DcOptions.Endpoint(id, flags, ip, port, secret)
            self._data[id].append(endpoint)

        def constructFromBuiltIn(self) -> None:
            def addToData(dcs: list[BuiltInDc], flags: MTP.DcOptions.Flag) -> None:
                for dc in dcs:
                    self.applyOneGuarded(dc.id, flags, dc.ip, dc.port, b"")

            if self.isTestMode():
                dcs, dcs_ipv6 = BuiltInDc.kBuiltInDcsTest, BuiltInDc.kBuiltInDcsIPv6Test
            else:
                dcs, dcs_ipv6 = BuiltInDc.kBuiltInDcs, BuiltInDc.kBuiltInDcsIPv6

            addToData(dcs, MTP.DcOptions.Flag.f_static)  # type: ignore
            addToData(
                dcs_ipv6,
                MTP.DcOptions.Flag(
                    MTP.DcOptions.Flag.f_static | MTP.DcOptions.Flag.f_ipv6
                ),
            )

        def constructFromSerialized(self, serialized: QByteArray) -> None:
            stream = _qt_stream(serialized)

            minusVersion = stream.readInt32()
            version = (-minusVersion) if (minusVersion < 0) else 0
            count = stream.readInt32() if version > 0 else minusVersion

            self._data.clear()
            self._cdnPublicKeys.clear()

            for i in range(count):
                dcId = DcId(stream.readInt32())
                flags = MTP.DcOptions.Flag(stream.readInt32())
                port = stream.readInt32()
                ipSize = stream.readInt32()

                Expects(
                    condition=((ipSize > 0) and (ipSize <= _MAX_IP_SIZE)),
                    exception=TDataBadConfigData("Bad ipSize data"),
                )

                ip = stream.readRawData(ipSize).decode("ascii")

                secret = b""
                if version > 0:
                    secretSize = stream.readInt32()
                    Expects(
                        condition=(
                            (secretSize >= 0) and (secretSize <= _MAX_SECRET_SIZE)
                        ),
                        exception=TDataBadConfigData("Bad secretSize data"),
                    )
                    if secretSize > 0:
                        secret = stream.readRawData(secretSize)

                ExpectStreamStatus(stream, "Could not stream config data")
                self.applyOneGuarded(dcId, flags, ip, port, secret)

            if (not stream.atEnd()) and (version > 1):
                keysCount = stream.readInt32()
                ExpectStreamStatus(stream, "Could not stream CDN config data")

                for i in range(keysCount):
                    keyDcId = stream.readInt32()
                    n, e = QByteArray(), QByteArray()
                    stream >> n >> e
                    ExpectStreamStatus(stream, "Could not stream CDN public key")

                    self._cdnPublicKeys.append(
                        MTP.RSAPublicKey(keyDcId, bytes(n), bytes(e))
                    )

        def Serialize(self) -> QByteArray:
            filtered = [
                endpoint
                for dcId, endpoints in self._data.items()
                # kTemporaryMainDc (1000) and above are never persisted.
                if DcId.BareDcId(dcId) < _MAX_SERIALIZED_DC_ID
                for endpoint in endpoints
            ]

            result = QByteArray()
            stream = _qt_stream(result, write=True)

            stream.writeInt32(-MTP.DcOptions.kVersion)
            stream.writeInt32(len(filtered))

            for endpoint in filtered:
                stream.writeInt32(endpoint.id)
                stream.writeInt32(endpoint.flags)
                stream.writeInt32(endpoint.port)
                stream.writeInt32(len(endpoint.ip))
                stream.writeRawData(endpoint.ip.encode("ascii"))
                stream.writeInt32(len(endpoint.secret))
                stream.writeRawData(endpoint.secret)

            stream.writeInt32(len(self._cdnPublicKeys))
            for key in self._cdnPublicKeys:
                stream.writeInt32(key.dcId)
                stream << QByteArray(key.n) << QByteArray(key.e)

            return result

        class Address(IntEnum):
            IPv4 = 0
            IPv6 = 1

        class Protocol(IntEnum):
            Tcp = 0
            Http = 1

        class Flag(int):
            f_ipv6 = 1 << 0
            f_media_only = 1 << 1
            f_tcpo_only = 1 << 2
            f_cdn = 1 << 3
            f_static = 1 << 4
            ThisPortOnly = 1 << 5
            f_secret = 1 << 10

        class Endpoint(BaseObject):
            def __init__(
                self,
                id: int,
                flags: MTP.DcOptions.Flag,
                ip: str,
                port: int,
                secret: bytes,
            ) -> None:
                self.id = id
                self.flags = flags
                self.ip = ip
                self.port = port
                self.secret = secret

    class ConfigFields(BaseObject):
        def __init__(self) -> None:
            self.chatSizeMax = 200
            self.megagroupSizeMax = 10000
            self.forwardedCountMax = 100
            self.onlineUpdatePeriod = 120000
            self.offlineBlurTimeout = 5000
            self.offlineIdleTimeout = 30000
            self.onlineFocusTimeout = 1000
            self.onlineCloudTimeout = 300000
            self.notifyCloudDelay = 30000
            self.notifyDefaultDelay = 1500
            self.savedGifsLimit = 200
            self.editTimeLimit = 172800
            self.revokeTimeLimit = 172800
            self.revokePrivateTimeLimit = 172800
            self.revokePrivateInbox = False
            self.stickersRecentLimit = 30
            self.stickersFavedLimit = 5
            self.pinnedDialogsCountMax = 5
            self.pinnedDialogsInFolderMax = 100
            self.internalLinksDomain = "https://t.me/"
            self.channelsReadMediaPeriod = 86400 * 7
            self.callReceiveTimeoutMs = 20000
            self.callRingTimeoutMs = 90000
            self.callConnectTimeoutMs = 30000
            self.callPacketTimeoutMs = 10000
            self.webFileDcId = 4
            self.txtDomainString = ""
            self.phoneCallsEnabled = True
            self.blockedMode = False
            self.captionLengthMax = 1024
            # Optional tail, appended by newer tdesktop and read only if present.
            self.reactionDefaultEmoji = "\N{THUMBS UP SIGN}"
            self.reactionDefaultCustom = 0
            self.ratingDecay = 2419200
            self.gifSearchUsername = "gif"
            self.venueSearchUsername = "foursquare"

    class Config(BaseObject):
        kVersion = 1

        _SERIALIZED_FIELDS: ClassVar[list[str]] = [
            "chatSizeMax",
            "megagroupSizeMax",
            "forwardedCountMax",
            "onlineUpdatePeriod",
            "offlineBlurTimeout",
            "offlineIdleTimeout",
            "onlineFocusTimeout",
            "onlineCloudTimeout",
            "notifyCloudDelay",
            "notifyDefaultDelay",
            "savedGifsLimit",
            "editTimeLimit",
            "revokeTimeLimit",
            "revokePrivateTimeLimit",
            "revokePrivateInbox",
            "stickersRecentLimit",
            "stickersFavedLimit",
            "pinnedDialogsCountMax",
            "pinnedDialogsInFolderMax",
            "internalLinksDomain",
            "channelsReadMediaPeriod",
            "callReceiveTimeoutMs",
            "callRingTimeoutMs",
            "callConnectTimeoutMs",
            "callPacketTimeoutMs",
            "webFileDcId",
            "txtDomainString",
            "phoneCallsEnabled",
            "blockedMode",
            "captionLengthMax",
        ]

        def __init__(self, enviroment: MTP.Environment) -> None:
            self._dcOptions = MTP.DcOptions(enviroment)
            self._fields = MTP.ConfigFields()
            self._fields.webFileDcId = 2 if self._dcOptions.isTestMode() else 4
            self._fields.txtDomainString = (
                "tapv3.stel.com" if self._dcOptions.isTestMode() else "apv3.stel.com"
            )
            if self._dcOptions.isTestMode():
                self._fields.gifSearchUsername = "izgifbot"
                self._fields.venueSearchUsername = "foursquarebot"

        def endpoints(
            self, dcId: DcId = DcId._0
        ) -> dict[
            MTP.DcOptions.Address,
            dict[MTP.DcOptions.Protocol, list[MTP.DcOptions.Endpoint]],
        ]:
            Expects(
                condition=(dcId in self._dcOptions._data),
                exception=TDataDcIdNotFound(dcId),
            )

            endpoints = self._dcOptions._data[dcId]

            Address = MTP.DcOptions.Address
            Protocol = MTP.DcOptions.Protocol
            Flag = MTP.DcOptions.Flag
            Endpoint = MTP.DcOptions.Endpoint

            results: dict[Address, dict[Protocol, list[Endpoint]]] = {}  # type: ignore[valid-type]
            results[Address.IPv4] = {Protocol.Tcp: [], Protocol.Http: []}
            results[Address.IPv6] = {Protocol.Tcp: [], Protocol.Http: []}

            for endpoint in endpoints:
                if dcId == 0 or endpoint.id == dcId:
                    flags = endpoint.flags
                    address = Address.IPv6 if (flags & Flag.f_ipv6) else Address.IPv4
                    results[address][Protocol.Tcp].append(endpoint)

                    if not (flags & (Flag.f_tcpo_only | Flag.f_secret)):
                        results[address][Protocol.Http].append(endpoint)

            return results

        @staticmethod
        def _write_field(stream: QDataStream, value: bool | int | str) -> None:
            if isinstance(value, bool):
                stream.writeInt32(1 if value else 0)
            elif isinstance(value, int):
                stream.writeInt32(value)
            elif isinstance(value, str):
                stream.writeQString(value)

        @staticmethod
        def _read_field(
            stream: QDataStream,
            field_type: type[bool | int | str],
        ) -> bool | int | str:
            if field_type is bool:
                return stream.readInt32() == 1
            elif field_type is int:
                return stream.readInt32()
            elif field_type is str:
                return stream.readQString()
            raise ValueError(f"Unsupported field type: {field_type}")

        def Serialize(self) -> QByteArray:
            options = self._dcOptions.Serialize()

            result = QByteArray()
            stream = _qt_stream(result, write=True)

            stream.writeInt32(MTP.Config.kVersion)
            stream.writeInt32(
                MTP.Environment.Test
                if self._dcOptions.isTestMode()
                else MTP.Environment.Production
            )

            stream << options

            for name in self._SERIALIZED_FIELDS:
                self._write_field(stream, getattr(self._fields, name))

            fields = self._fields
            stream.writeQString(fields.reactionDefaultEmoji)
            stream.writeUInt64(fields.reactionDefaultCustom)
            stream.writeInt32(fields.ratingDecay)
            stream.writeQString(fields.gifSearchUsername)
            stream.writeQString(fields.venueSearchUsername)

            return result

        @staticmethod
        def FromSerialized(serialized: QByteArray) -> MTP.Config:
            stream = _qt_stream(serialized)

            version = stream.readInt32()
            Expects(
                version == MTP.Config.kVersion,
                "version != kVersion, something went wrong",
            )

            enviroment = MTP.Environment(stream.readInt32())
            result = MTP.Config(enviroment)

            dcOptionsSerialized = QByteArray()
            stream >> dcOptionsSerialized

            fields = result._fields
            for name in MTP.Config._SERIALIZED_FIELDS:
                field_type = type(getattr(fields, name))
                setattr(fields, name, MTP.Config._read_field(stream, field_type))

            # Each group was appended by a later tdesktop (mtproto_config.cpp).
            if not stream.atEnd():
                fields.reactionDefaultEmoji = stream.readQString()
                fields.reactionDefaultCustom = stream.readUInt64()
            if not stream.atEnd():
                fields.ratingDecay = stream.readInt32()
            if not stream.atEnd():
                fields.gifSearchUsername = stream.readQString()
                fields.venueSearchUsername = stream.readQString()

            ExpectStreamStatus(stream, "Could not stream MtpData serialized")
            result._dcOptions.constructFromSerialized(dcOptionsSerialized)
            return result
