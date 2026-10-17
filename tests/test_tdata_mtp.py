from __future__ import annotations

import pytest

from src.exception import OpenTeleException
from src.qt_compat import QByteArray, QDataStream, QIODevice
from src.td.configs import DcId
from src.td.mtp import MTP, TDataDcIdNotFound

Flag = MTP.DcOptions.Flag


def _flatten(dcOptions: MTP.DcOptions) -> list[tuple[int, str, int, int, bytes]]:
    return sorted(
        (
            int(endpoint.id),
            endpoint.ip,
            endpoint.port,
            int(endpoint.flags),
            bytes(endpoint.secret),
        )
        for endpoints in dcOptions._data.values()
        for endpoint in endpoints
    )


def _writeStream(data: QByteArray) -> QDataStream:
    stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
    stream.setVersion(QDataStream.Version.Qt_5_1)
    return stream


def test_builtin_round_trip_preserves_every_field() -> None:
    source = MTP.DcOptions(MTP.Environment.Production)
    source.constructAddOne(DcId._2, Flag.f_secret, "10.0.0.7", 8443, b"\x01\x02\x03")

    target = MTP.DcOptions(MTP.Environment.Production)
    target.constructFromSerialized(source.Serialize())

    assert _flatten(target) == _flatten(source)
    assert ("10.0.0.7", 8443, b"\x01\x02\x03") in [
        (endpoint.ip, endpoint.port, bytes(endpoint.secret))
        for endpoint in target._data[DcId._2]
    ]


def test_serialize_is_stable_across_a_round_trip() -> None:
    source = MTP.DcOptions(MTP.Environment.Test)
    serialized = source.Serialize()

    target = MTP.DcOptions(MTP.Environment.Test)
    target.constructFromSerialized(serialized)

    assert bytes(target.Serialize()) == bytes(serialized)


def test_ports_survive_serialization() -> None:
    source = MTP.DcOptions(MTP.Environment.Production)
    source.constructAddOne(DcId._3, Flag.f_tcpo_only, "10.0.0.8", 8888, b"")

    target = MTP.DcOptions(MTP.Environment.Production)
    target.constructFromSerialized(source.Serialize())

    ports = [endpoint.port for endpoint in target._data[DcId._3]]
    assert 8888 in ports
    assert all(port > 0 for port in ports)


def test_apply_one_guarded_dedupes_same_ip_and_port() -> None:
    dcOptions = MTP.DcOptions(MTP.Environment.Production)
    before = len(dcOptions._data[DcId._1])

    dcOptions.applyOneGuarded(DcId._1, Flag.f_static, "10.0.0.9", 443, b"")
    dcOptions.applyOneGuarded(DcId._1, Flag.f_static, "10.0.0.9", 443, b"")

    assert len(dcOptions._data[DcId._1]) == before + 1

    dcOptions.applyOneGuarded(DcId._1, Flag.f_static, "10.0.0.9", 444, b"")
    assert len(dcOptions._data[DcId._1]) == before + 2


def test_builtin_construction_is_idempotent() -> None:
    dcOptions = MTP.DcOptions(MTP.Environment.Production)
    counts = {dcId: len(endpoints) for dcId, endpoints in dcOptions._data.items()}

    dcOptions.constructFromBuiltIn()

    assert {dcId: len(e) for dcId, e in dcOptions._data.items()} == counts


def test_endpoints_raises_opentele_exception_for_missing_dc() -> None:
    config = MTP.Config(MTP.Environment.Production)

    with pytest.raises(TDataDcIdNotFound) as info:
        config.endpoints(DcId(77))

    assert issubclass(TDataDcIdNotFound, OpenTeleException)
    assert info.value.dcId == 77
    assert "77" in str(info.value)


def test_endpoints_still_resolves_a_known_dc() -> None:
    config = MTP.Config(MTP.Environment.Production)
    results = config.endpoints(DcId._1)

    tcp = results[MTP.DcOptions.Address.IPv4][MTP.DcOptions.Protocol.Tcp]
    assert tcp and all(endpoint.port == 443 for endpoint in tcp)


def _blobWithCdnKeys() -> QByteArray:
    result = QByteArray()
    stream = _writeStream(result)

    stream.writeInt32(-MTP.DcOptions.kVersion)
    stream.writeInt32(1)

    ip = "10.1.2.3"
    stream.writeInt32(int(DcId._4))
    stream.writeInt32(int(Flag.f_cdn))
    stream.writeInt32(9443)
    stream.writeInt32(len(ip))
    stream.writeRawData(ip.encode("ascii"))
    stream.writeInt32(2)
    stream.writeRawData(b"\xaa\xbb")

    stream.writeInt32(1)
    stream.writeInt32(int(DcId._4))
    stream << QByteArray(b"modulus-n") << QByteArray(b"exponent-e")

    return result


def test_cdn_public_keys_are_parsed_and_reemitted() -> None:
    dcOptions = MTP.DcOptions(MTP.Environment.Production)
    dcOptions.constructFromSerialized(_blobWithCdnKeys())

    assert len(dcOptions._cdnPublicKeys) == 1
    key = dcOptions._cdnPublicKeys[0]
    assert (int(key.dcId), key.n, key.e) == (int(DcId._4), b"modulus-n", b"exponent-e")

    reread = MTP.DcOptions(MTP.Environment.Production)
    reread.constructFromSerialized(dcOptions.Serialize())

    assert [(int(k.dcId), k.n, k.e) for k in reread._cdnPublicKeys] == [
        (int(DcId._4), b"modulus-n", b"exponent-e")
    ]
    assert _flatten(reread) == [
        (int(DcId._4), "10.1.2.3", 9443, int(Flag.f_cdn), b"\xaa\xbb")
    ]


def test_config_round_trip_keeps_dc_options() -> None:
    config = MTP.Config(MTP.Environment.Production)
    config._dcOptions.constructAddOne(DcId._5, Flag.f_static, "10.4.4.4", 8080, b"\x09")

    restored = MTP.Config.FromSerialized(config.Serialize())

    assert _flatten(restored._dcOptions) == _flatten(config._dcOptions)
    assert restored._fields.txtDomainString == config._fields.txtDomainString


def test_flag_has_this_port_only_bit() -> None:
    assert Flag.ThisPortOnly == 1 << 5
    assert not hasattr(Flag, "MAX_FIELD")


def _tailSize(fields: MTP.ConfigFields) -> int:
    def qstring(value: str) -> int:
        return 4 + len(value.encode("utf-16-be"))

    return (
        qstring(fields.reactionDefaultEmoji)
        + 8
        + 4
        + qstring(fields.gifSearchUsername)
        + qstring(fields.venueSearchUsername)
    )


def test_config_round_trips_the_tdesktop_7_3_tail() -> None:
    config = MTP.Config(MTP.Environment.Production)
    fields = config._fields
    fields.reactionDefaultEmoji = "\N{FIRE}"
    fields.reactionDefaultCustom = 0xFEDCBA9876543210
    fields.ratingDecay = 86400
    fields.gifSearchUsername = "gifbot"
    fields.venueSearchUsername = "venuebot"

    restored = MTP.Config.FromSerialized(config.Serialize())._fields

    assert restored.reactionDefaultEmoji == "\N{FIRE}"
    assert restored.reactionDefaultCustom == 0xFEDCBA9876543210
    assert restored.ratingDecay == 86400
    assert restored.gifSearchUsername == "gifbot"
    assert restored.venueSearchUsername == "venuebot"


def test_a_config_written_without_the_tail_keeps_defaults() -> None:
    config = MTP.Config(MTP.Environment.Production)
    config._fields.captionLengthMax = 4096
    full = bytes(config.Serialize())
    legacy = QByteArray(full[: len(full) - _tailSize(config._fields)])

    restored = MTP.Config.FromSerialized(legacy)._fields

    assert restored.captionLengthMax == 4096
    assert restored.reactionDefaultEmoji == "\N{THUMBS UP SIGN}"
    assert restored.ratingDecay == 2419200
    assert restored.gifSearchUsername == "gif"


def test_test_environment_defaults_match_tdesktop() -> None:
    fields = MTP.Config(MTP.Environment.Test)._fields

    assert fields.gifSearchUsername == "izgifbot"
    assert fields.venueSearchUsername == "foursquarebot"
