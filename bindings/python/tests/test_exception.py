"""Tests of opentele2.exception: the 1.5.0 names, hierarchy, messages,
Expects and ExpectStreamStatus of src/exception.py, and the mapping of every
``CoreError`` code of opentele2._native onto the 1.5.0 exceptions."""

from __future__ import annotations

import builtins
from typing import TYPE_CHECKING, Any

import pytest

from opentele2 import _native, exception
from opentele2._native import CoreError
from opentele2.exception import (
    CORE_ERROR_TYPES,
    Expects,
    ExpectStreamStatus,
    NoInstanceMatched,
    OpenTeleException,
    QDataStreamFailed,
    TDataKeyDataInvalid,
    TDataSaveFailed,
    TFileNotFound,
    raise_core_error,
)

if TYPE_CHECKING:
    from pathlib import Path

    from opentele2._native import SrpParams

# 1.5.0 src/exception.py __all__.
ALL_1_5_0 = [
    "AccountAuthKeyNotFound",
    "ExpectStreamStatus",
    "Expects",
    "LoginFlagInvalid",
    "MaxAccountLimit",
    "NoInstanceMatched",
    "NoPasswordProvided",
    "OpenTeleException",
    "PasswordIncorrect",
    "QDataStreamFailed",
    "SessionFileInvalid",
    "SessionFileNotFound",
    "TDAccountNotLoaded",
    "TDataAuthKeyNotFound",
    "TDataBadConfigData",
    "TDataBadDecryptKey",
    "TDataBadDecryptedDataSize",
    "TDataBadEncryptedDataSize",
    "TDataInvalidCheckSum",
    "TDataInvalidMagic",
    "TDataReadMapDataFailed",
    "TDataReadMapDataIncorrectPasscode",
    "TDataSaveFailed",
    "TDataWrongPasscode",
    "TDesktopHasNoAccount",
    "TDesktopNotLoaded",
    "TDesktopUnauthorized",
    "TFileNotFound",
    "TelethonUnauthorized",
]
# Every code opentele2._native raises: Error::code of crates/opentele2-core
# src/error.rs and srp_code of bindings/python/src/auth.rs.
CORE_CODES = {
    "TFILE_NOT_FOUND": "TFileNotFound",
    "TDATA_INVALID_MAGIC": "TDataInvalidMagic",
    "TDATA_INVALID_CHECKSUM": "TDataInvalidCheckSum",
    "TDATA_BAD_DECRYPT_KEY": "TDataBadDecryptKey",
    "TDATA_WRONG_PASSCODE": "TDataWrongPasscode",
    "TDATA_BAD_ENCRYPTED_DATA_SIZE": "TDataBadEncryptedDataSize",
    "TDATA_BAD_DECRYPTED_DATA_SIZE": "TDataBadDecryptedDataSize",
    "TDATA_BAD_CONFIG_DATA": "TDataBadConfigData",
    "QDATASTREAM_FAILED": "QDataStreamFailed",
    "TDATA_READ_MAP_DATA_FAILED": "TDataReadMapDataFailed",
    "TDATA_READ_MAP_DATA_INCORRECT_PASSCODE": "TDataReadMapDataIncorrectPasscode",
    "TDATA_AUTH_KEY_NOT_FOUND": "TDataAuthKeyNotFound",
    "MAX_ACCOUNT_LIMIT": "MaxAccountLimit",
    "TDATA_SAVE_FAILED": "TDataSaveFailed",
    "TDATA_KEY_DATA_INVALID": "TDataKeyDataInvalid",
    "BAD_LENGTH": "ValueError",
    "IO": "OSError",
    "SRP_BAD_PRIME_OR_GENERATOR": "ValueError",
    "SRP_BAD_B": "ValueError",
    "SRP_NO_GOOD_RANDOM": "ValueError",
    "SRP_RANDOM_UNAVAILABLE": "ValueError",
    "SRP_FAILED": "ValueError",
}


def test_all_and_hierarchy_match_1_5_0() -> None:
    assert exception.__all__ == ALL_1_5_0
    assert issubclass(OpenTeleException, BaseException)
    assert not issubclass(OpenTeleException, Exception)
    for name in ALL_1_5_0:
        value = getattr(exception, name)
        if name in ("Expects", "ExpectStreamStatus"):
            assert callable(value)
        elif name != "OpenTeleException":
            assert isinstance(value, type)
            assert value.__bases__ == (OpenTeleException,), name
    # 1.5.0 src/td/key_data.py: a direct OpenTeleException too.
    assert TDataKeyDataInvalid.__bases__ == (OpenTeleException,)


class Caller:
    def make(self, number: int, label: str = "x") -> OpenTeleException:
        return TFileNotFound("boom")


class SubCaller(Caller):
    pass


def make_plain(value: int) -> OpenTeleException:
    return TDataSaveFailed(None)


def make_base() -> OpenTeleException:
    return OpenTeleException()


def test_str_names_the_caller_as_1_5_0() -> None:
    error = SubCaller().make(1)
    assert str(error) == "TFileNotFound: boom [ Called by Caller.SubCaller.make() ]"
    assert error.message == "boom"
    assert error.desc == "TFileNotFound"
    assert error.args == ("boom",)
    assert error._caller_method_params.startswith("self=")
    assert error._caller_method_params.endswith(", number=1, label=x")

    plain = make_plain(3)
    assert str(plain) == "TDataSaveFailed [ Called by make_plain() ]"
    assert plain.args == ("",)
    assert plain._caller_method_params == "value=3"

    assert str(make_base()) == "Unexpected Exception [ Called by make_base() ]"

    namespace: dict[str, Any] = {"TFileNotFound": TFileNotFound}
    exec(compile("error = TFileNotFound('top')", "<module-level>", "exec"), namespace)
    assert str(namespace["error"]) == "TFileNotFound: top [ Called by __main__() ]"


def test_expects_passes_or_raises_as_1_5_0() -> None:
    done: list[str] = []
    failed: list[OpenTeleException] = []
    assert Expects(True, done=lambda: done.append("done")) is True
    assert done == ["done"]

    with pytest.raises(OpenTeleException) as raised:
        Expects(False, "plain message")
    assert type(raised.value) is OpenTeleException
    assert str(raised.value).startswith("Unexpected Exception: plain message [ Called by ")

    specific = NoInstanceMatched("no match")
    with pytest.raises(NoInstanceMatched) as raised_specific:
        Expects(False, specific, fail=failed.append)
    assert raised_specific.value is specific
    assert failed == [specific]

    with pytest.raises(OpenTeleException, match="Unexpected error"):
        Expects(False)

    wrong: Any = ValueError("not an OpenTeleException")
    with pytest.raises(OpenTeleException, match="No instance of Expects"):
        Expects(False, wrong)

    failed.clear()
    assert Expects(False, "quiet", fail=failed.append, silent=True) is False
    assert [error.message for error in failed] == ["quiet"]


class FakeStream:
    def __init__(self, status: int) -> None:
        self._status = status

    def status(self) -> int:
        return self._status


def test_expect_stream_status() -> None:
    ExpectStreamStatus(FakeStream(0))
    with pytest.raises(QDataStreamFailed, match="Could not stream data"):
        ExpectStreamStatus(FakeStream(1))
    with pytest.raises(QDataStreamFailed, match="short read"):
        ExpectStreamStatus(FakeStream(2), "short read")


def test_every_core_code_has_its_1_5_0_exception() -> None:
    assert {code: kind.__name__ for code, kind in CORE_ERROR_TYPES.items()} == CORE_CODES
    for code, name in CORE_CODES.items():
        kind = CORE_ERROR_TYPES[code]
        owner = exception if issubclass(kind, OpenTeleException) else builtins
        assert getattr(owner, name) is kind, code


class Loader:
    def load(self, path: Path) -> _native.TData:
        try:
            return _native.TData.load(path)
        except CoreError as error:
            raise_core_error(error)


def test_raise_core_error_maps_native_errors(tmp_path: Path) -> None:
    with pytest.raises(TFileNotFound) as missing:
        Loader().load(tmp_path / "missing")
    cause = missing.value.__cause__
    assert isinstance(cause, CoreError)
    assert cause.code == "TFILE_NOT_FOUND"
    assert missing.value.message == cause.message
    assert str(missing.value) == (
        f"TFileNotFound: {missing.value.message} [ Called by Loader.load() ]"
    )

    with pytest.raises(CoreError) as bad_length:
        _native.key_id(b"short")
    with pytest.raises(ValueError, match="bad length") as as_value:
        raise_core_error(bad_length.value)
    assert as_value.value.__cause__ is bad_length.value

    with pytest.raises(CoreError) as invalid_json:
        _native.profile_from_session_json("[]")
    with pytest.raises(OSError, match="session JSON"):
        raise_core_error(invalid_json.value)

    params: SrpParams = {
        "srp_id": 1,
        "g": 3,
        "p": b"\x01" * 256,
        "salt1": b"a",
        "salt2": b"b",
        "srp_b": b"\x02" * 256,
    }
    with pytest.raises(CoreError) as srp:
        _native.srp_check(params, "password")
    assert srp.value.code == "SRP_BAD_PRIME_OR_GENERATOR"
    with pytest.raises(ValueError, match="bad p/g"):
        raise_core_error(srp.value)

    unknown = CoreError("SOME_FUTURE_CODE", "new failure")
    with pytest.raises(CoreError) as kept:
        raise_core_error(unknown)
    assert kept.value is unknown
