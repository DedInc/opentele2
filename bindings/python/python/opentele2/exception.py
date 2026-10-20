"""The opentele2 exception hierarchy, and the mapping of core errors onto it.

Every ``CoreError`` code of :mod:`opentele2._native` has an entry in
:data:`CORE_ERROR_TYPES`; :func:`raise_core_error` raises a ``CoreError`` as
the exception of this hierarchy, or the builtin, that names the failure.
"""

from __future__ import annotations

import builtins
import inspect
import sys
import types
import typing

from . import _native

if typing.TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from ._native import CoreError

__all__ = [
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


class OpenTeleException(BaseException):
    def __init__(self, message: str | None = None, stack_index: int = 1) -> None:
        super().__init__(message if (message is not None) else "")

        self.message = message
        self.desc = self.__class__.__name__

        # Depth 0 is this __init__ frame, so stack_index walks back to the
        # caller the same way stack_index f_back steps from currentframe() do.
        self.frame = sys._getframe(stack_index)

        self._caller_class = (
            self.frame.f_locals["self"].__class__ if "self" in self.frame.f_locals else None
        )
        self._caller_method = self.frame.f_code.co_name

        if self._caller_method != "<module>":
            args, _, _, locals = inspect.getargvalues(self.frame)
            parameters = {arg: locals[arg] for arg in args}
            self._caller_method_params = "".join(f"{i}={parameters[i]}, " for i in parameters)[:-2]
        else:
            self._caller_method = "__main__"
            self._caller_method_params = ""

        if self.desc == "OpenTeleException":
            self.desc = "Unexpected Exception"

    def __str__(self) -> str:
        reason = self.desc.__str__()

        if self.message is not None:
            reason += f": {self.message}"

        reason += " [ Called by "
        if self._caller_class is not None:
            parent_list = []
            base = self._caller_class
            while hasattr(base, "__name__"):
                parent_list.append(base.__name__)
                base = base.__base__

            parent_list.reverse()
            reason += "".join(f"{i}." for i in parent_list[1:])
            reason += self._caller_method + "() ]"
        else:
            reason += f"{self._caller_method}() ]"
        return reason


class TFileNotFound(OpenTeleException):
    pass


class TDataInvalidMagic(OpenTeleException):
    pass


class TDataInvalidCheckSum(OpenTeleException):
    pass


class TDataBadDecryptKey(OpenTeleException):
    pass


class TDataWrongPasscode(OpenTeleException):
    pass


class TDataBadEncryptedDataSize(OpenTeleException):
    pass


class TDataBadDecryptedDataSize(OpenTeleException):
    pass


class TDataBadConfigData(OpenTeleException):
    pass


class QDataStreamFailed(OpenTeleException):
    pass


class AccountAuthKeyNotFound(OpenTeleException):
    pass


class TDataReadMapDataFailed(OpenTeleException):
    pass


class TDataReadMapDataIncorrectPasscode(OpenTeleException):
    pass


class TDataAuthKeyNotFound(OpenTeleException):
    pass


class MaxAccountLimit(OpenTeleException):
    pass


class TDesktopUnauthorized(OpenTeleException):
    pass


class TelethonUnauthorized(OpenTeleException):
    pass


class TDataSaveFailed(OpenTeleException):
    pass


class TDesktopNotLoaded(OpenTeleException):
    pass


class TDesktopHasNoAccount(OpenTeleException):
    pass


class TDAccountNotLoaded(OpenTeleException):
    pass


class NoPasswordProvided(OpenTeleException):
    pass


class PasswordIncorrect(OpenTeleException):
    pass


class LoginFlagInvalid(OpenTeleException):
    pass


class NoInstanceMatched(OpenTeleException):
    pass


class SessionFileNotFound(OpenTeleException):
    pass


class SessionFileInvalid(OpenTeleException):
    pass


class TDataKeyDataInvalid(OpenTeleException):
    """Invalid tdata key data. It lives here so the core error table can name
    it, outside ``__all__`` so that a star import of this module leaves it
    out."""


def _legacy_class(name: str) -> type[BaseException]:
    """The exception class the core names ``name``: the one this module
    defines under that name, else the builtin."""
    kind = globals().get(name, getattr(builtins, name, None))
    if not (isinstance(kind, type) and issubclass(kind, BaseException)):
        raise TypeError(f"the core names {name!r}, which is not an exception class")
    return kind


# The exception raised for the failure each core code reports, by the class
# name the core gives it: an OpenTeleException of this module, or a builtin
# for codes with no class of their own.
CORE_ERROR_TYPES: Mapping[str, type[BaseException]] = {
    code: _legacy_class(name) for code, name in _native.core_error_classes().items()
}


def raise_core_error(error: CoreError, stack_index: int = 1) -> typing.NoReturn:
    """Raise ``error`` as the exception :data:`CORE_ERROR_TYPES` names for
    its code, chained to it, with that exception's stable message
    (``error.legacy_message``). An OpenTeleException reports the caller
    ``stack_index`` frames up from here; a code the table does not know
    re-raises ``error`` itself."""
    exception_type = CORE_ERROR_TYPES.get(error.code)
    if exception_type is None:
        raise error
    if issubclass(exception_type, OpenTeleException):
        raise exception_type(error.legacy_message, stack_index + 1) from error
    raise exception_type(error.legacy_message) from error


@typing.overload
def Expects(
    condition: bool,
    exception: str | None = None,
    done: Callable[[], None] | None = None,
    fail: Callable[[OpenTeleException], None] | None = None,
    silent: bool = False,
    stack_index: int = 1,
) -> bool: ...


@typing.overload
def Expects(
    condition: bool,
    exception: OpenTeleException | None = None,
    done: Callable[[], None] | None = None,
    fail: Callable[[OpenTeleException], None] | None = None,
    silent: bool = False,
    stack_index: int = 1,
) -> bool: ...


def Expects(
    condition: bool,
    exception: OpenTeleException | str | None = None,
    done: Callable[[], None] | None = None,
    fail: Callable[[OpenTeleException], None] | None = None,
    silent: bool = False,
    stack_index: int = 1,
) -> bool:
    if condition:
        if done is not None:
            done()
        return condition

    if isinstance(exception, str):
        exception = OpenTeleException(exception, 2)
    elif exception is not None and not isinstance(exception, OpenTeleException):
        raise OpenTeleException("No instance of Expects() match the arguments given", 2)

    if exception is None:
        exception = OpenTeleException("Unexpected error", 2)

    if silent:
        if fail is not None:
            fail(exception)
        return condition

    stack = inspect.stack()
    frame = stack[stack_index].frame
    tb = types.TracebackType(None, frame, frame.f_lasti, frame.f_lineno)
    exception = exception.with_traceback(tb)

    if fail is not None:
        fail(exception)

    raise exception


# QDataStream::Ok, the status a stream reports while every operation succeeded.
_STREAM_STATUS_OK = 0


class _DataStream(typing.Protocol):
    """The part of a QDataStream that ExpectStreamStatus reads."""

    def status(self) -> int: ...


def ExpectStreamStatus(stream: _DataStream, message: str = "Could not stream data") -> None:
    Expects(
        stream.status() == _STREAM_STATUS_OK,
        stack_index=2,
        exception=QDataStreamFailed(message, stack_index=2),
    )
