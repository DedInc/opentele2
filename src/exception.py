from __future__ import annotations
import inspect
import types
import typing
from .qt_compat import QDataStream

__all__ = [
    "OpenTeleException",
    "TFileNotFound",
    "TDataInvalidMagic",
    "TDataInvalidCheckSum",
    "TDataBadDecryptKey",
    "TDataWrongPasscode",
    "TDataBadEncryptedDataSize",
    "TDataBadDecryptedDataSize",
    "TDataBadConfigData",
    "QDataStreamFailed",
    "AccountAuthKeyNotFound",
    "TDataReadMapDataFailed",
    "TDataReadMapDataIncorrectPasscode",
    "TDataAuthKeyNotFound",
    "MaxAccountLimit",
    "TDesktopUnauthorized",
    "TelethonUnauthorized",
    "TDataSaveFailed",
    "TDesktopNotLoaded",
    "TDesktopHasNoAccount",
    "TDAccountNotLoaded",
    "NoPasswordProvided",
    "PasswordIncorrect",
    "LoginFlagInvalid",
    "NoInstanceMatched",
    "Expects",
    "ExpectStreamStatus",
]


class OpenTeleException(BaseException):  # nocov
    """Base exception of the library."""

    def __init__(self, message: str = None, stack_index: int = 1) -> None:
        super().__init__(message if (message is not None) else "")

        self.message = message
        self.desc = self.__class__.__name__

        self.frame = inspect.currentframe()
        for i in range(stack_index):
            self.frame = self.frame.f_back

        self._caller_class = (
            self.frame.f_locals["self"].__class__
            if "self" in self.frame.f_locals
            else None
        )
        self._caller_method = self.frame.f_code.co_name

        if self._caller_method != "<module>":
            args, _, _, locals = inspect.getargvalues(self.frame)
            parameters = {arg: locals[arg] for arg in args}
            self._caller_method_params = "".join(
                f"{i}={parameters[i]}, " for i in parameters
            )[:-2]
        else:
            self._caller_method = "__main__"
            self._caller_method_params = ""

        if self.desc == "OpenTeleException":
            self.desc = "Unexpected Exception"

    def __str__(self):
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


@typing.overload
def Expects(
    condition: bool,
    message: str = None,
    done: typing.Callable[[], None] = None,
    fail: typing.Callable[[OpenTeleException], None] = None,
    silent: bool = False,
    stack_index: int = 1,
) -> bool: ...


@typing.overload
def Expects(  # noqa: F811
    condition: bool,
    exception: OpenTeleException = None,
    done: typing.Callable[[], None] = None,
    fail: typing.Callable[[OpenTeleException], None] = None,
    silent: bool = False,
    stack_index: int = 1,
) -> bool: ...


def Expects(  # noqa: F811
    condition: bool,
    exception: typing.Union[OpenTeleException, str] = None,
    done: typing.Callable[[], None] = None,
    fail: typing.Callable[[OpenTeleException], None] = None,
    silent: bool = False,
    stack_index: int = 1,
) -> bool:  # nocov
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
    tb = types.TracebackType(None, frame, frame.f_lasti, frame.f_lineno)  # type: ignore
    exception = exception.with_traceback(tb)

    if fail is not None:
        fail(exception)

    raise exception


def ExpectStreamStatus(stream: QDataStream, message: str = "Could not stream data"):
    Expects(
        stream.status() == QDataStream.Status.Ok,
        stack_index=2,
        exception=QDataStreamFailed(message, stack_index=2),
    )
