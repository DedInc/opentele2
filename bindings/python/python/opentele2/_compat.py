"""What 1.5.0 ``src/utils.py`` held: the class helpers the public classes are
built on, the tdata version constants and the ``PrettyTable`` text table.
``opentele2.tl.configs`` re-exports all of it, as 1.5.0 did."""

from __future__ import annotations

import abc
import functools
import sys
from typing import TYPE_CHECKING, Generic, Protocol, TypeVar

from . import _native

if sys.version_info < (3, 10):
    from typing_extensions import ParamSpec
else:
    from typing import ParamSpec

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

__all__ = [
    "APP_VERSION",
    "APP_VERSION_STR",
    "TDF_MAGIC",
    "BaseMetaClass",
    "BaseObject",
    "PrettyTable",
    "format_app_version",
    "sharemethod",
]

# The core exports no version constant of its own; a new TData carries the
# version every save writes into the TDF$ header (core tdata::APP_VERSION).
APP_VERSION: int = _native.TData.new([]).app_version
# The first four bytes of every tdata file (core tdf::MAGIC).
TDF_MAGIC: bytes = _native.TDF_MAGIC
# A packed tdesktop version as ``AppVersionStr`` spells it, a zero patch
# omitted: 7003000 is "7.3" and 7003001 is "7.3.1".
format_app_version = _native.format_app_version

APP_VERSION_STR = format_app_version(APP_VERSION)

_R = TypeVar("_R")
_R_co = TypeVar("_R_co", covariant=True)
_P = ParamSpec("_P")


class _NamedFunction(Protocol[_P, _R_co]):
    """A function as ``def`` makes it: callable, and named and annotated."""

    __name__: str
    __qualname__: str
    __annotations__: dict[str, object]

    def __call__(self, *args: _P.args, **kwargs: _P.kwargs) -> _R_co: ...


class BaseMetaClass(abc.ABCMeta):
    """The metaclass of every 1.5.0 public class."""


class BaseObject(metaclass=BaseMetaClass):
    pass


class sharemethod(Generic[_R]):
    """A method bound to the instance when called on one, else to the class.

    The first parameter receives whichever it was called on, so one body can
    serve ``API.TelegramDesktop.copy()`` and ``api.copy()`` alike.
    """

    def __init__(self, func: _NamedFunction[..., _R]) -> None:
        self.__fget__ = func
        # The metadata functools.update_wrapper copies, set directly: that
        # helper is typed for callable wrappers, and a sharemethod is a
        # descriptor, not a callable.
        self.__module__ = func.__module__
        self.__name__ = func.__name__
        self.__qualname__ = func.__qualname__
        self.__doc__ = func.__doc__
        self.__annotations__ = func.__annotations__
        self.__dict__.update(func.__dict__)
        self.__wrapped__ = func

    def __get__(self, obj: object | None, cls: type | None = None) -> Callable[..., _R]:
        return functools.partial(self.__fget__, cls if obj is None else obj)


def PrettyTable(table: Sequence[Mapping[str, object]], addSplit: list[int] | None = None) -> str:
    """1.5.0's bordered text table: one column per key of the first row, each
    cell centred in its column, and a splitter line before every row index in
    ``addSplit``, rendered by ``_native.format_table`` from the ``str()`` of
    every cell. ``TelegramClient.PrintSessions`` prints the core's own
    rendering of the same layout (``_native.format_sessions``)."""
    headers = [str(label) for label in table[0]]
    rows = [[str(row[label]) for label in table[0]] for row in table]
    return _native.format_table(headers, rows, addSplit)
