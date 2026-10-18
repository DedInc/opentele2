from __future__ import annotations

import abc
import functools
from collections.abc import Callable, Mapping, Sequence
from typing import Generic, ParamSpec, Protocol, TypeVar

from . import debug

APP_VERSION = 7003001
TDF_MAGIC = b"TDF$"


def format_app_version(version: int) -> str:
    """Render a packed tdesktop version the way ``AppVersionStr`` spells it.

    Mirrors tdesktop's ``FormatVersionDisplay``: a zero patch is omitted, so
    7003000 is ``"7.3"`` and 7003001 is ``"7.3.1"``.
    """
    major, rest = divmod(version, 1000000)
    minor, patch = divmod(rest, 1000)
    return f"{major}.{minor}.{patch}" if patch else f"{major}.{minor}"


APP_VERSION_STR = format_app_version(APP_VERSION)

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
    def __new__(
        cls, clsName: str, bases: tuple[type, ...], attrs: dict[str, object]
    ) -> BaseMetaClass:
        if debug.IS_DEBUG_MODE:
            ignore_list = [
                "__new__",
                "__del__",
                "__get__",
                "__call__",
                "__set_name__",
                "__str__",
                "__repr__",
            ]

            for attr, val in attrs.items():
                if (
                    attr not in ignore_list
                    and callable(val)
                    and not isinstance(val, type)
                    and not isinstance(val, (staticmethod, classmethod))
                ):
                    newVal = debug.DebugMethod(val)
                    attrs[attr] = newVal

        result = super().__new__(cls, clsName, bases, attrs)

        return result


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
        # descriptor, not a callable (which also keeps BaseMetaClass's debug
        # mode from wrapping it).
        self.__module__ = func.__module__
        self.__name__ = func.__name__
        self.__qualname__ = func.__qualname__
        self.__doc__ = func.__doc__
        self.__annotations__ = func.__annotations__
        self.__dict__.update(func.__dict__)
        self.__wrapped__ = func

    def __get__(self, obj: object | None, cls: type | None = None) -> Callable[..., _R]:
        return functools.partial(self.__fget__, cls if obj is None else obj)


def PrettyTable(
    table: Sequence[Mapping[str, object]], addSplit: list[int] | None = None
) -> str:
    if addSplit is None:
        addSplit = []
    padding = {}

    result = ""

    for label in table[0]:
        padding[label] = len(label)

    for row in table:
        for label, value in row.items():
            text = str(value)
            padding[label] = max(padding[label], len(text))

    def addpadding(text: object, spaces: int) -> str:
        text = str(text)
        spaceLeft = spaces - len(text)
        padLeft = spaceLeft // 2
        padRight = spaceLeft - padLeft
        return " " * padLeft + text + " " * padRight

    header = "|".join(
        addpadding(label, spaces + 2) for label, spaces in padding.items()
    )
    splitter = "+".join(("-" * (spaces + 2)) for label, spaces in padding.items())
    rows = [
        "|".join(
            addpadding(row[label], spaces + 2) for label, spaces in padding.items()
        )
        for row in table
    ]

    result += f"|{splitter}|\n"
    result += f"|{header}|\n"
    result += f"|{splitter}|\n"

    for index, row_text in enumerate(rows):
        if index in addSplit:
            result += f"|{splitter}|\n"
        result += f"|{row_text}|\n"

    result += f"|{splitter}|"

    return result
