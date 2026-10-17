from __future__ import annotations

import abc
from collections.abc import Callable
from typing import TypeVar

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
    "format_app_version",
    "TDF_MAGIC",
    "BaseMetaClass",
    "BaseObject",
    "sharemethod",
    "PrettyTable",
]

_T = TypeVar("_T")
_F = TypeVar("_F", bound=Callable[..., object])


class BaseMetaClass(abc.ABCMeta):
    def __new__(
        cls: type[_T], clsName: str, bases: tuple[type], attrs: dict[str, object]
    ) -> _T:
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


class sharemethod(type):
    def __get__(self, obj: object | None, cls: type[object] | None) -> sharemethod:
        self.__owner__ = obj if obj else cls
        return self

    def __call__(self, *args: object) -> object:
        return self.__fget__.__get__(self.__owner__)(*args)

    def __set_name__(self, owner: type[object], name: str) -> None:
        self.__owner__ = owner

    def __new__(cls: type[_T], func: _F) -> type[_F]:
        clsName = func.__class__.__name__
        bases = func.__class__.__bases__
        attrs = func.__dict__
        result = super().__new__(cls, clsName, bases, attrs)
        result.__fget__ = func

        return result


def PrettyTable(table: list[dict[str, object]], addSplit: list[int] = []) -> str:
    padding = {}

    result = ""

    for label in table[0]:
        padding[label] = len(label)

    for row in table:
        for label, value in row.items():
            text = str(value)
            if padding[label] < len(text):
                padding[label] = len(text)

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
