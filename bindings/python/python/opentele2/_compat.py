"""Class helpers the 1.5.0 public classes are built on (1.5.0 ``src/utils.py``)."""

from __future__ import annotations

import abc
import functools
import sys
from typing import TYPE_CHECKING, Generic, Protocol, TypeVar

if sys.version_info < (3, 10):
    from typing_extensions import ParamSpec
else:
    from typing import ParamSpec

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["BaseMetaClass", "BaseObject", "sharemethod"]

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
