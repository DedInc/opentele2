from __future__ import annotations

import atexit
import os
import time
import typing as t

_DEBUG_ENV_VAR = "OPENTELE_DEBUG"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def is_debug_mode_enabled() -> bool:
    """Return True when debug instrumentation is requested via the environment.

    Defaults to False so the shipped library stays instrumentation-free when no
    environment variable is set.
    """
    return os.environ.get(_DEBUG_ENV_VAR, "").strip().lower() in _TRUTHY


IS_DEBUG_MODE = False

if is_debug_mode_enabled():
    IS_DEBUG_MODE = True

if IS_DEBUG_MODE:
    from rich import print

    _F = t.TypeVar("_F", bound=t.Callable[..., object])

    class DebugInfo:
        def __init__(self) -> None:
            self.list: list[tuple[str, int, float, float]] = []

        def add(self, name: str, total_called: int, total_time: float) -> None:
            self.list.append(
                (
                    name,
                    total_called,
                    total_time,
                    round(total_time / total_called * 1000, 4),
                )
            )

        def on_exit(self) -> None:
            self.list = sorted(self.list, key=lambda item: item[3])

            for item in self.list:
                name = item[0]
                total_called = item[1]
                avg_time = item[3]

                text = name.ljust(40)
                text += f"called {total_called}".ljust(15)
                text += f"average time: {avg_time} ms".ljust(25)
                print(text)

    dbgInfo = DebugInfo()
    atexit.register(dbgInfo.on_exit)

    class DebugMethod(type):
        def __get__(self, obj: object | None, cls: type[object] | None) -> DebugMethod:
            self.__owner__ = obj if obj else cls
            return self

        def __call2__(self, *args: object, **kwargs: object) -> tuple[object, float]:
            begin = time.perf_counter()
            result = self.__fget__(*args, **kwargs)
            diff = time.perf_counter() - begin

            return result, diff

        def __call__(self, *args: object, **kwargs: object) -> object:
            if hasattr(self, "__owner__"):
                result, diff = DebugMethod.__call2__(
                    self, self.__owner__, *args, **kwargs
                )
            else:
                result, diff = DebugMethod.__call2__(self, *args, **kwargs)

            self.__total_called += 1
            self.__total_time += diff

            return result

        def __getfullname(self) -> str:
            if hasattr(self, "__ownername__"):
                if self.__fname__ == "__init__":
                    return f"{self.__ownername__}()"

                return f"{self.__ownername__}.{self.__fname__}()"
            else:
                return f"{self.__fget__.__name__}()"

        def on_exit(self) -> None:
            if self.__total_called > 0:
                dbgInfo.add(
                    DebugMethod.__getfullname(self),
                    self.__total_called,
                    self.__total_time,
                )

        def __set_name__(self, owner: type[object], name: str) -> None:
            self.__owner__ = owner
            self.__ownername__ = owner.__name__
            self.__fname__ = name
            if self.__fname__.startswith(f"_{self.__ownername__}__"):
                self.__fname__ = self.__fname__[len(self.__ownername__) + 1 :]

        def __new__(cls, decorated_func: _F) -> type[object]:
            firstdct = dict(decorated_func.__dict__)
            for i, x in cls.__dict__.items():
                firstdct[i] = x

            result = type.__new__(
                cls,
                decorated_func.__class__.__name__,
                decorated_func.__class__.__bases__,
                firstdct,
            )

            result.__fget__ = decorated_func
            result.__total_time = 0
            result.__total_called = 0
            atexit.register(result.on_exit, result)
            return result

    def parse_arg(value: object) -> str:
        if isinstance(value, type):
            return value.__name__
        if isinstance(value, str):
            return f"'{value}'"
        if isinstance(value, int):
            return f"{value}"
        return value.__class__.__name__ + "(...)"

    class runtime(type):
        def __get__(self, obj: object | None, cls: type[object] | None) -> runtime:
            self.__owner__ = obj if obj else cls
            return self

        def __call__(self, *args: object, **kwargs: object) -> object:
            begin = time.perf_counter()
            result = self.__fget__(self.__owner__, *args, **kwargs)
            diff = round((time.perf_counter() - begin) * 1000, 2)
            print(f"{self.__fname__} took {diff}ms")
            return result

        def __set_name__(self, owner: type[object], name: str) -> None:
            print("set_name")
            self.__owner__ = owner
            self.__ownername__ = owner.__name__
            self.__fname__ = name

        def __new__(cls, decorated_func: _F) -> type[object]:
            firstdct = dict(decorated_func.__dict__)
            for i, x in cls.__dict__.items():
                firstdct[i] = x

            result = type.__new__(
                cls,
                decorated_func.__name__,
                decorated_func.__class__.__bases__,
                firstdct,
            )
            result.__fget__ = decorated_func
            return result
