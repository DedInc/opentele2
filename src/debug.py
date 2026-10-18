from __future__ import annotations

import atexit
import functools
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

    class DebugMethod:
        """Times every call of a method; the report is printed at exit."""

        def __init__(self, decorated_func: t.Callable[..., object]) -> None:
            self.__fget__ = decorated_func
            self._ownername: str | None = None
            self._fname = getattr(decorated_func, "__name__", repr(decorated_func))
            self._total_time = 0.0
            self._total_called = 0
            functools.update_wrapper(self, decorated_func)
            atexit.register(self.on_exit)

        def __set_name__(self, owner: type, name: str) -> None:
            self._ownername = owner.__name__
            self._fname = name
            mangled = f"_{self._ownername}__"
            if self._fname.startswith(mangled):
                self._fname = self._fname[len(self._ownername) + 1 :]

        def __get__(self, obj: object | None, cls: type | None = None) -> t.Any:
            if obj is None:
                return self
            return functools.partial(self.__call__, obj)

        def __call__(self, *args: object, **kwargs: object) -> object:
            begin = time.perf_counter()
            try:
                return self.__fget__(*args, **kwargs)
            finally:
                self._total_called += 1
                self._total_time += time.perf_counter() - begin

        def _fullname(self) -> str:
            if self._ownername is None:
                return f"{self._fname}()"
            if self._fname == "__init__":
                return f"{self._ownername}()"
            return f"{self._ownername}.{self._fname}()"

        def on_exit(self) -> None:
            if self._total_called > 0:
                dbgInfo.add(self._fullname(), self._total_called, self._total_time)
