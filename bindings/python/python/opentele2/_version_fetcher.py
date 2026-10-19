"""The release-feed fetch of 1.5.0 ``src/version_fetcher.py``, over
``_native.fetch_versions``: one fetch per process, cached, and skipped
entirely when ``OPENTELE_NO_FETCH`` is set."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from . import _native

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ._native import VersionsPatch

__all__ = ["fetch_all_versions"]

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_CACHED: dict[str, str | int] | None = None


def fetch_all_versions(timeout: float = _TIMEOUT) -> dict[str, str | int]:
    """The fields the release feeds answered, fetched once and cached.

    An empty answer never overwrites a default, so empty and missing values
    are dropped. Any failure yields an empty result, as in 1.5.0.
    """
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    if os.environ.get("OPENTELE_NO_FETCH"):
        _CACHED = {}
        return _CACHED

    result: dict[str, str | int] = {}
    try:
        patch = _native.fetch_versions(timeout)
    except Exception as exc:
        logger.debug("Version fetch failed: %s", exc, exc_info=True)
    else:
        for key, value in patch.items():
            if isinstance(value, (str, int)) and value != "":
                result[key] = value

    _CACHED = result
    return result


def _text(fetched: Mapping[str, str | int], key: str) -> str | None:
    value = fetched.get(key)
    return value if isinstance(value, str) else None


def _number(fetched: Mapping[str, str | int], key: str) -> int | None:
    value = fetched.get(key)
    return value if isinstance(value, int) else None


def versions_patch(fetched: Mapping[str, str | int]) -> VersionsPatch:
    """``fetched`` as the patch ``_native.apply_versions_patch`` takes; a
    field it lacks, or holds with the wrong type, is absent (None)."""
    return {
        "desktop_app_version": _text(fetched, "desktop_app_version"),
        "android_app_version": _text(fetched, "android_app_version"),
        "android_app_version_code": _number(fetched, "android_app_version_code"),
        "android_x_app_version": _text(fetched, "android_x_app_version"),
        "ios_app_version": _text(fetched, "ios_app_version"),
        "ios_build_number": _number(fetched, "ios_build_number"),
        "macos_app_version": _text(fetched, "macos_app_version"),
        "macos_build_number": _number(fetched, "macos_build_number"),
        "web_k_version": _text(fetched, "web_k_version"),
        "web_a_version": _text(fetched, "web_a_version"),
    }
