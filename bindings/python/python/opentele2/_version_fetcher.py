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

__all__ = ["fetch_all_versions"]

logger = logging.getLogger(__name__)

_TIMEOUT = _native.DEFAULT_TIMEOUT
_CACHED: dict[str, str | int] | None = None


def fetch_all_versions(timeout: float = _TIMEOUT) -> dict[str, str | int]:
    """The fields the release feeds answered, fetched once and cached.

    The native patch is taken as is: it only holds fields a source answered
    with a non-empty value. Any failure yields an empty result, as in 1.5.0.
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
        result = patch

    _CACHED = result
    return result


def versions_patch(fetched: Mapping[str, str | int]) -> dict[str, str | int]:
    """``fetched`` as the patch ``_native.apply_versions_patch`` takes, every
    field kept; the core rejects an unknown field or a wrongly typed value."""
    return dict(fetched)
