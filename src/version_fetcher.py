"""Fetch latest Telegram client versions from official sources.

Runs all fetches in parallel using threads. Results are cached after the
first successful call.  If any individual fetch fails, its values are
silently skipped and the hardcoded defaults in ``PlatformVersions`` remain.

Set the environment variable ``OPENTELE_NO_FETCH=1`` to disable automatic
fetching entirely (useful for offline / CI environments).
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List

__all__ = ["fetch_all_versions"]

logger = logging.getLogger(__name__)

_TIMEOUT = 10  # per-request timeout in seconds
_CACHED: Dict[str, object] | None = None


# ---------------------------------------------------------------------------
# Individual fetchers — each returns a dict of version fields
# ---------------------------------------------------------------------------


def _fetch_url(url: str) -> str:
    """GET *url* and return the response body as a string."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "opentele2",
            "Accept": "application/json, text/plain, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read().decode("utf-8")


def _fetch_tdesktop() -> dict:
    """Telegram Desktop — GitHub releases tag."""
    data = json.loads(
        _fetch_url(
            "https://api.github.com/repos/telegramdesktop/tdesktop/releases/latest"
        )
    )
    tag: str = data["tag_name"].lstrip("v")
    return {"desktop_app_version": tag}


def _fetch_android() -> dict:
    """Telegram for Android — Google Play Store version."""
    data = json.loads(
        _fetch_url("https://play.rajkumaar.co.in/json?id=org.telegram.messenger")
    )
    return {"android_app_version": data["version"]}


def _fetch_telegram_x() -> dict:
    """Telegram X for Android — GitHub releases tag."""
    data = json.loads(
        _fetch_url(
            "https://api.github.com/repos/TGX-Android/Telegram-X/releases/latest"
        )
    )
    tag: str = data["tag_name"].lstrip("v")
    return {"android_x_app_version": tag}


def _fetch_ios() -> dict:
    """Telegram for iOS — App Store version via iTunes lookup."""
    data = json.loads(_fetch_url("https://itunes.apple.com/lookup?id=686449807"))
    return {"ios_app_version": data["results"][0]["version"]}


def _fetch_macos() -> dict:
    """Telegram for macOS — App Store version via iTunes lookup."""
    data = json.loads(_fetch_url("https://itunes.apple.com/lookup?id=747648890"))
    return {"macos_app_version": data["results"][0]["version"]}


def _fetch_web_k() -> dict:
    """Telegram Web K — version file from source."""
    content = _fetch_url(
        "https://raw.githubusercontent.com/morethanwords/tweb/master/public/version"
    ).strip()
    # Format: "2.2 (625)" — extract the version before the parenthesis
    version = content.split("(")[0].strip() if "(" in content else content
    return {"web_k_version": f"{version} K"}


def _fetch_web_a() -> dict:
    """Telegram Web A (Web Z redirects here) — version.txt from source."""
    content = _fetch_url(
        "https://raw.githubusercontent.com/Ajaxy/telegram-tt/"
        "refs/heads/master/public/version.txt"
    ).strip()
    return {
        "web_a_version": f"{content} A",
    }


_FETCHERS: List[Callable[[], dict]] = [
    _fetch_tdesktop,
    _fetch_android,
    _fetch_telegram_x,
    _fetch_ios,
    _fetch_macos,
    _fetch_web_k,
    _fetch_web_a,
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def fetch_all_versions(timeout: float = _TIMEOUT) -> Dict[str, object]:
    """Fetch the latest client versions from all sources in parallel.

    Returns a flat ``{field_name: value}`` dict.  Keys match the attribute
    names of :class:`~src.fingerprint.PlatformVersions` where possible;
    extra keys (prefixed with nothing special) may be used by callers to
    patch API class attributes.

    The result is cached after the first call; subsequent calls return the
    same dict immediately.
    """
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    # Honour kill-switch
    if os.environ.get("OPENTELE_NO_FETCH"):
        _CACHED = {}
        return _CACHED

    result: Dict[str, object] = {}
    try:
        with ThreadPoolExecutor(max_workers=len(_FETCHERS)) as pool:
            futures = {pool.submit(fn): fn.__name__ for fn in _FETCHERS}
            for future in as_completed(futures, timeout=timeout + 5):
                name = futures[future]
                try:
                    data = future.result(timeout=2)
                    result.update(data)
                except Exception as exc:
                    logger.debug("Version fetch %s failed: %s", name, exc)
    except Exception as exc:
        logger.debug("Version fetch pool error: %s", exc)

    _CACHED = result
    return result
