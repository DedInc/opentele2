from __future__ import annotations

import json
import logging
import os
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List

__all__ = ["fetch_all_versions"]

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_CACHED: Dict[str, object] | None = None


def _fetch_url(url: str) -> str:
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
    data = json.loads(
        _fetch_url(
            "https://api.github.com/repos/telegramdesktop/tdesktop/releases/latest"
        )
    )
    tag: str = data["tag_name"].lstrip("v")
    return {"desktop_app_version": tag}


def _fetch_android() -> dict:
    data = json.loads(
        _fetch_url("https://play.rajkumaar.co.in/json?id=org.telegram.messenger")
    )
    return {"android_app_version": data["version"]}


def _fetch_telegram_x() -> dict:
    data = json.loads(
        _fetch_url(
            "https://api.github.com/repos/TGX-Android/Telegram-X/releases/latest"
        )
    )
    tag: str = data["tag_name"].lstrip("v")
    return {"android_x_app_version": tag}


def _fetch_ios() -> dict:
    data = json.loads(_fetch_url("https://itunes.apple.com/lookup?id=686449807"))
    return {"ios_app_version": data["results"][0]["version"]}


def _fetch_macos() -> dict:
    data = json.loads(_fetch_url("https://itunes.apple.com/lookup?id=747648890"))
    return {"macos_app_version": data["results"][0]["version"]}


def _fetch_web_k() -> dict:
    content = _fetch_url(
        "https://raw.githubusercontent.com/morethanwords/tweb/master/public/version"
    ).strip()
    version = content.split("(")[0].strip() if "(" in content else content
    return {"web_k_version": f"{version} K"}


def _fetch_web_a() -> dict:
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


def fetch_all_versions(timeout: float = _TIMEOUT) -> Dict[str, object]:
    global _CACHED
    if _CACHED is not None:
        return _CACHED

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
