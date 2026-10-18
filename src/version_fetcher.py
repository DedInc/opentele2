from __future__ import annotations

import html
import json
import logging
import os
import re
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

__all__ = ["fetch_all_versions"]

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_CACHED: dict[str, object] | None = None

_TG_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.0.0 Safari/537.36"
)


def _fetch_url(url: str, *, headers: dict[str, str] | None = None) -> str:
    req = urllib.request.Request(
        url,
        headers=headers
        or {
            "User-Agent": "opentele2",
            "Accept": "application/json, text/plain, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read().decode("utf-8")


def _fetch_tg_page(query: str) -> str:
    return _fetch_url(
        f"https://t.me/s/tgstable?q={urllib.parse.quote(query)}",
        headers={
            "User-Agent": _TG_UA,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        },
    )


def _parse_tg_messages(html_text: str, platform: str | None = None) -> list[dict]:
    """Version posts from a t.me/s page, oldest first as the page lists them.

    A search for one platform also returns posts for the others, so
    ``platform`` keeps only posts announcing "Telegram for <platform>".
    """
    results: list[dict] = []
    version_pattern = re.compile(
        r"New\s+version\s*:\s*([^\s\(\)]+)(?:\s*\((\d+)\))?",
        re.IGNORECASE,
    )
    platform_pattern = (
        re.compile(rf"Telegram\s+for\s+{re.escape(platform)}\b", re.IGNORECASE)
        if platform
        else None
    )
    # The div carries more than one class ("tgme_widget_message_text js-...").
    for m in re.finditer(
        r'<div[^>]*class="tgme_widget_message_text(?:\s[^"]*)?"[^>]*>(.*?)</div>',
        html_text,
        re.DOTALL,
    ):
        text = html.unescape(re.sub(r"<[^>]+>", "", m.group(1)).strip())
        if platform_pattern and not platform_pattern.search(text):
            continue
        vm = version_pattern.search(text)
        if vm:
            results.append(
                {
                    "version": vm.group(1),
                    "build_code": int(vm.group(2)) if vm.group(2) else None,
                }
            )
    return results


def _fetch_tdesktop() -> dict:
    data = json.loads(
        _fetch_url(
            "https://api.github.com/repos/telegramdesktop/tdesktop/releases/latest"
        )
    )
    tag: str = data["tag_name"].lstrip("v")
    return {"desktop_app_version": tag}


def _fetch_android() -> dict:
    try:
        html_text = _fetch_tg_page("android versions:")
        posts = _parse_tg_messages(html_text, "Android")
        if posts:
            latest = posts[-1]
            result: dict = {"android_app_version": latest["version"]}
            if latest["build_code"] is not None:
                result["android_app_version_code"] = latest["build_code"]
            return result
    except Exception as exc:
        logger.debug("TG android version fetch failed: %s", exc, exc_info=True)

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
    try:
        html_text = _fetch_tg_page("ios versions:")
        posts = _parse_tg_messages(html_text, "iOS")
        if posts:
            latest = posts[-1]
            result: dict = {"ios_app_version": latest["version"]}
            if latest["build_code"] is not None:
                result["ios_build_number"] = latest["build_code"]
            return result
    except Exception as exc:
        logger.debug("TG ios version fetch failed: %s", exc, exc_info=True)

    data = json.loads(_fetch_url("https://itunes.apple.com/lookup?id=686449807"))
    return {"ios_app_version": data["results"][0]["version"]}


def _fetch_macos() -> dict:
    try:
        data = json.loads(_fetch_url("https://formulae.brew.sh/api/cask/telegram.json"))
        raw_version: str = data.get("version", "")
        if raw_version and "," in raw_version:
            parts = raw_version.split(",", 1)
            version = parts[0].strip()
            build_code = parts[1].strip()
            return {
                "macos_app_version": version,
                "macos_build_number": int(build_code)
                if build_code.isdigit()
                else build_code,
            }
        if raw_version:
            return {"macos_app_version": raw_version}
    except Exception as exc:
        logger.debug("Homebrew macos version fetch failed: %s", exc, exc_info=True)

    data = json.loads(_fetch_url("https://itunes.apple.com/lookup?id=747648890"))
    return {"macos_app_version": data["results"][0]["version"]}


def _fetch_web_k() -> dict:
    content = _fetch_url(
        "https://raw.githubusercontent.com/morethanwords/tweb/master/public/version"
    ).strip()
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    version_line = ""
    for line in lines:
        if not line.startswith(("<<<", "===", ">>>")):
            version_line = line
            break
    if not version_line and lines:
        version_line = lines[0]
    version = (
        version_line.split("(")[0].strip() if "(" in version_line else version_line
    )
    return {"web_k_version": f"{version} K"}


def _fetch_web_a() -> dict:
    content = _fetch_url(
        "https://raw.githubusercontent.com/Ajaxy/telegram-tt/"
        "refs/heads/master/public/version.txt"
    ).strip()
    return {
        "web_a_version": f"{content} A",
    }


_FETCHERS: list[Callable[[], dict]] = [
    _fetch_tdesktop,
    _fetch_android,
    _fetch_telegram_x,
    _fetch_ios,
    _fetch_macos,
    _fetch_web_k,
    _fetch_web_a,
]


def fetch_all_versions(timeout: float = _TIMEOUT) -> dict[str, object]:
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    if os.environ.get("OPENTELE_NO_FETCH"):
        _CACHED = {}
        return _CACHED

    result: dict[str, object] = {}
    try:
        with ThreadPoolExecutor(max_workers=len(_FETCHERS)) as pool:
            futures = {pool.submit(fn): fn.__name__ for fn in _FETCHERS}
            for future in as_completed(futures, timeout=timeout + 5):
                name = futures[future]
                try:
                    data = future.result(timeout=2)
                    # An empty answer must not overwrite a working default.
                    result.update(
                        {k: v for k, v in data.items() if v not in ("", None)}
                    )
                except Exception as exc:
                    logger.debug(
                        "Version fetch %s failed: %s", name, exc, exc_info=True
                    )
    except Exception as exc:
        logger.debug("Version fetch pool error: %s", exc, exc_info=True)

    _CACHED = result
    return result
