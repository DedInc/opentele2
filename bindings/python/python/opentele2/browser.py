"""Browser HTTP headers and fingerprints shaped as browserforge's, drawn by
:mod:`opentele2._native` from the Rust port in ``crates/opentele2-browser``.

:class:`HeaderGenerator` and :class:`FingerprintGenerator` take browserforge's
argument names and defaults. Their ``generate`` methods also take ``seed``
(a ``str`` or ``int``): the same seed and options always give the same
output, on any platform; without one every call draws from the operating
system's entropy. Options that cannot be met, or that are invalid, raise
``ValueError`` as in browserforge.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from . import _native

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from typing import Literal, Union

    from typing_extensions import TypeAlias

    from ._native import BrowserSpec, FingerprintData, HeaderOptions, ScreenSpec

    _Texts: TypeAlias = Union[str, Sequence[str]]
    _HttpVersion: TypeAlias = Literal[1, 2, "1", "2"]

__all__ = [
    "SUPPORTED_BROWSERS",
    "SUPPORTED_DEVICES",
    "SUPPORTED_HTTP_VERSIONS",
    "SUPPORTED_OPERATING_SYSTEMS",
    "Browser",
    "Fingerprint",
    "FingerprintGenerator",
    "HeaderGenerator",
    "NavigatorFingerprint",
    "Screen",
    "ScreenFingerprint",
    "VideoCard",
]

SUPPORTED_BROWSERS = ("chrome", "firefox", "safari", "edge")
SUPPORTED_OPERATING_SYSTEMS = ("windows", "macos", "linux", "android", "ios")
SUPPORTED_DEVICES = ("desktop", "mobile")
SUPPORTED_HTTP_VERSIONS = ("1", "2")


@dataclass
class Browser:
    """A browser the headers may come from, with optional bounds on its major
    version and the HTTP version it speaks."""

    name: str
    min_version: int | None = None
    max_version: int | None = None
    http_version: str | int = "2"

    def __post_init__(self) -> None:
        if isinstance(self.http_version, int):
            self.http_version = str(self.http_version)
        if (
            self.min_version is not None
            and self.max_version is not None
            and self.min_version > self.max_version
        ):
            raise ValueError(
                f"Browser min version constraint ({self.min_version}) cannot exceed max "
                f"version ({self.max_version})"
            )


@dataclass
class Screen:
    """Bounds on the screen dimensions of a generated fingerprint, each
    inclusive; ``None`` leaves that side open."""

    min_width: int | None = None
    max_width: int | None = None
    min_height: int | None = None
    max_height: int | None = None

    def __post_init__(self) -> None:
        def inverted(low: int | None, high: int | None) -> bool:
            return low is not None and high is not None and low > high

        if inverted(self.min_width, self.max_width) or inverted(self.min_height, self.max_height):
            raise ValueError(
                "Invalid screen constraints: min values cannot be greater than max values"
            )

    def is_set(self) -> bool:
        """Whether any bound is set."""
        return any(
            value is not None
            for value in (self.min_width, self.max_width, self.min_height, self.max_height)
        )


@dataclass
class ScreenFingerprint:
    availHeight: int
    availWidth: int
    availTop: int
    availLeft: int
    colorDepth: int
    height: int
    pixelDepth: int
    width: int
    devicePixelRatio: float
    pageXOffset: int
    pageYOffset: int
    innerHeight: int
    outerHeight: int
    outerWidth: int
    innerWidth: int
    screenX: int
    clientWidth: int
    clientHeight: int
    hasHDR: bool


@dataclass
class NavigatorFingerprint:
    userAgent: str
    userAgentData: dict[str, Any] | None
    doNotTrack: str | None
    appCodeName: str
    appName: str
    appVersion: str
    oscpu: str | None
    webdriver: Any
    language: str
    languages: list[str]
    platform: str
    deviceMemory: float | None
    hardwareConcurrency: int
    product: str
    productSub: str
    vendor: str | None
    vendorSub: str | None
    maxTouchPoints: int
    extraProperties: dict[str, Any] | None


@dataclass
class VideoCard:
    renderer: str
    vendor: str


@dataclass
class Fingerprint:
    """A generated browser fingerprint and the headers it was drawn for."""

    screen: ScreenFingerprint
    navigator: NavigatorFingerprint
    headers: dict[str, str]
    videoCodecs: dict[str, str] | None
    audioCodecs: dict[str, str] | None
    pluginsData: dict[str, Any] | None
    battery: dict[str, Any] | None
    videoCard: VideoCard | None
    multimediaDevices: dict[str, Any] | None
    fonts: list[str] | None
    mockWebRTC: bool | None
    slim: bool | None

    def dumps(self) -> str:
        """The fingerprint as a JSON string, as browserforge's ``dumps``."""
        return json.dumps(asdict(self))

    @classmethod
    def _from_data(cls, data: FingerprintData) -> Fingerprint:
        card = data["videoCard"]
        return cls(
            screen=ScreenFingerprint(**data["screen"]),
            navigator=NavigatorFingerprint(**data["navigator"]),
            headers=data["headers"],
            videoCodecs=data["videoCodecs"],
            audioCodecs=data["audioCodecs"],
            pluginsData=data["pluginsData"],
            battery=data["battery"],
            videoCard=VideoCard(**card) if card else None,
            multimediaDevices=data["multimediaDevices"],
            fonts=data["fonts"],
            mockWebRTC=data["mockWebRTC"],
            slim=data["slim"],
        )


def _tuplify(value: Any) -> tuple[Any, ...]:
    """A ``str`` (or a single :class:`Browser`) as a one-item tuple, any other
    iterable as a tuple, as browserforge's ``tuplify``."""
    if isinstance(value, (str, Browser)):
        return (value,)
    return tuple(value)


def _http(value: object) -> Literal["1", "2"]:
    """An HTTP version as browserforge spells it; another raises
    ``ValueError``."""
    text = str(value)
    if text == "1":
        return "1"
    if text == "2":
        return "2"
    raise ValueError(f"http_version must be 1 or 2, not {value!r}")


def _browser_spec(browser: Browser) -> BrowserSpec:
    return {
        "name": browser.name,
        "min_version": browser.min_version,
        "max_version": browser.max_version,
        "http_version": _http(browser.http_version),
    }


def _screen_spec(screen: Screen | None) -> ScreenSpec | None:
    if screen is None:
        return None
    return {
        "min_width": screen.min_width,
        "max_width": screen.max_width,
        "min_height": screen.min_height,
        "max_height": screen.max_height,
    }


def _first(*values: Any) -> Any:
    return next((value for value in values if value is not None), None)


class HeaderGenerator:
    """Generates browser HTTP headers consistent with a set of constraints,
    as browserforge's ``HeaderGenerator``."""

    def __init__(
        self,
        browser: _Texts | Iterable[str | Browser] = SUPPORTED_BROWSERS,
        os: _Texts = SUPPORTED_OPERATING_SYSTEMS,
        device: _Texts = SUPPORTED_DEVICES,
        locale: _Texts = "en-US",
        http_version: _HttpVersion = 2,
        strict: bool = False,
    ) -> None:
        http = str(http_version)
        self.options: dict[str, Any] = {
            "browsers": self._prepare_browsers(_tuplify(browser), http),
            "os": _tuplify(os),
            "devices": _tuplify(device),
            "locales": _tuplify(locale),
            "http_version": http,
            "strict": strict,
        }

    @staticmethod
    def _prepare_browsers(browsers: Iterable[str | Browser], http_version: str) -> list[Browser]:
        """Names as :class:`Browser` objects speaking ``http_version``;
        :class:`Browser` objects keep their own version."""
        return [
            Browser(name=browser, http_version=http_version)
            if isinstance(browser, str)
            else browser
            for browser in browsers
        ]

    def _native_options(
        self,
        browser: _Texts | Iterable[str | Browser] | None = None,
        os: _Texts | None = None,
        device: _Texts | None = None,
        locale: _Texts | None = None,
        http_version: _HttpVersion | None = None,
        user_agent: _Texts | None = None,
        strict: bool | None = None,
        request_dependent_headers: dict[str, str] | None = None,
    ) -> HeaderOptions:
        """The generator's options with the given overrides, as
        browserforge's ``generate`` merges them."""
        http: str = str(http_version) if http_version else self.options["http_version"]
        if browser is not None:
            browsers = self._prepare_browsers(_tuplify(browser), http)
        elif http != self.options["http_version"]:
            # A new HTTP version applies to every configured browser.
            browsers = [
                Browser(
                    name=known.name,
                    min_version=known.min_version,
                    max_version=known.max_version,
                    http_version=http,
                )
                for known in self.options["browsers"]
            ]
        else:
            browsers = self.options["browsers"]
        return {
            "browser": [_browser_spec(known) for known in browsers],
            "os": _tuplify(_first(os, self.options["os"])),
            "device": _tuplify(_first(device, self.options["devices"])),
            "locale": _tuplify(_first(locale, self.options["locales"])),
            "http_version": _http(http),
            "strict": bool(_first(strict, self.options["strict"])),
            "user_agent": None if user_agent is None else _tuplify(user_agent),
            "request_dependent_headers": request_dependent_headers,
        }

    def generate(
        self,
        *,
        browser: _Texts | Iterable[str | Browser] | None = None,
        os: _Texts | None = None,
        device: _Texts | None = None,
        locale: _Texts | None = None,
        http_version: _HttpVersion | None = None,
        user_agent: _Texts | None = None,
        strict: bool | None = None,
        request_dependent_headers: dict[str, str] | None = None,
        seed: str | int | None = None,
    ) -> dict[str, str]:
        """One set of headers, name to value in sending order, from the
        generator's options and the overrides given; reproducible with
        ``seed``."""
        options = self._native_options(
            browser=browser,
            os=os,
            device=device,
            locale=locale,
            http_version=http_version,
            user_agent=user_agent,
            strict=strict,
            request_dependent_headers=request_dependent_headers,
        )
        return _native.generate_headers(options, seed=seed)


class FingerprintGenerator:
    """Generates browser fingerprints with matching headers, as
    browserforge's ``FingerprintGenerator``; ``header_kwargs`` are the
    :class:`HeaderGenerator` arguments."""

    def __init__(
        self,
        screen: Screen | None = None,
        strict: bool = False,
        mock_webrtc: bool = False,
        slim: bool = False,
        **header_kwargs: Any,
    ) -> None:
        self.header_generator: HeaderGenerator = HeaderGenerator(**header_kwargs)
        self.screen: Screen | None = screen
        self.strict: bool = strict
        self.mock_webrtc: bool = mock_webrtc
        self.slim: bool = slim

    def generate(
        self,
        *,
        screen: Screen | None = None,
        strict: bool | None = None,
        mock_webrtc: bool | None = None,
        slim: bool | None = None,
        seed: str | int | None = None,
        **header_kwargs: Any,
    ) -> Fingerprint:
        """One fingerprint and its headers from the generator's options and
        the overrides given (``header_kwargs`` as for
        :meth:`HeaderGenerator.generate`); reproducible with ``seed``."""
        data = _native.generate_fingerprint(
            {
                "screen": _screen_spec(_first(screen, self.screen)),
                "strict": bool(_first(strict, self.strict)),
                "mock_webrtc": bool(_first(mock_webrtc, self.mock_webrtc)),
                "slim": bool(_first(slim, self.slim)),
                "header": self.header_generator._native_options(**header_kwargs),
            },
            seed=seed,
        )
        return Fingerprint._from_data(data)
