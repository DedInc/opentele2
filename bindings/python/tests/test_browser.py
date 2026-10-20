"""opentele2.browser: browserforge-shaped header and fingerprint generation
over the Rust port, and the natives it draws through."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from opentele2 import _native
from opentele2.browser import (
    Browser,
    Fingerprint,
    FingerprintGenerator,
    HeaderGenerator,
    NavigatorFingerprint,
    Screen,
    ScreenFingerprint,
    VideoCard,
)

SEEDS = range(12)

# browserforge's Fingerprint, ScreenFingerprint and NavigatorFingerprint
# dataclass fields.
FINGERPRINT_KEYS = {
    "screen",
    "navigator",
    "headers",
    "videoCodecs",
    "audioCodecs",
    "pluginsData",
    "battery",
    "videoCard",
    "multimediaDevices",
    "fonts",
    "mockWebRTC",
    "slim",
}
SCREEN_KEYS = {
    "availHeight",
    "availWidth",
    "availTop",
    "availLeft",
    "colorDepth",
    "height",
    "pixelDepth",
    "width",
    "devicePixelRatio",
    "pageXOffset",
    "pageYOffset",
    "innerHeight",
    "outerHeight",
    "outerWidth",
    "innerWidth",
    "screenX",
    "clientWidth",
    "clientHeight",
    "hasHDR",
}
NAVIGATOR_KEYS = {
    "userAgent",
    "userAgentData",
    "doNotTrack",
    "appCodeName",
    "appName",
    "appVersion",
    "oscpu",
    "webdriver",
    "language",
    "languages",
    "platform",
    "deviceMemory",
    "hardwareConcurrency",
    "product",
    "productSub",
    "vendor",
    "vendorSub",
    "maxTouchPoints",
    "extraProperties",
}


def _major(user_agent: str, token: str) -> int:
    found = re.search(token + r"/(\d+)", user_agent)
    assert found, user_agent
    return int(found.group(1))


# Seeded determinism.


def test_a_seed_reproduces_the_headers() -> None:
    generator = HeaderGenerator()
    for seed in SEEDS:
        assert generator.generate(seed=seed) == HeaderGenerator().generate(seed=seed)
        assert list(generator.generate(seed=seed)) == list(generator.generate(seed=seed))


def test_a_seed_reproduces_the_fingerprint() -> None:
    generator = FingerprintGenerator()
    for seed in ("alpha", "beta", 7):
        first = generator.generate(seed=seed)
        assert first == FingerprintGenerator().generate(seed=seed)
        assert first.dumps() == generator.generate(seed=seed).dumps()


def test_an_int_seed_is_its_decimal_text() -> None:
    assert HeaderGenerator().generate(seed=42) == HeaderGenerator().generate(seed="42")


def test_different_seeds_give_different_fingerprints() -> None:
    dumps = {FingerprintGenerator().generate(seed=seed).dumps() for seed in SEEDS}
    assert len(dumps) > 1


def test_unseeded_calls_vary() -> None:
    headers = {json.dumps(HeaderGenerator().generate()) for _ in range(20)}
    fingerprints = {FingerprintGenerator().generate().dumps() for _ in range(20)}
    assert len(headers) > 1
    assert len(fingerprints) > 1


# Constraints.


def test_browser_os_and_device_constrain_the_user_agent() -> None:
    generator = HeaderGenerator(browser="firefox", os="linux", device="desktop")
    for seed in SEEDS:
        user_agent = generator.generate(seed=seed)["User-Agent"]
        assert "Firefox/" in user_agent
        assert "Linux" in user_agent
        assert "Mobile" not in user_agent


def test_a_mobile_android_device_gives_a_mobile_user_agent() -> None:
    generator = HeaderGenerator(browser="chrome", os="android", device="mobile")
    for seed in SEEDS:
        user_agent = generator.generate(seed=seed)["User-Agent"]
        assert "Android" in user_agent
        assert "Mobile" in user_agent


def test_browser_version_bounds_are_honoured() -> None:
    newest = max(
        _major(
            HeaderGenerator(browser="chrome", os="windows").generate(seed=s)["User-Agent"], "Chrome"
        )
        for s in SEEDS
    )
    generator = HeaderGenerator(browser=[Browser("chrome", min_version=newest)], os="windows")
    for seed in SEEDS:
        assert _major(generator.generate(seed=seed)["User-Agent"], "Chrome") >= newest


def test_generate_overrides_replace_the_generator_options() -> None:
    generator = HeaderGenerator(browser="firefox")
    for seed in SEEDS:
        user_agent = generator.generate(browser="chrome", os="windows", seed=seed)["User-Agent"]
        assert "Chrome/" in user_agent
        assert "Firefox" not in user_agent
        assert "Windows" in user_agent


def test_locales_fill_accept_language() -> None:
    headers = HeaderGenerator(locale=["de-DE", "en"]).generate(seed=1)
    assert headers["Accept-Language"] == "de-DE;q=1.0, en;q=0.9"
    fingerprint = FingerprintGenerator(locale=["de-DE", "en"]).generate(seed=1)
    assert fingerprint.navigator.languages == ["de-DE", "en"]
    assert fingerprint.navigator.language == "de-DE"


def test_user_agent_and_request_dependent_headers_are_honoured() -> None:
    user_agent = HeaderGenerator(browser="firefox").generate(seed=3)["User-Agent"]
    for seed in SEEDS:
        headers = HeaderGenerator().generate(
            user_agent=user_agent,
            request_dependent_headers={"Referer": "https://example.org/"},
            seed=seed,
        )
        assert headers["User-Agent"] == user_agent
        assert headers["Referer"] == "https://example.org/"


def test_screen_min_width_is_honoured() -> None:
    generator = FingerprintGenerator(screen=Screen(min_width=1920), strict=True)
    for seed in SEEDS:
        assert generator.generate(seed=seed).screen.width >= 1920


def test_screen_override_and_flags_reach_the_fingerprint() -> None:
    generator = FingerprintGenerator(mock_webrtc=True)
    fingerprint = generator.generate(screen=Screen(max_width=1400), slim=True, seed=5)
    assert fingerprint.screen.width <= 1400
    assert fingerprint.mockWebRTC is True
    assert fingerprint.slim is True
    assert generator.generate(seed=5).slim is False


def test_fingerprint_headers_match_the_navigator() -> None:
    for seed in SEEDS:
        fingerprint = FingerprintGenerator(browser="chrome").generate(seed=seed)
        assert fingerprint.headers["User-Agent"] == fingerprint.navigator.userAgent
        assert "Chrome/" in fingerprint.navigator.userAgent


# Errors.


def test_inverted_bounds_raise_value_error() -> None:
    with pytest.raises(ValueError, match="cannot exceed max version"):
        Browser("chrome", min_version=120, max_version=100)
    with pytest.raises(ValueError, match="min values cannot be greater"):
        Screen(min_width=1000, max_width=800)


def test_strict_unsatisfiable_headers_raise_value_error() -> None:
    generator = HeaderGenerator(browser="safari", os="windows", strict=True)
    with pytest.raises(ValueError, match="No headers based on this input"):
        generator.generate(seed=1)


def test_non_strict_headers_relax_the_constraints() -> None:
    headers = HeaderGenerator(browser="safari", os="windows").generate(seed=1)
    assert headers["User-Agent"]


def test_strict_unsatisfiable_screen_raises_value_error() -> None:
    generator = FingerprintGenerator(screen=Screen(min_width=99_999), strict=True)
    with pytest.raises(ValueError, match="screen constraints are too restrictive"):
        generator.generate(seed=1)
    assert FingerprintGenerator(screen=Screen(min_width=99_999)).generate(seed=1).screen.width


def test_too_many_locales_and_bad_http_versions_raise_value_error() -> None:
    with pytest.raises(ValueError, match="at most 10 locales"):
        HeaderGenerator(locale=[f"l{n}" for n in range(11)]).generate(seed=1)
    bad_version: Any = 3
    with pytest.raises(ValueError, match="http_version must be 1 or 2"):
        HeaderGenerator(http_version=bad_version).generate(seed=1)


# Output shape.


def test_fingerprint_json_keys_are_browserforge_s() -> None:
    fingerprint = FingerprintGenerator().generate(seed="keys")
    assert isinstance(fingerprint, Fingerprint)
    assert isinstance(fingerprint.screen, ScreenFingerprint)
    assert isinstance(fingerprint.navigator, NavigatorFingerprint)
    assert fingerprint.videoCard is None or isinstance(fingerprint.videoCard, VideoCard)
    dumped = json.loads(fingerprint.dumps())
    assert set(dumped) == FINGERPRINT_KEYS
    assert set(dumped["screen"]) == SCREEN_KEYS
    assert set(dumped["navigator"]) == NAVIGATOR_KEYS
    assert dumped["headers"] == fingerprint.headers


def test_http2_headers_are_pascalized_and_http1_headers_too() -> None:
    for version in (1, 2):
        headers = HeaderGenerator(browser="firefox", http_version=version).generate(seed=2)
        assert "User-Agent" in headers
        assert "user-agent" not in headers


def test_native_options_dict_and_keyword_arguments_agree() -> None:
    by_dict = _native.generate_headers({"browser": ["firefox"], "os": "linux"}, seed="n")
    by_kwargs = _native.generate_headers(seed="n", browser=["firefox"], os="linux")
    assert by_dict == by_kwargs
    fingerprint = _native.generate_fingerprint(screen={"min_width": 1920}, seed="n")
    assert set(fingerprint) == FINGERPRINT_KEYS
    assert fingerprint["screen"]["width"] >= 1920


def test_native_unknown_option_raises_type_error() -> None:
    # Typed Any: the stub's TypedDicts reject these keys statically.
    misspelt: Any = {"browsers": ["firefox"]}
    bad_screen: Any = {"screen": {"width": 1}}
    with pytest.raises(TypeError, match="unexpected option"):
        _native.generate_headers(misspelt)
    with pytest.raises(TypeError, match="unexpected option"):
        _native.generate_fingerprint(bad_screen)
