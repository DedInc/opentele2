from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from src import devices
from src.devices import WebBrowserDevice

pytest.importorskip("browserforge")

# Far past any bundled browserforge dataset, so the window must slide.
_LIVE_CHROME = 160
_LIVE_FIREFOX = 158


@pytest.fixture
def regenerated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(
        WebBrowserDevice, "_fetch_max_chromium", classmethod(lambda cls: _LIVE_CHROME)
    )
    monkeypatch.setattr(
        devices,
        "_get_firefox_latest_version",
        lambda: (_LIVE_FIREFOX, _LIVE_FIREFOX - 3),
    )
    monkeypatch.setattr(WebBrowserDevice, "_generated", False)
    monkeypatch.setattr(WebBrowserDevice, "deviceList", [])
    monkeypatch.setattr(WebBrowserDevice, "_k_deviceList", [])
    WebBrowserDevice.__gen__()
    yield


def _majors(pattern: str) -> set[int]:
    return {
        int(m.group(1))
        for d in WebBrowserDevice.deviceList
        if (m := re.search(pattern, d.model))
    }


def test_a_live_version_newer_than_the_dataset_keeps_several_uas(
    regenerated: None,
) -> None:
    uas = {d.model for d in WebBrowserDevice.deviceList}

    assert len(uas) > 1
    assert any("Firefox" in ua for ua in uas)
    assert any("Edg/" in ua for ua in uas)
    assert any("Chrome/" in ua and "Edg/" not in ua for ua in uas)


def test_shifted_versions_land_in_the_live_window(regenerated: None) -> None:
    chrome = _majors(r"Chrome/(\d+)\.")
    firefox = _majors(r"Firefox/(\d+)\.")

    assert chrome and max(chrome) <= _LIVE_CHROME
    assert min(chrome) >= _LIVE_CHROME - 6
    assert firefox and max(firefox) <= _LIVE_FIREFOX
    assert min(firefox) >= _LIVE_FIREFOX - 3


def test_firefox_rv_and_product_token_agree(regenerated: None) -> None:
    for d in WebBrowserDevice.deviceList:
        if "Firefox/" not in d.model:
            continue
        rv = re.search(r"rv:(\d+)", d.model)
        product = re.search(r"Firefox/(\d+)", d.model)
        assert rv and product and rv.group(1) == product.group(1)


def test_shift_is_a_no_op_without_an_offset() -> None:
    ua = "Mozilla/5.0 Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0"

    assert WebBrowserDevice._shift_ua_major("edge", ua, 0) == ua
    assert WebBrowserDevice._shift_ua_major("edge", ua, 8) == (
        "Mozilla/5.0 Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0"
    )
