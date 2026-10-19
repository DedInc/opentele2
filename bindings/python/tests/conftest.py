"""Shared pytest configuration: tests marked ``live`` need the network and
run only with ``OPENTELE2_LIVE=1``, as the npm tests do."""

from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("OPENTELE2_LIVE") == "1":
        return
    skip_live = pytest.mark.skip(reason="needs the network; set OPENTELE2_LIVE=1")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
