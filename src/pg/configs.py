from __future__ import annotations

DC_ADDRESSES: dict[int, tuple[str, int]] = {
    1: ("149.154.175.53", 443),
    2: ("149.154.167.51", 443),
    3: ("149.154.175.100", 443),
    4: ("149.154.167.91", 443),
    5: ("91.108.56.130", 443),
}

DC_ADDRESSES_TEST: dict[int, tuple[str, int]] = {
    1: ("149.154.175.10", 443),
    2: ("149.154.167.40", 443),
    3: ("149.154.175.117", 443),
}

PYRO_SCHEMA_VERSION = 3

SESSION_STRING_FORMAT = ">BI?256sQ?"
SESSION_STRING_SIZE = 271 

SESSION_STRING_FORMAT_OLD = ">BI?256sI?"
SESSION_STRING_SIZE_OLD = 267
