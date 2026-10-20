"""opentele2: a Telegram client identity toolkit on a Rust core.

It reads and writes Telegram Desktop ``tdata`` folders, converts their
accounts to Telethon sessions (and mtcute string sessions), and provides the
official client API profiles and devices, ``initConnection`` fingerprints and
browser fingerprints, all computed by the core in ``opentele2._native``."""

import importlib
import sys

# Telethon binds a top-level cryptg once, when telethon.crypto.aes is first
# imported, so the core's AES-IGE must be registered before anything imports
# telethon. A real cryptg, when installed, is left in charge.
try:
    importlib.import_module("cryptg")
except ImportError:
    sys.modules["cryptg"] = importlib.import_module("opentele2._native.cryptg")

# Telethon's AES-CTR, PQ factorisation, SHA-1/SHA-256 and password hashing
# are names its modules bind at their own import, so importing
# _telethon_crypto imports those modules and rebinds the names in place
# (_telethon_crypto.install): it works whether telethon was imported before or
# after opentele2. It comes after the cryptg registration because importing
# telethon binds cryptg.
from . import _telethon_crypto as _telethon_crypto

# Importing api imports fingerprint, which fetches and applies the current
# platform versions (unless OPENTELE_NO_FETCH is set), and then syncs the
# API class attributes to them.
from . import api as api
from . import consistency as consistency
from . import fingerprint as fingerprint
from . import td as td
from . import tl as tl
