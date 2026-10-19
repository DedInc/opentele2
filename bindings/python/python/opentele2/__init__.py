"""opentele2: Telegram Desktop tdata, Telethon and mtcute sessions and official
API fingerprints, on the Rust core in ``opentele2._native``."""

import importlib
import sys

# Telethon binds a top-level cryptg once, when telethon.crypto.aes is first
# imported, so the core's AES-IGE must be registered before anything imports
# telethon. A real cryptg, when installed, is left in charge.
try:
    importlib.import_module("cryptg")
except ImportError:
    sys.modules["cryptg"] = importlib.import_module("opentele2._native.cryptg")
