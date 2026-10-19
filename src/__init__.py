import importlib
import sys

# Telethon binds a top-level cryptg once, when telethon.crypto.aes is first
# imported, so the core's AES-IGE must be registered before td and tl import
# telethon. A real cryptg, when installed, is left in charge.
try:
    importlib.import_module("cryptg")
except ImportError:
    sys.modules["cryptg"] = importlib.import_module("opentele2_core.cryptg")

from . import consistency as consistency
from . import fingerprint as fingerprint
from . import td as td
from . import tl as tl
