"""``import opentele2`` hands the core's AES-IGE to Telethon as ``cryptg``.

Each case runs in a fresh, isolated interpreter: Telethon binds the top-level
cryptg once, when telethon.crypto.aes is first imported, so the registration
must happen before that import and cannot be observed in the pytest process.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

# Raising from find_spec hides any installed cryptg, so the rule sees "no real
# cryptg"; once sys.modules["cryptg"] is set the finder is never consulted.
NO_REAL_CRYPTG = textwrap.dedent(
    """
    import importlib.abc
    import sys


    class NoRealCryptg(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path, target=None):
            if name == "cryptg":
                raise ImportError("no real cryptg in this interpreter")
            return None


    sys.meta_path.insert(0, NoRealCryptg())
    assert "cryptg" not in sys.modules
    assert "telethon" not in sys.modules

    import opentele2
    from opentele2 import _native

    assert sys.modules["cryptg"] is _native.cryptg

    from telethon.crypto import aes

    assert aes.cryptg is _native.cryptg

    key = bytes(range(32))
    iv = bytes(range(32, 64))
    plain = bytes(range(64, 128))
    cipher = aes.AES.encrypt_ige(plain, key, iv)
    assert cipher == _native.aes_ige_encrypt(plain, key, iv)
    assert aes.AES.decrypt_ige(cipher, key, iv) == plain

    # Telethon's own pure-Python IGE must agree with the registered cryptg.
    aes.cryptg = None
    aes.libssl.encrypt_ige = None
    aes.libssl.decrypt_ige = None
    assert aes.AES.encrypt_ige(plain, key, iv) == cipher
    assert aes.AES.decrypt_ige(cipher, key, iv) == plain
    print("registered")
    """
)

REAL_CRYPTG = textwrap.dedent(
    """
    import sys

    sys.path.insert(0, sys.argv[1])

    import opentele2
    from opentele2 import _native

    real = sys.modules["cryptg"]
    assert real is not _native.cryptg
    assert real.MARKER == "real cryptg"
    print("left in charge")
    """
)


def run_fresh(source: str, *args: str) -> str:
    completed = subprocess.run(
        [sys.executable, "-I", "-c", source, *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def test_import_registers_cryptg_for_telethon() -> None:
    assert run_fresh(NO_REAL_CRYPTG) == "registered"


def test_real_cryptg_is_left_in_charge(tmp_path: Path) -> None:
    (tmp_path / "cryptg.py").write_text('MARKER = "real cryptg"\n', encoding="utf-8")
    assert run_fresh(REAL_CRYPTG, str(tmp_path)) == "left in charge"
