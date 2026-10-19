"""The Python package runs its AES-IGE on opentele2_core and hands the core's
cryptg to Telethon when no real cryptg is installed."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import opentele2_core
import pytest

from src.qt_compat import QByteArray
from src.td.auth import AuthKey
from src.td.storage import Storage

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "crates" / "opentele2-core" / "tests" / "vectors" / "crypto.json"

# Telethon binds cryptg once per interpreter, so the binding is checked in a
# fresh one where nothing has imported telethon before src.
_BRIDGE_PROBE = """
import importlib.util
import json
import os

real_cryptg = importlib.util.find_spec("cryptg") is not None

import src
import opentele2_core
import telethon.crypto.aes as aes

key = bytes(range(32))
iv = bytes(range(32, 64))
plain = os.urandom(64)
encrypted = aes.AES.encrypt_ige(plain, key, iv)
print("bridge-probe:" + json.dumps({
    "real_cryptg": real_cryptg,
    "bound_to_core": aes.cryptg is opentele2_core.cryptg,
    "registered": __import__("sys").modules.get("cryptg") is opentele2_core.cryptg,
    "matches_core": encrypted == opentele2_core.aes_ige_encrypt(plain, key, iv),
    "round_trips": aes.AES.decrypt_ige(encrypted, key, iv) == plain,
}))
"""


def _encrypt_local_vectors() -> list[dict[str, str]]:
    return json.loads(VECTORS.read_text(encoding="utf-8"))["encrypt_local"]


def test_importing_src_gives_telethon_the_core_cryptg() -> None:
    probe = subprocess.run(
        [sys.executable, "-c", _BRIDGE_PROBE],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    # src.debug may print its call profile at exit, so the result is tagged.
    marker = "bridge-probe:"
    lines = [ln for ln in probe.stdout.splitlines() if ln.startswith(marker)]
    assert len(lines) == 1, probe.stdout
    result = json.loads(lines[0][len(marker) :])
    if result["real_cryptg"]:
        raise pytest.skip.Exception("a real cryptg is installed and stays in charge")
    assert result["registered"]
    assert result["bound_to_core"]
    assert result["matches_core"]
    assert result["round_trips"]


@pytest.mark.parametrize("index", range(6))
def test_core_ige_matches_the_1_5_0_encrypt_local_vectors(index: int) -> None:
    vector = _encrypt_local_vectors()[index]
    localKey = bytes.fromhex(vector["local_key"])
    msgKey = bytes.fromhex(vector["msg_key"])
    # The IGE plaintext is the length-prefixed payload plus its random padding.
    plain = bytes.fromhex(vector["decrypted"]) + bytes.fromhex(vector["padding"])
    encrypted = bytes.fromhex(vector["encrypted"])
    assert encrypted[:16] == msgKey
    cipher = encrypted[16:]

    aesKey, aesIv = opentele2_core.prepare_aes_oldmtp(localKey, msgKey, False)
    assert opentele2_core.aes_ige_encrypt(plain, aesKey, aesIv) == cipher
    assert opentele2_core.cryptg.encrypt_ige(plain, aesKey, aesIv) == cipher

    authKey = AuthKey(localKey)
    viaStorage = Storage.aesEncryptLocal(QByteArray(plain), authKey, QByteArray(msgKey))
    assert bytes(viaStorage) == cipher
    viaStorageBack = Storage.aesDecryptLocal(viaStorage, authKey, QByteArray(msgKey))
    assert bytes(viaStorageBack) == plain


def test_the_vector_file_holds_six_encrypt_local_cases() -> None:
    assert len(_encrypt_local_vectors()) == 6


def test_core_cryptg_reports_bad_lengths_as_value_errors() -> None:
    with pytest.raises(ValueError):
        opentele2_core.cryptg.encrypt_ige(bytes(15), bytes(32), bytes(32))
    with pytest.raises(ValueError):
        opentele2_core.cryptg.decrypt_ige(bytes(16), bytes(31), bytes(32))
