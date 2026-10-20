"""``import opentele2`` routes Telethon's AES-CTR, PQ factorisation, SHA-1,
SHA-256 and password hashing through the Rust core (opentele2/_telethon_crypto.py),
and the results are the ones Telethon computes itself."""

from __future__ import annotations

import hashlib
import inspect
import logging
import os
import random
import struct
import subprocess
import sys
import textwrap
import time

import pyaes
import pytest
import telethon.crypto
import telethon.crypto.aesctr
import telethon.crypto.authkey
import telethon.crypto.cdndecrypter
import telethon.crypto.factorization
import telethon.crypto.rsa
import telethon.helpers
import telethon.network.authenticator
import telethon.network.connection.tcpmtproxy
import telethon.network.connection.tcpobfuscated
import telethon.network.mtprotostate
from telethon import password, types
from telethon.crypto import AES, AuthKey, Factorization
from telethon.network.mtprotostate import MTProtoState

from opentele2 import _telethon_crypto

# The 2FA fixture of test_tl.py (crates/opentele2-core/tests/auth.rs SRP_ONE):
# Telegram's 2048-bit prime and a draw Telethon accepts on its first try.
SRP_P = bytes.fromhex(
    "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f"
    "48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37"
    "20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64"
    "2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4"
    "a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754"
    "fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4"
    "e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f"
    "0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b"
)
SRP_ID = 2479236611711966277
SRP_SALT1 = bytes.fromhex(
    "713a69e9a27390a0968da87fbf1a8510a4c5da97ed6f64447cbc4135821f3eeeabd5317c3ca6d03e"
)
SRP_SALT2 = bytes.fromhex("6c2fffb7af6a052438d3305e2f42f538")
SRP_B = bytes.fromhex(
    "aabfadc340a660e89e0f964c749c62a91d955fa812f58ea17083c3b6b2ddd8e9"
    "04a40c3c3300a5cd6216ceea87982328fff1b08959e9587dfb2b2956954b948a"
    "fb689767e50254d9c732524af2f6e3e25c1db60f99672311669f1b4c50fe8ee0"
    "f8202dd71faee5864581146e4bdd933b8e043b1f3a84c5c8acae2d31215346a1"
    "eee0d52dd684ac451af249703afe79ab55bbf9e111ec157619205a8d900ae35a"
    "5508670b1da74bde487e58464481343d9b40f26bfac6c43b785e7e0853251b6c"
    "1de9315c25cfc22f474c6803f6eb7879f7198c7e0eed715c236da7a5de2a347b"
    "4ffc471c0f8982bf908e72ea264bced63a635bc3e148b61f0dd248443c06b39d"
)
SRP_DRAW = bytes.fromhex(
    "5e62ea01ba87e020b0b69300dbef2f1c0b8bd99ad78b1a54c8f29f462be3beda"
    "8e96b717b5e98c7f0c9c1be816e57afa06f372a2678876dbaee2ad3f5b37d829"
    "a49bbda90e92eb7bb5ca56defcf971319b8b87c7f1613886bfc067baef17920f"
    "6318981f3626ecbda3ad3194506e9fecd1fbdaa6eced7b2af8b2878c5a40e3f4"
    "ef7368d3fb76a170f5303830f4a07d621adf717a26c5a4fb68a308065a3ba5f6"
    "03b3cac89049642698fbf5ef7bf9455d69bfaae9ab57b7746573f33c54971f6a"
    "0988bbc32fcf75edb64dd438d7807007f598cc96c5ae3d2afe62f1ed109758a9"
    "8a37469dcb7f18505bd39d152b9273e48a69b70734b8fbc0dc90d07804483988"
)
SRP_PASSWORD = "hunter2-fixture"

# (pq, p, q): the core.telegram.org example, and products of 31-bit primes.
KNOWN_PQ = (
    (0x17ED48941A08F981, 0x494C553B, 0x53911073),
    (2147483647 * 2147483629, 2147483629, 2147483647),
    (1000000007 * 998244353, 998244353, 1000000007),
)

PATCHED_NAMES = (
    (telethon.crypto, "AESModeCTR", _telethon_crypto.AESModeCTR),
    (telethon.crypto.aesctr, "AESModeCTR", _telethon_crypto.AESModeCTR),
    (telethon.crypto.cdndecrypter, "AESModeCTR", _telethon_crypto.AESModeCTR),
    (telethon.network.connection.tcpobfuscated, "AESModeCTR", _telethon_crypto.AESModeCTR),
    (telethon.crypto.authkey, "sha1", _telethon_crypto.Sha1Hash),
    (telethon.crypto.rsa, "sha1", _telethon_crypto.Sha1Hash),
    (telethon.helpers, "sha1", _telethon_crypto.Sha1Hash),
    (telethon.network.authenticator, "sha1", _telethon_crypto.Sha1Hash),
    (telethon.network.mtprotostate, "sha256", _telethon_crypto.Sha256Hash),
    (telethon.crypto.cdndecrypter, "sha256", _telethon_crypto.Sha256Hash),
    (password, "hashlib", _telethon_crypto.hashlib_bridge),
    (telethon.network.connection.tcpmtproxy, "hashlib", _telethon_crypto.hashlib_bridge),
)

# Checks every patched name in a fresh interpreter; argv[1] says whether
# telethon is imported before opentele2.
ORDER_CHECK = textwrap.dedent(
    """
    import importlib
    import inspect
    import sys

    first = sys.argv[1]
    if first == "telethon":
        import telethon
        import opentele2
    else:
        import opentele2
        import telethon

    from opentele2 import _telethon_crypto as bridge

    expected = {
        "telethon.crypto": [("AESModeCTR", bridge.AESModeCTR)],
        "telethon.crypto.aesctr": [("AESModeCTR", bridge.AESModeCTR)],
        "telethon.crypto.cdndecrypter": [
            ("AESModeCTR", bridge.AESModeCTR),
            ("sha256", bridge.Sha256Hash),
        ],
        "telethon.network.connection.tcpobfuscated": [("AESModeCTR", bridge.AESModeCTR)],
        "telethon.crypto.authkey": [("sha1", bridge.Sha1Hash)],
        "telethon.crypto.rsa": [("sha1", bridge.Sha1Hash)],
        "telethon.helpers": [("sha1", bridge.Sha1Hash)],
        "telethon.network.authenticator": [("sha1", bridge.Sha1Hash)],
        "telethon.network.mtprotostate": [("sha256", bridge.Sha256Hash)],
        "telethon.password": [("hashlib", bridge.hashlib_bridge)],
        "telethon.network.connection.tcpmtproxy": [("hashlib", bridge.hashlib_bridge)],
    }
    for module_name, names in expected.items():
        module = importlib.import_module(module_name)
        for name, value in names:
            assert getattr(module, name) is value, (module_name, name)
    factorization = importlib.import_module("telethon.crypto.factorization")
    assert inspect.getattr_static(factorization.Factorization, "factorize") is bridge.factorize
    assert factorization.Factorization.factorize(0x17ED48941A08F981) == (0x494C553B, 0x53911073)
    print("patched after " + first)
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


def pyaes_ctr(key: bytes, iv: bytes) -> pyaes.AESModeOfOperationCTR:
    # Telethon's AESModeCTR: a pyaes CTR whose 16-byte counter starts at iv.
    return pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(int.from_bytes(iv, "big")))


def reference_calc_key(auth_key: bytes, msg_key: bytes, client: bool) -> tuple[bytes, bytes]:
    x = 0 if client else 8
    sha256a = hashlib.sha256(msg_key + auth_key[x : x + 36]).digest()
    sha256b = hashlib.sha256(auth_key[x + 40 : x + 76] + msg_key).digest()
    aes_key = sha256a[:8] + sha256b[8:24] + sha256a[24:32]
    aes_iv = sha256b[:8] + sha256a[8:24] + sha256b[24:32]
    return aes_key, aes_iv


class TestPatchedNames:
    @pytest.mark.parametrize(("module", "name", "value"), PATCHED_NAMES)
    def test_name_is_opentele2s(self, module: object, name: str, value: object) -> None:
        assert getattr(module, name) is value

    def test_factorize_is_opentele2s(self) -> None:
        patched = inspect.getattr_static(Factorization, "factorize")
        assert patched is _telethon_crypto.factorize
        assert telethon.crypto.factorization.Factorization is Factorization

    def test_install_is_idempotent(self) -> None:
        original = _telethon_crypto._Originals.factorize
        ctr = _telethon_crypto._Originals.ctr
        _telethon_crypto.install()
        assert _telethon_crypto._Originals.factorize is original
        assert _telethon_crypto._Originals.ctr is ctr
        assert inspect.getattr_static(Factorization, "factorize") is _telethon_crypto.factorize

    @pytest.mark.parametrize("first", ["telethon", "opentele2"])
    def test_either_import_order_patches(self, first: str) -> None:
        assert run_fresh(ORDER_CHECK, first) == f"patched after {first}"


class TestAesCtr:
    def test_matches_pyaes_over_random_chunks(self) -> None:
        rng = random.Random(278)
        for _ in range(20):
            key, iv = os.urandom(32), os.urandom(16)
            ours = telethon.crypto.AESModeCTR(key, iv)
            reference = pyaes_ctr(key, iv)
            for _ in range(8):
                chunk = os.urandom(rng.randrange(0, 300))
                assert ours.encrypt(chunk) == reference.encrypt(chunk)

    def test_encrypt_and_decrypt_share_one_keystream(self) -> None:
        key, iv = os.urandom(32), os.urandom(16)
        plain = os.urandom(1000)
        sender = _telethon_crypto.AESModeCTR(key, iv)
        cipher = sender.encrypt(plain[:333]) + sender.decrypt(plain[333:])
        assert cipher == pyaes_ctr(key, iv).encrypt(plain)
        receiver = _telethon_crypto.AESModeCTR(key=key, iv=iv)
        assert receiver.decrypt(cipher[:17]) + receiver.decrypt(cipher[17:]) == plain

    def test_counter_wraps_like_pyaes(self) -> None:
        key, iv = os.urandom(32), b"\xff" * 16
        plain = os.urandom(100)
        expected = pyaes_ctr(key, iv).encrypt(plain)
        assert _telethon_crypto.AESModeCTR(key, iv).encrypt(plain) == expected

    def test_short_keys_stay_on_pyaes(self) -> None:
        for size in (16, 24):
            key, iv = os.urandom(size), os.urandom(16)
            plain = os.urandom(77)
            expected = pyaes_ctr(key, iv).encrypt(plain)
            assert _telethon_crypto.AESModeCTR(key, iv).encrypt(plain) == expected


class TestFactorize:
    @pytest.mark.parametrize(("pq", "p", "q"), KNOWN_PQ)
    def test_matches_telethons_algorithm(self, pq: int, p: int, q: int) -> None:
        original = _telethon_crypto._Originals.factorize
        assert original is not None
        assert Factorization.factorize(pq) == (p, q)
        assert original(pq) == (p, q)

    @pytest.mark.parametrize("pq", [2, 4, 6, 1000003, (2**61 - 1) * 2147483647])
    def test_outside_the_core_falls_back_to_telethon(self, pq: int) -> None:
        original = _telethon_crypto._Originals.factorize
        assert original is not None
        assert Factorization.factorize(pq) == original(pq)


class TestHashes:
    @pytest.mark.parametrize(
        ("ours", "real"),
        [(_telethon_crypto.Sha1Hash, hashlib.sha1), (_telethon_crypto.Sha256Hash, hashlib.sha256)],
    )
    def test_hash_object_matches_hashlib(self, ours: type, real: type) -> None:
        data = os.urandom(200)
        mine = ours(data[:50])
        theirs = real(data[:50])
        assert (mine.name, mine.digest_size, mine.block_size) == (
            theirs.name,
            theirs.digest_size,
            theirs.block_size,
        )
        fork = mine.copy()
        mine.update(bytearray(data[50:]))
        theirs.update(data[50:])
        assert mine.digest() == theirs.digest()
        assert mine.hexdigest() == theirs.hexdigest()
        assert fork.digest() == real(data[:50]).digest()
        assert ours().digest() == real().digest()
        with pytest.raises(TypeError):
            ours("text")

    def test_hashlib_bridge(self) -> None:
        bridge = _telethon_crypto.hashlib_bridge
        assert bridge.sha256(b"abc").digest() == hashlib.sha256(b"abc").digest()
        assert bridge.md5 is hashlib.md5
        for name in ("sha1", "sha256", "sha512"):
            assert bridge.pbkdf2_hmac(name, b"pw", b"salt", 3) == hashlib.pbkdf2_hmac(
                name, b"pw", b"salt", 3
            )
        assert bridge.pbkdf2_hmac("sha512", b"pw", b"salt", 2, 10) == hashlib.pbkdf2_hmac(
            "sha512", b"pw", b"salt", 2, 10
        )
        assert bridge.pbkdf2_hmac("md5", b"pw", b"salt", 2) == hashlib.pbkdf2_hmac(
            "md5", b"pw", b"salt", 2
        )
        with pytest.raises(ValueError, match="iteration"):
            bridge.pbkdf2_hmac("sha512", b"pw", b"salt", 0)


class TestTelethonFlows:
    def test_mtproto_state_round_trip(self) -> None:
        key = os.urandom(256)
        auth_key = AuthKey(key)
        assert auth_key.key_id == struct.unpack("<Q", hashlib.sha1(key).digest()[12:20])[0]
        loggers = {"telethon.network.mtprotostate": logging.getLogger("test_telethon_crypto")}
        state = MTProtoState(auth_key, loggers)
        state.salt = 0x1122334455667788

        # Client to server: the server side of the derivation, on real hashlib.
        data = os.urandom(64)
        body = state.encrypt_message_data(data)
        msg_key = body[8:24]
        aes_key, aes_iv = reference_calc_key(key, msg_key, True)
        plain = AES.decrypt_ige(body[24:], aes_key, aes_iv)
        assert hashlib.sha256(key[88:120] + plain).digest()[8:24] == msg_key
        assert plain[:16] == struct.pack("<qq", state.salt, state.id)
        assert plain[16 : 16 + len(data)] == data

        # Server to client, built on real hashlib and read by MTProtoState.
        pong = bytes(types.Pong(msg_id=7, ping_id=9))
        remote_msg_id = (int(time.time()) << 32) | 1
        inner = struct.pack("<qqqii", 1, state.id, remote_msg_id, 1, len(pong)) + pong
        inner += os.urandom(-(len(inner) + 12) % 16 + 12)
        server_key = hashlib.sha256(key[96:128] + inner).digest()[8:24]
        aes_key, aes_iv = reference_calc_key(key, server_key, False)
        packet = (
            struct.pack("<Q", auth_key.key_id)
            + server_key
            + AES.encrypt_ige(inner, aes_key, aes_iv)
        )
        message = state.decrypt_message_data(packet)
        assert message is not None
        assert message.msg_id == remote_msg_id
        assert isinstance(message.obj, types.Pong)
        assert (message.obj.msg_id, message.obj.ping_id) == (7, 9)

    def test_compute_check_matches_real_hashlib(self, monkeypatch: pytest.MonkeyPatch) -> None:
        algo = types.PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow(
            salt1=SRP_SALT1, salt2=SRP_SALT2, g=3, p=SRP_P
        )
        request = types.account.Password(
            new_algo=types.PasswordKdfAlgoUnknown(),
            new_secure_algo=types.SecurePasswordKdfAlgoUnknown(),
            secure_random=b"",
            has_password=True,
            current_algo=algo,
            srp_B=SRP_B,
            srp_id=SRP_ID,
        )
        monkeypatch.setattr(password.os, "urandom", lambda size: SRP_DRAW[:size])
        assert password.hashlib is _telethon_crypto.hashlib_bridge
        patched = password.compute_check(request, SRP_PASSWORD)
        monkeypatch.setattr(password, "hashlib", hashlib)
        real = password.compute_check(request, SRP_PASSWORD)
        assert patched.srp_id == real.srp_id == SRP_ID
        assert patched.A == real.A
        assert patched.M1 == real.M1
