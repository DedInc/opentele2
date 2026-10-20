"""Telethon's protocol crypto on the Rust core.

Telethon reaches the core's AES-IGE through the ``cryptg`` registration in
``opentele2/__init__.py``; everything else it computes itself. ``install``
rebinds the remaining names Telethon looks up at call time:

- ``AESModeCTR`` in telethon.crypto, telethon.crypto.aesctr,
  telethon.crypto.cdndecrypter, telethon.network.connection.tcpobfuscated and
  telethon.network.connection.tcpmtproxy, over ``_native.AesCtr`` instead of pure-Python pyaes;
- ``Factorization.factorize`` in telethon.crypto.factorization, over
  ``_native.factorize_pq``;
- ``sha1`` and ``sha256`` bound by ``from hashlib import ...`` in
  telethon.crypto.authkey, telethon.crypto.rsa, telethon.helpers,
  telethon.network.authenticator, telethon.network.mtprotostate and
  telethon.crypto.cdndecrypter, over ``_native.sha1``/``_native.sha256``;
- ``hashlib`` in telethon.password and telethon.network.connection.tcpmtproxy,
  whose ``sha256`` and ``pbkdf2_hmac`` run on the core.

Those modules bind the names at their own import, so ``install`` imports
them itself and rebinds the names in place, once when this module is first
imported (from ``opentele2/__init__.py``): the patch holds whether telethon
was imported before or after opentele2. A module or name that is missing is
skipped and logged at debug. DH and RSA arithmetic (Python ``pow``) and
``os.urandom`` stay Telethon's.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import logging
from types import ModuleType
from typing import Any, Callable, Union

from . import _native

logger = logging.getLogger(__name__)

_BytesLike = Union[bytes, bytearray, memoryview]

# The only key size the core's AES-CTR takes; Telethon always passes 32 bytes.
_NATIVE_CTR_KEY_SIZE = 32
# factorize_pq takes pq as at most 8 big-endian bytes.
_PQ_LIMIT = 1 << 64
_PQ_SIZE = 8
# Digest sizes of the PBKDF2 hashes the core implements; pbkdf2_hmac's dklen
# defaults to them, as hashlib's does.
_PBKDF2_DIGEST_SIZES: dict[str, int] = {"sha1": 20, "sha256": 32, "sha512": 64}


class _Originals:
    """Telethon's own implementations, kept for what the core does not take:
    AES-CTR keys other than 32 bytes, and factorisation of a prime or of an
    integer beyond 64 bits (telethon.password's prime checks)."""

    ctr: Callable[[bytes, bytes], Any] | None = None
    factorize: Callable[[int], tuple[int, int]] | None = None


class AESModeCTR:
    """Telethon's AESModeCTR over the core: one keystream per instance,
    advanced by every ``encrypt`` and ``decrypt`` call, as pyaes does."""

    def __init__(self, key: bytes, iv: bytes) -> None:
        fallback = _Originals.ctr
        if len(key) != _NATIVE_CTR_KEY_SIZE and fallback is not None:
            self._process: Callable[[bytes], bytes] = fallback(key, iv).encrypt
        else:
            self._process = _native.AesCtr(key, iv).process

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt ``data`` with the next bytes of the keystream."""
        return self._process(data)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt ``data`` with the next bytes of the keystream."""
        return self._process(data)


class _NativeHash:
    """A hashlib-shaped hash object; the data is buffered and hashed in one
    core call per digest."""

    name = ""
    digest_size = 0
    block_size = 64

    def __init__(self, data: _BytesLike = b"") -> None:
        self._buffer = bytearray()
        self.update(data)

    def update(self, data: _BytesLike) -> None:
        # memoryview refuses str and int, as hashlib does.
        self._buffer += memoryview(data)

    def _hash(self, data: bytearray) -> bytes:
        raise NotImplementedError

    def digest(self) -> bytes:
        return self._hash(self._buffer)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> _NativeHash:
        clone = type(self)()
        clone._buffer = bytearray(self._buffer)
        return clone


class Sha1Hash(_NativeHash):
    """hashlib.sha1 over ``_native.sha1``."""

    name = "sha1"
    digest_size = 20

    def _hash(self, data: bytearray) -> bytes:
        return _native.sha1(data)


class Sha256Hash(_NativeHash):
    """hashlib.sha256 over ``_native.sha256``."""

    name = "sha256"
    digest_size = 32

    def _hash(self, data: bytearray) -> bytes:
        return _native.sha256(data)


class HashlibBridge:
    """The ``hashlib`` Telethon's password and MTProxy code see: ``sha256``
    and ``pbkdf2_hmac`` on the core, every other attribute the real hashlib's."""

    sha256 = Sha256Hash

    @staticmethod
    def pbkdf2_hmac(
        hash_name: str,
        password: _BytesLike,
        salt: _BytesLike,
        iterations: int,
        dklen: int | None = None,
    ) -> bytes:
        digest_size = _PBKDF2_DIGEST_SIZES.get(hash_name)
        if digest_size is None or iterations < 1 or (dklen is not None and dklen < 1):
            # A hash the core lacks, or arguments hashlib refuses with its own
            # errors.
            return hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
        key_len = digest_size if dklen is None else dklen
        return _native.pbkdf2(
            memoryview(password).tobytes(),
            memoryview(salt).tobytes(),
            iterations,
            key_len,
            hash_name,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(hashlib, name)

    def __repr__(self) -> str:
        return "<opentele2 hashlib bridge>"


hashlib_bridge = HashlibBridge()


def _factorize(cls: type, pq: int) -> tuple[int, int]:
    """Factorization.factorize over the core: (p, q) with p <= q."""
    if 0 < pq < _PQ_LIMIT:
        try:
            p, q = _native.factorize_pq(pq.to_bytes(_PQ_SIZE, "big"))
        except _native.CoreError as error:
            # A prime or 1, which Telethon's algorithm answers itself.
            if error.code != "INVALID_INPUT":
                raise
        else:
            return int.from_bytes(p, "big"), int.from_bytes(q, "big")
    original = _Originals.factorize
    if original is None:
        raise ValueError(f"cannot factorize {pq} without Telethon's Factorization")
    return original(pq)


factorize = classmethod(_factorize)

_CTR_MODULES = (
    "telethon.crypto.aesctr",
    "telethon.crypto",
    "telethon.crypto.cdndecrypter",
    "telethon.network.connection.tcpobfuscated",
    "telethon.network.connection.tcpmtproxy",
)
_NAME_PATCHES: tuple[tuple[str, str, object], ...] = (
    ("telethon.crypto.authkey", "sha1", Sha1Hash),
    ("telethon.crypto.rsa", "sha1", Sha1Hash),
    ("telethon.helpers", "sha1", Sha1Hash),
    ("telethon.network.authenticator", "sha1", Sha1Hash),
    ("telethon.network.mtprotostate", "sha256", Sha256Hash),
    ("telethon.crypto.cdndecrypter", "sha256", Sha256Hash),
    ("telethon.password", "hashlib", hashlib_bridge),
    ("telethon.network.connection.tcpmtproxy", "hashlib", hashlib_bridge),
)


def _import(module_name: str) -> ModuleType | None:
    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        logger.debug("Telethon crypto patch: %s skipped (%s)", module_name, error)
        return None


def _replace(module_name: str, attribute: str, replacement: object) -> None:
    module = _import(module_name)
    if module is None:
        return
    if not hasattr(module, attribute):
        logger.debug("Telethon crypto patch: %s.%s missing, skipped", module_name, attribute)
        return
    setattr(module, attribute, replacement)


def _install_ctr() -> None:
    aesctr = _import(_CTR_MODULES[0])
    if aesctr is not None:
        current = getattr(aesctr, "AESModeCTR", None)
        if current is not None and current is not AESModeCTR:
            _Originals.ctr = current
    for module_name in _CTR_MODULES:
        _replace(module_name, "AESModeCTR", AESModeCTR)


def _install_factorize() -> None:
    module = _import("telethon.crypto.factorization")
    if module is None:
        return
    factorization = getattr(module, "Factorization", None)
    if factorization is None or not hasattr(factorization, "factorize"):
        logger.debug("Telethon crypto patch: Factorization.factorize missing, skipped")
        return
    if inspect.getattr_static(factorization, "factorize") is not factorize:
        _Originals.factorize = factorization.factorize
    factorization.factorize = factorize


def install() -> None:
    """Rebind Telethon's protocol crypto names to the core's; idempotent."""
    _install_ctr()
    _install_factorize()
    for module_name, attribute, replacement in _NAME_PATCHES:
        _replace(module_name, attribute, replacement)


install()
