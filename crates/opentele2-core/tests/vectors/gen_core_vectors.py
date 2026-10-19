"""Golden vectors from the opentele2 1.5.0 Python code for the Rust core port.

    python gen_core_vectors.py --source DIR           write the vectors
    python gen_core_vectors.py --source DIR --check   regenerate and compare

DIR is a checkout of opentele2 1.5.0 (it must contain ``src/td``); it defaults
to the repository root and is only read, never written. Every input is
synthetic: byte strings come from SHA-256 in counter mode over a fixed label
(see ``PatternBytes``), and wherever 1.5.0 draws randomness (``os.urandom`` for
padding, salts and generated local keys) the draw is served from the same
construction while the vector is produced. The output lands in the directory
holding this script and is byte-for-byte reproducible.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
VECTORS_DIR = SCRIPT_PATH.parent
# crates/opentele2-core/tests/vectors -> repository root.
REPO_ROOT = VECTORS_DIR.parents[3]
# The committed vectors record the generator's original path; keep it so they
# stay byte-identical after the move.
GENERATOR_NAME = "scripts/gen_core_vectors.py"
# Files in VECTORS_DIR that belong to the generator, not to the vectors.
GENERATOR_FILES = frozenset({SCRIPT_PATH.name})
SOURCE_VERSION = "1.5.0"
MAX_TOTAL_SIZE = 2 * 1024 * 1024
PASSCODE = "opentele2"

PATTERN_DOC = (
    "bytes(label, n): SHA-256(utf8(label) || counter as u32 big-endian) for "
    "counter = 0, 1, 2, ..., concatenated and cut to n bytes"
)
RNG_DOC = (
    "os.urandom is replaced by one bytes(label, ...) stream per vector; each "
    "call takes the next len bytes of that stream"
)


class PatternBytes:
    """SHA-256 in counter mode over a label, consumed front to back."""

    def __init__(self, label: str) -> None:
        self._label = label.encode("utf-8")
        self._counter = 0
        self._pending = b""

    def take(self, size: int) -> bytes:
        while len(self._pending) < size:
            block = self._label + self._counter.to_bytes(4, "big")
            self._pending += hashlib.sha256(block).digest()
            self._counter += 1
        chunk, self._pending = self._pending[:size], self._pending[size:]
        return chunk


def pattern(label: str, size: int) -> bytes:
    return PatternBytes(label).take(size)


@contextlib.contextmanager
def fixed_urandom(label: str) -> Iterator[list[bytes]]:
    """Serve ``os.urandom`` from ``PatternBytes(label)``; yields the draws."""
    source = PatternBytes(label)
    draws: list[bytes] = []
    original = os.urandom

    def urandom(size: int) -> bytes:
        chunk = source.take(size)
        draws.append(chunk)
        return chunk

    os.urandom = urandom
    try:
        yield draws
    finally:
        os.urandom = original


class SourceError(Exception):
    """``--source`` does not point at a 1.5.0 checkout."""


def bootstrap(source: Path) -> None:
    """Make ``import src`` from ``source`` work offline, as its test suite does."""
    if not (source / "src" / "td").is_dir():
        raise SourceError(
            f"--source {source}: no src/td directory; pass a checkout of "
            f"opentele2 {SOURCE_VERSION}"
        )
    # Without this, importing src fetches live client versions over the network
    # and the generated app_version strings would drift.
    os.environ["OPENTELE_NO_FETCH"] = "1"
    # Never leave .pyc files inside the source checkout.
    sys.dont_write_bytecode = True
    root = str(source)
    if root in sys.path:
        sys.path.remove(root)
    sys.path.insert(0, root)


def meta(**extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "generator": GENERATOR_NAME,
        "source_version": SOURCE_VERSION,
        "pattern": PATTERN_DOC,
    }
    result.update(extra)
    return result


def dump_json(data: Any) -> bytes:
    text = json.dumps(data, sort_keys=True, indent=1, ensure_ascii=False)
    return (text + "\n").encode("utf-8")


# --------------------------------------------------------------------- devices

DEVICE_ENTRY_POINTS: tuple[tuple[str, str | None], ...] = (
    ("TelegramDesktop", None),
    ("TelegramDesktop", "windows"),
    ("TelegramDesktop", "macos"),
    ("TelegramDesktop", "linux"),
    ("TelegramAndroid", None),
    ("TelegramAndroidX", None),
    ("TelegramIOS", None),
    ("TelegramMacOS", None),
)

_STRING_SEED_SHAPES: tuple[Callable[[int], str], ...] = (
    lambda i: f"seed-{i:03d}",
    lambda i: f"user{i}@example.org",
    lambda i: f"ключ-{i}",
    lambda i: f"☃ snow \U0001f511 {i}",
    lambda i: f"  padded\t{i}  ",
    lambda i: f"{i * 7919}",
    lambda i: "ab" * (i % 37 + 1) + f"/{i}",
)


def string_seeds() -> list[str]:
    seeds = [""]
    seeds += [_STRING_SEED_SHAPES[i % 7](i) for i in range(1, 300)]
    if len(set(seeds)) != 300:
        raise AssertionError("string seeds are not distinct")
    return seeds


def int_seeds() -> list[int]:
    seeds = [
        0,
        1,
        -1,
        7,
        42,
        2**31 - 1,
        -(2**31),
        2**32,
        2**53 + 1,
        2**63 - 1,
        -(2**63),
        2**64 - 1,
        10**12,
        10**12 - 1,
    ]
    seeds += [(i * 2654435761) % 2**40 - 2**39 for i in range(2, 38)]
    if len(seeds) != 50 or len(set(seeds)) != 50:
        raise AssertionError("int seeds are not 50 distinct values")
    return seeds


def device_vectors() -> dict[str, Any]:
    from src.api import API

    cases: list[dict[str, Any]] = []
    seeds: list[tuple[str, str | int]] = [("str", s) for s in string_seeds()]
    seeds += [("int", s) for s in int_seeds()]
    for name, system in DEVICE_ENTRY_POINTS:
        api_cls = getattr(API, name)
        for kind, seed in seeds:
            if system is None:
                api = api_cls.Generate(unique_id=seed)
            else:
                api = api_cls.Generate(system=system, unique_id=seed)
            cases.append(
                {
                    "entry_point": name,
                    "system": system,
                    "seed_kind": kind,
                    "seed": seed,
                    "device_model": api.device_model,
                    "system_version": api.system_version,
                    "app_version": api.app_version,
                    "lang_pack": api.lang_pack,
                    "system_lang_code": api.system_lang_code,
                }
            )
    return {
        "meta": meta(
            call=(
                "API.<entry_point>.Generate(unique_id=seed) when system is null, "
                "else API.TelegramDesktop.Generate(system=system, unique_id=seed); "
                "int seeds are hashed as their decimal str()"
            ),
            excluded="TelegramWeb_A, TelegramWeb_K, Webogram: not deterministic",
        ),
        "cases": cases,
    }


# ---------------------------------------------------------------------- crypto


def crypto_vectors() -> dict[str, Any]:
    from src.qt_compat import QByteArray
    from src.td import AuthKey, Storage
    from src.td.key_data import (
        create_passcode_key,
        default_passcode_kdf,
        unwrap_local_key,
        wrap_local_key,
    )

    keys = [
        bytes(256),
        bytes(range(256)),
        pattern("crypto/auth_key/0", 256),
        pattern("crypto/auth_key/1", 256),
    ]
    key_ids = []
    for key in keys:
        # 1.5.0 computes the key id once in AuthKey.__init__ and keeps it only
        # as a private attribute; read that value instead of recomputing it.
        key_id = AuthKey(key)._AuthKey__keyId
        if not isinstance(key_id, int):
            raise TypeError("AuthKey key id is not an int")
        key_ids.append(
            {
                "auth_key": key.hex(),
                "key_id": str(key_id),
                "key_id_le": key_id.to_bytes(8, "little").hex(),
            }
        )

    prepare = []
    for k, key in enumerate(keys[1:]):
        for m in range(2):
            msg_key = pattern(f"crypto/msg_key/{k}/{m}", 16)
            for send in (True, False):
                aes_key, aes_iv = AuthKey(key).prepareAES_oldmtp(msg_key, send)
                prepare.append(
                    {
                        "auth_key": key.hex(),
                        "msg_key": msg_key.hex(),
                        "send": send,
                        "aes_key": aes_key.hex(),
                        "aes_iv": aes_iv.hex(),
                    }
                )

    local_key = pattern("crypto/local_key", 256)
    encrypt = []
    for size in (1, 12, 13, 28, 100, 256):
        payload = pattern(f"crypto/encrypt_local/payload/{size}", size)
        descriptor = Storage.EncryptedDescriptor(size)
        descriptor.stream.writeRawData(payload)
        with fixed_urandom(f"crypto/encrypt_local/padding/{size}") as draws:
            encrypted = Storage.PrepareEncrypted(descriptor, AuthKey(local_key))
        decrypted = Storage.DecryptLocal(encrypted, AuthKey(local_key))
        if decrypted.data.data()[4:] != payload:
            raise AssertionError(f"encrypt-local round trip failed for {size}")
        encrypt.append(
            {
                "local_key": local_key.hex(),
                "payload": payload.hex(),
                "padding": b"".join(draws).hex(),
                "msg_key": encrypted.data()[:16].hex(),
                "encrypted": encrypted.data().hex(),
                "decrypted": decrypted.data.data().hex(),
            }
        )

    local_keys = []
    legacy_keys = []
    for n in range(2):
        salt = pattern(f"crypto/local_key_salt/{n}", 32)
        for passcode in (None, PASSCODE):
            arg = None if passcode is None else QByteArray(passcode.encode("utf-8"))
            modern = Storage.CreateLocalKey(QByteArray(salt), arg)
            legacy = Storage.CreateLegacyLocalKey(QByteArray(salt), arg)
            entry = {"salt": salt.hex(), "passcode": passcode or ""}
            local_keys.append({**entry, "key": modern.key.hex()})
            legacy_keys.append({**entry, "key": legacy.key.hex()})

    kdf = default_passcode_kdf()
    wrap_salt = pattern("crypto/argon2/salt", 32)
    wrap_key = create_passcode_key(PASSCODE.encode("utf-8"), QByteArray(wrap_salt), kdf)
    wrapped_key = pattern("crypto/argon2/local_key", 256)
    with fixed_urandom("crypto/argon2/wrap_padding") as draws:
        wrapped = wrap_local_key(AuthKey(wrapped_key), wrap_key)
    if unwrap_local_key(wrapped, wrap_key).key != wrapped_key:
        raise AssertionError("wrap_local_key round trip failed")

    return {
        "meta": meta(rng=RNG_DOC),
        "key_id": key_ids,
        "prepare_aes_oldmtp": prepare,
        "encrypt_local": encrypt,
        "create_local_key": local_keys,
        "create_legacy_local_key": legacy_keys,
        "argon2id_wrap": {
            "passcode": PASSCODE,
            "salt": wrap_salt.hex(),
            "kind": kdf.kind,
            "memory_kib": kdf.memory,
            "time": kdf.time,
            "lanes": kdf.parallel,
            "argon2_version": 0x13,
            "wrap_key": wrap_key.key.hex(),
            "local_key": wrapped_key.hex(),
            "padding": b"".join(draws).hex(),
            "key_encrypted": wrapped.data().hex(),
        },
    }


# ------------------------------------------------------------------------- tdf


def tdf_vectors(workdir: Path) -> dict[str, Any]:
    from src.qt_compat import QByteArray, QDataStream, QIODevice
    from src.td import Storage
    from src.utils import APP_VERSION, TDF_MAGIC

    def encode(write: Callable[[QDataStream], None]) -> bytes:
        out = QByteArray()
        stream = QDataStream(out, QIODevice.OpenModeFlag.WriteOnly)
        stream.setVersion(QDataStream.Version.Qt_5_1)
        write(stream)
        return out.data()

    def reader(data: bytes) -> QDataStream:
        stream = QDataStream(QByteArray(data))
        stream.setVersion(QDataStream.Version.Qt_5_1)
        return stream

    qint32 = []
    for value in (0, 1, -1, 0x12345678, 2**31 - 1, -(2**31)):
        data = encode(lambda s, v=value: s.writeInt32(v))
        if reader(data).readInt32() != value:
            raise AssertionError(f"qint32 round trip failed for {value}")
        qint32.append({"value": value, "encoded": data.hex()})

    qint64 = []
    for value in (0, 1, -1, 0x123456789ABCDEF0, 2**63 - 1, -(2**63)):
        data = encode(lambda s, v=value: s.writeInt64(v))
        if reader(data).readInt64() != value:
            raise AssertionError(f"qint64 round trip failed for {value}")
        qint64.append({"value": str(value), "encoded": data.hex()})

    byte_arrays = []
    samples: list[bytes | None] = [
        None,
        b"",
        b"\x00\x01\x02",
        pattern("tdf/qbytearray", 300),
    ]
    for sample in samples:
        array = QByteArray() if sample is None else QByteArray(sample)
        data = encode(lambda s, a=array: s << a)
        back = QByteArray()
        reader(data) >> back
        if back.isNull() != (sample is None) or back.data() != (sample or b""):
            raise AssertionError("QByteArray round trip failed")
        byte_arrays.append(
            {
                "null": sample is None,
                "value": "" if sample is None else sample.hex(),
                "encoded": data.hex(),
            }
        )

    strings = []
    for text in (None, "", PASSCODE, "ключ", "\U0001f511 key"):
        data = encode(lambda s, t=text: s.writeQString(t))
        if reader(data).readQString() != (text or ""):
            raise AssertionError(f"QString round trip failed for {text!r}")
        strings.append(
            {"null": text is None, "value": text or "", "encoded": data.hex()}
        )

    blobs: list[bytes | None] = [
        b"opentele2 tdf vector",
        None,
        b"",
        pattern("tdf/file/blob", 100),
    ]
    writer = Storage.FileWriteDescriptor("vector", str(workdir))
    for blob in blobs:
        writer.writeData(QByteArray() if blob is None else QByteArray(blob))
    writer.finish()
    file_bytes = (workdir / "vectors").read_bytes()
    read = Storage.ReadFile("vector", str(workdir))
    if read.version != APP_VERSION:
        raise AssertionError("TDF$ version did not round trip")
    for blob in blobs:
        back = QByteArray()
        read.stream >> back
        if back.isNull() != (blob is None) or back.data() != (blob or b""):
            raise AssertionError("TDF$ blob did not round trip")

    return {
        "meta": meta(byte_order="big-endian", qdatastream_version=16),
        "qint32": qint32,
        "qint64": qint64,
        "qbytearray": byte_arrays,
        "qstring": strings,
        "tdf_file": {
            "name": "vector",
            "written_name": "vectors",
            "magic": TDF_MAGIC.hex(),
            "version": APP_VERSION,
            "blobs": [
                {"null": b is None, "value": "" if b is None else b.hex()}
                for b in blobs
            ],
            "md5": file_bytes[-16:].hex(),
            "file": file_bytes.hex(),
        },
    }


# -------------------------------------------------------------------- sessions

SESSION_ENDPOINTS: tuple[tuple[int, str, int], ...] = (
    (1, "192.0.2.10", 443),
    (2, "198.51.100.20", 443),
    (4, "203.0.113.40", 80),
    (5, "192.0.2.255", 5222),
    (2, "2001:db8::20", 443),
    (3, "2001:db8:f003::a", 80),
    (4, "2001:db8:1:2:3:4:5:6", 443),
)


def session_vectors() -> dict[str, Any]:
    from telethon.crypto import AuthKey
    from telethon.sessions import StringSession

    cases = []
    for n, (dc_id, ip, port) in enumerate(SESSION_ENDPOINTS):
        key = pattern(f"sessions/auth_key/{n}", 256)
        session = StringSession()
        session.set_dc(dc_id, ip, port)
        session.auth_key = AuthKey(key)
        encoded = session.save()
        back = StringSession(encoded)
        if (back.dc_id, back.server_address, back.port) != (dc_id, ip, port) or (
            back.auth_key is None or back.auth_key.key != key
        ):
            raise AssertionError(f"StringSession round trip failed for {ip}")
        cases.append(
            {
                "dc_id": dc_id,
                "ip": ip,
                "ip_version": 6 if ":" in ip else 4,
                "port": port,
                "auth_key": key.hex(),
                "string_session": encoded,
            }
        )
    return {"meta": meta(format="Telethon StringSession version '1'"), "cases": cases}


# ----------------------------------------------------------------------- tdata


@dataclass(frozen=True)
class SyntheticAccount:
    index: int
    user_id: int
    main_dc: int


TDATA_ACCOUNTS: dict[str, tuple[SyntheticAccount, ...]] = {
    "tdata_plain": (
        SyntheticAccount(0, 100000001, 2),
        SyntheticAccount(1, 5000000123, 4),
    ),
    "tdata_passcode": (
        SyntheticAccount(0, 200000002, 1),
        SyntheticAccount(1, 6000000456, 5),
    ),
}

PERFORMANCE_FOLDERS: tuple[tuple[str, bool], ...] = (
    ("performance_on", True),
    ("performance_off", False),
)


def account_key(kind: str, account: SyntheticAccount) -> bytes:
    return pattern(f"{kind}/account{account.index}/auth_key", 256)


def write_tdata(
    target: Path, kind: str, passcode: str | None, performance: bool
) -> dict[str, Any]:
    from src.td import Account, AuthKey, AuthKeyType, TDesktop
    from src.td.configs import DcId

    TDesktop.PerformanceMode(performance)
    try:
        desktop = TDesktop()
        for spec in TDATA_ACCOUNTS[kind]:
            dc = DcId(spec.main_dc)
            key = AuthKey(account_key(kind, spec), AuthKeyType.ReadFromFile, dc)
            # The same two calls Account.FromTelethon makes for a new account.
            account = Account(desktop, api=desktop.api, index=spec.index)
            account._setMtpAuthorizationCustom(dc, spec.user_id, [key])
            desktop._addSingleAccount(account)

        label = f"{target.parent.name}/{target.name}/rng"
        with fixed_urandom(label) as draws:
            desktop.SaveTData(str(target), passcode=passcode)

        loaded = TDesktop(str(target), passcode=passcode)
        main = loaded.mainAccount
        readback = []
        for account in loaded.accounts:
            auth_key = account.authKey
            if auth_key is None:
                raise AssertionError("loaded account has no auth key")
            readback.append(
                {
                    "index": account.index,
                    "user_id": account.UserId,
                    "main_dc": int(account.MainDcId),
                    "auth_key": auth_key.key.hex(),
                }
            )
    finally:
        TDesktop.PerformanceMode(True)

    expected = [
        {
            "index": spec.index,
            "user_id": spec.user_id,
            "main_dc": spec.main_dc,
            "auth_key": account_key(kind, spec).hex(),
        }
        for spec in TDATA_ACCOUNTS[kind]
    ]
    if readback != expected:
        raise AssertionError(
            f"{target.name}: the 1.5.0 loader read back other accounts"
        )

    return {
        "passcode": passcode or "",
        "performance_mode": performance,
        "key_file": "data",
        "accounts": readback,
        "main_account_index": None if main is None else main.index,
        "rng_label": label,
        "rng_draws": [d.hex() for d in draws],
    }


LEGACY_ACCOUNTS: dict[str, tuple[SyntheticAccount, ...]] = {
    "plain": (
        SyntheticAccount(0, 300000003, 2),
        SyntheticAccount(1, 7000000789, 4),
    ),
    "passcode": (
        SyntheticAccount(0, 400000004, 5),
        SyntheticAccount(1, 8000000987, 1),
    ),
}

# A pre-7.3 client stores the index of the account in use; not the first one,
# so a migration that loses it shows.
LEGACY_ACTIVE_INDEX = 1

LEGACY_DOC = (
    "tdata_legacy/<name>: a pre-7.3 folder (key file without the 7.3 trailer, "
    "the local key bytes(tdata_legacy/<name>/local_key, 256) wrapped under "
    "Storage.CreateLocalKey(bytes(tdata_legacy/<name>/salt, 32), passcode)) "
    "whose accounts and key file 1.5.0's TDesktop.__writeAccounts writes with "
    "performance mode off; tdata_legacy/<name>_saved: what 1.5.0 SaveTData "
    "writes after loading it with performance mode on (the migrated key file)"
)


def legacy_account_key(name: str, account: SyntheticAccount) -> bytes:
    return pattern(f"tdata_legacy/{name}/account{account.index}/auth_key", 256)


def legacy_readback(folder: Path, passcode: str | None) -> tuple[Any, Any]:
    """Load ``folder`` with the 1.5.0 loader; return it and its accounts."""
    from src.td import TDesktop

    loaded = TDesktop(str(folder), passcode=passcode)
    readback = []
    for account in loaded.accounts:
        auth_key = account.authKey
        if auth_key is None:
            raise AssertionError("loaded account has no auth key")
        readback.append(
            {
                "index": account.index,
                "user_id": account.UserId,
                "main_dc": int(account.MainDcId),
                "auth_key": auth_key.key.hex(),
            }
        )
    return loaded, readback


def folder_files(target: Path) -> list[str]:
    return sorted(
        p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()
    )


def write_legacy_tdata(
    target: Path, saved: Path, name: str, passcode: str | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Write a pre-7.3 folder, then what 1.5.0 SaveTData migrates it to."""
    from src.qt_compat import QByteArray
    from src.td import Account, AuthKey, AuthKeyType, Storage, TDesktop
    from src.td.configs import DcId
    from src.td.key_data import LOCAL_ENCRYPT_SALT_SIZE, KeyData, wrap_local_key

    label = f"tdata_legacy/{name}"
    local_key = AuthKey(pattern(f"{label}/local_key", AuthKey.kSize))
    salt = QByteArray(pattern(f"{label}/salt", LOCAL_ENCRYPT_SALT_SIZE))
    passcode_bytes = (passcode or "").encode("utf-8")
    # Before 7.3 the passcode itself made the open wrap key, as 1.5.0's
    # open_local_key reads a legacy key file.
    wrap_key = Storage.CreateLocalKey(salt, QByteArray(passcode_bytes))

    # A real pre-7.3 client writes the configs file as well.
    TDesktop.PerformanceMode(False)
    try:
        desktop = TDesktop()
        desktop._TDesktop__localKey = local_key
        for spec in LEGACY_ACCOUNTS[name]:
            dc = DcId(spec.main_dc)
            key = AuthKey(legacy_account_key(name, spec), AuthKeyType.ReadFromFile, dc)
            account = Account(desktop, api=desktop.api, index=spec.index)
            account._setMtpAuthorizationCustom(dc, spec.user_id, [key])
            desktop._addSingleAccount(account)
        desktop._TDesktop__active_index = LEGACY_ACTIVE_INDEX
        build_label = f"{label}/rng"
        with fixed_urandom(build_label) as build_draws:
            desktop._TDesktop__keyData = KeyData(
                openSalt=salt,
                openKeyEncrypted=wrap_local_key(local_key, wrap_key),
                legacy=True,
            )
            # __writeAccounts leaves the trailer out of a legacy key file.
            desktop._TDesktop__writeAccounts(str(target))
    finally:
        TDesktop.PerformanceMode(True)

    expected = [
        {
            "index": spec.index,
            "user_id": spec.user_id,
            "main_dc": spec.main_dc,
            "auth_key": legacy_account_key(name, spec).hex(),
        }
        for spec in LEGACY_ACCOUNTS[name]
    ]

    loaded, readback = legacy_readback(target, passcode)
    if not loaded._TDesktop__keyData.legacy or readback != expected:
        raise AssertionError(f"{label}: the 1.5.0 loader did not read it as legacy")
    main = loaded.mainAccount
    if main is None or main.index != LEGACY_ACTIVE_INDEX:
        raise AssertionError(f"{label}: the 1.5.0 loader lost the active index")

    save_label = f"{label}_saved/rng"
    with fixed_urandom(save_label) as save_draws:
        loaded.SaveTData(str(saved))

    migrated, readback_saved = legacy_readback(saved, passcode)
    if migrated._TDesktop__keyData.legacy or readback_saved != expected:
        raise AssertionError(f"{label}_saved: 1.5.0 did not migrate the key file")
    local = migrated.localKey
    if local is None or local.key != local_key.key:
        raise AssertionError(f"{label}_saved: the migration changed the local key")
    main_saved = migrated.mainAccount

    common = {"passcode": passcode or "", "key_file": "data", "accounts": expected}
    legacy_entry = {
        **common,
        "legacy": True,
        "performance_mode": False,
        "main_account_index": main.index,
        "rng_label": build_label,
        "rng_draws": [d.hex() for d in build_draws],
        "files": folder_files(target),
    }
    saved_entry = {
        **common,
        "legacy": False,
        "source": label,
        "performance_mode": True,
        "main_account_index": None if main_saved is None else main_saved.index,
        "rng_label": save_label,
        "rng_draws": [d.hex() for d in save_draws],
        "files": folder_files(saved),
    }
    return legacy_entry, saved_entry


def tdata_vectors(workdir: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    folders: dict[str, Any] = {}
    files: dict[str, bytes] = {}
    for kind, passcode in (("tdata_plain", None), ("tdata_passcode", PASSCODE)):
        for sub, performance in PERFORMANCE_FOLDERS:
            target = workdir / kind / sub
            entry = write_tdata(target, kind, passcode, performance)
            written = sorted(
                p.relative_to(target).as_posix()
                for p in target.rglob("*")
                if p.is_file()
            )
            entry["files"] = written
            folders[f"{kind}/{sub}"] = entry
            for name in written:
                files[f"{kind}/{sub}/{name}"] = (target / name).read_bytes()
    for legacy_name, passcode in (("plain", None), ("passcode", PASSCODE)):
        target = workdir / "tdata_legacy" / legacy_name
        saved = workdir / "tdata_legacy" / f"{legacy_name}_saved"
        entries = write_legacy_tdata(target, saved, legacy_name, passcode)
        for folder, entry in zip((target, saved), entries, strict=True):
            key = f"tdata_legacy/{folder.name}"
            folders[key] = entry
            for name in entry["files"]:
                files[f"{key}/{name}"] = (folder / name).read_bytes()
    document = {
        "meta": meta(
            rng=RNG_DOC,
            loader="src.td.TDesktop(folder, passcode=passcode) under the same mode",
            legacy=LEGACY_DOC,
        ),
        "folders": folders,
    }
    return document, files


# ------------------------------------------------------------------------ main


def build_vectors(source: Path) -> dict[str, bytes]:
    bootstrap(source)
    files: dict[str, bytes] = {
        # Keep git from rewriting line endings in byte-exact fixtures.
        ".gitattributes": b"* -text\n",
        "devices.json": dump_json(device_vectors()),
        "crypto.json": dump_json(crypto_vectors()),
        "sessions.json": dump_json(session_vectors()),
    }
    with tempfile.TemporaryDirectory() as tmp:
        files["tdf.json"] = dump_json(tdf_vectors(Path(tmp)))
    with tempfile.TemporaryDirectory() as tmp:
        document, tdata_files = tdata_vectors(Path(tmp))
    files["tdata.json"] = dump_json(document)
    files.update(tdata_files)

    total = sum(len(data) for data in files.values())
    if total > MAX_TOTAL_SIZE:
        raise AssertionError(f"vectors are {total} bytes, above {MAX_TOTAL_SIZE}")
    return files


def existing_files() -> dict[str, Path]:
    if not VECTORS_DIR.is_dir():
        return {}
    files = {}
    for path in VECTORS_DIR.rglob("*"):
        name = path.relative_to(VECTORS_DIR).as_posix()
        if path.is_file() and name not in GENERATOR_FILES:
            files[name] = path
    return files


def check(expected: dict[str, bytes]) -> int:
    present = existing_files()
    problems = []
    for name in sorted(set(expected) | set(present)):
        if name not in present:
            problems.append(f"missing: {name}")
        elif name not in expected:
            problems.append(f"unexpected: {name}")
        elif present[name].read_bytes() != expected[name]:
            problems.append(f"differs: {name}")
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"check failed: {len(problems)} file(s) out of date", file=sys.stderr)
        return 1
    print(f"check ok: {len(expected)} files match {VECTORS_DIR}")
    return 0


def write(expected: dict[str, bytes]) -> int:
    for name, path in existing_files().items():
        if name not in expected:
            path.unlink()
    for name, data in sorted(expected.items()):
        path = VECTORS_DIR / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for directory in sorted(VECTORS_DIR.rglob("*"), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    total = sum(len(data) for data in expected.values())
    print(f"wrote {len(expected)} files, {total} bytes, to {VECTORS_DIR}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in memory and exit non-zero if the committed files differ",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=REPO_ROOT,
        metavar="DIR",
        help=(
            f"checkout of opentele2 {SOURCE_VERSION} to import src from "
            "(default: the repository root)"
        ),
    )
    args = parser.parse_args(argv)
    try:
        expected = build_vectors(args.source.resolve())
    except SourceError as error:
        parser.error(str(error))
    return check(expected) if args.check else write(expected)


if __name__ == "__main__":
    sys.exit(main())
