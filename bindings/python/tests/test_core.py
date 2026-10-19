"""Tests of the opentele2._native extension against the golden vectors of
crates/opentele2-core/tests/vectors.

Key material is compared with ``assert_same``, which never prints the bytes.
"""

from __future__ import annotations

import base64
import importlib
import ipaddress
import json
import struct
from importlib import metadata
from pathlib import Path
from typing import Any

import pytest

import opentele2
from opentele2 import _native
from opentele2._native import Account, CoreError, TData, cryptg

VECTORS = Path(__file__).resolve().parents[3] / "crates" / "opentele2-core" / "tests" / "vectors"
FOLDERS = (
    "tdata_plain/performance_on",
    "tdata_plain/performance_off",
    "tdata_passcode/performance_on",
    "tdata_passcode/performance_off",
)
# The first TCP endpoint of each production DC in 1.5.0, as (IPv4, IPv6).
PRODUCTION = {
    1: ("149.154.175.50", "2001:b28:f23d:f001::a"),
    2: ("149.154.167.51", "2001:67c:4e8:f002::a"),
    3: ("149.154.175.100", "2001:b28:f23d:f003::a"),
    4: ("149.154.167.91", "2001:67c:4e8:f004::a"),
    5: ("149.154.171.5", "2001:b28:f23f:f005::a"),
}
CLIENTS = (
    "TelegramDesktop",
    "TelegramAndroid",
    "TelegramAndroidX",
    "TelegramIOS",
    "TelegramMacOS",
    "TelegramWeb_A",
    "TelegramWeb_K",
    "Webogram",
)
PROFILE_FIELDS = {
    "api_id",
    "api_hash",
    "device_model",
    "system_version",
    "app_version",
    "lang_code",
    "system_lang_code",
    "lang_pack",
}
MTCUTE_BOOL_FALSE = 0xBC799737


def load_json(name: str) -> Any:
    with (VECTORS / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def unhex(case: dict[str, Any], key: str) -> bytes:
    return bytes.fromhex(case[key])


def assert_same(actual: bytes, expected: bytes, label: str) -> None:
    """Fails without showing either value, so key bytes never reach the log."""
    if actual != expected:
        raise AssertionError(f"{label} differs") from None


def core_code(error: object) -> str:
    assert isinstance(error, CoreError)
    return error.code


@pytest.fixture(scope="module")
def crypto_vectors() -> Any:
    return load_json("crypto.json")


@pytest.fixture(scope="module")
def manifest() -> Any:
    return load_json("tdata.json")["folders"]


# ---------------------------------------------------------------- module


def test_module_metadata() -> None:
    assert _native.__version__ == metadata.version("opentele2")
    package = Path(opentele2.__file__).parent
    assert Path(_native.__file__).parent == package
    assert (package / "py.typed").is_file()
    assert (package / "_native.pyi").is_file()
    assert importlib.import_module("opentele2._native.cryptg") is cryptg


def test_core_error_shape() -> None:
    assert issubclass(CoreError, Exception)
    error = CoreError("TDATA_WRONG_PASSCODE", "tdata passcode is wrong")
    assert error.code == "TDATA_WRONG_PASSCODE"
    assert error.message == "tdata passcode is wrong"
    assert str(error) == "TDATA_WRONG_PASSCODE: tdata passcode is wrong"
    assert error.args == ("TDATA_WRONG_PASSCODE", "tdata passcode is wrong")


# ---------------------------------------------------------------- crypto


def test_key_id_vectors(crypto_vectors: Any) -> None:
    for case in crypto_vectors["key_id"]:
        key_id = _native.key_id(unhex(case, "auth_key"))
        assert key_id == int(case["key_id"])
        assert key_id.to_bytes(8, "little").hex() == case["key_id_le"]


def test_prepare_aes_oldmtp_vectors(crypto_vectors: Any) -> None:
    cases = crypto_vectors["prepare_aes_oldmtp"]
    assert {case["send"] for case in cases} == {True, False}
    for n, case in enumerate(cases):
        aes_key, aes_iv = _native.prepare_aes_oldmtp(
            unhex(case, "auth_key"), unhex(case, "msg_key"), case["send"]
        )
        assert_same(aes_key, unhex(case, "aes_key"), f"aes_key case {n}")
        assert_same(aes_iv, unhex(case, "aes_iv"), f"aes_iv case {n}")


def test_local_encryption_vectors(crypto_vectors: Any) -> None:
    for n, case in enumerate(crypto_vectors["encrypt_local"]):
        key = unhex(case, "local_key")
        payload = unhex(case, "payload")
        encrypted = unhex(case, "encrypted")
        assert_same(_native.decrypt_local(encrypted, key), payload, f"payload {n}")
        assert_same(
            _native.decrypt_local(bytearray(encrypted), bytearray(key)),
            payload,
            f"bytearray payload {n}",
        )

        # Raw IGE of the body reproduces descriptor plus padding, both ways.
        aes_key, aes_iv = _native.prepare_aes_oldmtp(key, encrypted[:16])
        body = encrypted[16:]
        plain = unhex(case, "decrypted") + unhex(case, "padding")
        assert_same(_native.aes_ige_decrypt(body, aes_key, aes_iv), plain, f"ige {n}")
        assert_same(_native.aes_ige_encrypt(plain, aes_key, aes_iv), body, f"ige {n}")
        assert_same(cryptg.decrypt_ige(body, aes_key, aes_iv), plain, f"cryptg {n}")
        assert_same(cryptg.encrypt_ige(plain, aes_key, aes_iv), body, f"cryptg {n}")

        # Random padding: a fresh encryption has the 1.5.0 size and round trips.
        fresh = _native.encrypt_local(payload, key)
        assert len(fresh) == len(encrypted)
        assert_same(_native.decrypt_local(fresh, key), payload, f"round trip {n}")


def test_local_encryption_failures() -> None:
    key = bytes(range(256))
    encrypted = _native.encrypt_local(b"opentele2", key)
    with pytest.raises(CoreError) as wrong_key:
        _native.decrypt_local(encrypted, b"\x5a" * 256)
    assert wrong_key.value.code == "TDATA_BAD_DECRYPT_KEY"
    with pytest.raises(CoreError) as bad_size:
        _native.decrypt_local(b"\x00" * 16, key)
    assert bad_size.value.code == "TDATA_BAD_ENCRYPTED_DATA_SIZE"
    with pytest.raises(CoreError) as short_key:
        _native.encrypt_local(b"data", key[:255])
    assert short_key.value.code == "BAD_LENGTH"
    with pytest.raises(CoreError) as short_msg_key:
        _native.prepare_aes_oldmtp(key, b"\x00" * 15)
    assert short_msg_key.value.code == "BAD_LENGTH"


def test_kdf_vectors(crypto_vectors: Any) -> None:
    for n, case in enumerate(crypto_vectors["create_local_key"]):
        key = _native.create_local_key(case["passcode"], unhex(case, "salt"))
        assert_same(key, unhex(case, "key"), f"local key {n}")
        encoded = _native.create_local_key(case["passcode"].encode("utf-8"), unhex(case, "salt"))
        assert_same(encoded, key, f"local key bytes passcode {n}")
    for n, case in enumerate(crypto_vectors["create_legacy_local_key"]):
        key = _native.create_legacy_local_key(case["passcode"], unhex(case, "salt"))
        assert_same(key, unhex(case, "key"), f"legacy local key {n}")


def test_argon2id_wrap_vector(crypto_vectors: Any) -> None:
    case = crypto_vectors["argon2id_wrap"]
    wrap = _native.argon2id(
        case["passcode"], unhex(case, "salt"), case["memory_kib"], case["time"], case["lanes"]
    )
    assert len(wrap) == 256
    assert_same(wrap, unhex(case, "wrap_key"), "wrap_key")
    local_key = _native.decrypt_local(unhex(case, "key_encrypted"), wrap)
    assert_same(local_key, unhex(case, "local_key"), "local_key")
    with pytest.raises(CoreError) as empty:
        _native.argon2id(b"", unhex(case, "salt"), 64, 1, 1)
    assert empty.value.code == "BAD_LENGTH"


def test_cryptg_raises_value_error_on_bad_lengths() -> None:
    key, iv = b"\x07" * 32, b"\x09" * 32
    for function in (cryptg.encrypt_ige, cryptg.decrypt_ige):
        with pytest.raises(ValueError, match="buffer"):
            function(b"\x01" * 15, key, iv)
        with pytest.raises(ValueError, match="key"):
            function(b"\x01" * 16, key[:31], iv)
        with pytest.raises(ValueError, match="iv"):
            function(b"\x01" * 16, key, iv + b"\x00")
        assert not issubclass(CoreError, ValueError)
        assert function(b"", key, iv) == b""
    with pytest.raises(CoreError) as core:
        _native.aes_ige_encrypt(b"\x01" * 15, key, iv)
    assert core.value.code == "BAD_LENGTH"


# ---------------------------------------------------------------- sessions


def decode_telethon(string: str) -> tuple[int, str, int, bytes]:
    assert string[0] == "1"
    body = base64.urlsafe_b64decode(string[1:])
    ip_len = len(body) - 1 - 2 - 256
    dc_id, ip, port, key = struct.unpack(f">B{ip_len}sH256s", body)
    return dc_id, str(ipaddress.ip_address(ip)), port, key


def encode_telethon(dc_id: int, ip: str, port: int, key: bytes) -> str:
    packed = ipaddress.ip_address(ip).packed
    body = struct.pack(f">B{len(packed)}sH256s", dc_id, packed, port, key)
    return "1" + base64.urlsafe_b64encode(body).decode("ascii")


def test_telethon_string_session_vectors() -> None:
    cases = load_json("sessions.json")["cases"]
    assert len(cases) == 7
    for n, case in enumerate(cases):
        key = unhex(case, "auth_key")
        ipv6 = case["ip_version"] == 6
        # The reference layout reproduces the vector exactly.
        dc_id, ip, port, decoded_key = decode_telethon(case["string_session"])
        assert (dc_id, ip, port) == (case["dc_id"], case["ip"], case["port"])
        assert_same(decoded_key, key, f"vector key {n}")
        assert encode_telethon(dc_id, ip, port, key) == case["string_session"]

        # The binding writes the same layout for the production endpoint.
        account = Account(0, 1, case["dc_id"], [(case["dc_id"], key)])
        session = _native.telethon_string_session(account, ipv6=ipv6)
        production = PRODUCTION[case["dc_id"]][1 if ipv6 else 0]
        assert session == encode_telethon(case["dc_id"], production, 443, key)


def test_sessions_of_vector_accounts(manifest: Any) -> None:
    entry = manifest["tdata_plain/performance_on"]
    tdata = TData.load(VECTORS / "tdata_plain/performance_on")
    for account, want in zip(tdata.accounts, entry["accounts"]):
        key = unhex(want, "auth_key")
        for ipv6 in (False, True):
            dc_id, ip, port, decoded_key = decode_telethon(
                _native.telethon_string_session(account, ipv6)
            )
            assert (dc_id, ip, port) == (want["main_dc"], PRODUCTION[dc_id][int(ipv6)], 443)
            assert_same(decoded_key, key, "telethon key")

        mtcute = _native.mtcute_string_session(account)
        assert "=" not in mtcute
        raw = base64.urlsafe_b64decode(mtcute + "=" * (-len(mtcute) % 4))
        assert raw[0] == 3
        assert struct.unpack("<i", raw[1:5]) == (1,)
        assert raw[-272:-260] == struct.pack("<QI", want["user_id"], MTCUTE_BOOL_FALSE)
        assert raw[-260:-256] == b"\xfe\x00\x01\x00"
        assert_same(raw[-256:], key, "mtcute key")


# ---------------------------------------------------------------- tdata


def listed_files(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())


def check_accounts(tdata: TData, entry: Any, label: str) -> None:
    wanted = entry["accounts"]
    assert [a.index for a in tdata.accounts] == [w["index"] for w in wanted], label
    for account, want in zip(tdata.accounts, wanted):
        assert account.user_id == want["user_id"], label
        assert account.main_dc == want["main_dc"], label
        assert_same(account.auth_key, unhex(want, "auth_key"), f"{label} auth_key")
        dcs = [dc for dc, _ in account.keys]
        assert want["main_dc"] in dcs, label
        assert "Account(index=" in repr(account)
    main = tdata.main_account
    assert main is not None
    assert main.index == entry["main_account_index"], label


@pytest.mark.parametrize("folder", FOLDERS)
def test_tdata_load_save_round_trip(folder: str, manifest: Any, tmp_path: Path) -> None:
    entry = manifest[folder]
    loaded = TData.load(VECTORS / folder, entry["passcode"], entry["key_file"])
    check_accounts(loaded, entry, f"{folder} load")
    # Every vector stores -1, so the main account falls back to the first.
    assert loaded.active_index == -1

    # A loaded folder saves in performance mode, which writes no configs.
    saved = tmp_path / "saved"
    loaded.save(saved)
    expected = sorted(name for name in entry["files"] if not name.endswith("/configs"))
    assert listed_files(saved) == expected
    reloaded = TData.load(str(saved), entry["passcode"].encode("utf-8"))
    check_accounts(reloaded, entry, f"{folder} reload")


@pytest.mark.parametrize("folder", FOLDERS)
def test_tdata_new_writes_the_vector_layout(folder: str, manifest: Any, tmp_path: Path) -> None:
    entry = manifest[folder]
    accounts = [
        Account(w["index"], w["user_id"], w["main_dc"], [(w["main_dc"], unhex(w, "auth_key"))])
        for w in entry["accounts"]
    ]
    created = TData.new(accounts, entry["passcode"], entry["performance_mode"])
    assert created.active_index == -1
    created.save(tmp_path)
    assert listed_files(tmp_path) == sorted(entry["files"])
    reloaded = TData.load(tmp_path, entry["passcode"])
    assert [a.user_id for a in reloaded.accounts] == [w["user_id"] for w in entry["accounts"]]
    for account, want in zip(reloaded.accounts, entry["accounts"]):
        assert_same(account.auth_key, unhex(want, "auth_key"), f"{folder} new auth_key")


def test_tdata_errors(tmp_path: Path) -> None:
    with pytest.raises(CoreError) as plain_wrong:
        TData.load(VECTORS / "tdata_plain/performance_on", "opentele2")
    assert plain_wrong.value.code == "TDATA_BAD_DECRYPT_KEY"
    with pytest.raises(CoreError) as passcode_wrong:
        TData.load(VECTORS / "tdata_passcode/performance_on", b"not-the-passcode")
    assert passcode_wrong.value.code == "TDATA_BAD_DECRYPT_KEY"
    with pytest.raises(CoreError) as missing:
        TData.load(tmp_path / "missing")
    assert missing.value.code == "TFILE_NOT_FOUND"
    assert "TFILE_NOT_FOUND" in str(missing.value)

    with pytest.raises(CoreError) as keyless:
        Account(0, 1, 2, [(4, bytes(256))])
    assert keyless.value.code == "TDATA_AUTH_KEY_NOT_FOUND"
    with pytest.raises(CoreError) as short:
        Account(0, 1, 2, [(2, bytes(255))])
    assert short.value.code == "BAD_LENGTH"
    with pytest.raises(CoreError) as unknown_dc:
        _native.telethon_string_session(Account(0, 1, 7, [(7, bytes(256))]))
    assert unknown_dc.value.code == "TDATA_BAD_CONFIG_DATA"
    with pytest.raises(CoreError) as empty:
        TData.new([]).save(tmp_path / "empty")
    assert empty.value.code == "TDATA_SAVE_FAILED"


def test_load_many_keeps_order(manifest: Any, tmp_path: Path) -> None:
    passcode = manifest["tdata_passcode/performance_on"]["passcode"]
    requests: list[Any] = [
        VECTORS / "tdata_plain/performance_on",
        str(tmp_path / "missing"),
        (VECTORS / "tdata_passcode/performance_on", passcode),
        (VECTORS / "tdata_plain/performance_off", b"", "data"),
        (VECTORS / "tdata_plain/performance_on", "wrong"),
        (VECTORS / "tdata_plain/performance_on", b"", "other"),
    ]
    results = _native.load_many(requests, threads=2)
    assert len(results) == len(requests)
    first, missing, passcode_folder, plain_off, wrong, other = results
    assert isinstance(first, TData)
    check_accounts(first, manifest["tdata_plain/performance_on"], "load_many 0")
    assert core_code(missing) == "TFILE_NOT_FOUND"
    assert isinstance(passcode_folder, TData)
    check_accounts(passcode_folder, manifest["tdata_passcode/performance_on"], "load_many 2")
    assert isinstance(plain_off, TData)
    check_accounts(plain_off, manifest["tdata_plain/performance_off"], "load_many 3")
    assert core_code(wrong) == "TDATA_BAD_DECRYPT_KEY"
    assert core_code(other) == "TFILE_NOT_FOUND"

    assert _native.load_many([]) == []
    with pytest.raises(ValueError, match="threads"):
        _native.load_many(requests, threads=0)


# ---------------------------------------------------------------- fingerprints


def test_generate_matches_device_vectors() -> None:
    cases = load_json("devices.json")["cases"]
    assert len(cases) == 2800
    sample = cases[::10]
    assert len(sample) >= 200
    assert {case["seed_kind"] for case in sample} == {"str", "int"}
    for n, case in enumerate(sample):
        profile = _native.generate(case["entry_point"], seed=case["seed"], system=case["system"])
        assert set(profile) == PROFILE_FIELDS
        for field in ("device_model", "system_version", "app_version", "lang_pack"):
            assert profile[field] == case[field], f"case {n} {field}"
        assert profile["system_lang_code"] == case["system_lang_code"], f"case {n}"


def test_profiles_and_generate_errors() -> None:
    for client in CLIENTS:
        profile = _native.profile(client)
        assert set(profile) == PROFILE_FIELDS
        assert profile["lang_code"] == "en"
    desktop = _native.profile("TelegramDesktop")
    assert desktop["api_id"] == 2040
    assert desktop["lang_pack"] == "tdesktop"

    android = _native.profile(
        "TelegramAndroid", {"android_app_version": "1.2.3", "android_app_version_code": 9}
    )
    assert android["app_version"] == "1.2.3 (9)"
    linux = _native.generate("TelegramDesktop", seed="opentele2", system="linux")
    assert linux["app_version"] == desktop["app_version"].split(" ")[0]
    assert _native.generate("TelegramIOS", seed=7) == _native.generate("TelegramIOS", seed="7")
    assert set(_native.generate("TelegramAndroid")) == PROFILE_FIELDS

    web = _native.generate("TelegramWeb_A", seed="x")
    assert _native.generate("TelegramWeb_A", seed="x") == web
    assert "Mozilla/5.0" in web["device_model"]
    assert web["app_version"] == _native.profile("TelegramWeb_A")["app_version"]
    web_models = {
        _native.generate("TelegramWeb_A", seed=seed)["device_model"] for seed in "abcdefgh"
    }
    assert len(web_models) > 1
    # Values the stub rejects, typed as Any to reach the runtime checks.
    bad_client: Any = "Telegram"
    bad_versions: Any = {"bogus": "1"}
    with pytest.raises(ValueError, match="unknown client"):
        _native.profile(bad_client)
    with pytest.raises(ValueError, match="unknown versions field"):
        _native.profile("TelegramDesktop", bad_versions)
    with pytest.raises(ValueError, match="TelegramDesktop"):
        _native.generate("TelegramIOS", system="linux")
