# ruff: noqa: E402
"""Offline contract tests for the Telethon 1.44.0 session file writer."""

import pathlib
import sqlite3
import sys

base_dir = pathlib.Path(__file__).parent.parent.absolute().__str__()
sys.path.insert(0, base_dir)

import pytest

from telethon.sessions.sqlite import CURRENT_VERSION, SQLiteSession

from src import td
from src.tl.session_io import SESSION_VERSION, write_session_file
from src.tl.telethon import _select_endpoint_address

AUTH_KEY = bytes(range(256))


def _make_pre_v8_session(path: str) -> None:
    """Write the narrow pre-version-8 Telethon schema at ``path``."""
    conn = sqlite3.connect(path)
    try:
        c = conn.cursor()
        c.execute("create table version (version integer primary key)")
        c.execute("insert into version values (1)")
        c.execute(
            "create table sessions (dc_id integer primary key, "
            "server_address text, port integer, auth_key blob)"
        )
        c.execute("insert into sessions values (1, '149.154.175.50', 443, x'00')")
        c.execute(
            "create table entities (id integer primary key, hash integer not null, "
            "username text, phone integer, name text)"
        )
        c.execute(
            "create table sent_files (md5_digest blob, file_size integer, "
            "type integer, id integer, hash integer, "
            "primary key(md5_digest, file_size, type))"
        )
        c.execute(
            "create table update_state (id integer primary key, pts integer, "
            "qts integer, date integer, seq integer)"
        )
        conn.commit()
    finally:
        conn.close()


def _columns(path: str, table: str) -> list:
    conn = sqlite3.connect(path)
    try:
        return [row[1] for row in conn.execute(f"pragma table_info({table})")]
    finally:
        conn.close()


def _version(path: str) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("select version from version").fetchone()[0]
    finally:
        conn.close()


def test_fresh_write_round_trips_through_sqlite_session(tmp_path):
    base = str(tmp_path / "fresh")
    full_path = write_session_file(base, 2, "149.154.167.51", 443, AUTH_KEY)

    assert full_path == base + ".session"
    assert _version(full_path) == CURRENT_VERSION == SESSION_VERSION

    session = SQLiteSession(base)
    try:
        assert session.dc_id == 2
        assert session.server_address == "149.154.167.51"
        assert session.port == 443
        assert session.auth_key is not None
        assert session.auth_key.key == AUTH_KEY
    finally:
        session.close()


def test_write_over_pre_v8_session_rebuilds_schema(tmp_path):
    base = str(tmp_path / "legacy")
    full_path = base + ".session"
    _make_pre_v8_session(full_path)
    assert _columns(full_path, "sessions") == [
        "dc_id",
        "server_address",
        "port",
        "auth_key",
    ]

    # Regression: this used to leave the narrow table stamped as version 8 and
    # raise "table sessions has 4 columns but 6 values supplied".
    write_session_file(base, 4, "149.154.167.91", 443, AUTH_KEY)

    assert _columns(full_path, "sessions") == [
        "dc_id",
        "server_address",
        "port",
        "auth_key",
        "takeout_id",
        "tmp_auth_key",
    ]
    assert _version(full_path) == CURRENT_VERSION

    session = SQLiteSession(base)
    try:
        assert session.dc_id == 4
        assert session.server_address == "149.154.167.91"
        assert session.port == 443
        assert session.auth_key.key == AUTH_KEY
    finally:
        session.close()


def test_pre_v8_file_is_never_stamped_v8_with_old_schema(tmp_path):
    """The stamp and the layout must move together, never independently."""
    base = str(tmp_path / "stamp")
    full_path = base + ".session"
    _make_pre_v8_session(full_path)
    write_session_file(base, 1, "149.154.175.50", 443, AUTH_KEY)

    conn = sqlite3.connect(full_path)
    try:
        version = conn.execute("select version from version").fetchone()[0]
        row = conn.execute("select * from sessions").fetchone()
    finally:
        conn.close()

    assert version == CURRENT_VERSION
    assert len(row) == 6
    # takeout_id and tmp_auth_key stay NULL: telethon 1.44.0 unpacks them in
    # the opposite order to its own DDL, so NULL keeps that harmless.
    assert row[4] is None
    assert row[5] is None


def test_rewrite_of_current_schema_preserves_entities(tmp_path):
    base = str(tmp_path / "keep")
    full_path = write_session_file(base, 2, "149.154.167.51", 443, AUTH_KEY)

    conn = sqlite3.connect(full_path)
    try:
        conn.execute("insert into entities values (7, 11, 'u', NULL, 'n', 0)")
        conn.commit()
    finally:
        conn.close()

    write_session_file(base, 5, "91.108.56.100", 443, AUTH_KEY)

    conn = sqlite3.connect(full_path)
    try:
        assert conn.execute("select count(*) from entities").fetchone()[0] == 1
        assert conn.execute("select count(*) from sessions").fetchone()[0] == 1
    finally:
        conn.close()

    session = SQLiteSession(base)
    try:
        assert session.dc_id == 5
        assert session.server_address == "91.108.56.100"
    finally:
        session.close()


def test_write_leaves_no_open_handle(tmp_path):
    """The writer's connection is closed before the path is handed onward."""
    base = str(tmp_path / "handle")
    full_path = write_session_file(base, 2, "149.154.167.51", 443, AUTH_KEY)

    session = SQLiteSession(base)
    session.set_dc(2, "149.154.167.51", 443)
    session.save()
    session.close()

    pathlib.Path(full_path).unlink()
    assert not pathlib.Path(full_path).exists()


Address = td.MTP.DcOptions.Address
Protocol = td.MTP.DcOptions.Protocol


def _endpoints(ipv4, ipv6):
    return {
        Address.IPv4: {Protocol.Tcp: ipv4, Protocol.Http: []},
        Address.IPv6: {Protocol.Tcp: ipv6, Protocol.Http: []},
    }


@pytest.mark.parametrize(
    ("use_ipv6", "ipv4", "ipv6", "expected"),
    [
        (True, ["v4"], ["v6"], Address.IPv6),
        (False, ["v4"], ["v6"], Address.IPv4),
        (True, ["v4"], [], Address.IPv4),
        (False, ["v4"], [], Address.IPv4),
    ],
)
def test_select_endpoint_address(use_ipv6, ipv4, ipv6, expected):
    assert _select_endpoint_address(_endpoints(ipv4, ipv6), use_ipv6) is expected


def test_select_endpoint_address_handles_missing_ipv6_family():
    endpoints = {Address.IPv4: {Protocol.Tcp: ["v4"], Protocol.Http: []}}
    assert _select_endpoint_address(endpoints, True) is Address.IPv4
