"""Tests of ``opentele2.tl.TelegramClient`` and ``opentele2.consistency``:
construction, sessions, the advertised layer and the consistency checks.

Every client is offline: a MemorySession that never connects, and a
``FakeClient`` that answers requests from a table instead of the network.
SRP outputs are compared with ``assert_same``, so they never reach the log.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import warnings
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import telethon
from telethon import functions, password, types
from telethon.errors.rpcerrorlist import (
    FreshResetAuthorisationForbiddenError,
    HashInvalidError,
    PasswordHashInvalidError,
)
from telethon.sessions.memory import MemorySession

import opentele2
import opentele2.exception
from opentele2 import _native, consistency, fingerprint, tl
from opentele2.api import API, APIData
from opentele2.consistency import CheckResult, ConsistencyChecker, ConsistencyReport
from opentele2.exception import NoPasswordProvided, OpenTeleException, PasswordIncorrect
from opentele2.fingerprint import FingerprintConfig, StrictMode
from opentele2.tl import shared
from opentele2.tl import telethon as tl_telethon
from opentele2.tl.telethon import TelegramClient

# A 2FA fixture of crates/opentele2-core/tests/auth.rs (SRP_ONE): Telegram's
# 2048-bit prime, and a recorded exponent Telethon accepts on its first draw.
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

REFS = Path(__file__).resolve().parents[3] / "refs"
SCHEMAS = {
    "tdesktop": REFS / "tdesktop-dev/Telegram/SourceFiles/mtproto/scheme/api.tl",
    "telethon": REFS / "telethon/telethon_generator/data/api.tl",
}


def assert_same(actual: bytes, expected: bytes, label: str) -> None:
    """Fails without showing either value, so secrets never reach the log."""
    if actual != expected:
        raise AssertionError(f"{label} differs") from None


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def offline_client(*args: Any, **kwargs: Any) -> TelegramClient:
    """A never-connected client, built on a running loop: Telethon binds the
    current loop at construction, and on 3.8 there is none outside one."""

    async def build() -> TelegramClient:
        return TelegramClient(*args, **kwargs)

    return run(build())


class FakeClient(TelegramClient):
    """Answers each request with the entry for its type: a value, or an
    exception to raise; records every request it was sent."""

    def __init__(self, responses: dict[type, Any], **kwargs: Any) -> None:
        super().__init__(None, auto_post_login=False, **kwargs)
        self.responses = responses
        self.requests: list[Any] = []

    async def __call__(
        self, request: Any, ordered: bool = False, flood_sleep_threshold: Any = None
    ) -> Any:
        self.requests.append(request)
        response = self.responses[type(request)]
        if isinstance(response, BaseException):
            raise response
        return response


def fake(responses: dict[type, Any], **kwargs: Any) -> FakeClient:
    async def build() -> FakeClient:
        return FakeClient(responses, **kwargs)

    return run(build())


def authorization(current: bool, official: bool, api_id: int = 2040, **fields: Any) -> Any:
    values: dict[str, Any] = {
        "hash": 1000 + api_id,
        "device_model": "PC 64bit",
        "platform": "Windows",
        "system_version": "Windows 11",
        "api_id": api_id,
        "app_name": "Telegram Desktop",
        "app_version": "6.1 x64",
        "date_created": None,
        "date_active": None,
        "ip": "192.0.2.1",
        "country": "DE",
        "region": "",
        "current": current,
        "official_app": official,
    }
    values.update(fields)
    return types.Authorization(**values)


def authorizations(*auths: Any) -> Any:
    return types.account.Authorizations(authorization_ttl_days=180, authorizations=list(auths))


def reference_pretty_table(table: list[dict[str, object]], addSplit: list[int]) -> str:
    """A reference ``PrettyTable`` renderer, the expected PrintSessions output."""
    padding = {}
    result = ""
    for label in table[0]:
        padding[label] = len(label)
    for row in table:
        for label, value in row.items():
            padding[label] = max(padding[label], len(str(value)))

    def addpadding(text: object, spaces: int) -> str:
        text = str(text)
        spaceLeft = spaces - len(text)
        padLeft = spaceLeft // 2
        return " " * padLeft + text + " " * (spaceLeft - padLeft)

    header = "|".join(addpadding(label, spaces + 2) for label, spaces in padding.items())
    splitter = "+".join(("-" * (spaces + 2)) for spaces in padding.values())
    rows = [
        "|".join(addpadding(row[label], spaces + 2) for label, spaces in padding.items())
        for row in table
    ]
    result += f"|{splitter}|\n|{header}|\n|{splitter}|\n"
    for index, row_text in enumerate(rows):
        if index in addSplit:
            result += f"|{splitter}|\n"
        result += f"|{row_text}|\n"
    return result + f"|{splitter}|"


# ---------------------------------------------------------------- package


def test_package_imports_td_and_tl() -> None:
    assert opentele2.tl is tl
    assert opentele2.consistency is consistency
    assert opentele2.td.TDesktop.__module__ == "opentele2.td.tdesktop"
    assert tl.TelegramClient is TelegramClient
    assert shared.__all__ == [
        "DEFAULT_CONFIG",
        "LAYER",
        "PLATFORM_VERSIONS",
        "CheckResult",
        "ConsistencyChecker",
        "ConsistencyReport",
        "FingerprintConfig",
        "PlatformVersions",
        "StrictMode",
        "TelegramClient",
        "TransportRecommendation",
        "validate_init_connection_params",
    ]
    assert shared.ConsistencyChecker is ConsistencyChecker
    assert shared.LAYER == fingerprint.LAYER


def test_configs_namespace_names() -> None:
    from opentele2.tl import configs

    for name in ("API", "APIData", "AuthKey", "MemorySession", "StringSession", "td", "tl"):
        assert name in configs.__all__, name
        assert hasattr(configs, name), name
    for name in opentele2.exception.__all__:
        assert getattr(configs, name) is getattr(opentele2.exception, name), name
    assert configs.Dict is dict
    assert configs.td is opentele2.td


# ---------------------------------------------------------------- constructor


class TestTelegramClientConstructor:
    def test_default_api(self) -> None:
        client = offline_client()
        assert client.api_id == API.TelegramDesktop.api_id
        assert client.api_hash == API.TelegramDesktop.api_hash

    def test_custom_api_id(self) -> None:
        client = offline_client(None, 1234, "testhash")
        assert client.api_id == 1234
        assert client.api_hash == "testhash"
        assert client._api_data is None

    def test_positional_api_id_and_hash_forms(self) -> None:
        assert offline_client(None, 1234, "opentele").api_id == 1234
        assert offline_client(None, None, 1234, "opentele").api_id == 1234

    def test_api_object(self) -> None:
        client = offline_client(None, api=API.TelegramAndroid)
        assert client.api_id == API.TelegramAndroid.api_id
        assert client._api_data == API.TelegramAndroid()

    def test_api_instance(self) -> None:
        api = API.TelegramIOS()
        client = offline_client(None, api=api)
        assert client.api_id == API.TelegramIOS.api_id
        assert client._api_data is api

    def test_none_session_becomes_memory_session(self) -> None:
        client = offline_client(None)
        assert isinstance(client.session, MemorySession)

    def test_missing_api_hash_raises_telethons_value_error(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            offline_client(None, api_id=1234)

    def test_user_id_prefers_the_logged_in_id(self) -> None:
        client = offline_client()
        assert client.UserId is None
        client.UserId = 77
        assert client.UserId == 77

    def test_fingerprint_issues_never_break_construction(self) -> None:
        strict = FingerprintConfig(strict_mode=StrictMode.STRICT)
        odd = APIData(1, "hash", "", "", "", "e", "e", "nope")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            client = offline_client(None, api=odd, fingerprint_config=strict)
        assert client._fingerprint_config is strict
        assert client._init_request.lang_pack == "nope"

    def test_warn_mode_warns_about_the_profile(self) -> None:
        odd = APIData(1, "hash", "", "", "", "e", "e", "nope")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            client = offline_client(None, api=odd)
        init = client._init_request
        issues = fingerprint._init_issues(
            api_id=init.api_id,
            device_model=init.device_model,
            system_version=init.system_version,
            app_version=init.app_version,
            system_lang_code=init.system_lang_code,
            lang_pack=init.lang_pack,
            lang_code=init.lang_code,
        )
        assert issues
        assert [str(w.message) for w in caught] == [_native.issues_message(issues)]


class TestAutoPostLogin:
    def test_auto_post_login_defaults_true(self) -> None:
        client = offline_client(api=API.TelegramDesktop)
        assert client._auto_post_login is True

    def test_auto_post_login_can_be_disabled(self) -> None:
        client = offline_client(api=API.TelegramDesktop, auto_post_login=False)
        assert client._auto_post_login is False

    def test_post_login_done_starts_false(self) -> None:
        client = offline_client(api=API.TelegramDesktop)
        assert client._post_login_done is False

    def test_has_run_post_login_method(self) -> None:
        assert hasattr(TelegramClient, "_run_post_login_requests")

    def test_has_connect_override(self) -> None:
        source = inspect.getsource(TelegramClient.connect)
        assert "_run_post_login_requests" in source
        assert "_auto_post_login" in source

    def test_post_login_requests_follow_the_official_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        delays: list[float] = []

        async def no_sleep(seconds: float) -> None:
            delays.append(seconds)

        monkeypatch.setattr(tl_telethon.asyncio, "sleep", no_sleep)
        client = fake(
            {
                functions.help.GetConfigRequest: "config",
                functions.help.GetNearestDcRequest: RuntimeError("refused"),
                functions.account.UpdateStatusRequest: True,
                functions.langpack.GetLanguagesRequest: [],
                functions.help.GetAppUpdateRequest: "update",
                functions.help.GetTermsOfServiceUpdateRequest: "tos",
                functions.help.GetCountriesListRequest: "countries",
            },
            api=API.TelegramDesktop,
        )
        run(client._run_post_login_requests())
        run(client._run_post_login_requests())
        assert [type(request) for request in client.requests] == [
            functions.help.GetConfigRequest,
            functions.help.GetNearestDcRequest,
            functions.account.UpdateStatusRequest,
            functions.langpack.GetLanguagesRequest,
            functions.help.GetAppUpdateRequest,
            functions.help.GetTermsOfServiceUpdateRequest,
            functions.help.GetCountriesListRequest,
        ]
        assert client.requests[3].lang_pack == "tdesktop"
        assert client.requests[2].offline is False
        assert len(delays) == 6
        assert all(0.05 <= delay <= 0.5 for delay in delays)

        web = fake(
            {
                functions.help.GetConfigRequest: "config",
                functions.help.GetNearestDcRequest: "dc",
                functions.account.UpdateStatusRequest: True,
                functions.help.GetAppUpdateRequest: "update",
                functions.help.GetTermsOfServiceUpdateRequest: "tos",
                functions.help.GetCountriesListRequest: "countries",
            },
            api=API.TelegramWeb_A,
        )
        run(web._run_post_login_requests())
        assert functions.langpack.GetLanguagesRequest not in [type(r) for r in web.requests]

    def test_connect_runs_post_login_once_when_authorized(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[str] = []

        async def offline_connect(self: telethon.TelegramClient) -> None:
            events.append("connect")

        async def authorized(self: telethon.TelegramClient) -> bool:
            return True

        async def post_login(self: TelegramClient) -> None:
            events.append("post_login")
            self._post_login_done = True

        monkeypatch.setattr(telethon.TelegramClient, "connect", offline_connect)
        monkeypatch.setattr(telethon.TelegramClient, "is_user_authorized", authorized)
        monkeypatch.setattr(TelegramClient, "_run_post_login_requests", post_login)

        async def scenario() -> None:
            client = TelegramClient()
            await client.connect()
            await client.connect()
            disabled = TelegramClient(auto_post_login=False)
            await disabled.connect()

        run(scenario())
        assert events == ["connect", "post_login", "connect", "connect"]


# ---------------------------------------------------------------- sessions


class TestTelegramClientSessions:
    def test_print_sessions_without_sessions_raises(self) -> None:
        client = fake({functions.account.GetAuthorizationsRequest: None})
        with pytest.raises(OpenTeleException, match="Could not fetch the account's sessions"):
            run(client.PrintSessions())

    def test_print_sessions_prints_the_sessions_table(self, capsys: pytest.CaptureFixture) -> None:
        auths = authorizations(
            authorization(True, True),
            authorization(False, False, api_id=6, app_name="Telegram Android", platform="ab"),
            authorization(False, True, api_id=10840, device_model="iPhone 15 Pro Max"),
        )
        client = fake({functions.account.GetAuthorizationsRequest: auths})
        run(client.PrintSessions())
        printed = capsys.readouterr().out
        table = [
            {
                " ": "Current" if auth.current else index,
                "Device": auth.device_model,
                "Platform": auth.platform,
                "System": auth.system_version,
                "API_ID": auth.api_id,
                "App name": f"{auth.app_name} {auth.app_version}",
                "Official App": "✔" if auth.official_app else "✖",
            }
            for index, auth in enumerate(auths.authorizations)
        ]
        assert printed == reference_pretty_table(table, [1]) + "\n"
        # A given Authorizations is printed without a request.
        silent = fake({})
        run(silent.PrintSessions(auths))
        assert capsys.readouterr().out == printed
        assert silent.requests == []

    def test_current_session_and_official_app(self) -> None:
        auths = authorizations(authorization(False, False), authorization(True, True))
        client = fake({functions.account.GetAuthorizationsRequest: auths})
        current = run(client.GetCurrentSession())
        assert current is auths.authorizations[1]
        assert run(client.is_official_app()) is True
        unofficial = fake(
            {functions.account.GetAuthorizationsRequest: authorizations(authorization(True, False))}
        )
        assert run(unofficial.is_official_app()) is False
        nothing = fake({functions.account.GetAuthorizationsRequest: authorizations()})
        assert run(nothing.GetCurrentSession()) is None
        assert run(nothing.is_official_app()) is False

    def test_terminate_sessions(self) -> None:
        auths = authorizations(
            authorization(True, True, api_id=1), authorization(False, True, api_id=2)
        )
        client = fake(
            {
                functions.account.GetAuthorizationsRequest: auths,
                functions.account.ResetAuthorizationRequest: True,
            }
        )
        assert run(client.TerminateAllSessions()) is True
        reset = [
            r for r in client.requests if isinstance(r, functions.account.ResetAuthorizationRequest)
        ]
        assert [r.hash for r in reset] == [1002]
        none = fake({functions.account.GetAuthorizationsRequest: None})
        assert run(none.TerminateAllSessions()) is False

    @pytest.mark.parametrize("error", [FreshResetAuthorisationForbiddenError, HashInvalidError])
    def test_terminate_session_reraises_telethons_error(self, error: Any) -> None:
        client = fake({functions.account.ResetAuthorizationRequest: error(None)})
        with pytest.raises(error) as raised:
            run(client.TerminateSession(5))
        # TerminateSession hands its text to the error as the request, which Telethon
        # names in its own message.
        assert str(raised.value).endswith("(caused by str)")


# ---------------------------------------------------------------- 2FA


def _password_request() -> Any:
    algo = types.PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow(
        salt1=SRP_SALT1, salt2=SRP_SALT2, g=3, p=SRP_P
    )
    return types.account.Password(
        new_algo=types.PasswordKdfAlgoUnknown(),
        new_secure_algo=types.SecurePasswordKdfAlgoUnknown(),
        secure_random=b"",
        has_password=True,
        current_algo=algo,
        srp_B=SRP_B,
        srp_id=SRP_ID,
    )


class TestTwoFactor:
    def test_check_matches_telethon_compute_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        request = _password_request()
        monkeypatch.setattr(password.os, "urandom", lambda size: SRP_DRAW[:size])
        expected = password.compute_check(request, SRP_PASSWORD)

        native_check = _native.srp_check

        def recorded(params: Any, secret: str) -> Any:
            return native_check(params, secret, [SRP_DRAW])

        monkeypatch.setattr(tl_telethon._native, "srp_check", recorded)
        check = tl_telethon._compute_check(request, SRP_PASSWORD)
        assert isinstance(check, types.InputCheckPasswordSRP)
        assert check.srp_id == expected.srp_id == SRP_ID
        assert_same(check.A, expected.A, "A")
        assert_same(check.M1, expected.M1, "M1")

    def test_check_refusals_are_telethons(self) -> None:
        request = _password_request()
        request.srp_B = bytes(256)
        with pytest.raises(ValueError, match="bad b in check"):
            tl_telethon._compute_check(request, SRP_PASSWORD)
        request.srp_B = None
        with pytest.raises(ValueError, match="bad b in check"):
            tl_telethon._compute_check(request, SRP_PASSWORD)
        request.current_algo = types.PasswordKdfAlgoUnknown()
        with pytest.raises(
            ValueError, match="unsupported password algorithm PasswordKdfAlgoUnknown"
        ):
            tl_telethon._compute_check(request, SRP_PASSWORD)

    def test_handle_2fa_logs_in_with_the_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        user = types.User(id=4242, is_self=True)
        logins: list[Any] = []

        async def on_login(self: TelegramClient, logged_in: Any) -> Any:
            logins.append(logged_in)
            return logged_in

        monkeypatch.setattr(TelegramClient, "_on_login", on_login)
        new_client = fake(
            {
                functions.account.GetPasswordRequest: _password_request(),
                functions.auth.CheckPasswordRequest: types.auth.Authorization(user=user),
            }
        )
        old_client = fake({})
        assert run(old_client._handle2FA(new_client, SRP_PASSWORD)) is new_client
        assert logins == [user]
        check = new_client.requests[1].password
        assert isinstance(check, types.InputCheckPasswordSRP)
        assert check.srp_id == SRP_ID
        assert len(check.A) == _native.SRP_NUMBER_SIZE
        assert len(check.M1) == 32

    def test_handle_2fa_errors(self) -> None:
        old_client = fake({})
        with pytest.raises(NoPasswordProvided) as missing:
            run(old_client._handle2FA(fake({}), None))
        assert missing.value.message == (
            "Two-step verification is enabled for this account.\n"
            "You need to provide the `password` to argument"
        )
        wrong = fake(
            {
                functions.account.GetPasswordRequest: _password_request(),
                functions.auth.CheckPasswordRequest: PasswordHashInvalidError(None),
            }
        )
        with pytest.raises(PasswordIncorrect, match="password"):
            run(old_client._handle2FA(wrong, SRP_PASSWORD))


# ---------------------------------------------------------------- consistency


class TestConsistencyDataclasses:
    def test_check_result_passed(self) -> None:
        cr = CheckResult(name="test", passed=True, detail="OK")
        assert cr.passed
        assert cr.name == "test"
        assert cr.detail == "OK"

    def test_check_result_failed(self) -> None:
        cr = CheckResult(name="test", passed=False, detail="bad")
        assert not cr.passed

    def test_report_all_passed(self) -> None:
        r = ConsistencyReport(
            checks=[
                CheckResult(name="a", passed=True, detail="ok"),
                CheckResult(name="b", passed=True, detail="ok"),
            ]
        )
        assert r.all_passed

    def test_report_not_all_passed(self) -> None:
        r = ConsistencyReport(
            checks=[
                CheckResult(name="a", passed=True, detail="ok"),
                CheckResult(name="b", passed=False, detail="bad"),
            ]
        )
        assert not r.all_passed

    def test_report_summary(self) -> None:
        r = ConsistencyReport(
            checks=[
                CheckResult(name="a", passed=True, detail="ok"),
                CheckResult(name="b", passed=False, detail="fail"),
            ]
        )
        assert r.summary == "Consistency: 1/2 checks passed\n  [OK] a: ok\n  [FAIL] b: fail"

    def test_report_str(self) -> None:
        r = ConsistencyReport(checks=[CheckResult(name="x", passed=True, detail="d")])
        assert str(r) == r.summary

    def test_empty_report_passes(self) -> None:
        r = ConsistencyReport()
        assert r.all_passed
        assert r.summary == "Consistency: 0/0 checks passed"


class TestConsistencyChecker:
    def test_checker_has_nearest_dc_method(self) -> None:
        assert hasattr(ConsistencyChecker, "check_nearest_dc")

    def test_run_all_lists_nearest_dc(self) -> None:
        source = inspect.getsource(ConsistencyChecker.run_all)
        assert "check_nearest_dc" in source

    def test_run_all_details(self, monkeypatch: pytest.MonkeyPatch) -> None:
        advertised = fingerprint.get_advertised_layer()
        monkeypatch.setattr(fingerprint, "_detect_telethon_layer", lambda: advertised)
        client = fake(
            {
                functions.help.GetConfigRequest: SimpleNamespace(this_dc=2),
                functions.help.GetNearestDcRequest: types.NearestDc("DE", 2, 4),
                functions.account.GetAuthorizationsRequest: authorizations(
                    authorization(True, True)
                ),
                functions.langpack.GetLanguagesRequest: ["en", "de", "ru"],
                functions.help.GetAppUpdateRequest: types.help.NoAppUpdate(),
                functions.help.GetTermsOfServiceUpdateRequest: "tos",
            }
        )
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            report = run(client.RunConsistencyChecks())
        assert [(c.name, c.passed, c.detail) for c in report.checks] == [
            ("get_config", True, "Config OK (DC 2)"),
            ("nearest_dc", True, "country='DE', this_dc=2, nearest_dc=4"),
            (
                "current_session",
                True,
                "api_id=2040, official=True, device='PC 64bit', app='Telegram Desktop 6.1 x64'",
            ),
            (
                "layer_match",
                True,
                f"Telethon layer={advertised}, advertised schema layer={advertised}, diff=0",
            ),
            ("lang_pack", True, "lang_pack 'tdesktop' valid (3 languages)"),
            ("app_update", True, "No update available (app_version accepted)"),
            ("terms_of_service", True, "ToS check OK"),
        ]
        assert report.all_passed
        assert report.checks[1].server_response == types.NearestDc("DE", 2, 4)
        assert [c.name for c in report.checks] == _native.consistency_checks()

    def test_run_all_failures(self, monkeypatch: pytest.MonkeyPatch) -> None:
        advertised = fingerprint.get_advertised_layer()
        monkeypatch.setattr(fingerprint, "_detect_telethon_layer", lambda: advertised)
        client = fake(
            {
                functions.help.GetConfigRequest: RuntimeError("boom"),
                functions.help.GetNearestDcRequest: RuntimeError("no dc"),
                functions.account.GetAuthorizationsRequest: RuntimeError("no auths"),
                functions.langpack.GetLanguagesRequest: RuntimeError("bad pack"),
                functions.help.GetAppUpdateRequest: types.help.AppUpdate(
                    id=1, version="9.9", text="", entities=[]
                ),
                functions.help.GetTermsOfServiceUpdateRequest: RuntimeError("tos down"),
            }
        )
        with pytest.warns(UserWarning, match="opentele2 consistency check issues") as warned:
            report = run(ConsistencyChecker(client).run_all())
        assert [(c.name, c.passed, c.detail) for c in report.checks] == [
            ("get_config", False, "Server rejected getConfig: boom"),
            ("nearest_dc", False, "Error calling getNearestDc: no dc"),
            ("current_session", False, "Error: no auths"),
            (
                "layer_match",
                True,
                f"Telethon layer={advertised}, advertised schema layer={advertised}, diff=0",
            ),
            ("lang_pack", False, "lang_pack 'tdesktop' rejected: bad pack"),
            ("app_update", True, "Update available: v9.9 (but request succeeded)"),
            ("terms_of_service", False, "Error: tos down"),
        ]
        assert str(warned[0].message) == (f"opentele2 consistency check issues:\n{report.summary}")

    def test_missing_session_web_lang_pack_and_raising_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = fake(
            {functions.account.GetAuthorizationsRequest: authorizations()},
            api=API.TelegramWeb_A,
        )
        checker = ConsistencyChecker(client, auto_warn=False)
        missing = run(checker.check_current_session())
        assert (missing.passed, missing.detail) == (False, "Could not retrieve current session")
        web = run(checker.check_lang_pack())
        assert (web.passed, web.detail) == (True, "lang_pack is empty (web client mode)")

        def broken() -> int:
            raise RuntimeError("layer probe failed")

        monkeypatch.setattr(fingerprint, "_detect_telethon_layer", broken)
        report = run(ConsistencyChecker(fake({}), auto_warn=False).run_all())
        layer = report.checks[3]
        assert (layer.name, layer.passed, layer.detail) == (
            "layer_match",
            False,
            "Exception: layer probe failed",
        )
        assert [c.name for c in report.checks] == _native.consistency_checks()
        assert all(not c.passed for c in report.checks[:3])


# ---------------------------------------------------------------- layer


class TestAdvertisedLayer:
    @pytest.mark.parametrize("ref", sorted(SCHEMAS))
    def test_advertised_layer_matches_reference_schema(self, ref: str) -> None:
        api_tl = SCHEMAS[ref]
        if not api_tl.is_file():
            raise pytest.skip.Exception(f"missing {ref} reference checkout: {api_tl}")
        source = api_tl.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"^// LAYER (\d+)", source, re.MULTILINE)
        assert match is not None, "LAYER marker not found in api.tl"
        assert fingerprint.get_advertised_layer() == int(match.group(1))

    def test_installed_telethon_passes_the_layer_check(self) -> None:
        result = _run_layer_check()
        assert result.passed, result.detail


def _run_layer_check() -> CheckResult:
    async def check() -> CheckResult:
        checker = ConsistencyChecker(TelegramClient(), auto_warn=False)
        return await checker.check_layer_match()

    return run(check())


class TestLayerCheck:
    def test_advertised_layer_is_a_standalone_constant(self) -> None:
        assert fingerprint.get_advertised_layer() == fingerprint.LAYER

    def test_layer_check_passes_when_layers_agree(self, monkeypatch: pytest.MonkeyPatch) -> None:
        advertised = fingerprint.get_advertised_layer()
        monkeypatch.setattr(fingerprint, "_detect_telethon_layer", lambda: advertised)

        result = _run_layer_check()
        assert result.passed
        assert "diff=0" in result.detail

    def test_layer_check_reports_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        detected = fingerprint._detect_telethon_layer()
        monkeypatch.setattr(fingerprint, "get_advertised_layer", lambda: detected - 40)

        result = _run_layer_check()
        assert not result.passed
        assert "diff=40" in result.detail
        assert str(detected) in result.detail

    def test_layer_check_uses_detected_telethon_layer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        advertised = fingerprint.get_advertised_layer()
        monkeypatch.setattr(fingerprint, "_detect_telethon_layer", lambda: advertised + 100)

        result = _run_layer_check()
        assert not result.passed
        assert "diff=100" in result.detail

    @pytest.mark.parametrize(("offset", "passed"), [(15, True), (16, False), (-15, True)])
    def test_layer_tolerance_is_fifteen(
        self, monkeypatch: pytest.MonkeyPatch, offset: int, passed: bool
    ) -> None:
        detected = fingerprint.get_advertised_layer() + offset
        monkeypatch.setattr(fingerprint, "_detect_telethon_layer", lambda: detected)
        assert _run_layer_check().passed is passed
