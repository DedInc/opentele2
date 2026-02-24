from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Any, List

__all__ = [
    "ConsistencyChecker",
    "ConsistencyReport",
    "CheckResult",
]


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    server_response: Any = None


@dataclass
class ConsistencyReport:
    checks: List[CheckResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def summary(self) -> str:
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c.passed)
        lines = [f"Consistency: {passed}/{total} checks passed"]
        for c in self.checks:
            status = "OK" if c.passed else "FAIL"
            lines.append(f"  [{status}] {c.name}: {c.detail}")
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.summary


class ConsistencyChecker:
    def __init__(self, client, *, auto_warn: bool = True):
        self._client = client
        self._auto_warn = auto_warn

    async def run_all(self) -> ConsistencyReport:
        report = ConsistencyReport()

        checks = [
            self.check_get_config,
            self.check_nearest_dc,
            self.check_current_session,
            self.check_layer_match,
            self.check_lang_pack,
            self.check_app_update,
            self.check_terms_of_service,
        ]

        for check_fn in checks:
            try:
                result = await check_fn()
                report.checks.append(result)
            except Exception as e:
                report.checks.append(
                    CheckResult(
                        name=check_fn.__name__.replace("check_", ""),
                        passed=False,
                        detail=f"Exception: {e}",
                    )
                )

        if self._auto_warn and not report.all_passed:
            warnings.warn(
                f"opentele2 consistency check issues:\n{report.summary}",
                stacklevel=2,
            )

        return report

    async def check_get_config(self) -> CheckResult:
        from telethon import functions

        try:
            config = await self._client(functions.help.GetConfigRequest())
            dc_id = getattr(config, "this_dc", None)
            return CheckResult(
                name="get_config",
                passed=True,
                detail=f"Config OK (DC {dc_id})",
                server_response=config,
            )
        except Exception as e:
            return CheckResult(
                name="get_config",
                passed=False,
                detail=f"Server rejected getConfig: {e}",
            )

    async def check_nearest_dc(self) -> CheckResult:
        from telethon import functions

        try:
            result = await self._client(functions.help.GetNearestDcRequest())
            return CheckResult(
                name="nearest_dc",
                passed=True,
                detail=(
                    f"country='{result.country}', "
                    f"this_dc={result.this_dc}, "
                    f"nearest_dc={result.nearest_dc}"
                ),
                server_response=result,
            )
        except Exception as e:
            return CheckResult(
                name="nearest_dc",
                passed=False,
                detail=f"Error calling getNearestDc: {e}",
            )

    async def check_current_session(self) -> CheckResult:
        try:
            auth = await self._client.GetCurrentSession()
            if auth is None:
                return CheckResult(
                    name="current_session",
                    passed=False,
                    detail="Could not retrieve current session",
                )

            is_official = bool(auth.official_app)
            detail = (
                f"api_id={auth.api_id}, official={is_official}, "
                f"device='{auth.device_model}', "
                f"app='{auth.app_name} {auth.app_version}'"
            )
            return CheckResult(
                name="current_session",
                passed=is_official,
                detail=detail,
                server_response=auth,
            )
        except Exception as e:
            return CheckResult(
                name="current_session",
                passed=False,
                detail=f"Error: {e}",
            )

    async def check_layer_match(self) -> CheckResult:
        from .fingerprint import LAYER, _detect_telethon_layer

        telethon_layer = _detect_telethon_layer()
        diff = abs(telethon_layer - LAYER)

        passed = diff <= 15
        detail = (
            f"Telethon layer={telethon_layer}, "
            f"official schema layer={LAYER}, "
            f"diff={diff}"
        )
        return CheckResult(name="layer_match", passed=passed, detail=detail)

    def _get_sender_lang_pack(self) -> str:
        init_req = getattr(self._client, "_init_request", None)
        if init_req is not None:
            lp = getattr(init_req, "lang_pack", "")
            if lp:
                return lp
        sender = getattr(self._client, "_sender", None)
        if sender is None:
            return ""
        init_req = getattr(sender, "_init_request", None)
        if init_req is None:
            return ""
        return getattr(init_req, "lang_pack", "")

    async def check_lang_pack(self) -> CheckResult:
        from telethon import functions

        lang_pack = self._get_sender_lang_pack()

        if not lang_pack:
            return CheckResult(
                name="lang_pack",
                passed=True,
                detail="lang_pack is empty (web client mode)",
            )

        try:
            languages = await self._client(
                functions.langpack.GetLanguagesRequest(lang_pack=lang_pack)
            )
            return CheckResult(
                name="lang_pack",
                passed=True,
                detail=f"lang_pack '{lang_pack}' valid ({len(languages)} languages)",
                server_response=languages,
            )
        except Exception as e:
            return CheckResult(
                name="lang_pack",
                passed=False,
                detail=f"lang_pack '{lang_pack}' rejected: {e}",
            )

    async def check_app_update(self) -> CheckResult:
        from telethon import functions, types

        try:
            result = await self._client(functions.help.GetAppUpdateRequest(source=""))
            if isinstance(result, types.help.NoAppUpdate):
                return CheckResult(
                    name="app_update",
                    passed=True,
                    detail="No update available (app_version accepted)",
                    server_response=result,
                )
            else:
                version = getattr(result, "version", "?")
                return CheckResult(
                    name="app_update",
                    passed=True,
                    detail=f"Update available: v{version} (but request succeeded)",
                    server_response=result,
                )
        except Exception as e:
            return CheckResult(
                name="app_update",
                passed=False,
                detail=f"Error calling getAppUpdate: {e}",
            )

    async def check_terms_of_service(self) -> CheckResult:
        from telethon import functions

        try:
            result = await self._client(functions.help.GetTermsOfServiceUpdateRequest())
            return CheckResult(
                name="terms_of_service",
                passed=True,
                detail="ToS check OK",
                server_response=result,
            )
        except Exception as e:
            return CheckResult(
                name="terms_of_service",
                passed=False,
                detail=f"Error: {e}",
            )
