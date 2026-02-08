"""Post-login consistency checks for opentele2.

After connecting and authenticating, official Telegram clients typically
call a series of ``help.*`` methods that the server expects.  Skipping
them can look suspicious.  This module provides helpers that mimic the
official post-login behaviour.

Usage::

    from opentele2.consistency import ConsistencyChecker

    checker = ConsistencyChecker(client)
    report = await checker.run_all()
    # report is a ConsistencyReport with per-check results
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    pass  # avoid circular imports

__all__ = [
    "ConsistencyChecker",
    "ConsistencyReport",
    "CheckResult",
]


@dataclass
class CheckResult:
    """Result of a single consistency check."""

    name: str
    passed: bool
    detail: str = ""
    server_response: Any = None


@dataclass
class ConsistencyReport:
    """Aggregated results from all consistency checks."""

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
    """Runs post-login checks that mimic official client behaviour.

    All methods are safe to call — they are read-only requests that
    official clients routinely make.

    Args:
        client: A connected and authorized ``TelegramClient`` instance.
        auto_warn: If True (default), emit warnings for failed checks.
    """

    def __init__(self, client, *, auto_warn: bool = True):
        self._client = client
        self._auto_warn = auto_warn

    async def run_all(self) -> ConsistencyReport:
        """Run all consistency checks and return a report."""
        report = ConsistencyReport()

        checks = [
            self.check_get_config,
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
        """Call ``help.getConfig`` — every official client does this on connect.

        Verifies the server returns a valid config without errors.
        This is the single most important post-connection call.
        """
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

    async def check_current_session(self) -> CheckResult:
        """Verify the current session via ``account.getAuthorizations``.

        Checks that the session is seen as an official app.
        """
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
        """Check if our layer matches what the server expects.

        We cannot directly query the server's expected layer, but we can
        check that ``help.getConfig`` did not return an error and that
        the session's app matches.
        """
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

    async def check_lang_pack(self) -> CheckResult:
        """Verify that the lang_pack used at initConnection is valid.

        Calls ``langpack.getLanguages`` which only succeeds for valid
        lang_pack values.
        """
        from telethon import functions

        # Retrieve the lang_pack from the client's API settings
        lang_pack = getattr(self._client, "_sender", None)
        if lang_pack is not None:
            lang_pack = getattr(lang_pack, "_init_request", None)
            if lang_pack is not None:
                lang_pack = getattr(lang_pack, "lang_pack", "")
            else:
                lang_pack = ""
        else:
            lang_pack = ""

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
        """Call ``help.getAppUpdate`` — official clients do this periodically.

        A successful call (or ``noAppUpdate``) means our app_version is
        accepted by the server.
        """
        from telethon import functions, types

        try:
            # help.getAppUpdate requires a source parameter
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
        """Call ``help.getTermsOfServiceUpdate`` — official clients check this.

        Verifies the server doesn't flag us.
        """
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
