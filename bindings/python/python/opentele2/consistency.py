"""Server-side checks of a connected
:class:`~opentele2.tl.TelegramClient`, with every detail line, summary, pass
rule, session row and the report of :meth:`ConsistencyChecker.run_all` from
:mod:`opentele2._native`."""

from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from . import _native, fingerprint

if TYPE_CHECKING:
    from ._native import CheckOutcome
    from ._native import CheckResult as _NativeCheckResult
    from .tl.telethon import TelegramClient

logger = logging.getLogger(__name__)

__all__ = [
    "CheckResult",
    "ConsistencyChecker",
    "ConsistencyReport",
]


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    server_response: Any = None


def _native_result(result: CheckResult) -> _NativeCheckResult:
    return {"name": result.name, "passed": result.passed, "detail": result.detail}


@dataclass
class ConsistencyReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def summary(self) -> str:
        return _native.consistency_summary([_native_result(c) for c in self.checks])

    def __str__(self) -> str:
        return self.summary


class ConsistencyChecker:
    def __init__(self, client: TelegramClient, *, auto_warn: bool = True) -> None:
        self._client = client
        self._auto_warn = auto_warn

    async def run_all(self) -> ConsistencyReport:
        # In _native.consistency_checks() order; the core names each entry
        # after its place in that order.
        checks = [
            self.check_get_config,
            self.check_nearest_dc,
            self.check_current_session,
            self.check_layer_match,
            self.check_lang_pack,
            self.check_app_update,
            self.check_terms_of_service,
        ]

        server_responses: list[Any] = []
        outcomes: list[CheckOutcome] = []
        for check_fn in checks:
            try:
                result = await check_fn()
            except Exception as e:
                logger.debug("Consistency check raised", exc_info=True)
                server_responses.append(None)
                outcomes.append({"raised": str(e)})
            else:
                server_responses.append(result.server_response)
                outcomes.append({"passed": result.passed, "detail": result.detail})

        native = _native.consistency_report(outcomes)
        report = ConsistencyReport(
            checks=[
                CheckResult(
                    name=entry["name"],
                    passed=entry["passed"],
                    detail=entry["detail"],
                    server_response=server_response,
                )
                for entry, server_response in zip(native["checks"], server_responses)
            ]
        )

        warning = native["warning"]
        if self._auto_warn and warning is not None:
            warnings.warn(warning, stacklevel=2)

        return report

    async def check_get_config(self) -> CheckResult:
        from telethon import functions

        try:
            config = await self._client(functions.help.GetConfigRequest())
            dc_id = getattr(config, "this_dc", None)
            return CheckResult(
                name="get_config",
                passed=True,
                detail=_native.get_config_detail(dc_id),
                server_response=config,
            )
        except Exception as e:
            logger.debug("Consistency check raised", exc_info=True)
            return CheckResult(
                name="get_config",
                passed=False,
                detail=_native.get_config_error(str(e)),
            )

    async def check_nearest_dc(self) -> CheckResult:
        from telethon import functions

        try:
            result = await self._client(functions.help.GetNearestDcRequest())
            return CheckResult(
                name="nearest_dc",
                passed=True,
                detail=_native.nearest_dc_detail(result.country, result.this_dc, result.nearest_dc),
                server_response=result,
            )
        except Exception as e:
            logger.debug("Consistency check raised", exc_info=True)
            return CheckResult(
                name="nearest_dc",
                passed=False,
                detail=_native.nearest_dc_error(str(e)),
            )

    async def check_current_session(self) -> CheckResult:
        try:
            auth = await self._client.GetCurrentSession()
            if auth is None:
                return CheckResult(
                    name="current_session",
                    passed=False,
                    detail=_native.CURRENT_SESSION_MISSING,
                )

            row = _native.session_row(auth)
            return CheckResult(
                name="current_session",
                passed=row.get("official_app", False),
                detail=_native.current_session_detail(row),
                server_response=auth,
            )
        except Exception as e:
            logger.debug("Consistency check raised", exc_info=True)
            return CheckResult(
                name="current_session",
                passed=False,
                detail=_native.check_error(str(e)),
            )

    async def check_layer_match(self) -> CheckResult:
        result = _native.layer_result(
            fingerprint._detect_telethon_layer(), fingerprint.get_advertised_layer()
        )
        return CheckResult(name=result["name"], passed=result["passed"], detail=result["detail"])

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
                detail=_native.LANG_PACK_EMPTY,
            )

        try:
            languages = await self._client(
                functions.langpack.GetLanguagesRequest(lang_pack=lang_pack)
            )
            return CheckResult(
                name="lang_pack",
                passed=True,
                detail=_native.lang_pack_detail(lang_pack, len(languages)),
                server_response=languages,
            )
        except Exception as e:
            logger.debug("Consistency check raised", exc_info=True)
            return CheckResult(
                name="lang_pack",
                passed=False,
                detail=_native.lang_pack_error(lang_pack, str(e)),
            )

    async def check_app_update(self) -> CheckResult:
        from telethon import functions, types

        try:
            result = await self._client(functions.help.GetAppUpdateRequest(source=""))
            if isinstance(result, types.help.NoAppUpdate):
                return CheckResult(
                    name="app_update",
                    passed=True,
                    detail=_native.NO_APP_UPDATE,
                    server_response=result,
                )
            version = getattr(result, "version", None)
            return CheckResult(
                name="app_update",
                passed=True,
                detail=_native.app_update_detail(None if version is None else str(version)),
                server_response=result,
            )
        except Exception as e:
            logger.debug("Consistency check raised", exc_info=True)
            return CheckResult(
                name="app_update",
                passed=False,
                detail=_native.app_update_error(str(e)),
            )

    async def check_terms_of_service(self) -> CheckResult:
        from telethon import functions

        try:
            result = await self._client(functions.help.GetTermsOfServiceUpdateRequest())
            return CheckResult(
                name="terms_of_service",
                passed=True,
                detail=_native.TERMS_OF_SERVICE_OK,
                server_response=result,
            )
        except Exception as e:
            logger.debug("Consistency check raised", exc_info=True)
            return CheckResult(
                name="terms_of_service",
                passed=False,
                detail=_native.check_error(str(e)),
            )
