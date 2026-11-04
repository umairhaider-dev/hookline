"""Runs the analysis stages in order: read, parse, check, look up, assess, score, report."""

import logging
import time
from collections.abc import Sequence
from pathlib import Path
from types import TracebackType
from typing import Self

from hookline.checks import Check, build_checks
from hookline.config import Settings
from hookline.errors import InputError
from hookline.intel import ThreatIntel, build_threat_intel, disabled_reason
from hookline.models.ai import AIRun, AIStatus
from hookline.models.email import ParsedEmail
from hookline.models.indicator import Indicator
from hookline.models.intel import IntelRun, IntelStatus
from hookline.models.report import Report
from hookline.parsing import parse_email
from hookline.scoring import score_indicators

logger = logging.getLogger(__name__)


def read_email_file(path: Path, *, max_bytes: int) -> bytes:
    """Read an email file's raw bytes, enforcing a size limit.

    Raises:
        InputError: If the file is missing, not a regular file, empty, too
            large or unreadable.
    """
    if not path.exists():
        raise InputError(f"File not found: {path}")
    if not path.is_file():
        raise InputError(f"Not a regular file: {path}")
    try:
        with path.open("rb") as handle:
            # Read one byte past the limit so growth after a stat() is still caught.
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        raise InputError(f"Could not read {path}: {exc.strerror or exc}") from exc
    if not raw:
        raise InputError(f"File is empty: {path}")
    if len(raw) > max_bytes:
        raise InputError(
            f"{path} is larger than the {max_bytes:,}-byte limit (see HOOKLINE_MAX_EMAIL_BYTES)"
        )
    return raw


class Analyzer:
    """Analyzes one email at a time using the configured checks.

    Holds network clients when threat intelligence is configured, so close it
    when done, ideally by using it as a context manager.
    """

    def __init__(
        self,
        settings: Settings,
        checks: Sequence[Check] | None = None,
        threat_intel: ThreatIntel | None = None,
    ) -> None:
        self._settings = settings
        self._checks = list(checks) if checks is not None else build_checks(settings.checks)
        self._intel = threat_intel if threat_intel is not None else build_threat_intel(settings)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Release network clients and the threat intelligence cache."""
        if self._intel is not None:
            self._intel.close()

    def analyze_file(self, path: Path) -> Report:
        """Read and analyze an ``.eml`` file."""
        raw = read_email_file(path, max_bytes=self._settings.max_email_bytes)
        return self.analyze_bytes(raw, source_file=path.name)

    def analyze_bytes(self, raw: bytes, *, source_file: str | None = None) -> Report:
        """Analyze raw message bytes and build the report."""
        started = time.perf_counter()
        email = parse_email(raw)
        indicators, warnings = self._run_checks(email)
        intel_indicators, intel_run = self._run_threat_intel(email)
        indicators = _merge(indicators, intel_indicators)
        ai_run = self._run_ai()
        verdict = score_indicators(indicators, self._settings.scoring)
        duration_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Analyzed %s: %s (score %.0f, %d indicators) in %.1f ms",
            source_file or "message",
            verdict.label.value,
            verdict.score,
            len(indicators),
            duration_ms,
        )
        return Report(
            source_file=source_file,
            email=email,
            indicators=indicators,
            threat_intel=intel_run,
            ai=ai_run,
            verdict=verdict,
            warnings=warnings,
            duration_ms=duration_ms,
        )

    def _run_checks(self, email: ParsedEmail) -> tuple[tuple[Indicator, ...], tuple[str, ...]]:
        """Run every check, de-duplicating indicators by id.

        A failing check is logged and reported as a warning instead of aborting
        the whole analysis, so one bug cannot hide the other checks' findings.
        """
        found: dict[str, Indicator] = {}
        warnings: list[str] = []
        for check in self._checks:
            try:
                results = list(check.run(email))
            except Exception as exc:
                # Deliberately broad: a bug in one check must not abort the analysis.
                logger.exception("Check %s failed", check.name)
                warnings.append(f"Check '{check.name}' failed and was skipped: {exc}")
                continue
            for indicator in results:
                found.setdefault(indicator.id, indicator)
        return tuple(found.values()), tuple(warnings)

    def _run_threat_intel(self, email: ParsedEmail) -> tuple[tuple[Indicator, ...], IntelRun]:
        if self._intel is None:
            reason = disabled_reason(self._settings) or "Threat intelligence is not configured."
            return (), IntelRun(status=IntelStatus.DISABLED, note=reason)
        try:
            return self._intel.investigate(email)
        except Exception as exc:
            # Deliberately broad: lookups are optional and must never abort the analysis.
            logger.exception("Threat intelligence failed")
            return (), IntelRun(
                status=IntelStatus.FAILED,
                providers=self._intel.provider_names,
                problems=(f"Threat intelligence failed and was skipped: {exc}",),
            )

    def _run_ai(self) -> AIRun:
        if not self._settings.ai_enabled:
            return AIRun(status=AIStatus.DISABLED)
        return AIRun(
            status=AIStatus.UNAVAILABLE,
            error="no language model provider is configured",
        )


def _merge(first: tuple[Indicator, ...], second: tuple[Indicator, ...]) -> tuple[Indicator, ...]:
    """Combine indicator lists, keeping the first of any duplicates."""
    merged: dict[str, Indicator] = {}
    for indicator in (*first, *second):
        merged.setdefault(indicator.id, indicator)
    return tuple(merged.values())
