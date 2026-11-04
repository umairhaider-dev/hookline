"""Run threat intelligence lookups for one email and turn matches into indicators."""

import logging
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from hookline.config import ThreatIntelSettings
from hookline.intel.base import IntelProvider
from hookline.intel.errors import IntelLookupError, ProviderUnavailableError, QuotaExceededError
from hookline.intel.observables import collect_observables
from hookline.intel.ratelimit import RateLimiter
from hookline.intel.store import IntelStore, now_utc
from hookline.models.email import ParsedEmail
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity
from hookline.models.intel import (
    MAX_SUMMARY_LENGTH,
    IntelResult,
    IntelRun,
    IntelStatus,
    IntelVerdict,
    Observable,
)

logger = logging.getLogger(__name__)

DEFAULT_PAUSE_SECONDS = 60.0
MAX_REFERENCE_LENGTH = 500
NOTHING_TO_LOOK_UP = (
    "The message has no public URLs, domains, IP addresses or attachments to look up."
)

_FLAGGED = frozenset({IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS})


@dataclass
class _ProviderState:
    lookups: int = 0
    stopped: str | None = None
    skipped: int = 0
    over_budget: int = 0


class ThreatIntel:
    """Looks observables up with every configured provider, using the cache first."""

    def __init__(
        self,
        providers: Sequence[IntelProvider],
        store: IntelStore,
        settings: ThreatIntelSettings,
        *,
        protected_domains: Sequence[str] = (),
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._providers = list(providers)
        self._store = store
        self._settings = settings
        self._protected = tuple(protected_domains)
        self._clock = clock
        self._limiters = {
            provider.name: RateLimiter(
                store, provider.name, provider.limits, clock=clock, sleep=sleep
            )
            for provider in self._providers
        }

    @property
    def provider_names(self) -> tuple[str, ...]:
        """Names of the configured providers, in lookup order."""
        return tuple(provider.name for provider in self._providers)

    def investigate(self, email: ParsedEmail) -> tuple[tuple[Indicator, ...], IntelRun]:
        """Look up the email's observables and return match indicators plus a run record."""
        started = time.perf_counter()
        observables = collect_observables(email, self._settings, self._protected)
        problems = [f"Threat intelligence: {self._store.problem}"] if self._store.problem else []
        if not observables:
            run = IntelRun(
                status=IntelStatus.PARTIAL if problems else IntelStatus.COMPLETED,
                providers=self.provider_names,
                problems=tuple(problems),
                note=NOTHING_TO_LOOK_UP,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
            return (), run

        states = {provider.name: _ProviderState() for provider in self._providers}
        results: list[IntelResult] = []
        for observable in observables:
            for provider in self._providers:
                if observable.kind in provider.kinds:
                    result = self._lookup(provider, observable, states[provider.name], problems)
                    if result is not None:
                        results.append(result)
        problems.extend(self._summarise(states))

        indicators = matches_to_indicators(results)
        logger.info(
            "Threat intelligence: %d answer(s) for %d observable(s), %d match(es)",
            len(results),
            len(observables),
            len(indicators),
        )
        run = IntelRun(
            status=IntelStatus.PARTIAL if problems else IntelStatus.COMPLETED,
            providers=self.provider_names,
            results=tuple(results),
            problems=tuple(problems),
            duration_ms=(time.perf_counter() - started) * 1000,
        )
        return indicators, run

    def close(self) -> None:
        """Close every provider's connection and the store."""
        for provider in self._providers:
            provider.close()
        self._store.close()

    def _lookup(
        self,
        provider: IntelProvider,
        observable: Observable,
        state: _ProviderState,
        problems: list[str],
    ) -> IntelResult | None:
        cached = self._store.cached(provider.name, observable)
        if cached is not None:
            return cached
        if state.stopped is not None:
            state.skipped += 1
            return None
        if state.lookups >= self._settings.max_lookups_per_provider:
            state.over_budget += 1
            return None
        refusal = self._limiters[provider.name].acquire(self._settings.max_wait_seconds)
        if refusal is not None:
            state.stopped = f"{provider.name}: {refusal}"
            state.skipped += 1
            return None

        state.lookups += 1
        try:
            answer = provider.lookup(observable)
        except QuotaExceededError as exc:
            pause = exc.retry_after if exc.retry_after is not None else DEFAULT_PAUSE_SECONDS
            self._store.pause(provider.name, self._clock() + pause)
            state.stopped = str(exc)
            state.skipped += 1
            return None
        except ProviderUnavailableError as exc:
            state.stopped = str(exc)
            state.skipped += 1
            return None
        except IntelLookupError as exc:
            problems.append(f"{observable.kind.value} lookup failed: {exc}")
            return None

        result = IntelResult(
            provider=provider.name,
            observable=observable,
            verdict=answer.verdict,
            summary=answer.summary[:MAX_SUMMARY_LENGTH],
            reference=answer.reference[:MAX_REFERENCE_LENGTH] if answer.reference else None,
            checked_at=now_utc(self._clock),
        )
        self._store.save(result)
        logger.debug("%s: %s %s", provider.name, observable.kind.value, result.verdict.value)
        return result

    def _summarise(self, states: dict[str, _ProviderState]) -> list[str]:
        problems = []
        for name, state in states.items():
            if state.stopped is not None:
                # The lookup that hit the problem is counted among the skipped ones.
                problems.append(f"{state.stopped}; {state.skipped} lookup(s) not made")
            if state.over_budget:
                problems.append(
                    f"{name}: only {self._settings.max_lookups_per_provider} lookups are made "
                    f"per message; {state.over_budget} skipped"
                )
        return problems


def matches_to_indicators(results: Sequence[IntelResult]) -> tuple[Indicator, ...]:
    """One indicator per observable that any provider rated malicious or suspicious."""
    by_observable: defaultdict[Observable, list[IntelResult]] = defaultdict(list)
    for result in results:
        by_observable[result.observable].append(result)

    indicators = []
    for observable, answers in by_observable.items():
        flagged = [answer for answer in answers if answer.verdict in _FLAGGED]
        if not flagged:
            continue
        malicious = any(answer.verdict is IntelVerdict.MALICIOUS for answer in flagged)
        parts = [
            f"{answer.provider} ({answer.verdict.value}): {answer.summary}"
            + (f" See {answer.reference}" if answer.reference else "")
            for answer in flagged
        ]
        clean = [answer.provider for answer in answers if answer.verdict is IntelVerdict.CLEAN]
        if clean:
            parts.append(f"Rated clean by {', '.join(clean)}.")
        indicators.append(
            Indicator(
                type=IndicatorType.THREAT_INTEL_MATCH,
                value=observable.value,
                severity=Severity.CRITICAL if malicious else Severity.MEDIUM,
                evidence=" ".join(parts),
                source=IndicatorSource.THREAT_INTEL,
            )
        )
    return tuple(indicators)
