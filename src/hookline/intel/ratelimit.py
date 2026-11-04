"""Per-provider rate limiting over a sliding minute and day.

Request times live in the shared store, so separate processes using the same
cache directory respect the same budget. When no slot is free the limiter waits
for one, but never longer than the caller allows.
"""

from collections.abc import Callable

from hookline.config import ProviderLimits
from hookline.intel.store import DAY_SECONDS, IntelStore

MINUTE_SECONDS = 60.0
MIN_SLEEP_SECONDS = 0.05


class RateLimiter:
    """Hands out request slots for one provider."""

    def __init__(
        self,
        store: IntelStore,
        provider: str,
        limits: ProviderLimits,
        *,
        clock: Callable[[], float],
        sleep: Callable[[float], None],
    ) -> None:
        self._store = store
        self._provider = provider
        self._limits = limits
        self._clock = clock
        self._sleep = sleep

    def acquire(self, max_wait: float) -> str | None:
        """Reserve a slot, waiting up to ``max_wait`` seconds for one.

        Returns None once a slot is reserved, or the reason no slot was
        available in time.
        """
        deadline = self._clock() + max_wait
        while True:
            now = self._clock()
            free_at, reason = self._next_free_slot(now)
            if free_at is None:
                self._store.record_request(self._provider, now)
                return None
            if free_at > deadline:
                return reason
            self._sleep(max(free_at - now, MIN_SLEEP_SECONDS))

    def _next_free_slot(self, now: float) -> tuple[float | None, str]:
        paused = self._store.paused_until(self._provider)
        if paused is not None:
            return paused, "the provider asked for a pause"
        per_minute = self._store.request_times(self._provider, now - MINUTE_SECONDS)
        if len(per_minute) >= self._limits.requests_per_minute:
            oldest = per_minute[len(per_minute) - self._limits.requests_per_minute]
            return oldest + MINUTE_SECONDS, "the per-minute request limit was reached"
        per_day_limit = self._limits.requests_per_day
        if per_day_limit is not None:
            per_day = self._store.request_times(self._provider, now - DAY_SECONDS)
            if len(per_day) >= per_day_limit:
                oldest = per_day[len(per_day) - per_day_limit]
                return oldest + DAY_SECONDS, "the daily request limit was reached"
        return None, ""
