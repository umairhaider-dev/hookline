"""Test doubles for the threat intelligence layer."""

from collections.abc import Callable, Sequence
from pathlib import Path

import httpx

from hookline.config import ProviderLimits, ThreatIntelSettings
from hookline.intel import IntelStore, ProviderAnswer, ThreatIntel
from hookline.models import IntelVerdict, Observable, ObservableKind

START = 1_800_000_000.0


class FakeClock:
    """A clock that only moves when told to, or when something sleeps."""

    def __init__(self, now: float = START) -> None:
        self.now = now
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


Behaviour = ProviderAnswer | Exception | Callable[[Observable], ProviderAnswer]

CLEAN = ProviderAnswer(IntelVerdict.CLEAN, "Nothing known.")


class FakeProvider:
    """A provider whose answers are scripted per observable value."""

    def __init__(
        self,
        name: str = "Fake",
        *,
        kinds: Sequence[ObservableKind] = tuple(ObservableKind),
        answers: dict[str, Behaviour] | None = None,
        default: Behaviour = CLEAN,
        limits: ProviderLimits | None = None,
    ) -> None:
        self.name = name
        self.kinds = frozenset(kinds)
        self.limits = limits or ProviderLimits(requests_per_minute=1000)
        self._answers = answers or {}
        self._default = default
        self.calls: list[Observable] = []
        self.closed = False

    def lookup(self, observable: Observable) -> ProviderAnswer:
        self.calls.append(observable)
        behaviour = self._answers.get(observable.value, self._default)
        if isinstance(behaviour, Exception):
            raise behaviour
        if isinstance(behaviour, ProviderAnswer):
            return behaviour
        return behaviour(observable)

    def close(self) -> None:
        self.closed = True


def make_service(
    *providers: FakeProvider,
    clock: FakeClock | None = None,
    cache_dir: Path | None = None,
    protected: Sequence[str] = (),
    **settings: object,
) -> ThreatIntel:
    clock = clock or FakeClock()
    config = ThreatIntelSettings.model_validate(settings)
    store = IntelStore(cache_dir, ttl_seconds=config.cache_ttl_hours * 3600, clock=clock)
    return ThreatIntel(
        providers, store, config, protected_domains=protected, clock=clock, sleep=clock.sleep
    )


def recording_transport(
    handler: Callable[[httpx.Request], httpx.Response],
) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    """A mock transport that keeps every request it receives."""
    requests: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    return httpx.MockTransport(record), requests
