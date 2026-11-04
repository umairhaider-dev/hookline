import sqlite3
from pathlib import Path

import pytest

from hookline.config import ProviderLimits
from hookline.intel import IntelStore
from hookline.intel.ratelimit import RateLimiter
from hookline.intel.store import DATABASE_NAME, DAY_SECONDS, now_utc
from hookline.models import IntelResult, IntelVerdict, Observable, ObservableKind
from tests.intel_helpers import FakeClock

OBSERVABLE = Observable(kind=ObservableKind.DOMAIN, value="example.net")


def result(clock: FakeClock, provider: str = "Fake") -> IntelResult:
    return IntelResult(
        provider=provider,
        observable=OBSERVABLE,
        verdict=IntelVerdict.CLEAN,
        summary="Nothing known.",
        checked_at=now_utc(clock),
    )


def store_at(path: Path | None, clock: FakeClock, ttl: float = 3600) -> IntelStore:
    return IntelStore(path, ttl_seconds=ttl, clock=clock)


def test_results_are_cached_until_they_expire(tmp_path: Path) -> None:
    clock = FakeClock()
    store = store_at(tmp_path / "cache", clock)
    assert store.cached("Fake", OBSERVABLE) is None
    store.save(result(clock))
    cached = store.cached("Fake", OBSERVABLE)
    assert cached is not None
    assert cached.from_cache
    assert store.cached("Other", OBSERVABLE) is None
    clock.now += 3601
    assert store.cached("Fake", OBSERVABLE) is None
    store.close()
    assert (tmp_path / "cache" / DATABASE_NAME).is_file()


def test_cache_survives_between_instances(tmp_path: Path) -> None:
    clock = FakeClock()
    first = store_at(tmp_path, clock)
    first.save(result(clock))
    first.record_request("Fake", clock.now)
    first.close()
    second = store_at(tmp_path, clock)
    assert second.cached("Fake", OBSERVABLE) is not None
    assert second.request_times("Fake", clock.now - 60) == [clock.now]
    assert second.request_times("Fake", clock.now) == []
    second.close()


def test_zero_ttl_turns_the_cache_off() -> None:
    clock = FakeClock()
    store = store_at(None, clock, ttl=0)
    store.save(result(clock))
    assert store.cached("Fake", OBSERVABLE) is None
    store.close()


def test_unreadable_cache_entry_is_ignored(tmp_path: Path) -> None:
    clock = FakeClock()
    store = store_at(tmp_path, clock)
    store.save(result(clock))
    store.close()
    with sqlite3.connect(tmp_path / DATABASE_NAME) as connection:
        connection.execute("UPDATE results SET body = 'not json'")
    connection.close()
    reopened = store_at(tmp_path, clock)
    assert reopened.cached("Fake", OBSERVABLE) is None
    reopened.close()


def test_request_log_is_pruned_after_a_day() -> None:
    clock = FakeClock()
    store = store_at(None, clock)
    store.record_request("Fake", clock.now)
    store.record_request("Fake", clock.now + DAY_SECONDS + 1)
    assert store.request_times("Fake", 0) == [clock.now + DAY_SECONDS + 1]
    store.close()


def test_pauses_expire() -> None:
    clock = FakeClock()
    store = store_at(None, clock)
    assert store.paused_until("Fake") is None
    store.pause("Fake", clock.now + 30)
    assert store.paused_until("Fake") == clock.now + 30
    clock.now += 31
    assert store.paused_until("Fake") is None
    store.close()


def test_unusable_directory_falls_back_to_memory(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    clock = FakeClock()
    store = store_at(blocker / "cache", clock)
    assert store.problem is not None
    assert "could not be used" in store.problem
    store.save(result(clock))
    assert store.cached("Fake", OBSERVABLE) is not None
    store.close()


def test_corrupt_database_falls_back_to_memory(tmp_path: Path) -> None:
    (tmp_path / DATABASE_NAME).write_bytes(b"this is not a database" * 100)
    store = store_at(tmp_path, FakeClock())
    assert store.problem is not None
    store.close()


def test_database_errors_are_logged_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    clock = FakeClock()
    store = store_at(None, clock)
    store.close()
    store.save(result(clock))
    assert store.cached("Fake", OBSERVABLE) is None
    assert "cache write failed" in caplog.text
    assert "cache read failed" in caplog.text


# --- rate limiting ------------------------------------------------------------


def limiter(
    clock: FakeClock, per_minute: int = 2, per_day: int | None = None
) -> tuple[RateLimiter, IntelStore]:
    store = store_at(None, clock)
    limits = ProviderLimits(requests_per_minute=per_minute, requests_per_day=per_day)
    return RateLimiter(store, "Fake", limits, clock=clock, sleep=clock.sleep), store


def test_slots_are_handed_out_until_the_minute_is_full() -> None:
    clock = FakeClock()
    rate, store = limiter(clock)
    assert rate.acquire(max_wait=0) is None
    assert rate.acquire(max_wait=0) is None
    assert rate.acquire(max_wait=0) == "the per-minute request limit was reached"
    assert clock.slept == []
    store.close()


def test_waits_for_a_slot_when_allowed() -> None:
    clock = FakeClock()
    rate, store = limiter(clock)
    rate.acquire(max_wait=0)
    clock.now += 10
    rate.acquire(max_wait=0)
    assert rate.acquire(max_wait=60) is None
    assert clock.slept == [50]
    store.close()


def test_daily_limit() -> None:
    clock = FakeClock()
    rate, store = limiter(clock, per_minute=100, per_day=2)
    rate.acquire(max_wait=0)
    clock.now += 3600
    rate.acquire(max_wait=0)
    assert rate.acquire(max_wait=600) == "the daily request limit was reached"
    store.close()


def test_provider_pause_is_respected() -> None:
    clock = FakeClock()
    rate, store = limiter(clock)
    store.pause("Fake", clock.now + 120)
    assert rate.acquire(max_wait=60) == "the provider asked for a pause"
    assert rate.acquire(max_wait=130) is None
    assert clock.slept == [120]
    store.close()
