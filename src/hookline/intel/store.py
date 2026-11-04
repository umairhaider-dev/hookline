"""Local SQLite store for lookup results and the request log used for rate limiting.

Results are keyed by a hash of provider, kind and value. The store is shared
by every process using the same cache directory, so rate limits hold across
separate CLI runs. Problems with the database never stop an analysis: the
store falls back to memory and reports why.
"""

import hashlib
import logging
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from hookline.models.intel import IntelResult, Observable

logger = logging.getLogger(__name__)

DATABASE_NAME = "intel.sqlite3"
DAY_SECONDS = 86_400.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    key TEXT PRIMARY KEY, stored_at REAL NOT NULL, body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (provider TEXT NOT NULL, at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS requests_by_provider ON requests (provider, at);
CREATE TABLE IF NOT EXISTS pauses (provider TEXT PRIMARY KEY, until REAL NOT NULL);
"""


class IntelStore:
    """Cached lookup results, recent request times and provider-requested pauses."""

    def __init__(
        self,
        directory: Path | None,
        *,
        ttl_seconds: float,
        clock: Callable[[], float],
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self.problem: str | None = None
        self._connection = self._open(directory)

    def _open(self, directory: Path | None) -> sqlite3.Connection:
        if directory is not None:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                connection = sqlite3.connect(
                    directory / DATABASE_NAME, timeout=5, check_same_thread=False
                )
                try:
                    connection.executescript(_SCHEMA)
                except sqlite3.Error:
                    connection.close()
                    raise
            except (OSError, sqlite3.Error) as exc:
                logger.warning("Threat intelligence cache unavailable: %s", exc)
                self.problem = f"the cache in {directory} could not be used ({exc})"
            else:
                return connection
        connection = sqlite3.connect(":memory:", check_same_thread=False)
        connection.executescript(_SCHEMA)
        return connection

    def close(self) -> None:
        """Close the database."""
        with self._lock:
            self._connection.close()

    # --- cached results -------------------------------------------------------

    def cached(self, provider: str, observable: Observable) -> IntelResult | None:
        """Return a stored, unexpired answer, marked as coming from the cache."""
        if self._ttl <= 0:
            return None
        row = self._fetch_one(
            "SELECT body FROM results WHERE key = ? AND stored_at >= ?",
            (_key(provider, observable), self._clock() - self._ttl),
        )
        if row is None:
            return None
        try:
            result = IntelResult.model_validate_json(row[0])
        except ValidationError:
            logger.debug("Ignoring unreadable cache entry for %s", provider)
            return None
        return result.model_copy(update={"from_cache": True})

    def save(self, result: IntelResult) -> None:
        """Store an answer for later runs."""
        if self._ttl <= 0:
            return
        self._execute(
            "INSERT OR REPLACE INTO results (key, stored_at, body) VALUES (?, ?, ?)",
            (_key(result.provider, result.observable), self._clock(), result.model_dump_json()),
        )

    # --- rate limiting --------------------------------------------------------

    def record_request(self, provider: str, at: float) -> None:
        """Log one request and forget requests older than a day."""
        self._execute("INSERT INTO requests (provider, at) VALUES (?, ?)", (provider, at))
        self._execute("DELETE FROM requests WHERE at < ?", (at - DAY_SECONDS,))

    def request_times(self, provider: str, since: float) -> list[float]:
        """Times of requests to ``provider`` after ``since``, oldest first."""
        rows = self._fetch_all(
            "SELECT at FROM requests WHERE provider = ? AND at > ? ORDER BY at",
            (provider, since),
        )
        return [float(row[0]) for row in rows]

    def pause(self, provider: str, until: float) -> None:
        """Remember that ``provider`` asked not to be called before ``until``."""
        self._execute(
            "INSERT OR REPLACE INTO pauses (provider, until) VALUES (?, ?)", (provider, until)
        )

    def paused_until(self, provider: str) -> float | None:
        """When a pause requested by ``provider`` ends, if one is active."""
        row = self._fetch_one("SELECT until FROM pauses WHERE provider = ?", (provider,))
        if row is None or float(row[0]) <= self._clock():
            return None
        return float(row[0])

    # --- database access ------------------------------------------------------

    def _execute(self, sql: str, parameters: tuple[object, ...]) -> None:
        with self._lock:
            try:
                with self._connection:
                    self._connection.execute(sql, parameters)
            except sqlite3.Error as exc:
                logger.warning("Threat intelligence cache write failed: %s", exc)

    def _fetch_one(self, sql: str, parameters: tuple[object, ...]) -> tuple[Any, ...] | None:
        rows = self._fetch_all(sql, parameters)
        return rows[0] if rows else None

    def _fetch_all(self, sql: str, parameters: tuple[object, ...]) -> list[tuple[Any, ...]]:
        with self._lock:
            try:
                return list(self._connection.execute(sql, parameters).fetchall())
            except sqlite3.Error as exc:
                logger.warning("Threat intelligence cache read failed: %s", exc)
                return []


def now_utc(clock: Callable[[], float]) -> datetime:
    """The clock's current time as an aware UTC datetime."""
    return datetime.fromtimestamp(clock(), UTC)


def _key(provider: str, observable: Observable) -> str:
    raw = f"{provider}|{observable.kind.value}|{observable.value}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
