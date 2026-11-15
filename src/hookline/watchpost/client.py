"""HTTP client for Watchpost's ingest API.

Authentication matches the other Watchpost integrations: ``WATCHPOST_TOKEN``
(a bearer token from ``POST /api/auth/token``), or ``WATCHPOST_USERNAME`` and
``WATCHPOST_PASSWORD``, which are exchanged for a token and exchanged again
once if it expires during a push. The Watchpost user needs the analyst or
admin role. Connection errors and 429/502/503/504 answers are retried with
backoff, honouring ``Retry-After``.
"""

import logging
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self

import httpx

from hookline import __version__
from hookline.config import Settings, WatchpostSettings
from hookline.errors import HooklineError

logger = logging.getLogger(__name__)

URL_ENV = "WATCHPOST_URL"
TOKEN_PATH = "/api/auth/token"  # noqa: S105 - a URL path, not a secret
UPLOAD_PATH = "/api/ingest/uploads"
JOB_PATH = "/api/ingest/jobs/{job_id}"
PARSER = "json"
RETRY_STATUSES = frozenset({429, 502, 503, 504})
BACKOFF_SECONDS = 1.0
FINISHED_JOB_STATES = frozenset({"completed", "failed"})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class WatchpostError(HooklineError):
    """Watchpost could not be reached or refused the request."""


@dataclass(frozen=True)
class Credentials:
    """How to authenticate: a token, or a username and password to exchange for one."""

    token: str | None = None
    username: str | None = None
    password: str | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> "Credentials":
        """Read credentials from the environment-backed settings."""
        return cls(
            token=settings.watchpost_token.get_secret_value() if settings.watchpost_token else None,
            username=settings.watchpost_username,
            password=(
                settings.watchpost_password.get_secret_value()
                if settings.watchpost_password
                else None
            ),
        )

    @property
    def can_sign_in(self) -> bool:
        """Whether a fresh token can be obtained."""
        return bool(self.username and self.password)

    @property
    def usable(self) -> bool:
        """Whether there is any way to authenticate."""
        return bool(self.token) or self.can_sign_in


def resolve_url(explicit: str | None, settings: Settings) -> str:
    """The Watchpost URL: ``--url``, then ``WATCHPOST_URL`` (environment or .env), then config."""
    url = explicit or settings.watchpost_url or settings.watchpost.url
    if not url:
        raise WatchpostError(
            f"No Watchpost URL: pass --url, set {URL_ENV} or set url in [watchpost]"
        )
    if not url.startswith(("http://", "https://")):
        raise WatchpostError(f"The Watchpost URL must start with http:// or https://: {url}")
    if url.startswith("http://") and httpx.URL(url).host not in _LOOPBACK_HOSTS:
        logger.warning(
            "Sending to Watchpost over plain HTTP: the token is not encrypted in transit"
        )
    return url.rstrip("/")


def tls_verification(settings: WatchpostSettings) -> bool | ssl.SSLContext:
    """Certificate verification: the default CAs, a private CA bundle, or none."""
    if settings.ca_bundle is not None:
        try:
            return ssl.create_default_context(cafile=str(settings.ca_bundle))
        except (OSError, ssl.SSLError) as exc:
            raise WatchpostError(f"Cannot load CA bundle {settings.ca_bundle}: {exc}") from exc
    return settings.verify_tls


class WatchpostClient:
    """Uploads event files to Watchpost and reads back the ingestion job."""

    def __init__(
        self,
        base_url: str,
        credentials: Credentials,
        *,
        timeout: float = 30.0,
        max_retries: int = 2,
        verify: bool | ssl.SSLContext = True,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not credentials.usable:
            raise WatchpostError(
                "No Watchpost credentials: set WATCHPOST_TOKEN, or WATCHPOST_USERNAME and "
                "WATCHPOST_PASSWORD"
            )
        self._credentials = credentials
        self._token = credentials.token
        self._max_retries = max_retries
        self._sleep = sleep
        self._client = httpx.Client(
            base_url=base_url,
            timeout=httpx.Timeout(timeout),
            verify=verify,
            follow_redirects=False,
            headers={"User-Agent": f"hookline/{__version__}", "Accept": "application/json"},
            transport=transport,
        )

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
        """Close the HTTP client."""
        self._client.close()

    def upload(self, content: bytes, *, filename: str, host_name: str) -> dict[str, Any]:
        """Upload a JSON lines file for ingestion and return the queued job."""
        response = self._authorized(
            "POST",
            UPLOAD_PATH,
            files={"file": (filename, content, "application/x-ndjson")},
            data={"parser": PARSER, "host_name": host_name},
        )
        return _json(response)

    def job(self, job_id: int) -> dict[str, Any]:
        """The current state of an ingestion job."""
        return _json(self._authorized("GET", JOB_PATH.format(job_id=job_id)))

    def wait_for_job(
        self, job_id: int, *, timeout: float = 60.0, interval: float = 2.0
    ) -> dict[str, Any]:
        """Poll the job until it finishes or ``timeout`` seconds pass; returns its last state."""
        waited = 0.0
        while True:
            state = self.job(job_id)
            if state.get("status") in FINISHED_JOB_STATES or waited >= timeout:
                return state
            self._sleep(interval)
            waited += interval

    def _authorized(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        if self._token is None:
            self._token = self._sign_in()
        response = self._send(method, path, headers=self._auth_header(), **kwargs)
        if response.status_code == 401 and self._credentials.can_sign_in:
            logger.info("Watchpost token rejected; signing in again")
            self._token = self._sign_in()
            response = self._send(method, path, headers=self._auth_header(), **kwargs)
        self._check(response)
        return response

    def _auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def _sign_in(self) -> str:
        form = {
            "username": self._credentials.username or "",
            "password": self._credentials.password or "",
        }
        response = self._send("POST", TOKEN_PATH, data=form)
        if response.status_code in {400, 401}:
            raise WatchpostError("Watchpost rejected the username or password")
        self._check(response)
        token = _json(response).get("access_token")
        if not isinstance(token, str) or not token:
            raise WatchpostError("Watchpost's sign-in answer contained no token")
        return token

    def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        attempt = 0
        while True:
            try:
                response = self._client.request(method, path, **kwargs)
            except httpx.TransportError as exc:
                if attempt >= self._max_retries:
                    raise WatchpostError(f"Could not reach Watchpost: {exc}") from exc
                delay = BACKOFF_SECONDS * 2**attempt
                logger.warning("Request to Watchpost failed (%s); retrying in %.1fs", exc, delay)
            else:
                if response.status_code not in RETRY_STATUSES or attempt >= self._max_retries:
                    return response
                delay = _retry_after(response) or BACKOFF_SECONDS * 2**attempt
                logger.warning(
                    "Watchpost answered %d; retrying in %.1fs", response.status_code, delay
                )
            self._sleep(delay)
            attempt += 1

    def _check(self, response: httpx.Response) -> None:
        code = response.status_code
        if code < 400:
            return
        detail = _detail(response)
        messages = {
            401: "Watchpost rejected the token",
            403: "the Watchpost user needs the analyst or admin role",
            413: "the upload is larger than Watchpost's limit",
            415: "Watchpost did not accept the file type",
            422: "Watchpost rejected the request",
        }
        reason = messages.get(code, f"Watchpost answered HTTP {code}")
        raise WatchpostError(f"{reason}{f': {detail}' if detail else ''}")


def _retry_after(response: httpx.Response) -> float | None:
    try:
        seconds = float(response.headers.get("Retry-After", ""))
    except ValueError:
        return None
    return seconds if seconds >= 0 else None


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError as exc:
        raise WatchpostError("Watchpost sent a response that is not JSON") from exc
    if not isinstance(data, dict):
        raise WatchpostError("Watchpost sent an unexpected response")
    return data


def _detail(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return ""
    detail = data.get("detail") if isinstance(data, dict) else None
    return str(detail)[:300] if detail else ""
