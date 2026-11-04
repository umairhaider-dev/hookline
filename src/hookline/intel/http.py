"""Shared HTTP handling for the providers.

Every failure is turned into one of the errors in :mod:`hookline.intel.errors`
with a message that is safe to show: API keys travel in headers and never
appear in these messages.
"""

import logging
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from hookline import __version__
from hookline.intel.errors import IntelLookupError, ProviderUnavailableError, QuotaExceededError

logger = logging.getLogger(__name__)

USER_AGENT = f"hookline/{__version__}"

ModelT = TypeVar("ModelT", bound=BaseModel)


def build_client(
    *,
    base_url: str,
    headers: dict[str, str],
    timeout: float,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    """Create a client for one provider.

    Redirects are not followed, and proxy settings from the environment are
    honoured so the tool works behind a corporate proxy.
    """
    return httpx.Client(
        base_url=base_url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json", **headers},
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        transport=transport,
    )


def send(client: httpx.Client, provider: str, request: httpx.Request) -> httpx.Response:
    """Send ``request`` and map transport errors and refusals to lookup errors.

    Returns successful and 404 responses; callers decide what 404 means.
    """
    try:
        response = client.send(request)
    except httpx.TimeoutException as exc:
        raise ProviderUnavailableError(f"{provider} did not answer in time") from exc
    except httpx.TransportError as exc:
        raise ProviderUnavailableError(
            f"could not reach {provider} ({type(exc).__name__})"
        ) from exc
    status = response.status_code
    logger.debug("%s answered %d for %s %s", provider, status, request.method, request.url.path)
    if status in {401, 403}:
        raise ProviderUnavailableError(f"{provider} rejected the API key (HTTP {status})")
    if status == 429:
        raise QuotaExceededError(
            f"{provider} reported that its rate limit or quota was reached",
            retry_after=_retry_after(response),
        )
    if status == 404 or 200 <= status < 300:
        return response
    if status >= 500:
        raise IntelLookupError(f"{provider} had a server error (HTTP {status})")
    raise IntelLookupError(f"{provider} refused the request (HTTP {status})")


def parse_json(response: httpx.Response, model: type[ModelT], provider: str) -> ModelT:
    """Validate a JSON response body against ``model``."""
    try:
        data: Any = response.json()
        return model.model_validate(data)
    except (ValueError, ValidationError) as exc:
        raise IntelLookupError(f"{provider} sent a response in an unexpected format") from exc


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After", "")
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if seconds >= 0 else None
