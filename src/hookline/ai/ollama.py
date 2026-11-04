"""Local language model through Ollama's chat API (https://ollama.com).

The email never leaves the machine. Requests ask for JSON matching the output
schema, at temperature 0, with an explicit context window so long prompts are
not silently cut.
"""

import logging
import time
from collections.abc import Callable
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from hookline.ai.base import ModelError, ModelRequest, ModelUnavailableError

logger = logging.getLogger(__name__)

NAME = "ollama"
BACKOFF_SECONDS = 1.0
# A local server accepts connections in microseconds. Without a short connect
# timeout, Windows spends several seconds retrying a refused loopback
# connection on every run when Ollama is not started.
LOCAL_CONNECT_TIMEOUT = 0.3
REMOTE_CONNECT_TIMEOUT = 10.0
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


class _Message(BaseModel):
    model_config = ConfigDict(extra="ignore")

    content: str = ""


class _ChatResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    message: _Message
    done_reason: str | None = None


class _TransientError(Exception):
    """A failure worth retrying: a timeout or a server error."""


class OllamaProvider:
    """Talks to a local or self-hosted Ollama server."""

    name = NAME
    is_cloud = False

    def __init__(
        self,
        *,
        url: str,
        model: str,
        timeout: float,
        max_retries: int,
        num_ctx: int,
        max_output_tokens: int,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.model = model
        self._url = url
        self._max_retries = max_retries
        self._options = {"temperature": 0, "num_ctx": num_ctx, "num_predict": max_output_tokens}
        self._sleep = sleep
        local = httpx.URL(url).host in _LOOPBACK_HOSTS
        connect = LOCAL_CONNECT_TIMEOUT if local else REMOTE_CONNECT_TIMEOUT
        self._client = httpx.Client(
            base_url=url,
            timeout=httpx.Timeout(timeout, connect=min(connect, timeout)),
            # TLS settings only apply to https URLs; skipping the CA bundle for
            # plain http saves about half a second per run.
            verify=url.startswith("https://"),
            transport=transport,
        )

    def complete(self, request: ModelRequest) -> str:
        """Send one chat request, retrying timeouts and server errors with backoff."""
        body = {
            "model": self.model,
            "stream": False,
            "format": request.schema or "json",
            "options": self._options,
            "messages": [
                {"role": "system", "content": request.system},
                *({"role": turn.role, "content": turn.text} for turn in request.turns),
            ],
        }
        attempt = 0
        while True:
            try:
                return self._send(body)
            except _TransientError as exc:
                if attempt >= self._max_retries:
                    raise ModelUnavailableError(str(exc)) from exc
                delay = BACKOFF_SECONDS * 2**attempt
                logger.info("Ollama: %s; retrying in %.0f s", exc, delay)
                self._sleep(delay)
                attempt += 1

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def _send(self, body: dict[str, Any]) -> str:
        try:
            response = self._client.post("/api/chat", json=body)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # Nothing listening: retrying will not help, so fail fast.
            raise ModelUnavailableError(
                f"Ollama is not reachable at {self._url} (is it running? try 'ollama serve')"
            ) from exc
        except httpx.TimeoutException as exc:
            raise _TransientError("Ollama did not answer in time") from exc
        except httpx.TransportError as exc:
            problem = f"the connection to Ollama failed ({type(exc).__name__})"
            raise _TransientError(problem) from exc
        if response.status_code == 404:
            raise ModelError(
                f"the model '{self.model}' is not available in Ollama; run: ollama pull "
                f"{self.model}"
            )
        if response.status_code >= 500:
            raise _TransientError(f"Ollama had a server error (HTTP {response.status_code})")
        if response.status_code != 200:
            raise ModelError(f"Ollama refused the request (HTTP {response.status_code})")
        try:
            reply = _ChatResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise ModelError("Ollama sent a response in an unexpected format") from exc
        if reply.done_reason == "length":
            logger.info("Ollama stopped at the output limit; the answer may be incomplete")
        return reply.message.content
