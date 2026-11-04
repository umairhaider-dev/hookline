"""Claude through the Anthropic API (optional cloud provider).

Uses the official SDK, installed with ``pip install "hookline[anthropic]"``.
One Messages API request per email:

* structured outputs (``output_config.format``) constrain the answer to the
  JSON schema, and it is still validated locally;
* effort is set explicitly, and ``max_tokens`` leaves room for the model's
  reasoning, which counts towards it;
* server-side refusal fallback (``fallbacks: "default"``) lets the API re-run a
  declined request on another model inside the same call, since phishing
  analysis can trip safety classifiers;
* the SDK retries connection errors, 429 and 5xx responses itself.

Personal data is redacted before sending unless redaction is set to "never".
"""

from typing import TYPE_CHECKING, Any

from hookline.ai.base import ModelError, ModelRefusalError, ModelRequest, ModelUnavailableError

if TYPE_CHECKING:
    import anthropic
    import httpx2
    from anthropic.types.beta import BetaMessageParam

NAME = "anthropic"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
INSTALL_HINT = 'the anthropic package is not installed; run: pip install "hookline[anthropic]"'


class AnthropicProvider:
    """Sends the prompt to Claude and returns the text of its answer."""

    name = NAME
    is_cloud = True

    def __init__(
        self,
        api_key: str,
        *,
        model: str,
        effort: str,
        max_output_tokens: int,
        timeout: float,
        max_retries: int,
        http_client: "httpx2.Client | None" = None,
    ) -> None:
        # Optional dependency, so it is imported only when this provider is used.
        try:
            import anthropic
        except ImportError as exc:
            raise ModelError(INSTALL_HINT) from exc
        self.model = model
        self._anthropic = anthropic
        self._effort = effort
        self._max_tokens = max_output_tokens
        self._client = anthropic.Anthropic(
            api_key=api_key, timeout=timeout, max_retries=max_retries, http_client=http_client
        )

    def complete(self, request: ModelRequest) -> str:
        """Send one request and return the answer's text blocks joined together."""
        sdk = self._anthropic
        output_config: Any = {"effort": self._effort}
        if request.schema:
            output_config["format"] = {"type": "json_schema", "schema": request.schema}
        messages: list[BetaMessageParam] = [
            {"role": "user", "content": turn.text}
            if turn.role == "user"
            else {"role": "assistant", "content": turn.text}
            for turn in request.turns
        ]
        try:
            response = self._client.beta.messages.create(
                model=self.model,
                max_tokens=self._max_tokens,
                system=request.system,
                messages=messages,
                output_config=output_config,
                betas=[FALLBACK_BETA],
                fallbacks="default",
            )
        except sdk.APITimeoutError as exc:
            raise ModelUnavailableError("the Anthropic API did not answer in time") from exc
        except sdk.APIConnectionError as exc:
            raise ModelUnavailableError("could not reach the Anthropic API") from exc
        except (sdk.AuthenticationError, sdk.PermissionDeniedError) as exc:
            raise ModelError("the Anthropic API rejected the API key") from exc
        except sdk.NotFoundError as exc:
            raise ModelError(f"the model '{self.model}' was not found") from exc
        except sdk.RateLimitError as exc:
            raise ModelUnavailableError("the Anthropic API rate limit was reached") from exc
        except sdk.APIStatusError as exc:
            if exc.status_code >= 500:
                raise ModelUnavailableError(
                    f"the Anthropic API had a server error (HTTP {exc.status_code})"
                ) from exc
            raise ModelError(
                f"the Anthropic API rejected the request (HTTP {exc.status_code}): "
                f"{str(exc.message)[:200]}"
            ) from exc
        return _answer_text(response)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


def _answer_text(response: "anthropic.types.beta.BetaMessage") -> str:
    if response.stop_reason == "refusal":
        category = response.stop_details.category if response.stop_details else None
        detail = f" (category: {category})" if category else ""
        raise ModelRefusalError(f"the model declined to assess this email{detail}")
    # Thinking blocks come first and carry no answer; only text blocks do.
    return "".join(block.text for block in response.content if block.type == "text")
