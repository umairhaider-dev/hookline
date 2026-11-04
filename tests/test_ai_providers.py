import json
import sys
from collections.abc import Callable
from typing import Any

import httpx
import httpx2
import pytest

from hookline.ai import (
    AnthropicProvider,
    ModelError,
    ModelRefusalError,
    ModelRequest,
    ModelUnavailableError,
    OllamaProvider,
    Turn,
)
from hookline.ai.anthropic_api import FALLBACK_BETA, INSTALL_HINT
from hookline.ai.prompt import OUTPUT_SCHEMA
from tests.ai_helpers import answer

REQUEST = ModelRequest(
    system="system rules",
    turns=(Turn("user", "first"), Turn("assistant", "bad"), Turn("user", "again")),
    schema=OUTPUT_SCHEMA,
)


# --- Ollama -------------------------------------------------------------------


def ollama(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    url: str = "http://localhost:11434",
    max_retries: int = 2,
) -> tuple[OllamaProvider, list[httpx.Request], list[float]]:
    requests: list[httpx.Request] = []
    slept: list[float] = []

    def record(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    provider = OllamaProvider(
        url=url,
        model="llama3.1:8b",
        timeout=30,
        max_retries=max_retries,
        num_ctx=8192,
        max_output_tokens=2048,
        transport=httpx.MockTransport(record),
        sleep=slept.append,
    )
    return provider, requests, slept


def chat_reply(content: str, **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"message": {"role": "assistant", "content": content}, **extra})


def test_ollama_request_and_answer() -> None:
    provider, requests, _ = ollama(lambda request: chat_reply(answer()))
    assert provider.complete(REQUEST) == answer()
    provider.close()
    (request,) = requests
    assert request.url == "http://localhost:11434/api/chat"
    body = json.loads(request.content)
    assert body["model"] == "llama3.1:8b"
    assert body["stream"] is False
    assert body["format"] == OUTPUT_SCHEMA
    assert body["options"] == {"temperature": 0, "num_ctx": 8192, "num_predict": 2048}
    assert [message["role"] for message in body["messages"]] == [
        "system",
        "user",
        "assistant",
        "user",
    ]
    assert body["messages"][0]["content"] == "system rules"


def test_ollama_without_schema_asks_for_json() -> None:
    provider, requests, _ = ollama(lambda request: chat_reply("{}", done_reason="length"))
    provider.complete(ModelRequest(system="s", turns=(Turn("user", "u"),)))
    provider.close()
    assert json.loads(requests[0].content)["format"] == "json"


def test_ollama_missing_model() -> None:
    provider, _, _ = ollama(lambda request: httpx.Response(404, json={"error": "not found"}))
    with pytest.raises(ModelError, match=r"ollama pull llama3.1:8b"):
        provider.complete(REQUEST)
    provider.close()


def test_ollama_retries_server_errors_with_backoff() -> None:
    replies = iter([httpx.Response(503), httpx.Response(500), chat_reply(answer())])
    provider, requests, slept = ollama(lambda request: next(replies))
    assert provider.complete(REQUEST) == answer()
    provider.close()
    assert len(requests) == 3
    assert slept == [1.0, 2.0]


def test_ollama_gives_up_after_retries() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    provider, requests, slept = ollama(slow, max_retries=1)
    with pytest.raises(ModelUnavailableError, match="did not answer in time"):
        provider.complete(REQUEST)
    provider.close()
    assert len(requests) == 2
    assert slept == [1.0]


def test_ollama_broken_connection_is_retried() -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("dropped")

    provider, requests, _ = ollama(broken, max_retries=1)
    with pytest.raises(
        ModelUnavailableError, match=r"connection to Ollama failed \(RemoteProtocolError\)"
    ):
        provider.complete(REQUEST)
    provider.close()
    assert len(requests) == 2


@pytest.mark.parametrize("error", [httpx.ConnectError("refused"), httpx.ConnectTimeout("slow")])
def test_ollama_not_running_fails_fast(error: Exception) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise error

    provider, requests, slept = ollama(refuse)
    with pytest.raises(ModelUnavailableError, match="is it running"):
        provider.complete(REQUEST)
    provider.close()
    assert len(requests) == 1
    assert slept == []


def test_ollama_other_errors() -> None:
    provider, _, _ = ollama(lambda request: httpx.Response(400))
    with pytest.raises(ModelError, match="refused the request \\(HTTP 400\\)"):
        provider.complete(REQUEST)
    provider.close()
    garbled, _, _ = ollama(lambda request: httpx.Response(200, text="<html>"))
    with pytest.raises(ModelError, match="unexpected format"):
        garbled.complete(REQUEST)
    garbled.close()


def test_ollama_https_url_keeps_certificate_checks() -> None:
    provider, requests, _ = ollama(lambda request: chat_reply("{}"), url="https://gpu.example.net")
    provider.complete(REQUEST)
    provider.close()
    assert requests[0].url == "https://gpu.example.net/api/chat"


# --- Anthropic ----------------------------------------------------------------


def anthropic_provider(
    handler: Callable[[httpx2.Request], httpx2.Response],
) -> tuple[AnthropicProvider, list[httpx2.Request]]:
    requests: list[httpx2.Request] = []

    def record(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return handler(request)

    provider = AnthropicProvider(
        "sk-ant-test",
        model="claude-opus-5-5",
        effort="medium",
        max_output_tokens=16000,
        timeout=30,
        max_retries=0,
        http_client=httpx2.Client(transport=httpx2.MockTransport(record)),
    )
    return provider, requests


def message(
    content: list[dict[str, Any]], stop_reason: str = "end_turn", **extra: Any
) -> dict[str, Any]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5-5",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
        **extra,
    }


def test_anthropic_request_and_answer() -> None:
    reply = message(
        [
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "text", "text": answer()[:20]},
            {"type": "text", "text": answer()[20:]},
        ]
    )
    provider, requests = anthropic_provider(lambda request: httpx2.Response(200, json=reply))
    assert provider.complete(REQUEST) == answer()
    provider.close()
    (request,) = requests
    assert request.url.path == "/v1/messages"
    assert request.headers["authorization"] == "Bearer sk-ant-test"
    assert FALLBACK_BETA in request.headers["anthropic-beta"]
    body = json.loads(request.content)
    assert body["model"] == "claude-opus-5-5"
    assert body["max_tokens"] == 16000
    assert body["system"] == "system rules"
    assert body["fallbacks"] == "default"
    assert body["output_config"] == {
        "effort": "medium",
        "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA},
    }
    assert [item["role"] for item in body["messages"]] == ["user", "assistant", "user"]
    assert "thinking" not in body


def test_anthropic_without_schema() -> None:
    reply = message([{"type": "text", "text": "{}"}])
    provider, requests = anthropic_provider(lambda request: httpx2.Response(200, json=reply))
    provider.complete(ModelRequest(system="s", turns=(Turn("user", "u"),)))
    provider.close()
    assert json.loads(requests[0].content)["output_config"] == {"effort": "medium"}


@pytest.mark.parametrize(
    ("details", "expected"),
    [
        ({"type": "refusal", "category": "cyber", "explanation": "x"}, "category: cyber"),
        (None, "declined to assess this email$"),
    ],
)
def test_anthropic_refusal(details: dict[str, str] | None, expected: str) -> None:
    reply = message([], stop_reason="refusal", stop_details=details)
    provider, _ = anthropic_provider(lambda request: httpx2.Response(200, json=reply))
    with pytest.raises(ModelRefusalError, match=expected):
        provider.complete(REQUEST)
    provider.close()


def api_error(status: int, message_text: str = "nope") -> httpx2.Response:
    return httpx2.Response(
        status, json={"type": "error", "error": {"type": "error", "message": message_text}}
    )


@pytest.mark.parametrize(
    ("status", "error", "text"),
    [
        (401, ModelError, "rejected the API key"),
        (403, ModelError, "rejected the API key"),
        (404, ModelError, "model 'claude-opus-5-5' was not found"),
        (429, ModelUnavailableError, "rate limit"),
        (500, ModelUnavailableError, "server error \\(HTTP 500\\)"),
        (400, ModelError, "rejected the request \\(HTTP 400\\)"),
    ],
)
def test_anthropic_status_errors(status: int, error: type[Exception], text: str) -> None:
    provider, _ = anthropic_provider(lambda request: api_error(status))
    with pytest.raises(error, match=text):
        provider.complete(REQUEST)
    provider.close()


@pytest.mark.parametrize(
    ("failure", "text"),
    [
        (httpx2.ConnectError("refused"), "could not reach the Anthropic API"),
        (httpx2.ReadTimeout("slow"), "did not answer in time"),
    ],
)
def test_anthropic_transport_errors(failure: Exception, text: str) -> None:
    def fail(request: httpx2.Request) -> httpx2.Response:
        raise failure

    provider, _ = anthropic_provider(fail)
    with pytest.raises(ModelUnavailableError, match=text):
        provider.complete(REQUEST)
    provider.close()


def test_anthropic_package_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "anthropic", None)
    with pytest.raises(ModelError, match="pip install"):
        AnthropicProvider(
            "k", model="m", effort="low", max_output_tokens=1000, timeout=5, max_retries=0
        )
    assert "hookline[anthropic]" in INSTALL_HINT
