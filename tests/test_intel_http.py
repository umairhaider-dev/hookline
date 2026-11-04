import httpx
import pytest
from pydantic import BaseModel

from hookline.intel import IntelLookupError, ProviderUnavailableError, QuotaExceededError
from hookline.intel.http import USER_AGENT, build_client, parse_json, send


def client_for(handler: httpx.MockTransport) -> httpx.Client:
    return build_client(
        base_url="https://api.example.net/", headers={"X-Key": "k"}, timeout=5, transport=handler
    )


def respond(response: httpx.Response) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: response)


def fail_with(error: Exception) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    return httpx.MockTransport(handler)


def do_send(transport: httpx.MockTransport) -> httpx.Response:
    with client_for(transport) as client:
        return send(client, "Example", client.build_request("GET", "thing"))


def test_client_sets_headers_and_does_not_follow_redirects() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"Location": "https://elsewhere.example.net/"})

    with pytest.raises(IntelLookupError, match="HTTP 302"):
        do_send(httpx.MockTransport(handler))
    (request,) = seen
    assert request.headers["User-Agent"] == USER_AGENT
    assert request.headers["Accept"] == "application/json"
    assert request.headers["X-Key"] == "k"
    assert str(request.url) == "https://api.example.net/thing"


@pytest.mark.parametrize("status", [200, 204, 404])
def test_successful_and_not_found_responses_are_returned(status: int) -> None:
    assert do_send(respond(httpx.Response(status))).status_code == status


def test_timeout_makes_provider_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="did not answer in time"):
        do_send(fail_with(httpx.ReadTimeout("slow")))


def test_connection_failure_makes_provider_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match=r"could not reach Example \(ConnectError\)"):
        do_send(fail_with(httpx.ConnectError("refused")))


@pytest.mark.parametrize("status", [401, 403])
def test_rejected_key(status: int) -> None:
    with pytest.raises(ProviderUnavailableError, match=f"rejected the API key \\(HTTP {status}\\)"):
        do_send(respond(httpx.Response(status)))


@pytest.mark.parametrize(
    ("header", "retry_after"), [("30", 30.0), ("soon", None), ("-5", None), (None, None)]
)
def test_rate_limited(header: str | None, retry_after: float | None) -> None:
    headers = {"Retry-After": header} if header is not None else {}
    with pytest.raises(QuotaExceededError) as caught:
        do_send(respond(httpx.Response(429, headers=headers)))
    assert caught.value.retry_after == retry_after


def test_server_and_client_errors_fail_one_lookup() -> None:
    with pytest.raises(IntelLookupError, match="server error \\(HTTP 503\\)") as server:
        do_send(respond(httpx.Response(503)))
    assert not isinstance(server.value, ProviderUnavailableError)
    with pytest.raises(IntelLookupError, match="refused the request \\(HTTP 400\\)"):
        do_send(respond(httpx.Response(400)))


class _Body(BaseModel):
    name: str


def test_parse_json() -> None:
    assert parse_json(httpx.Response(200, json={"name": "x"}), _Body, "Example").name == "x"
    with pytest.raises(IntelLookupError, match="unexpected format"):
        parse_json(httpx.Response(200, text="<html>"), _Body, "Example")
    with pytest.raises(IntelLookupError, match="unexpected format"):
        parse_json(httpx.Response(200, json={"other": 1}), _Body, "Example")
