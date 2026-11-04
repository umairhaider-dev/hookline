import json
import logging
from collections.abc import Callable
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from hookline.config import WatchpostSettings
from hookline.models import AIAssessment, AIRun, AIStatus, AttackType, EmailAddress, ReceivedHop
from hookline.models.verdict import VerdictLabel
from hookline.watchpost import (
    Credentials,
    WatchpostClient,
    WatchpostError,
    events_jsonl,
    meets,
    report_event,
    resolve_url,
    tls_verification,
)
from tests.factories import make_email, make_indicator, make_report
from tests.intel_helpers import recording_transport

TOKEN_REPLY = {"access_token": "fresh-token", "token_type": "bearer", "expires_in": 3600}
JOB = {"id": 7, "status": "queued"}
TOKEN_CREDENTIALS = Credentials(token="t0ken")


# --- events -------------------------------------------------------------------


def test_event_fields() -> None:
    email = make_email(
        subject="Invoice",
        from_address=EmailAddress(display_name="Billing", address="billing@evil.test"),
        to=(EmailAddress(address="sam@larkspur.test"),),
        received=(
            ReceivedHop(raw="a", from_ip=ip_address("10.0.0.1")),
            ReceivedHop(raw="b", from_ip=ip_address("203.0.113.5")),
        ),
        date=datetime(2026, 11, 3, 8, 0),  # noqa: DTZ001 - a Date header without a zone
    )
    ai = AIRun(
        status=AIStatus.COMPLETED,
        assessment=AIAssessment(
            phishing_likelihood=90, attack_type=AttackType.BEC, explanation="x"
        ),
    )
    report = make_report(email=email, indicators=[make_indicator()], ai=ai)
    event = report_event(report)
    assert event["@timestamp"] == "2026-11-03T08:00:00+00:00"
    assert event["event.action"] == "hookline_email_likely_safe"
    assert event["event.code"] == email.sha256
    assert event["user.name"] == "sam@larkspur.test"
    assert event["source.ip"] == "203.0.113.5"
    assert "url.original" not in event
    assert event["message"] == (
        "Hookline: likely safe email (score 15/100) from billing@evil.test: Invoice"
    )
    details = event["hookline"]
    assert details["indicators"][0]["type"] == "reply_to_mismatch"
    assert details["ai"] == {"status": "completed", "phishing_likelihood": 90, "attack_type": "bec"}
    assert details["from"] == '"Billing" <billing@evil.test>'


def test_event_without_sender_recipients_or_date() -> None:
    event = report_event(make_report())
    assert "user.name" not in event
    assert "source.ip" not in event
    assert "an unknown sender" in event["message"]
    assert event["hookline"]["ai"] == {"status": "disabled"}


def test_same_report_gives_identical_lines() -> None:
    report = make_report(indicators=[make_indicator()])
    again = report.model_copy(update={"report_id": report.report_id.__class__(int=1)})
    assert events_jsonl([report]) == events_jsonl([again])
    unicode_report = make_report(email=make_email(subject="caf\xe9"))
    assert "caf\xe9" in events_jsonl([unicode_report]).decode("utf-8")
    assert b"caf\\u00e9" in events_jsonl([unicode_report], ascii_only=True)


def test_verdict_threshold() -> None:
    safe = make_report()
    assert meets(safe, VerdictLabel.LIKELY_SAFE)
    assert not meets(safe, VerdictLabel.SUSPICIOUS)


# --- client -------------------------------------------------------------------


def watchpost(
    handler: Callable[[httpx.Request], httpx.Response],
    credentials: Credentials = TOKEN_CREDENTIALS,
    max_retries: int = 2,
) -> tuple[WatchpostClient, list[httpx.Request], list[float]]:
    transport, requests = recording_transport(handler)
    slept: list[float] = []
    client = WatchpostClient(
        "https://watchpost.example.net",
        credentials,
        max_retries=max_retries,
        transport=transport,
        sleep=slept.append,
    )
    return client, requests, slept


def test_upload_with_token() -> None:
    client, requests, _ = watchpost(lambda request: httpx.Response(202, json=JOB))
    with client:
        assert client.upload(b'{"a": 1}\n', filename="h.jsonl", host_name="hookline") == JOB
    (request,) = requests
    assert request.url == "https://watchpost.example.net/api/ingest/uploads"
    assert request.headers["Authorization"] == "Bearer t0ken"
    body = request.content.decode()
    assert 'name="parser"\r\n\r\njson' in body
    assert 'name="host_name"\r\n\r\nhookline' in body
    assert 'filename="h.jsonl"' in body
    assert '{"a": 1}' in body


def test_sign_in_with_password_and_retry_once_on_expiry() -> None:
    replies = iter(
        [
            httpx.Response(200, json=TOKEN_REPLY),
            httpx.Response(401, json={"detail": "expired"}),
            httpx.Response(200, json=TOKEN_REPLY),
            httpx.Response(200, json={"id": 7, "status": "completed"}),
        ]
    )
    client, requests, _ = watchpost(
        lambda request: next(replies), Credentials(username="hookline", password="pw")
    )
    with client:
        assert client.job(7)["status"] == "completed"
    assert [request.url.path for request in requests] == [
        "/api/auth/token",
        "/api/ingest/jobs/7",
        "/api/auth/token",
        "/api/ingest/jobs/7",
    ]
    assert parse_qs(requests[0].content.decode()) == {"username": ["hookline"], "password": ["pw"]}
    assert requests[3].headers["Authorization"] == "Bearer fresh-token"


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        (httpx.Response(401), "rejected the username or password"),
        (httpx.Response(200, json={"token_type": "bearer"}), "contained no token"),
        (httpx.Response(200, text="<html>"), "not JSON"),
        (httpx.Response(200, json=[1]), "unexpected response"),
    ],
)
def test_sign_in_problems(reply: httpx.Response, message: str) -> None:
    client, _, _ = watchpost(lambda request: reply, Credentials(username="u", password="p"))
    with client, pytest.raises(WatchpostError, match=message):
        client.job(1)


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "rejected the token: expired"),
        (403, "analyst or admin role"),
        (413, "larger than Watchpost's limit"),
        (415, "did not accept the file type"),
        (422, "rejected the request"),
        (500, "answered HTTP 500"),
    ],
)
def test_error_answers(status: int, message: str) -> None:
    reply = httpx.Response(status, json={"detail": "expired"} if status == 401 else {})
    client, _, _ = watchpost(lambda request: reply)
    with client, pytest.raises(WatchpostError, match=message):
        client.upload(b"x", filename="h.jsonl", host_name="h")


def test_error_detail_that_is_not_json() -> None:
    client, _, _ = watchpost(lambda request: httpx.Response(500, text="oops"))
    with client, pytest.raises(WatchpostError, match=r"^Watchpost answered HTTP 500$"):
        client.job(1)


def test_busy_answers_and_network_errors_are_retried() -> None:
    replies: list[httpx.Response | Exception] = [
        httpx.Response(503, headers={"Retry-After": "7"}),
        httpx.ConnectError("refused"),
        httpx.Response(429, headers={"Retry-After": "soon"}),
        httpx.Response(202, json=JOB),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    client, requests, slept = watchpost(handler, max_retries=3)
    with client:
        assert client.upload(b"x", filename="h.jsonl", host_name="h") == JOB
    assert len(requests) == 4
    assert slept == [7.0, 2.0, 4.0]


def test_retries_run_out() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client, _, _ = watchpost(refuse, max_retries=1)
    with client, pytest.raises(WatchpostError, match="Could not reach Watchpost"):
        client.job(1)
    busy, _, _ = watchpost(lambda request: httpx.Response(503), max_retries=0)
    with busy, pytest.raises(WatchpostError, match="HTTP 503"):
        busy.job(1)


def test_wait_for_job() -> None:
    states = iter([{"status": "queued"}, {"status": "running"}, {"status": "completed"}])
    client, _, slept = watchpost(lambda request: httpx.Response(200, json=next(states)))
    with client:
        assert client.wait_for_job(7, interval=2)["status"] == "completed"
    assert slept == [2, 2]
    stuck, _, _ = watchpost(lambda request: httpx.Response(200, json={"status": "running"}))
    with stuck:
        assert stuck.wait_for_job(7, timeout=3, interval=2)["status"] == "running"


def test_credentials() -> None:
    with pytest.raises(WatchpostError, match="No Watchpost credentials"):
        WatchpostClient("https://w.example.net", Credentials(username="only-name"))
    assert Credentials(token="t").usable
    assert not Credentials(token="t").can_sign_in


def test_resolve_url(caplog: pytest.LogCaptureFixture) -> None:
    settings = WatchpostSettings(url="https://from-config.example.net/")
    assert resolve_url("https://cli.example.net/", settings, {}) == "https://cli.example.net"
    assert resolve_url(None, settings, {"WATCHPOST_URL": "https://env.example.net"}) == (
        "https://env.example.net"
    )
    assert resolve_url(None, settings, {}) == "https://from-config.example.net"
    with pytest.raises(WatchpostError, match="No Watchpost URL"):
        resolve_url(None, WatchpostSettings(), {})
    with pytest.raises(WatchpostError, match="must start with"):
        resolve_url("watchpost.example.net", settings, {})
    with caplog.at_level(logging.WARNING, logger="hookline"):
        resolve_url("http://localhost:8000", settings, {})
        assert "plain HTTP" not in caplog.text
        resolve_url("http://watchpost.example.net", settings, {})
    assert "plain HTTP" in caplog.text


def test_tls_verification(tmp_path: Path) -> None:
    assert tls_verification(WatchpostSettings()) is True
    assert tls_verification(WatchpostSettings(verify_tls=False)) is False
    bundle = tmp_path / "ca.pem"
    bundle.write_text("not a certificate", encoding="utf-8")
    with pytest.raises(WatchpostError, match="Cannot load CA bundle"):
        tls_verification(WatchpostSettings(ca_bundle=bundle))


def test_settings_validation() -> None:
    with pytest.raises(ValueError, match="must start with"):
        WatchpostSettings(url="watchpost.example.net")
    assert WatchpostSettings(url="https://w.example.net/").url == "https://w.example.net"


def test_events_file_is_valid_json_lines() -> None:
    content = events_jsonl([make_report(), make_report(indicators=[make_indicator()])])
    lines = content.decode().splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["event.provider"] == "hookline" for line in lines)
