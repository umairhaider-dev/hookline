from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from hookline import __version__
from hookline.config import Settings
from hookline.pipeline import Analyzer
from hookline.web import API_PREFIX, create_app
from tests.factories import SAMPLES_DIR

PHISH = (SAMPLES_DIR / "credential-phish.eml").read_bytes()
TOKEN = "s3cret-token"


def client_for(**settings: object) -> Iterator[TestClient]:
    config = Settings.model_validate({"ai_enabled": False, **settings})
    with TestClient(create_app(config)) as client:
        yield client


@pytest.fixture
def client() -> Iterator[TestClient]:
    yield from client_for()


@pytest.fixture
def locked() -> Iterator[TestClient]:
    yield from client_for(web_token=SecretStr(TOKEN))


def upload(name: str = "phish.eml", data: bytes = PHISH) -> dict[str, tuple[str, bytes, str]]:
    return {"file": (name, data, "message/rfc822")}


def test_upload_page_and_security_headers(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert '<form method="post" action="/analyze"' in response.text
    assert 'name="token"' not in response.text
    headers = response.headers
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"
    assert headers["referrer-policy"] == "no-referrer"


def test_form_upload_returns_the_html_report(client: TestClient) -> None:
    response = client.post("/analyze", files=upload("C:\\mail\\phish.eml"))
    assert response.status_code == 200
    assert "MALICIOUS" in response.text
    assert "phish.eml" in response.text
    assert "C:\\mail" not in response.text


def test_api_returns_the_json_report(client: TestClient) -> None:
    response = client.post(f"{API_PREFIX}/analyze", files=upload())
    assert response.status_code == 200
    report = response.json()
    assert report["verdict"]["label"] == "malicious"
    assert report["source_file"] == "phish.eml"
    assert report["mitre_techniques"][0]["technique_id"] == "T1566"


def test_empty_upload(client: TestClient) -> None:
    api = client.post(f"{API_PREFIX}/analyze", files=upload(data=b""))
    assert api.status_code == 400
    assert api.json() == {"detail": "the uploaded file is empty"}
    form = client.post("/analyze", files=upload(data=b""))
    assert form.status_code == 400
    assert "the uploaded file is empty" in form.text


def test_upload_over_the_limit_is_refused_while_reading() -> None:
    for client in client_for(max_email_bytes=1000):
        response = client.post(f"{API_PREFIX}/analyze", files=upload(data=b"x" * 1001))
        assert response.status_code == 413


def test_huge_request_is_refused_before_reading() -> None:
    for client in client_for(max_email_bytes=1000):
        response = client.post(
            f"{API_PREFIX}/analyze",
            content=b"x" * 70_000,
            headers={"content-type": "multipart/form-data; boundary=x"},
        )
        assert response.status_code == 413
        assert "limit" in response.json()["detail"]
        assert response.headers["cache-control"] == "no-store"


def test_missing_file_field(client: TestClient) -> None:
    assert client.post(f"{API_PREFIX}/analyze").status_code == 422


def test_api_token(locked: TestClient) -> None:
    missing = locked.post(f"{API_PREFIX}/analyze", files=upload())
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    wrong = locked.post(
        f"{API_PREFIX}/analyze", files=upload(), headers={"Authorization": "Bearer nope"}
    )
    assert wrong.status_code == 401
    basic = locked.post(
        f"{API_PREFIX}/analyze", files=upload(), headers={"Authorization": f"Basic {TOKEN}"}
    )
    assert basic.status_code == 401
    good = locked.post(
        f"{API_PREFIX}/analyze", files=upload(), headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert good.status_code == 200


def test_form_token(locked: TestClient) -> None:
    assert 'name="token"' in locked.get("/").text
    refused = locked.post("/analyze", files=upload(), data={"token": "nope"})
    assert refused.status_code == 401
    assert "access token is missing or wrong" in refused.text
    accepted = locked.post("/analyze", files=upload(), data={"token": TOKEN})
    assert accepted.status_code == 200


def test_health_and_openapi(client: TestClient) -> None:
    assert client.get(f"{API_PREFIX}/health").json() == {"status": "ok", "version": __version__}
    schema = client.get(f"{API_PREFIX}/openapi.json").json()
    assert f"{API_PREFIX}/analyze" in schema["paths"]
    assert "/analyze" not in schema["paths"]
    assert client.get("/docs").status_code == 404


def test_shared_analyzer_is_not_closed_by_the_app() -> None:
    analyzer = Analyzer(Settings(ai_enabled=False))
    closed: list[bool] = []
    analyzer.close = lambda: closed.append(True)  # type: ignore[method-assign]
    with TestClient(create_app(Settings(), analyzer=analyzer)) as client:
        assert client.post(f"{API_PREFIX}/analyze", files=upload()).status_code == 200
    assert closed == []


def test_unnamed_upload(client: TestClient) -> None:
    response = client.post(f"{API_PREFIX}/analyze", files={"file": ("", PHISH, "message/rfc822")})
    assert response.status_code in {200, 422}


def test_display_names() -> None:
    from hookline.web.app import _display_name

    assert _display_name(None) is None
    assert _display_name("") is None
    assert _display_name("/etc/../mail/x.eml") == "x.eml"
    assert _display_name("a\x00b.eml") == r"a\x00b.eml"
