"""CLI tests for the HTML report, push and serve commands."""

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

import hookline.cli as cli_module
from hookline.cli import EXIT_ANALYSIS_ERROR, EXIT_USAGE_ERROR, app
from hookline.evaluation import generate, write_dataset
from hookline.watchpost import WatchpostClient
from tests.factories import PROJECT_ROOT, SAMPLES_DIR

PHISH = str(SAMPLES_DIR / "credential-phish.eml")
BENIGN = str(SAMPLES_DIR / "benign-meeting.eml")
QUEUED = {"id": 3, "status": "queued"}

runner = CliRunner()


def test_html_report_to_stdout_and_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", PHISH, "-f", "html", "--no-ai"])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("<!doctype html>")
    target = tmp_path / "report.html"
    written = runner.invoke(app, ["analyze", PHISH, "-f", "html", "-o", str(target), "--no-ai"])
    assert written.exit_code == 0
    assert "MALICIOUS" in target.read_text(encoding="utf-8")


def test_terminal_shows_actions_mitre_and_iocs() -> None:
    result = runner.invoke(app, ["analyze", PHISH, "--no-ai"])
    assert "Recommended actions" in result.stdout
    assert "T1566.002" in result.stdout
    assert "hxxp://198.51.100[.]23" in result.stdout


def test_push_dry_run_prints_events_and_skips_safe_mail() -> None:
    result = runner.invoke(app, ["push", PHISH, BENIGN, "--dry-run"])
    assert result.exit_code == 0, result.output
    (line,) = result.stdout.splitlines()
    assert json.loads(line)["event.action"] == "hookline_email_malicious"
    assert result.stdout.isascii()
    assert "Skipped 1 email(s) below the suspicious verdict." in result.stderr


def test_push_nothing_to_send() -> None:
    result = runner.invoke(app, ["push", BENIGN, "--min-verdict", "malicious"])
    assert result.exit_code == 0
    assert "Nothing to push." in result.stderr


def test_push_reads_saved_reports(tmp_path: Path) -> None:
    saved = tmp_path / "r.json"
    runner.invoke(app, ["analyze", PHISH, "-f", "json", "-o", str(saved), "--no-ai"])
    result = runner.invoke(app, ["push", str(saved), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "hookline_email_malicious" in result.stdout
    broken = tmp_path / "broken.json"
    broken.write_text("{}", encoding="utf-8")
    bad = runner.invoke(app, ["push", str(broken), "--dry-run"])
    assert bad.exit_code == EXIT_ANALYSIS_ERROR
    assert "is not a Hookline JSON report" in bad.stderr
    missing = runner.invoke(app, ["push", str(tmp_path / "none.json"), "--dry-run"])
    assert "Could not read" in missing.stderr


def test_push_needs_url_and_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    no_url = runner.invoke(app, ["push", PHISH])
    assert no_url.exit_code == EXIT_ANALYSIS_ERROR
    assert "No Watchpost URL" in no_url.stderr
    monkeypatch.setenv("WATCHPOST_URL", "https://watchpost.example.net")
    no_credentials = runner.invoke(app, ["push", PHISH])
    assert "No Watchpost credentials" in no_credentials.stderr


def fake_watchpost(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> list[httpx.Request]:
    requests: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    class Client(WatchpostClient):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs.update(transport=httpx.MockTransport(record), sleep=lambda seconds: None)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(cli_module, "WatchpostClient", Client)
    monkeypatch.setenv("WATCHPOST_TOKEN", "t0ken")
    return requests


def job_handler(job: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json=QUEUED)
        return httpx.Response(200, json=job)

    return handler


def test_push_sends_and_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    job = {
        "id": 3,
        "status": "completed",
        "events_inserted": 1,
        "events_duplicate": 0,
        "detection": {"alerts_created": 1, "alerts_updated": 0},
    }
    requests = fake_watchpost(monkeypatch, job_handler(job))
    result = runner.invoke(app, ["push", PHISH, "--url", "https://watchpost.example.net", "--wait"])
    assert result.exit_code == 0, result.output
    assert "as ingestion job 3 (queued)." in result.stdout
    assert "Watchpost stored 1 new event(s) (0 already known)." in result.stdout
    assert "Detection: 1 alert(s) created, 0 updated." in result.stdout
    assert requests[0].url.path == "/api/ingest/uploads"
    assert requests[1].url.path == "/api/ingest/jobs/3"


@pytest.mark.parametrize(
    ("job", "expected", "code"),
    [
        ({"id": 3, "status": "running"}, "still processing the job (running)", 0),
        (
            {"id": 3, "status": "failed", "error": "bad file"},
            "could not ingest the events: bad file",
            EXIT_ANALYSIS_ERROR,
        ),
        (
            {"id": 3, "status": "completed", "events_inserted": 0, "events_duplicate": 1},
            "(1 already known)",
            0,
        ),
    ],
)
def test_push_wait_outcomes(
    monkeypatch: pytest.MonkeyPatch, job: dict[str, Any], expected: str, code: int
) -> None:
    fake_watchpost(monkeypatch, job_handler(job))
    monkeypatch.setattr(WatchpostClient, "wait_for_job", lambda self, job_id: job)
    result = runner.invoke(app, ["push", PHISH, "--url", "https://w.example.net", "--wait"])
    assert result.exit_code == code
    assert expected in result.output


def test_push_reports_watchpost_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_watchpost(monkeypatch, lambda request: httpx.Response(403, json={}))
    result = runner.invoke(app, ["push", PHISH, "--url", "https://w.example.net"])
    assert result.exit_code == EXIT_ANALYSIS_ERROR
    assert "analyst or admin role" in result.stderr


def test_serve_starts_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    started: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda application, **kwargs: started.append(kwargs))
    local = runner.invoke(app, ["serve"])
    assert local.exit_code == 0, local.output
    assert started[0]["host"] == "127.0.0.1"
    assert local.stderr == ""
    everywhere = "0.0.0.0"  # noqa: S104 - the case under test
    exposed = runner.invoke(app, ["serve", "--host", everywhere, "--port", "9000"])
    assert started[1] == {"host": everywhere, "port": 9000, "log_level": "warning"}
    assert "without HOOKLINE_WEB_TOKEN" in exposed.stderr


def test_serve_without_the_web_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "uvicorn", None)
    result = runner.invoke(app, ["serve"])
    assert result.exit_code == EXIT_USAGE_ERROR
    assert "hookline[web]" in result.stderr


EVAL_CONFIG = str(PROJECT_ROOT / "evaluation" / "hookline-eval.toml")


def test_eval_generate(tmp_path: Path) -> None:
    result = runner.invoke(app, ["eval", "generate", str(tmp_path / "dataset"), "--seed", "3"])
    assert result.exit_code == 0, result.output
    assert "Wrote 240 emails (120 phishing, 120 benign; 20 with an injection twin)" in result.stdout
    assert (tmp_path / "dataset" / "labels.csv").is_file()


def test_eval_run_falls_back_to_rules_without_a_model(tmp_path: Path) -> None:
    samples = generate(7)
    write_dataset(
        [samples[0], samples[200], *[s for s in samples if s.injection][:1]], tmp_path / "d"
    )
    out = tmp_path / "results"
    result = runner.invoke(
        app, ["--config", EVAL_CONFIG, "eval", "run", str(tmp_path / "d"), "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert "Language model not used (Ollama is not reachable" in result.stderr
    assert "| Rules only |" in result.stdout
    assert "not run: no language model was available" in result.stdout
    assert {path.name for path in out.iterdir()} == {
        "RESULTS.md",
        "results.json",
        "predictions.csv",
    }
    assert all(b"\r" not in path.read_bytes() for path in out.iterdir())
    quiet = runner.invoke(app, ["eval", "run", str(tmp_path / "d"), "-o", str(out), "--no-ai"])
    assert quiet.exit_code == 0
    assert "Language model not used" not in quiet.stderr


def test_eval_run_reports_missing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_dataset(generate(7)[:1], tmp_path / "d")
    monkeypatch.setenv("HOOKLINE_LLM__PROVIDER", "anthropic")
    result = runner.invoke(app, ["eval", "run", str(tmp_path / "d"), "-o", str(tmp_path / "o")])
    assert "ANTHROPIC_API_KEY is not set" in result.stderr


def test_eval_run_needs_a_dataset(tmp_path: Path) -> None:
    result = runner.invoke(app, ["eval", "run", str(tmp_path)])
    assert result.exit_code == EXIT_ANALYSIS_ERROR
    assert "No labels.csv" in result.stderr
