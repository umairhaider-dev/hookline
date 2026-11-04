import io
import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hookline import __version__
from hookline.cli import EXIT_ANALYSIS_ERROR, EXIT_USAGE_ERROR, _harden_output_streams, app
from tests.factories import SAMPLES_DIR

PHISH = str(SAMPLES_DIR / "credential-phish.eml")
SUBJECT = "\u26a0 Action required: your password expires today"

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"hookline {__version__}"


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "analyze" in result.output
    assert "Usage" in result.output


def test_analyze_terminal_summary() -> None:
    result = runner.invoke(app, ["analyze", PHISH])
    assert result.exit_code == 0, result.output
    assert "Hookline verdict" in result.stdout
    assert "it-support@larkspur-helpdesk.test" in result.stdout
    assert result.stderr == ""


def test_analyze_json_to_stdout_is_ascii_and_valid() -> None:
    result = runner.invoke(app, ["analyze", PHISH, "--format", "json"])
    assert result.exit_code == 0, result.output
    assert result.stdout.isascii()
    data = json.loads(result.stdout)
    assert data["email"]["subject"] == SUBJECT
    assert data["source_file"] == "credential-phish.eml"
    assert data["verdict"]["label"] in {"malicious", "suspicious", "likely_safe"}


def test_analyze_json_to_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    result = runner.invoke(app, ["analyze", PHISH, "-f", "json", "-o", str(target)])
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert "Report written to" in result.stderr
    content = target.read_text(encoding="utf-8")
    assert SUBJECT in content
    assert json.loads(content)["email"]["subject"] == SUBJECT


def test_output_file_needs_a_file_format(tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", PHISH, "-o", str(tmp_path / "report.txt")])
    assert result.exit_code == EXIT_USAGE_ERROR
    assert "--format json" in result.stderr


def test_unwritable_output_file(tmp_path: Path) -> None:
    target = tmp_path / "no-such-dir" / "report.json"
    result = runner.invoke(app, ["analyze", PHISH, "-f", "json", "-o", str(target)])
    assert result.exit_code == EXIT_ANALYSIS_ERROR
    assert "Could not write" in result.stderr


def test_missing_email_file() -> None:
    result = runner.invoke(app, ["analyze", "missing.eml"])
    assert result.exit_code == EXIT_ANALYSIS_ERROR
    assert result.stderr == "Error: File not found: missing.eml\n"
    assert result.stdout == ""


def test_no_ai_flag() -> None:
    result = runner.invoke(app, ["analyze", PHISH, "--no-ai", "-f", "json"])
    assert json.loads(result.stdout)["ai"]["status"] == "disabled"


def test_ai_unavailable_without_provider() -> None:
    result = runner.invoke(app, ["analyze", PHISH, "-f", "json"])
    assert json.loads(result.stdout)["ai"]["status"] == "unavailable"


def test_invalid_config_file(tmp_path: Path) -> None:
    config = tmp_path / "bad.toml"
    config.write_text('colour = "blue"\n', encoding="utf-8")
    result = runner.invoke(app, ["--config", str(config), "analyze", PHISH])
    assert result.exit_code == EXIT_USAGE_ERROR
    assert "Unknown setting(s)" in result.stderr


def test_missing_config_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["-c", str(tmp_path / "nope.toml"), "config"])
    assert result.exit_code == EXIT_USAGE_ERROR
    assert "Config file not found" in result.stderr


def test_config_command_masks_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-123")
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["anthropic_api_key"] == "**********"
    assert "sk-test-123" not in result.stdout
    assert data["llm"]["provider"] == "ollama"


@pytest.mark.parametrize(("flag", "level"), [("-v", "INFO"), ("-vv", "DEBUG")])
def test_verbose_flags_log_to_stderr(flag: str, level: str) -> None:
    result = runner.invoke(app, [flag, "analyze", PHISH, "-f", "json"])
    assert result.exit_code == 0
    assert level in result.stderr
    assert "Analyzed credential-phish.eml" in result.stderr
    json.loads(result.stdout)  # logs never leak into the report


def test_streams_tolerate_unencodable_text(monkeypatch: pytest.MonkeyPatch) -> None:
    legacy = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", legacy)
    _harden_output_streams()
    legacy.write("\u26a0 subject")
    legacy.flush()
    assert legacy.buffer.getvalue() == b"\\u26a0 subject"
