import io
import json
import logging

import pytest

from hookline.config import LogFormat
from hookline.logging_config import PACKAGE_LOGGER, configure_logging

log = logging.getLogger("hookline.tests")


def test_text_format() -> None:
    stream = io.StringIO()
    configure_logging("INFO", LogFormat.TEXT, stream=stream)
    log.info("analyzed %s", "sample.eml")
    line = stream.getvalue()
    assert "INFO" in line
    assert "hookline.tests: analyzed sample.eml" in line


def test_level_filters_records() -> None:
    stream = io.StringIO()
    configure_logging("WARNING", stream=stream)
    log.info("hidden")
    log.warning("shown")
    assert "hidden" not in stream.getvalue()
    assert "shown" in stream.getvalue()


def test_json_format_writes_one_object_per_line() -> None:
    stream = io.StringIO()
    configure_logging("DEBUG", LogFormat.JSON, stream=stream)
    log.warning("careful")
    try:
        raise ValueError("boom")
    except ValueError:
        log.exception("failed")

    first, second = (json.loads(line) for line in stream.getvalue().splitlines())
    assert first["level"] == "WARNING"
    assert first["logger"] == "hookline.tests"
    assert first["message"] == "careful"
    assert first["timestamp"].endswith("+00:00")
    assert "exception" not in first
    assert "ValueError: boom" in second["exception"]


def test_reconfiguring_replaces_the_handler() -> None:
    configure_logging("INFO", stream=io.StringIO())
    configure_logging("DEBUG", stream=io.StringIO())
    package_logger = logging.getLogger(PACKAGE_LOGGER)
    assert len(package_logger.handlers) == 1
    assert package_logger.level == logging.DEBUG


def test_logs_go_to_stderr_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    log.info("diagnostic")
    captured = capsys.readouterr()
    assert "diagnostic" in captured.err
    assert captured.out == ""
