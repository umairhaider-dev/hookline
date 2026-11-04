"""Logging setup.

Diagnostics always go to stderr so that stdout carries nothing but reports,
which keeps ``hookline analyze --format json > report.json`` safe to use.
"""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import TextIO

from hookline.config import LogFormat

PACKAGE_LOGGER = "hookline"
TEXT_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


class JsonFormatter(logging.Formatter):
    """Writes one JSON object per record, for log shippers and SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        """Render ``record`` as a single JSON line."""
        payload: dict[str, str] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(
    level: str = "WARNING",
    log_format: LogFormat = LogFormat.TEXT,
    stream: TextIO | None = None,
) -> None:
    """Send Hookline's log records to ``stream`` (stderr by default).

    Safe to call more than once; each call replaces the previous handler.
    """
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    if log_format is LogFormat.JSON:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(TEXT_FORMAT))

    package_logger = logging.getLogger(PACKAGE_LOGGER)
    for existing in list(package_logger.handlers):
        package_logger.removeHandler(existing)
    package_logger.addHandler(handler)
    package_logger.setLevel(level)
