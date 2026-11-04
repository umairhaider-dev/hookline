"""Builders for test data."""

import hashlib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from hookline.config import ScoringSettings
from hookline.models import (
    AIRun,
    AIStatus,
    Indicator,
    IndicatorSource,
    IndicatorType,
    ParsedEmail,
    Report,
    Severity,
)
from hookline.scoring import score_indicators

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = PROJECT_ROOT / "samples"

DEFAULT_HEADERS: tuple[tuple[str, str], ...] = (
    ("From", '"Dana Whitfield" <dana.whitfield@larkspur.test>'),
    ("To", "sam.ortega@larkspur.test"),
    ("Subject", "Hello"),
    ("Date", "Mon, 02 Nov 2026 15:02:08 +0000"),
    ("Message-ID", "<abc123@larkspur.test>"),
)


def build_eml(
    headers: Sequence[tuple[str, str]] = DEFAULT_HEADERS, body: str = "Hello.\r\n"
) -> bytes:
    head = "".join(f"{name}: {value}\r\n" for name, value in headers)
    return (head + "\r\n" + body).encode("utf-8")


def make_indicator(**overrides: Any) -> Indicator:
    fields: dict[str, Any] = {
        "type": IndicatorType.REPLY_TO_MISMATCH,
        "value": "account-review@mailbox-verify.test",
        "severity": Severity.MEDIUM,
        "evidence": "Replies go to mailbox-verify.test, not the sender's domain.",
        "source": IndicatorSource.HEADERS,
    }
    fields.update(overrides)
    return Indicator(**fields)


def make_email(**overrides: Any) -> ParsedEmail:
    raw = b"Subject: test\r\n\r\nbody"
    fields: dict[str, Any] = {
        "subject": "test",
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    fields.update(overrides)
    return ParsedEmail(**fields)


def make_report(
    *,
    indicators: Sequence[Indicator] = (),
    email: ParsedEmail | None = None,
    ai: AIRun | None = None,
    warnings: Sequence[str] = (),
) -> Report:
    return Report(
        email=email if email is not None else make_email(),
        indicators=tuple(indicators),
        ai=ai if ai is not None else AIRun(status=AIStatus.DISABLED),
        verdict=score_indicators(indicators, ScoringSettings()),
        warnings=tuple(warnings),
    )
