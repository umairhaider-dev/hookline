import logging
from collections.abc import Sequence
from pathlib import Path

import pytest

from hookline.checks import Check
from hookline.config import Settings
from hookline.errors import InputError
from hookline.models import (
    AIStatus,
    Indicator,
    IndicatorType,
    ParsedEmail,
    Severity,
    VerdictLabel,
)
from hookline.pipeline import Analyzer, read_email_file
from tests.factories import SAMPLES_DIR, build_eml, make_indicator


class StaticCheck:
    def __init__(self, name: str, indicators: Sequence[Indicator]) -> None:
        self.name = name
        self._indicators = list(indicators)

    def run(self, email: ParsedEmail) -> list[Indicator]:
        return list(self._indicators)


class BrokenCheck:
    name = "broken"

    def run(self, email: ParsedEmail) -> list[Indicator]:
        raise RuntimeError("bug in check")


def test_analyze_sample_file() -> None:
    report = Analyzer(Settings()).analyze_file(SAMPLES_DIR / "benign-meeting.eml")
    assert report.source_file == "benign-meeting.eml"
    assert report.email.subject == "Q4 planning notes"
    assert report.verdict.label is VerdictLabel.LIKELY_SAFE
    assert report.ai.status is AIStatus.UNAVAILABLE
    assert report.duration_ms > 0


def test_ai_can_be_disabled() -> None:
    report = Analyzer(Settings(ai_enabled=False)).analyze_bytes(build_eml())
    assert report.ai.status is AIStatus.DISABLED
    assert report.ai.error is None


def test_malformed_message_is_flagged() -> None:
    report = Analyzer(Settings()).analyze_bytes(build_eml([("Date", "whenever")]))
    assert IndicatorType.MALFORMED_MESSAGE in {i.type for i in report.indicators}
    assert report.verdict.label is VerdictLabel.LIKELY_SAFE


@pytest.mark.parametrize(
    ("sample", "label"),
    [
        ("benign-meeting.eml", VerdictLabel.LIKELY_SAFE),
        ("credential-phish.eml", VerdictLabel.MALICIOUS),
        ("bec-gift-card.eml", VerdictLabel.SUSPICIOUS),
        ("malware-attachment.eml", VerdictLabel.MALICIOUS),
        ("homoglyph-bank.eml", VerdictLabel.MALICIOUS),
    ],
)
def test_sample_verdicts_with_default_settings(sample: str, label: VerdictLabel) -> None:
    report = Analyzer(Settings()).analyze_file(SAMPLES_DIR / sample)
    assert report.verdict.label is label, report.verdict.summary


def test_benign_sample_has_only_informational_indicators() -> None:
    report = Analyzer(Settings()).analyze_file(SAMPLES_DIR / "benign-meeting.eml")
    assert {i.severity for i in report.indicators} == {Severity.INFO}


def test_phishing_sample_findings() -> None:
    report = Analyzer(Settings()).analyze_file(SAMPLES_DIR / "credential-phish.eml")
    found = {i.type for i in report.indicators}
    assert {
        IndicatorType.SPF_FAIL,
        IndicatorType.DMARC_FAIL,
        IndicatorType.REPLY_TO_MISMATCH,
        IndicatorType.SENDING_IP,
        IndicatorType.IP_ADDRESS_URL,
        IndicatorType.LINK_TEXT_MISMATCH,
        IndicatorType.CREDENTIAL_LOGIN_PATH,
        IndicatorType.URGENCY_LANGUAGE,
        IndicatorType.CREDENTIAL_REQUEST,
    } <= found


def test_duplicate_indicators_are_merged() -> None:
    first = make_indicator(severity=Severity.HIGH)
    duplicate = make_indicator(severity=Severity.HIGH, evidence="Same finding, other check.")
    checks = [StaticCheck("one", [first, first]), StaticCheck("two", [duplicate])]
    report = Analyzer(Settings(), checks=checks).analyze_bytes(build_eml())
    assert report.indicators == (first,)
    assert report.verdict.score == 30


def test_failing_check_becomes_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    survivor = make_indicator()
    checks: list[Check] = [BrokenCheck(), StaticCheck("ok", [survivor])]
    with caplog.at_level(logging.ERROR, logger="hookline"):
        report = Analyzer(Settings(), checks=checks).analyze_bytes(build_eml())
    assert report.indicators == (survivor,)
    assert report.warnings == ("Check 'broken' failed and was skipped: bug in check",)
    assert "Check broken failed" in caplog.text


def test_read_email_file(tmp_path: Path) -> None:
    path = tmp_path / "message.eml"
    path.write_bytes(build_eml())
    assert read_email_file(path, max_bytes=10_000) == build_eml()


def test_read_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="File not found"):
        read_email_file(tmp_path / "missing.eml", max_bytes=10_000)


def test_read_directory(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="Not a regular file"):
        read_email_file(tmp_path, max_bytes=10_000)


def test_read_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.eml"
    path.write_bytes(b"")
    with pytest.raises(InputError, match="empty"):
        read_email_file(path, max_bytes=10_000)


def test_read_file_over_limit(tmp_path: Path) -> None:
    path = tmp_path / "big.eml"
    path.write_bytes(b"x" * 101)
    assert read_email_file(path, max_bytes=101) == b"x" * 101
    with pytest.raises(InputError, match="100-byte limit"):
        read_email_file(path, max_bytes=100)


def test_read_error_is_wrapped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "locked.eml"
    path.write_bytes(build_eml())

    def deny(*_args: object, **_kwargs: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "open", deny)
    with pytest.raises(InputError, match=r"Could not read .*Permission denied"):
        read_email_file(path, max_bytes=10_000)
