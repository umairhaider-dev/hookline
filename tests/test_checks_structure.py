from hookline.checks import MessageStructureCheck, build_checks
from hookline.config import CheckSettings
from hookline.models import IndicatorSource, IndicatorType, Severity
from tests.factories import make_email


def test_clean_message_has_no_indicator() -> None:
    assert list(MessageStructureCheck().run(make_email())) == []


def test_defects_become_one_low_severity_indicator() -> None:
    email = make_email(defects=("MissingHeaderBodySeparatorDefect", "Date header: bad"))
    (indicator,) = MessageStructureCheck().run(email)
    assert indicator.type is IndicatorType.MALFORMED_MESSAGE
    assert indicator.severity is Severity.LOW
    assert indicator.source is IndicatorSource.PARSER
    assert indicator.value == "2 defect(s)"
    assert "MissingHeaderBodySeparatorDefect; Date header: bad" in indicator.evidence


def test_evidence_lists_at_most_five_defects() -> None:
    email = make_email(defects=tuple(f"defect {n}" for n in range(8)))
    (indicator,) = MessageStructureCheck().run(email)
    assert "defect 4" in indicator.evidence
    assert "defect 5" not in indicator.evidence
    assert indicator.evidence.endswith("and 3 more")


def test_default_checks_include_structure_check() -> None:
    checks = build_checks(CheckSettings())
    assert any(isinstance(check, MessageStructureCheck) for check in checks)
