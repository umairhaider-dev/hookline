from typing import Any

import pytest
from pydantic import ValidationError

from hookline.models import (
    AnalysisMode,
    ContributionSource,
    MitreTechnique,
    Report,
    ScoreContribution,
    Severity,
    Verdict,
    VerdictLabel,
)
from hookline.reporting import render_json
from tests.factories import make_email, make_indicator, make_report


@pytest.mark.parametrize(
    ("score", "label"),
    [
        (0, VerdictLabel.LIKELY_SAFE),
        (34.9, VerdictLabel.LIKELY_SAFE),
        (35, VerdictLabel.SUSPICIOUS),
        (69.9, VerdictLabel.SUSPICIOUS),
        (70, VerdictLabel.MALICIOUS),
        (100, VerdictLabel.MALICIOUS),
    ],
)
def test_label_for_score_uses_inclusive_thresholds(score: float, label: VerdictLabel) -> None:
    assert VerdictLabel.for_score(score, 35, 70) is label


def verdict(**overrides: Any) -> Verdict:
    fields: dict[str, Any] = {
        "label": VerdictLabel.LIKELY_SAFE,
        "score": 0.0,
        "mode": AnalysisMode.RULES_ONLY,
        "suspicious_threshold": 35.0,
        "malicious_threshold": 70.0,
    }
    fields.update(overrides)
    return Verdict(**fields)


def test_verdict_rejects_label_that_contradicts_score() -> None:
    with pytest.raises(ValidationError, match="does not match score"):
        verdict(label=VerdictLabel.LIKELY_SAFE, score=80.0)


def test_verdict_rejects_inverted_thresholds() -> None:
    with pytest.raises(ValidationError, match="lower than"):
        verdict(suspicious_threshold=70.0, malicious_threshold=35.0)


@pytest.mark.parametrize("score", [-1.0, 100.5])
def test_verdict_score_is_bounded(score: float) -> None:
    with pytest.raises(ValidationError):
        verdict(score=score)


def test_report_rejects_contribution_for_unknown_indicator() -> None:
    orphan = ScoreContribution(
        source=ContributionSource.INDICATOR, label="spf_fail", points=5, indicator_id="000000000000"
    )
    with pytest.raises(ValidationError, match="unknown indicator ids"):
        Report(
            email=make_email(),
            ai=make_report().ai,
            verdict=verdict(contributions=(orphan,)),
        )


def test_report_rejects_mitre_mapping_to_unknown_indicator() -> None:
    technique = MitreTechnique(
        technique_id="T1566.002", name="Spearphishing Link", indicator_ids=("ffffffffffff",)
    )
    base = make_report()
    with pytest.raises(ValidationError, match="unknown indicator ids"):
        Report(email=base.email, ai=base.ai, verdict=base.verdict, mitre_techniques=(technique,))


@pytest.mark.parametrize("technique_id", ["T1566", "T1566.001"])
def test_mitre_technique_ids_accepted(technique_id: str) -> None:
    assert MitreTechnique(technique_id=technique_id, name="Phishing").technique_id == technique_id


@pytest.mark.parametrize("technique_id", ["T1566.1", "X1566", "t1566", "T15660"])
def test_mitre_technique_ids_rejected(technique_id: str) -> None:
    with pytest.raises(ValidationError):
        MitreTechnique(technique_id=technique_id, name="Phishing")


def test_report_survives_a_json_round_trip() -> None:
    indicators = [
        make_indicator(),
        make_indicator(value="198.51.100.23", severity=Severity.HIGH),
    ]
    report = make_report(indicators=indicators, warnings=["check 'x' failed"])
    assert report.verdict.contributions  # the round trip must cover linked indicators
    assert Report.model_validate_json(render_json(report)) == report


def test_indicators_by_severity_sorts_most_severe_first() -> None:
    low = make_indicator(value="a", severity=Severity.LOW)
    high = make_indicator(value="b", severity=Severity.HIGH)
    info = make_indicator(value="c", severity=Severity.INFO)
    report = make_report(indicators=[low, high, info])
    assert report.indicators_by_severity() == [high, low, info]


def test_generated_at_is_timezone_aware() -> None:
    assert make_report().generated_at.utcoffset() is not None
