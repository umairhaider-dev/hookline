from hookline.config import ScoringSettings
from hookline.models import (
    AnalysisMode,
    ContributionSource,
    IndicatorType,
    Severity,
    VerdictLabel,
)
from hookline.scoring import score_indicators
from tests.factories import make_indicator


def test_no_indicators_is_likely_safe() -> None:
    verdict = score_indicators([], ScoringSettings())
    assert verdict.label is VerdictLabel.LIKELY_SAFE
    assert verdict.score == 0
    assert verdict.mode is AnalysisMode.RULES_ONLY
    assert verdict.contributions == ()


def test_points_follow_severity_and_link_to_indicators() -> None:
    medium = make_indicator(value="a", severity=Severity.MEDIUM)
    high = make_indicator(type=IndicatorType.DMARC_FAIL, value="b", severity=Severity.HIGH)
    verdict = score_indicators([medium, high], ScoringSettings())
    assert verdict.score == 45
    assert verdict.label is VerdictLabel.SUSPICIOUS
    assert [(c.indicator_id, c.points) for c in verdict.contributions] == [
        (high.id, 30),
        (medium.id, 15),
    ]
    assert all(c.source is ContributionSource.INDICATOR for c in verdict.contributions)
    assert verdict.contributions[0].note == "high severity"


def test_info_indicators_do_not_contribute() -> None:
    verdict = score_indicators([make_indicator(severity=Severity.INFO)], ScoringSettings())
    assert verdict.score == 0
    assert verdict.contributions == ()


def test_score_is_capped_at_100() -> None:
    kinds = (IndicatorType.SPF_FAIL, IndicatorType.DKIM_FAIL, IndicatorType.DMARC_FAIL)
    indicators = [make_indicator(type=kind, severity=Severity.CRITICAL) for kind in kinds]
    verdict = score_indicators(indicators, ScoringSettings())
    assert verdict.score == 100
    assert verdict.label is VerdictLabel.MALICIOUS
    assert "raw total 150, capped" in verdict.summary


def test_custom_points_and_thresholds() -> None:
    settings = ScoringSettings(
        severity_points={Severity.LOW: 20},
        suspicious_threshold=10,
        malicious_threshold=40,
    )
    indicators = [
        make_indicator(type=IndicatorType.SPF_FAIL, severity=Severity.LOW),
        make_indicator(type=IndicatorType.DKIM_FAIL, severity=Severity.LOW),
    ]
    verdict = score_indicators(indicators, settings)
    assert verdict.score == 40
    assert verdict.label is VerdictLabel.MALICIOUS
    assert (verdict.suspicious_threshold, verdict.malicious_threshold) == (10, 40)


def test_summary_wording() -> None:
    one = score_indicators([make_indicator()], ScoringSettings())
    assert one.summary == (
        "Score 15/100 from 1 scoring indicator. Suspicious from 35, malicious from 70."
    )


def test_repeats_of_one_type_count_once_at_their_highest_severity() -> None:
    low = make_indicator(value="a", severity=Severity.LOW)
    high = make_indicator(value="b", severity=Severity.HIGH)
    medium = make_indicator(value="c", severity=Severity.MEDIUM)
    verdict = score_indicators([low, high, medium], ScoringSettings())
    assert verdict.score == 30
    (contribution,) = verdict.contributions
    assert contribution.indicator_id == high.id
    assert contribution.note == "high severity; 2 more of this type not counted again"
