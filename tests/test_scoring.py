import pytest

from hookline.config import ScoringSettings
from hookline.models import (
    AIAssessment,
    AnalysisMode,
    AttackType,
    ContributionSource,
    IndicatorType,
    Severity,
    VerdictLabel,
)
from hookline.scoring import ai_points, score_indicators, score_verdict
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


def assessment(likelihood: int, attack_type: str = "credential_phishing") -> AIAssessment:
    return AIAssessment(
        phishing_likelihood=likelihood,
        attack_type=AttackType(attack_type),
        explanation="Reasons.",
    )


@pytest.mark.parametrize(
    ("likelihood", "points"), [(0, 0.0), (50, 0.0), (51, 0.8), (75, 20.0), (100, 40.0)]
)
def test_ai_points(likelihood: int, points: float) -> None:
    assert ai_points(likelihood, 40) == points


def test_combined_mode_adds_ai_points() -> None:
    high = make_indicator(type=IndicatorType.DMARC_FAIL, severity=Severity.HIGH)
    verdict = score_verdict([high], ScoringSettings(), assessment(90))
    assert verdict.mode is AnalysisMode.COMBINED
    assert verdict.score == 62
    ai_line = verdict.contributions[0]
    assert (ai_line.source, ai_line.label, ai_line.points) == (
        ContributionSource.AI,
        "ai_assessment",
        32,
    )
    assert ai_line.indicator_id is None
    assert "can never subtract" in ai_line.note
    assert verdict.summary.startswith("Score 62/100 from 1 scoring indicator and 32 AI point(s).")


@pytest.mark.parametrize("likelihood", [0, 10, 30, 50, 70, 100])
def test_the_ai_can_never_lower_the_rules_score(likelihood: int) -> None:
    indicators = [
        make_indicator(type=IndicatorType.PROMPT_INJECTION, severity=Severity.CRITICAL),
        make_indicator(type=IndicatorType.DMARC_FAIL, severity=Severity.HIGH),
    ]
    rules = score_verdict(indicators, ScoringSettings())
    combined = score_verdict(indicators, ScoringSettings(), assessment(likelihood, "benign"))
    assert combined.score >= rules.score
    assert combined.label is VerdictLabel.MALICIOUS
    rules_lines = {c.indicator_id for c in rules.contributions}
    assert rules_lines <= {c.indicator_id for c in combined.contributions}


def test_benign_ai_answer_adds_no_line() -> None:
    verdict = score_verdict([], ScoringSettings(), assessment(5, "benign"))
    assert verdict.contributions == ()
    assert verdict.label is VerdictLabel.LIKELY_SAFE


def test_ai_only_mode_uses_the_likelihood_alone() -> None:
    indicators = [make_indicator(severity=Severity.CRITICAL)]
    verdict = score_verdict(
        indicators, ScoringSettings(), assessment(40), mode=AnalysisMode.AI_ONLY
    )
    assert verdict.score == 40
    assert verdict.label is VerdictLabel.SUSPICIOUS
    (line,) = verdict.contributions
    assert line.source is ContributionSource.AI
    assert line.note.startswith("AI-only mode")


def test_explicit_rules_only_mode_ignores_the_assessment() -> None:
    verdict = score_verdict([], ScoringSettings(), assessment(100), mode=AnalysisMode.RULES_ONLY)
    assert verdict.score == 0
    assert verdict.mode is AnalysisMode.RULES_ONLY


@pytest.mark.parametrize("mode", [AnalysisMode.AI_ONLY, AnalysisMode.COMBINED])
def test_ai_modes_need_an_assessment(mode: AnalysisMode) -> None:
    with pytest.raises(ValueError, match="needs an AI assessment"):
        score_verdict([], ScoringSettings(), mode=mode)


def test_ai_weight_is_configurable() -> None:
    verdict = score_verdict([], ScoringSettings(ai_max_points=0), assessment(100))
    assert verdict.score == 0
