"""Turns indicators and the AI assessment into a transparent score and verdict.

Each indicator type adds the points configured for the severity of its most
severe instance, or the points configured for that type in ``type_points``,
which lets a team weight one kind of finding up or down. Repeats of the same
type (ten long tracking links, say) add nothing more, so a busy but harmless
newsletter is not scored like ten separate warning signs.

The AI assessment can only add. A likelihood of 50 or below adds nothing, and
above that it adds up to ``ai_max_points``; the contribution is clamped at zero,
so no answer from the model, whatever the email persuaded it to say, can lower
the deterministic score, remove a finding or soften the verdict. This is the
code-level guarantee behind "the AI assists, it does not decide alone".

The total is capped at 100 and compared against the suspicious and malicious
thresholds. Every non-zero contribution is kept so reports can show exactly
where the score came from.
"""

from collections import defaultdict
from collections.abc import Sequence

from hookline.config import ScoringSettings
from hookline.models.ai import AIAssessment
from hookline.models.indicator import Indicator, IndicatorType
from hookline.models.verdict import (
    MAX_SCORE,
    AnalysisMode,
    ContributionSource,
    ScoreContribution,
    Verdict,
    VerdictLabel,
)

AI_NEUTRAL_LIKELIHOOD = 50
AI_LABEL = "ai_assessment"


def score_indicators(indicators: Sequence[Indicator], settings: ScoringSettings) -> Verdict:
    """Score deterministic indicators alone (rules-only mode)."""
    return score_verdict(indicators, settings)


def score_verdict(
    indicators: Sequence[Indicator],
    settings: ScoringSettings,
    assessment: AIAssessment | None = None,
    *,
    mode: AnalysisMode | None = None,
) -> Verdict:
    """Score the evidence and return the verdict.

    The mode defaults to combined when an assessment is given and rules-only
    otherwise. AI-only mode, used to evaluate the model on its own, scores the
    likelihood directly and ignores the indicators.
    """
    if mode is None:
        mode = AnalysisMode.COMBINED if assessment is not None else AnalysisMode.RULES_ONLY
    if mode is not AnalysisMode.RULES_ONLY and assessment is None:
        raise ValueError(f"{mode.value} scoring needs an AI assessment")

    contributions = (
        [] if mode is AnalysisMode.AI_ONLY else _indicator_contributions(indicators, settings)
    )
    if assessment is not None and mode is not AnalysisMode.RULES_ONLY:
        ai = _ai_contribution(assessment, settings, mode)
        if ai.points > 0:
            contributions.append(ai)
    contributions.sort(key=lambda item: item.points, reverse=True)

    raw_total = sum(item.points for item in contributions)
    score = min(raw_total, MAX_SCORE)
    label = VerdictLabel.for_score(
        score, settings.suspicious_threshold, settings.malicious_threshold
    )
    return Verdict(
        label=label,
        score=score,
        mode=mode,
        suspicious_threshold=settings.suspicious_threshold,
        malicious_threshold=settings.malicious_threshold,
        contributions=tuple(contributions),
        summary=_summary(score, raw_total, contributions, settings),
    )


def ai_points(likelihood: int, max_points: float) -> float:
    """Points the AI adds in combined mode: never negative, at most ``max_points``."""
    above_neutral = max(likelihood - AI_NEUTRAL_LIKELIHOOD, 0)
    return round(max_points * above_neutral / (100 - AI_NEUTRAL_LIKELIHOOD), 1)


def _indicator_contributions(
    indicators: Sequence[Indicator], settings: ScoringSettings
) -> list[ScoreContribution]:
    by_type: defaultdict[IndicatorType, list[Indicator]] = defaultdict(list)
    for indicator in indicators:
        by_type[indicator.type].append(indicator)

    contributions = []
    for group in by_type.values():
        strongest = max(group, key=lambda item: item.severity.rank)
        configured = settings.type_points.get(strongest.type)
        points = (
            configured if configured is not None else settings.severity_points[strongest.severity]
        )
        if points <= 0:
            continue
        note = f"{strongest.severity.value} severity"
        if configured is not None:
            note += "; points set for this type in the configuration"
        if len(group) > 1:
            note += f"; {len(group) - 1} more of this type not counted again"
        contributions.append(
            ScoreContribution(
                source=ContributionSource.INDICATOR,
                label=strongest.type.value,
                points=points,
                indicator_id=strongest.id,
                note=note,
            )
        )
    return contributions


def _ai_contribution(
    assessment: AIAssessment, settings: ScoringSettings, mode: AnalysisMode
) -> ScoreContribution:
    likelihood = assessment.phishing_likelihood
    if mode is AnalysisMode.AI_ONLY:
        return ScoreContribution(
            source=ContributionSource.AI,
            label=AI_LABEL,
            points=float(likelihood),
            note=f"AI-only mode: the score is the model's likelihood ({likelihood}/100)",
        )
    return ScoreContribution(
        source=ContributionSource.AI,
        label=AI_LABEL,
        points=ai_points(likelihood, settings.ai_max_points),
        note=(
            f"phishing likelihood {likelihood}/100; adds up to {settings.ai_max_points:g} "
            f"points above {AI_NEUTRAL_LIKELIHOOD} and can never subtract"
        ),
    )


def _summary(
    score: float,
    raw_total: float,
    contributions: Sequence[ScoreContribution],
    settings: ScoringSettings,
) -> str:
    counted = sum(item.source is ContributionSource.INDICATOR for item in contributions)
    ai_total = sum(item.points for item in contributions if item.source is ContributionSource.AI)
    noun = "indicator" if counted == 1 else "indicators"
    text = f"Score {score:g}/100 from {counted} scoring {noun}"
    if ai_total:
        text += f" and {ai_total:g} AI point(s)"
    if raw_total > score:
        text += f" (raw total {raw_total:g}, capped)"
    return (
        f"{text}. Suspicious from {settings.suspicious_threshold:g}, "
        f"malicious from {settings.malicious_threshold:g}."
    )
