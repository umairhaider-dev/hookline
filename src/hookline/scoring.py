"""Turns indicators into a transparent score and verdict.

Each indicator type adds the points configured for the severity of its most
severe instance. Repeats of the same type (ten long tracking links, say) add
nothing more, so a busy but harmless newsletter is not scored like ten separate
warning signs. The total is capped at 100 and compared against the suspicious
and malicious thresholds. Every non-zero contribution is kept so reports can
show exactly where the score came from.
"""

from collections import defaultdict
from collections.abc import Sequence

from hookline.config import ScoringSettings
from hookline.models.indicator import Indicator, IndicatorType
from hookline.models.verdict import (
    MAX_SCORE,
    AnalysisMode,
    ContributionSource,
    ScoreContribution,
    Verdict,
    VerdictLabel,
)


def score_indicators(indicators: Sequence[Indicator], settings: ScoringSettings) -> Verdict:
    """Score deterministic indicators and return the resulting verdict."""
    by_type: defaultdict[IndicatorType, list[Indicator]] = defaultdict(list)
    for indicator in indicators:
        by_type[indicator.type].append(indicator)

    contributions = []
    for group in by_type.values():
        strongest = max(group, key=lambda item: item.severity.rank)
        points = settings.severity_points[strongest.severity]
        if points <= 0:
            continue
        note = f"{strongest.severity.value} severity"
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
    contributions.sort(key=lambda item: item.points, reverse=True)

    raw_total = sum(item.points for item in contributions)
    score = min(raw_total, MAX_SCORE)
    label = VerdictLabel.for_score(
        score, settings.suspicious_threshold, settings.malicious_threshold
    )
    return Verdict(
        label=label,
        score=score,
        mode=AnalysisMode.RULES_ONLY,
        suspicious_threshold=settings.suspicious_threshold,
        malicious_threshold=settings.malicious_threshold,
        contributions=tuple(contributions),
        summary=_summary(score, raw_total, len(contributions), settings),
    )


def _summary(score: float, raw_total: float, counted: int, settings: ScoringSettings) -> str:
    noun = "indicator" if counted == 1 else "indicators"
    text = f"Score {score:g}/100 from {counted} scoring {noun}"
    if raw_total > score:
        text += f" (raw total {raw_total:g}, capped)"
    return (
        f"{text}. Suspicious from {settings.suspicious_threshold:g}, "
        f"malicious from {settings.malicious_threshold:g}."
    )
