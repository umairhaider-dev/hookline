"""The final verdict and the score breakdown behind it."""

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from hookline.models.base import FrozenModel

MAX_SCORE = 100.0


class VerdictLabel(StrEnum):
    """The analyst-facing conclusion."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    LIKELY_SAFE = "likely_safe"

    @classmethod
    def for_score(
        cls, score: float, suspicious_threshold: float, malicious_threshold: float
    ) -> "VerdictLabel":
        """Map a score onto a label using the given thresholds (inclusive)."""
        if score >= malicious_threshold:
            return cls.MALICIOUS
        if score >= suspicious_threshold:
            return cls.SUSPICIOUS
        return cls.LIKELY_SAFE


class AnalysisMode(StrEnum):
    """Which evidence the score was built from."""

    RULES_ONLY = "rules_only"
    AI_ONLY = "ai_only"
    COMBINED = "combined"


class ContributionSource(StrEnum):
    """Where a score contribution came from."""

    INDICATOR = "indicator"
    AI = "ai"


class ScoreContribution(FrozenModel):
    """One line of the score breakdown shown in reports."""

    source: ContributionSource
    label: str = Field(description="Indicator type, or the AI factor being counted.")
    points: float
    indicator_id: str | None = Field(
        default=None, description="The indicator this line counts, if any."
    )
    note: str = Field(default="", description="How the points were worked out.")


class Verdict(FrozenModel):
    """The scored conclusion, with every contribution that produced it."""

    label: VerdictLabel
    score: float = Field(ge=0, le=MAX_SCORE)
    mode: AnalysisMode
    suspicious_threshold: float = Field(gt=0, le=MAX_SCORE)
    malicious_threshold: float = Field(gt=0, le=MAX_SCORE)
    contributions: tuple[ScoreContribution, ...] = ()
    summary: str = ""

    @model_validator(mode="after")
    def _label_matches_score(self) -> Self:
        if self.suspicious_threshold >= self.malicious_threshold:
            raise ValueError("suspicious_threshold must be lower than malicious_threshold")
        expected = VerdictLabel.for_score(
            self.score, self.suspicious_threshold, self.malicious_threshold
        )
        if self.label is not expected:
            raise ValueError(
                f"label {self.label.value!r} does not match score {self.score:g} "
                f"(expected {expected.value!r})"
            )
        return self
