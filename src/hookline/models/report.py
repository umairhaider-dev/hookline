"""The complete analysis report for one email."""

from datetime import UTC, datetime
from typing import Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, model_validator

from hookline import __version__
from hookline.models.ai import AIRun
from hookline.models.base import FrozenModel
from hookline.models.email import ParsedEmail
from hookline.models.indicator import Indicator
from hookline.models.verdict import Verdict


def _utcnow() -> datetime:
    return datetime.now(UTC)


class IOCSet(FrozenModel):
    """Indicators of compromise extracted from the message, for blocking and hunting."""

    urls: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    ip_addresses: tuple[str, ...] = ()
    email_addresses: tuple[str, ...] = ()
    sha256_hashes: tuple[str, ...] = ()


class MitreTechnique(FrozenModel):
    """A MITRE ATT&CK technique the findings map to."""

    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    name: str
    indicator_ids: tuple[str, ...] = ()


class Report(FrozenModel):
    """Everything Hookline concluded about one email."""

    report_id: UUID = Field(default_factory=uuid4)
    generated_at: AwareDatetime = Field(default_factory=_utcnow)
    tool_version: str = __version__
    source_file: str | None = Field(default=None, description="File name of the analyzed email.")
    email: ParsedEmail
    indicators: tuple[Indicator, ...] = ()
    ai: AIRun
    verdict: Verdict
    iocs: IOCSet = Field(default_factory=IOCSet)
    mitre_techniques: tuple[MitreTechnique, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = Field(
        default=(), description="Problems that made the analysis incomplete."
    )
    duration_ms: float = Field(default=0.0, ge=0)

    @model_validator(mode="after")
    def _references_are_known(self) -> Self:
        known = {indicator.id for indicator in self.indicators}
        referenced = {item.indicator_id for item in self.verdict.contributions if item.indicator_id}
        for technique in self.mitre_techniques:
            referenced.update(technique.indicator_ids)
        missing = referenced - known
        if missing:
            raise ValueError(f"report references unknown indicator ids: {sorted(missing)}")
        return self

    def indicators_by_severity(self) -> list[Indicator]:
        """Indicators sorted from most to least severe, keeping check order within a level."""
        return sorted(self.indicators, key=lambda item: item.severity.rank, reverse=True)
