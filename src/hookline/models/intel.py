"""Results of optional threat intelligence lookups."""

from enum import StrEnum

from pydantic import AwareDatetime, Field

from hookline.models.base import FrozenModel

MAX_SUMMARY_LENGTH = 1000


class ObservableKind(StrEnum):
    """What kind of value is being looked up."""

    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    SHA256 = "sha256"


class Observable(FrozenModel):
    """A value taken from the email that a provider can be asked about."""

    kind: ObservableKind
    value: str = Field(min_length=1)


class IntelVerdict(StrEnum):
    """A provider's opinion of one observable."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"  # the provider has no record of it


class IntelResult(FrozenModel):
    """One provider's answer about one observable."""

    provider: str
    observable: Observable
    verdict: IntelVerdict
    summary: str = Field(
        max_length=MAX_SUMMARY_LENGTH,
        description="What the provider reported. Comes from a third party, so treat as untrusted.",
    )
    reference: str | None = Field(default=None, description="Link to the provider's record.")
    checked_at: AwareDatetime
    from_cache: bool = False


class IntelStatus(StrEnum):
    """How the threat intelligence step went."""

    DISABLED = "disabled"
    COMPLETED = "completed"
    PARTIAL = "partial"  # some lookups failed or were skipped
    FAILED = "failed"


class IntelRun(FrozenModel):
    """Everything the threat intelligence step did for one email."""

    status: IntelStatus
    providers: tuple[str, ...] = ()
    results: tuple[IntelResult, ...] = ()
    problems: tuple[str, ...] = Field(
        default=(), description="Failed, rate-limited or skipped lookups."
    )
    note: str | None = Field(default=None, description="Why nothing was looked up, if so.")
    duration_ms: float = Field(default=0.0, ge=0)
