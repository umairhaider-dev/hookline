"""Models for the language model's assessment and how the call went."""

from enum import StrEnum
from typing import Annotated, Any, Self

from pydantic import ConfigDict, Field, StringConstraints, field_validator, model_validator

from hookline.models.base import FrozenModel

ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]

MAX_LIST_ITEMS = 10
MAX_EXPLANATION_CHARS = 4000


class AttackType(StrEnum):
    """The kind of attack the model believes the email represents."""

    CREDENTIAL_PHISHING = "credential_phishing"
    BEC = "bec"
    MALWARE_DELIVERY = "malware_delivery"
    SCAM = "scam"
    SPAM = "spam"
    BENIGN = "benign"


# Spellings models commonly produce for the categories above.
_ATTACK_TYPE_ALIASES = {
    "business_email_compromise": AttackType.BEC,
    "phishing": AttackType.CREDENTIAL_PHISHING,
    "credential_harvesting": AttackType.CREDENTIAL_PHISHING,
    "malware": AttackType.MALWARE_DELIVERY,
    "safe": AttackType.BENIGN,
    "legitimate": AttackType.BENIGN,
}


class AIAssessment(FrozenModel):
    """Structured judgement returned by the language model.

    This is the schema the model must answer in. Model output is untrusted, so
    every field is bounded. Unknown fields are ignored rather than rejected,
    since models often add commentary keys that carry no meaning for us.
    """

    model_config = ConfigDict(extra="ignore")

    phishing_likelihood: int = Field(ge=0, le=100)
    attack_type: AttackType
    tactics: tuple[ShortText, ...] = Field(
        default=(),
        max_length=MAX_LIST_ITEMS,
        description="Social engineering tactics, such as urgency or impersonation.",
    )
    explanation: str = Field(min_length=1, max_length=MAX_EXPLANATION_CHARS)
    recommended_actions: tuple[ShortText, ...] = Field(default=(), max_length=MAX_LIST_ITEMS)

    @field_validator("attack_type", mode="before")
    @classmethod
    def _normalize_attack_type(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        key = value.strip().lower().replace("-", "_").replace(" ", "_")
        return _ATTACK_TYPE_ALIASES.get(key, key)

    @field_validator("explanation", mode="before")
    @classmethod
    def _strip_explanation(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class AIStatus(StrEnum):
    """Outcome of consulting the language model."""

    COMPLETED = "completed"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    INVALID_OUTPUT = "invalid_output"
    FAILED = "failed"


class AIRun(FrozenModel):
    """What happened when the language model was consulted, and its answer if any."""

    status: AIStatus
    provider: str | None = None
    model: str | None = None
    attempts: int = Field(default=0, ge=0)
    duration_ms: float = Field(default=0.0, ge=0)
    redacted: bool = Field(
        default=False, description="Whether personal data was redacted before sending."
    )
    error: str | None = None
    notes: tuple[str, ...] = Field(
        default=(), description="What was done to the input or output, such as truncation."
    )
    assessment: AIAssessment | None = None

    @model_validator(mode="after")
    def _assessment_matches_status(self) -> Self:
        if (self.status is AIStatus.COMPLETED) != (self.assessment is not None):
            raise ValueError("an assessment must be present exactly when status is 'completed'")
        return self
