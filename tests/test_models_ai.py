from typing import Any

import pytest
from pydantic import ValidationError

from hookline.models import AIAssessment, AIRun, AIStatus, AttackType
from hookline.models.ai import MAX_EXPLANATION_CHARS, MAX_LIST_ITEMS

VALID: dict[str, Any] = {
    "phishing_likelihood": 87,
    "attack_type": "credential_phishing",
    "tactics": ["urgency", "authority"],
    "explanation": "Claims to be IT support and pushes a password reset to an IP address.",
    "recommended_actions": ["Block the sender domain"],
}


def assessment(**overrides: Any) -> AIAssessment:
    return AIAssessment.model_validate({**VALID, **overrides})


def test_valid_output_parses() -> None:
    result = assessment()
    assert result.phishing_likelihood == 87
    assert result.attack_type is AttackType.CREDENTIAL_PHISHING
    assert result.tactics == ("urgency", "authority")


@pytest.mark.parametrize("likelihood", [-1, 101, "very high", None])
def test_likelihood_must_be_0_to_100(likelihood: object) -> None:
    with pytest.raises(ValidationError):
        assessment(phishing_likelihood=likelihood)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Credential Phishing", AttackType.CREDENTIAL_PHISHING),
        ("BEC", AttackType.BEC),
        ("Business-Email Compromise", AttackType.BEC),
        ("malware", AttackType.MALWARE_DELIVERY),
        ("  benign ", AttackType.BENIGN),
        ("legitimate", AttackType.BENIGN),
    ],
)
def test_attack_type_spellings_are_normalized(raw: str, expected: AttackType) -> None:
    assert assessment(attack_type=raw).attack_type is expected


def test_unknown_attack_type_is_rejected() -> None:
    with pytest.raises(ValidationError):
        assessment(attack_type="ransomware")


def test_extra_keys_are_ignored() -> None:
    assert assessment(confidence="high", notes="extra").phishing_likelihood == 87


def test_list_lengths_are_capped() -> None:
    with pytest.raises(ValidationError):
        assessment(tactics=[f"tactic {i}" for i in range(MAX_LIST_ITEMS + 1)])


def test_blank_list_items_are_rejected() -> None:
    with pytest.raises(ValidationError):
        assessment(recommended_actions=["   "])


def test_explanation_is_stripped_and_required() -> None:
    assert assessment(explanation="  Looks fine.  ").explanation == "Looks fine."
    with pytest.raises(ValidationError):
        assessment(explanation="   ")


def test_explanation_length_is_capped() -> None:
    with pytest.raises(ValidationError):
        assessment(explanation="x" * (MAX_EXPLANATION_CHARS + 1))


def test_json_schema_carries_the_bounds() -> None:
    schema = AIAssessment.model_json_schema()
    likelihood = schema["properties"]["phishing_likelihood"]
    assert (likelihood["minimum"], likelihood["maximum"]) == (0, 100)
    assert set(schema["$defs"]["AttackType"]["enum"]) == {item.value for item in AttackType}


def test_completed_run_requires_an_assessment() -> None:
    with pytest.raises(ValidationError, match="exactly when status"):
        AIRun(status=AIStatus.COMPLETED)


@pytest.mark.parametrize("status", [s for s in AIStatus if s is not AIStatus.COMPLETED])
def test_other_statuses_cannot_carry_an_assessment(status: AIStatus) -> None:
    with pytest.raises(ValidationError):
        AIRun(status=status, assessment=assessment())


def test_completed_run() -> None:
    run = AIRun(
        status=AIStatus.COMPLETED,
        provider="ollama",
        model="llama3.1:8b",
        attempts=1,
        assessment=assessment(),
    )
    assert run.assessment is not None
