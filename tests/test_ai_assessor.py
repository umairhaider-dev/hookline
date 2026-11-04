import pytest

from hookline.ai import (
    ModelError,
    ModelRefusalError,
    ModelUnavailableError,
    parse_assessment,
    should_redact,
)
from hookline.ai.assessor import InvalidAnswerError
from hookline.config import RedactionMode
from hookline.models import AIStatus, AttackType, EmailAddress
from tests.ai_helpers import FakeModel, answer, make_assessor
from tests.factories import make_email, make_indicator

EMAIL = make_email(
    to=(EmailAddress(display_name="Sam Ortega", address="sam.ortega@larkspur.test"),),
    text_body="Dear Sam, confirm your password at https://evil.test/login?u=sam",
)


def test_valid_answer_completes() -> None:
    assessor, model = make_assessor()
    run = assessor.assess(EMAIL, (make_indicator(),))
    assert run.status is AIStatus.COMPLETED
    assert run.assessment is not None
    assert run.assessment.attack_type is AttackType.CREDENTIAL_PHISHING
    assert (run.provider, run.model, run.attempts) == ("fake", "fake-model", 1)
    assert not run.redacted
    assert run.duration_ms >= 0
    (request,) = model.requests
    assert request.schema["required"]
    assert [turn.role for turn in request.turns] == ["user"]
    assert "<<<EMAIL n0nce>>>" in request.system


def test_one_retry_after_an_invalid_answer() -> None:
    model = FakeModel(["I think it is phishing.", answer(phishing_likelihood=70)])
    assessor, _ = make_assessor(model)
    run = assessor.assess(EMAIL, ())
    assert run.status is AIStatus.COMPLETED
    assert run.attempts == 2
    assert run.notes == ("Answer 1 was invalid (it contained no JSON object).",)
    second = model.requests[1]
    assert [turn.role for turn in second.turns] == ["user", "assistant", "user"]
    assert second.turns[1].text == "I think it is phishing."
    assert "could not be used: it contained no JSON object" in second.turns[2].text


def test_two_invalid_answers_fall_back_to_rules() -> None:
    model = FakeModel(["", answer(phishing_likelihood=250)])
    assessor, _ = make_assessor(model)
    run = assessor.assess(EMAIL, ())
    assert run.status is AIStatus.INVALID_OUTPUT
    assert run.assessment is None
    assert run.attempts == 2
    assert run.error is not None
    assert run.error.startswith("no valid answer after 2 attempts: phishing_likelihood:")
    assert model.requests[1].turns[1].text == "(empty)"


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (ModelUnavailableError("Ollama is not reachable"), AIStatus.UNAVAILABLE),
        (ModelRefusalError("the model declined"), AIStatus.FAILED),
        (ModelError("the API key was rejected"), AIStatus.FAILED),
    ],
)
def test_model_errors(error: Exception, status: AIStatus) -> None:
    assessor, _ = make_assessor(FakeModel([error]))
    run = assessor.assess(EMAIL, ())
    assert run.status is status
    assert run.error == str(error)
    assert run.attempts == 1


def test_cloud_models_get_redacted_input() -> None:
    assessor, model = make_assessor(FakeModel(is_cloud=True))
    run = assessor.assess(EMAIL, ())
    assert run.redacted
    prompt = model.requests[0].turns[0].text
    assert "sam.ortega" not in prompt
    assert "Dear [recipient]" in prompt
    assert "u=[redacted]" in prompt
    assert any("personal data were redacted" in note for note in run.notes)


def test_local_models_get_the_original_text_unless_configured() -> None:
    assessor, model = make_assessor()
    assessor.assess(EMAIL, ())
    assert "Dear Sam" in model.requests[0].turns[0].text
    always, always_model = make_assessor(redaction=RedactionMode.ALWAYS)
    assert always.assess(EMAIL, ()).redacted
    assert "Dear Sam" not in always_model.requests[0].turns[0].text


@pytest.mark.parametrize(
    ("mode", "cloud", "expected"),
    [
        (RedactionMode.AUTO, True, True),
        (RedactionMode.AUTO, False, False),
        (RedactionMode.ALWAYS, False, True),
        (RedactionMode.NEVER, True, False),
    ],
)
def test_should_redact(mode: RedactionMode, cloud: bool, expected: bool) -> None:
    assert should_redact(mode, cloud=cloud) is expected


def test_close_closes_the_model() -> None:
    assessor, model = make_assessor()
    assessor.close()
    assert model.closed


@pytest.mark.parametrize(
    "reply",
    [
        answer(),
        f"```json\n{answer()}\n```",
        f"Here is my assessment:\n{answer()}\nThanks.",
        answer(attack_type="Business Email Compromise", unexpected="ignored"),
    ],
)
def test_parse_tolerates_wrapping(reply: str) -> None:
    assert parse_assessment(reply).phishing_likelihood == 90


@pytest.mark.parametrize(
    ("reply", "problem"),
    [
        ("no json here", "it contained no JSON object"),
        ("{not: json}", "it was not valid JSON"),
        ("[1, {2}]", "it was not valid JSON"),
        ('"a string with {} inside"', "phishing_likelihood: Field required"),
        (answer(attack_type="extortion"), "attack_type:"),
        (answer(explanation=""), "explanation:"),
        (answer(tactics=["x"] * 11), "tactics:"),
    ],
)
def test_parse_rejects_invalid_answers(reply: str, problem: str) -> None:
    with pytest.raises(InvalidAnswerError, match=problem):
        parse_assessment(reply)
