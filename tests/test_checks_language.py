import pytest

from hookline.checks import LanguageCheck, language
from hookline.checks.language import normalize_text
from hookline.models import Indicator, IndicatorSource, IndicatorType, Severity
from tests.factories import make_email

ZERO_WIDTH_SPACE = "\N{ZERO WIDTH SPACE}"
RIGHT_QUOTE = "\N{RIGHT SINGLE QUOTATION MARK}"


def run(text: str, subject: str = "") -> dict[IndicatorType, Indicator]:
    email = make_email(subject=subject, text_body=text)
    return {i.type: i for i in LanguageCheck().run(email)}


def test_ordinary_message_is_quiet() -> None:
    assert run("Hi Sam, the planning notes are in the shared folder. See you Tuesday.") == {}


@pytest.mark.parametrize(
    ("text", "kind", "severity"),
    [
        ("Please reply urgently.", IndicatorType.URGENCY_LANGUAGE, Severity.LOW),
        ("Confirm your password here.", IndicatorType.CREDENTIAL_REQUEST, Severity.MEDIUM),
        ("Your mailbox is full.", IndicatorType.CREDENTIAL_REQUEST, Severity.MEDIUM),
        (
            "Please send me the code you received.",
            IndicatorType.CREDENTIAL_REQUEST,
            Severity.MEDIUM,
        ),
        ("We updated our bank details.", IndicatorType.PAYMENT_REQUEST, Severity.MEDIUM),
        ("Please process a wire transfer.", IndicatorType.PAYMENT_REQUEST, Severity.HIGH),
        ("Buy a gift card for the event.", IndicatorType.GIFT_CARD_REQUEST, Severity.MEDIUM),
    ],
)
def test_categories(text: str, kind: IndicatorType, severity: Severity) -> None:
    found = run(text)
    assert found[kind].severity is severity
    assert found[kind].source is IndicatorSource.LANGUAGE


def test_several_phrases_raise_severity_and_are_listed() -> None:
    found = run(
        "Action required: your account will be suspended. Act now, within 24 hours. "
        "This is your final notice. Respond immediately or it is too late."
    )
    urgency = found[IndicatorType.URGENCY_LANGUAGE]
    assert urgency.severity is Severity.MEDIUM
    assert urgency.evidence.startswith("Found 6 pressure or secrecy phrase(s): 'immediately', ")
    assert urgency.evidence.endswith(" and 1 more.")
    assert urgency.value.count(";") == 4


def test_severity_bump_stops_at_high() -> None:
    found = run(
        "Purchase Apple cards, scratch the back and send pictures of the codes. Gift cards only."
    )
    assert found[IndicatorType.GIFT_CARD_REQUEST].severity is Severity.HIGH


def test_subject_is_included() -> None:
    assert IndicatorType.URGENCY_LANGUAGE in run("Hello", subject="URGENT: invoice")


def test_html_text_is_included() -> None:
    email = make_email(html_text="Verify your account today.")
    found = {i.type for i in LanguageCheck().run(email)}
    assert IndicatorType.CREDENTIAL_REQUEST in found


def test_evasion_with_invisible_characters_and_fullwidth_letters() -> None:
    hidden = f"conf{ZERO_WIDTH_SPACE}irm your   pass{ZERO_WIDTH_SPACE}word"
    assert IndicatorType.CREDENTIAL_REQUEST in run(hidden)
    fullwidth = "\N{FULLWIDTH LATIN CAPITAL LETTER U}RGENT"
    assert IndicatorType.URGENCY_LANGUAGE in run(fullwidth)


def test_normalize_text() -> None:
    assert normalize_text(f"Don{RIGHT_QUOTE}t\n\tWAIT") == "don't wait"


def test_only_the_start_of_long_bodies_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(language, "MAX_TEXT_CHARS", 50)
    assert run("x" * 60 + " urgent") == {}
    assert IndicatorType.URGENCY_LANGUAGE in run("urgent " + "x" * 60)
