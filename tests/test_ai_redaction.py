import pytest

from hookline.ai.redaction import NoRedaction, Redactor


def test_email_addresses_keep_their_domain_and_a_stable_placeholder() -> None:
    redactor = Redactor([])
    text = redactor.redact(
        "From Sam.Ortega@larkspur.test to it@helpdesk.test; reply to sam.ortega@larkspur.test"
    )
    assert text == (
        "From [person 1]@larkspur.test to [person 2]@helpdesk.test; reply to "
        "[person 1]@larkspur.test"
    )
    assert redactor.count == 3


def test_recipient_names_are_replaced_as_whole_words() -> None:
    redactor = Redactor(["Sam Ortega", "sam.ortega", "Al", ""])
    text = redactor.redact("Dear SAM, Ortega family; samples and Al stay")
    assert text == "Dear [recipient], [recipient] family; samples and Al stay"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Call +1 (555) 010-4477 now", "Call [phone] now"),
        ("Card 4111 1111 1111 1111 expires", "Card [card number] expires"),
        ("Not a card 4111 1111 1111 1112", "Not a card 4111 1111 1111 1112"),
        ("IBAN DE89 3704 0044 0532 0130 00 please", "IBAN [IBAN] please"),
        ("SSN 078-05-1120", "SSN [ID number]"),
        ("Invoice INV-2026-1147", "Invoice INV-2026-1147"),
        ("Sent 2026-11-03 08:14", "Sent 2026-11-03 08:14"),
        ("Ref 12345", "Ref 12345"),
        ("Server 198.51.100.23 answered", "Server 198.51.100.23 answered"),
    ],
)
def test_numbers(text: str, expected: str) -> None:
    assert Redactor([]).redact(text) == expected


def test_url_query_values_and_fragments_are_removed() -> None:
    redactor = Redactor([])
    text = redactor.redact(
        "Go to https://evil.test/login?user=sam%40larkspur.test&step=2#c2FtQGxhcmtzcHVy and "
        "https://evil.test/plain or https://evil.test/a?#"
    )
    assert text == (
        "Go to https://evil.test/login?user=[redacted]&step=[redacted]#[redacted] and "
        "https://evil.test/plain or https://evil.test/a?"
    )


def test_no_redaction_passes_text_through() -> None:
    redactor = NoRedaction()
    assert redactor.redact("sam@larkspur.test") == "sam@larkspur.test"
    assert redactor.count == 0
