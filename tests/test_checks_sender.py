import pytest

from hookline.checks import SenderCheck
from hookline.config import CheckSettings
from hookline.models import EmailAddress, Indicator, IndicatorType, Severity
from tests.factories import make_email

SETTINGS = CheckSettings(
    protected_domains=("larkspur.test", "office.com", "fernhill-bank.test"),
    freemail_domains=("inboxmail.test",),
)


def run(**fields: object) -> list[Indicator]:
    return list(SenderCheck(SETTINGS).run(make_email(**fields)))


def sender(address: str, name: str = "") -> EmailAddress:
    return EmailAddress(display_name=name, address=address)


def test_consistent_sender_is_quiet() -> None:
    found = run(
        from_address=sender("dana@larkspur.test", "Dana Whitfield"),
        reply_to=(sender("dana@mail.larkspur.test"),),
        return_path="bounce@bounces.larkspur.test",
    )
    assert found == []


def test_no_sender_or_no_domain() -> None:
    assert run() == []
    assert run(from_address=sender("undisclosed-recipients")) == []


def test_reply_to_mismatch() -> None:
    (indicator,) = run(
        from_address=sender("it@larkspur-helpdesk.test"),
        reply_to=(sender("review@mailbox-verify.test"), sender("nodomain")),
    )
    assert indicator.type is IndicatorType.REPLY_TO_MISMATCH
    assert indicator.severity is Severity.MEDIUM
    assert indicator.value == "review@mailbox-verify.test"


def test_reply_to_freemail_from_business_sender_is_high() -> None:
    (indicator,) = run(
        from_address=sender("ceo@vendor.test"), reply_to=(sender("ceo.vendor@inboxmail.test"),)
    )
    assert indicator.severity is Severity.HIGH
    assert "free webmail" in indicator.evidence


def test_return_path_mismatch_is_low() -> None:
    (indicator,) = run(
        from_address=sender("news@larkspur.test"), return_path="bounce-1@esp.example.test"
    )
    assert indicator.type is IndicatorType.RETURN_PATH_MISMATCH
    assert indicator.severity is Severity.LOW


def test_return_path_without_domain_is_ignored() -> None:
    assert run(from_address=sender("news@larkspur.test"), return_path="postmaster") == []


@pytest.mark.parametrize(
    "name",
    [
        "service@larkspur.test",
        "Larkspur IT <it@larkspur.test>",
        "billing.larkspur.test",
    ],
)
def test_display_name_showing_another_address_or_domain(name: str) -> None:
    (indicator,) = run(from_address=sender("x@evil.test", name))
    assert indicator.type is IndicatorType.DISPLAY_NAME_SPOOFING
    assert indicator.severity is Severity.HIGH
    assert indicator.value == f'"{name}" <x@evil.test>'


def test_display_name_showing_own_domain_is_fine() -> None:
    assert run(from_address=sender("it@larkspur.test", "it@larkspur.test")) == []
    assert run(from_address=sender("x@evil.test", "J. Smith, Ph.D")) == []


@pytest.mark.parametrize(
    "name", ["Larkspur IT Service Desk", "LARKSPUR payroll", "Iarkspur Support"]
)
def test_display_name_mentioning_protected_brand(name: str) -> None:
    (indicator,) = run(from_address=sender("it@larkspur-helpdesk.test", name))
    assert indicator.severity is Severity.MEDIUM
    assert "suggests larkspur.test" in indicator.evidence


def test_brand_name_from_freemail_is_high() -> None:
    (indicator,) = run(from_address=sender("dana@inboxmail.test", "Dana | Larkspur"))
    assert indicator.severity is Severity.HIGH
    assert "free webmail" in indicator.evidence


def test_brand_name_from_the_brand_itself_is_fine() -> None:
    assert run(from_address=sender("it@mail.larkspur.test", "Larkspur IT")) == []


def test_generic_brand_words_are_not_matched() -> None:
    assert run(from_address=sender("pat@smallbiz.test", "Office Manager")) == []


def test_name_without_claims() -> None:
    assert run(from_address=sender("pat@smallbiz.test", "Pat Lee")) == []


def test_file_names_in_display_names_are_not_domains() -> None:
    assert run(from_address=sender("scanner@larkspur.test", "scan.pdf sender")) == []
