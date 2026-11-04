import pytest

from hookline.checks import DomainCheck
from hookline.config import CheckSettings
from hookline.models import EmailAddress, Indicator, IndicatorType, Link, LinkOrigin, Severity
from tests.factories import make_email

CYRILLIC_A = "\N{CYRILLIC SMALL LETTER A}"
CYRILLIC_IE = "\N{CYRILLIC SMALL LETTER IE}"

SETTINGS = CheckSettings(
    protected_domains=(
        "larkspur.test",
        "fernhill-bank.test",
        "quillon-payroll.test",
        "microsoft.com",
        "office.com",
        "apple.com",
    ),
    suspicious_tlds=("zip", "top"),
)


def check_sender(domain: str) -> list[Indicator]:
    email = make_email(from_address=EmailAddress(address=f"someone@{domain}"))
    return list(DomainCheck(SETTINGS).run(email))


def kinds(indicators: list[Indicator]) -> list[tuple[IndicatorType, Severity]]:
    return [(i.type, i.severity) for i in indicators]


@pytest.mark.parametrize(
    "domain",
    ["larkspur.test", "mail.larkspur.test", "LARKSPUR.TEST.", "unrelated.test", "example.co.uk"],
)
def test_protected_and_unrelated_domains_are_quiet(domain: str) -> None:
    assert check_sender(domain) == []


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("larkspvr.test", (IndicatorType.LOOKALIKE_DOMAIN, Severity.HIGH)),
        ("larksupr.test", (IndicatorType.LOOKALIKE_DOMAIN, Severity.HIGH)),
        ("larkspurr.test", (IndicatorType.LOOKALIKE_DOMAIN, Severity.HIGH)),
        ("micrsooft.com", (IndicatorType.LOOKALIKE_DOMAIN, Severity.HIGH)),
        ("larkspur.example", (IndicatorType.LOOKALIKE_DOMAIN, Severity.MEDIUM)),
        ("larkspur-helpdesk.test", (IndicatorType.LOOKALIKE_DOMAIN, Severity.MEDIUM)),
        ("secure-larkspur.test", (IndicatorType.LOOKALIKE_DOMAIN, Severity.MEDIUM)),
        ("quillon-payroll-notify.test", (IndicatorType.LOOKALIKE_DOMAIN, Severity.MEDIUM)),
        ("larkspurpayroll.test", (IndicatorType.LOOKALIKE_DOMAIN, Severity.MEDIUM)),
        ("rnicrosoft.com", (IndicatorType.HOMOGLYPH_DOMAIN, Severity.HIGH)),
        ("app1e.com", (IndicatorType.HOMOGLYPH_DOMAIN, Severity.HIGH)),
    ],
)
def test_lookalikes(domain: str, expected: tuple[IndicatorType, Severity]) -> None:
    assert kinds(check_sender(domain)) == [expected]


def test_short_and_generic_names_are_not_fuzzy_matched() -> None:
    assert check_sender("apply.test") == []
    assert check_sender("offices.test") == []
    assert check_sender("office-supplies.test") == []
    assert check_sender("office.net") == []


def test_homoglyph_with_another_alphabet_is_critical() -> None:
    found = check_sender(f"l{CYRILLIC_A}rkspur.test")
    assert kinds(found) == [
        (IndicatorType.PUNYCODE_DOMAIN, Severity.MEDIUM),
        (IndicatorType.HOMOGLYPH_DOMAIN, Severity.CRITICAL),
    ]
    assert "U+0430 CYRILLIC SMALL LETTER A" in found[1].evidence
    assert "ASCII form xn--" in found[0].evidence


def test_punycode_sender_is_decoded_for_comparison() -> None:
    found = check_sender("xn--frnhill-bank-sck.test")
    assert kinds(found) == [
        (IndicatorType.PUNYCODE_DOMAIN, Severity.MEDIUM),
        (IndicatorType.HOMOGLYPH_DOMAIN, Severity.CRITICAL),
    ]
    assert f"f{CYRILLIC_IE}rnhill-bank.test" in found[0].evidence
    assert "ASCII form" not in found[0].evidence


def test_punycode_that_imitates_nothing() -> None:
    found = check_sender("xn--bcher-kva.test")
    assert kinds(found) == [(IndicatorType.PUNYCODE_DOMAIN, Severity.MEDIUM)]


def test_protected_domain_in_subdomain() -> None:
    found = check_sender("larkspur.test.account-verify.test")
    assert kinds(found) == [(IndicatorType.LOOKALIKE_DOMAIN, Severity.HIGH)]
    assert found[0].value == "larkspur.test.account-verify.test"
    assert "only a subdomain prefix" in found[0].evidence


def test_suspicious_tld() -> None:
    found = check_sender("invoices-online.top")
    assert kinds(found) == [(IndicatorType.SUSPICIOUS_TLD, Severity.LOW)]
    assert ".top" in found[0].evidence


def test_hosts_are_grouped_by_registrable_domain() -> None:
    email = make_email(
        from_address=EmailAddress(address="it@larkspur-helpdesk.test"),
        reply_to=(EmailAddress(address="x@larkspur-helpdesk.test"), EmailAddress(address="bad")),
        return_path="bounce@mailer.larkspur-helpdesk.test",
        links=(
            Link(url="https://portal.larkspur-helpdesk.test/x", origin=LinkOrigin.HTML_ANCHOR),
            Link(url="http://198.51.100.23/", origin=LinkOrigin.HTML_ANCHOR),
            Link(url="mailto:help@larkspvr.test", origin=LinkOrigin.HTML_ANCHOR),
            Link(url="http://[bad", origin=LinkOrigin.PLAIN_TEXT),
        ),
    )
    (indicator,) = DomainCheck(SETTINGS).run(email)
    assert indicator.value == "larkspur-helpdesk.test"
    assert indicator.evidence.startswith(
        "larkspur-helpdesk.test (in the From address, Reply-To, Return-Path, links; as "
        "mailer.larkspur-helpdesk.test, portal.larkspur-helpdesk.test)"
    )


def test_link_only_domain() -> None:
    email = make_email(
        links=(Link(url="https://larkspvr.test/login", origin=LinkOrigin.PLAIN_TEXT),)
    )
    (indicator,) = DomainCheck(SETTINGS).run(email)
    assert indicator.evidence.startswith("larkspvr.test (in the links)")


def test_strongest_lookalike_is_kept_across_protected_domains() -> None:
    found = check_sender("microsoft-larkspur.test")
    assert kinds(found) == [(IndicatorType.LOOKALIKE_DOMAIN, Severity.MEDIUM)]
    assert "'larkspur'" in found[0].evidence


def test_undecodable_punycode_has_no_letter_list() -> None:
    (indicator,) = check_sender("xn--99999999999.test")
    assert indicator.type is IndicatorType.PUNYCODE_DOMAIN
    assert "Non-ASCII characters" not in indicator.evidence


def test_long_lists_of_unusual_letters_are_shortened() -> None:
    label = "".join(chr(code) for code in range(0x0430, 0x0437))
    found = check_sender(f"{label}.test")
    assert "and 2 more." in found[0].evidence


def test_ip_literal_sender_domain_is_skipped() -> None:
    email = make_email(from_address=EmailAddress(address="x@[203.0.113.5]"))
    assert list(DomainCheck(SETTINGS).run(email)) == []
