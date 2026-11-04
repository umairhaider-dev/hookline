import base64
from collections.abc import Callable

import pytest

from hookline.checks import LinkCheck
from hookline.config import CheckSettings
from hookline.models import EmailAddress, Indicator, IndicatorType, Link, LinkOrigin, Severity
from tests.factories import make_email

SETTINGS = CheckSettings(protected_domains=("larkspur.test",), url_shorteners=("bit.ly",))
RECIPIENT = "sam.ortega@larkspur.test"


def run(*links: Link) -> list[Indicator]:
    email = make_email(links=links, to=(EmailAddress(address=RECIPIENT),))
    return list(LinkCheck(SETTINGS).run(email))


def anchor(url: str, text: str = "") -> Link:
    return Link(url=url, text=text, origin=LinkOrigin.HTML_ANCHOR)


def plain(url: str) -> Link:
    return Link(url=url, origin=LinkOrigin.PLAIN_TEXT)


def kinds(indicators: list[Indicator]) -> set[tuple[IndicatorType, Severity]]:
    return {(i.type, i.severity) for i in indicators}


def test_ordinary_links_are_quiet() -> None:
    assert (
        run(
            anchor("https://www.larkspur.test/news", "Read the news"),
            anchor("https://portal.larkspur.test/login", "portal.larkspur.test"),
            plain("https://docs.example.test/guide"),
            anchor("mailto:help@larkspur.test", "help@larkspur.test"),
            anchor("#section", "Jump"),
            plain("http://[broken"),
        )
        == []
    )


def test_ip_address_link() -> None:
    (indicator,) = run(plain("http://198.51.100.23/files"))
    assert (indicator.type, indicator.severity) == (IndicatorType.IP_ADDRESS_URL, Severity.HIGH)
    assert "unusual numeric form" not in indicator.evidence


def test_disguised_ip_address_link() -> None:
    (indicator,) = run(plain("http://3325256727/files"))
    assert indicator.type is IndicatorType.IP_ADDRESS_URL
    assert "'3325256727'" in indicator.evidence
    assert "198.51.100.23" in indicator.evidence


@pytest.mark.parametrize(
    ("text", "url"),
    [
        ("https://portal.larkspur.test/reset", "http://198.51.100.23/owa/login"),
        ("portal.larkspur.test", "https://larkspur-reset.example.test/"),
        ("Visit www.larkspur.test today", "https://evil.test/"),
        ("http://198.51.100.1/", "http://198.51.100.2/"),
    ],
)
def test_link_text_mismatch(text: str, url: str) -> None:
    found = run(anchor(url, text))
    mismatch = [i for i in found if i.type is IndicatorType.LINK_TEXT_MISMATCH]
    assert len(mismatch) == 1
    assert mismatch[0].severity is Severity.HIGH


@pytest.mark.parametrize(
    "text", ["Click here", "Download invoice.pdf", "Mr. Smith", "https://www.larkspur.test"]
)
def test_link_text_without_conflicting_domain(text: str) -> None:
    found = run(anchor("https://portal.larkspur.test/", text))
    assert IndicatorType.LINK_TEXT_MISMATCH not in {i.type for i in found}


def test_plain_text_links_have_no_text_to_compare() -> None:
    assert run(plain("https://evil.test/")) == []


def test_url_shortener() -> None:
    (indicator,) = run(plain("https://bit.ly/3xAmpl3"))
    assert (indicator.type, indicator.severity) == (IndicatorType.URL_SHORTENER, Severity.MEDIUM)


@pytest.mark.parametrize(
    "url", ["javascript:alert(1)", "data:text/html;base64,PGh0bWw+", "VBScript:x"]
)
def test_active_schemes(url: str) -> None:
    (indicator,) = run(anchor(url, "Open"))
    assert (indicator.type, indicator.severity) == (IndicatorType.OBFUSCATED_URL, Severity.HIGH)


def test_userinfo_trick() -> None:
    found = run(plain("https://portal.larkspur.test@evil.test/"))
    (indicator,) = [i for i in found if i.type is IndicatorType.OBFUSCATED_URL]
    assert indicator.severity is Severity.HIGH
    assert "real host is evil.test" in indicator.evidence


def test_percent_encoded_host() -> None:
    (indicator,) = run(plain("http://%65vil.test/"))
    assert indicator.severity is Severity.HIGH
    assert "percent-encodes its host" in indicator.evidence


def test_heavily_encoded_path() -> None:
    (indicator,) = run(plain("https://evil.test/" + "%41" * 12))
    assert indicator.severity is Severity.MEDIUM
    assert "12 escapes" in indicator.evidence


def test_embedded_redirect_and_long_url_are_low() -> None:
    url = "https://track.example.test/c?u=https%3A%2F%2Fevil.test%2Fx&pad=" + "a" * 300
    (indicator,) = run(plain(url))
    assert indicator.severity is Severity.LOW
    assert "https://evil.test/x" in indicator.evidence
    assert "characters long" in indicator.evidence


@pytest.mark.parametrize(
    "encode", [base64.b64encode, base64.urlsafe_b64encode], ids=["standard", "urlsafe"]
)
def test_recipient_address_hidden_in_base64(encode: Callable[[bytes], bytes]) -> None:
    token = encode(RECIPIENT.encode()).decode().rstrip("=")
    found = run(plain(f"https://evil.test/start#{token}"))
    (indicator,) = [i for i in found if i.type is IndicatorType.OBFUSCATED_URL]
    assert indicator.severity is Severity.MEDIUM
    assert RECIPIENT in indicator.evidence


def test_base64_noise_without_recipient_is_ignored() -> None:
    assert run(plain("https://cdn.example.test/assets/AbCdEfGhIjKlMnOpQrSt.js")) == []
    assert run(plain("https://cdn.example.test/a?k=QUJDREVGR0hJSktMTU5PUA")) == []


def test_recipient_check_needs_recipients() -> None:
    token = base64.b64encode(RECIPIENT.encode()).decode()
    email = make_email(links=(plain(f"https://evil.test/#{token}"),))
    assert list(LinkCheck(SETTINGS).run(email)) == []


def test_login_path_on_unprotected_domain() -> None:
    (indicator,) = run(plain("https://evil.test/owa/auth/logon.aspx?replaceCurrent=1"))
    assert indicator.type is IndicatorType.CREDENTIAL_LOGIN_PATH
    assert indicator.severity is Severity.MEDIUM
    assert "(auth, logon, owa)" in indicator.evidence


def test_login_path_on_protected_domain_is_expected() -> None:
    assert run(plain("https://sso.larkspur.test/login")) == []


def test_words_inside_other_words_do_not_count() -> None:
    assert run(plain("https://evil.test/accountant/authority-report")) == []


def test_forms_are_flagged() -> None:
    (indicator,) = run(Link(url="https://collect.evil.test/post", origin=LinkOrigin.HTML_FORM))
    assert indicator.type is IndicatorType.CREDENTIAL_LOGIN_PATH
    assert "HTML form" in indicator.evidence


def test_recipients_in_cc_count_too() -> None:
    token = base64.b64encode(b"priya@larkspur.test").decode()
    email = make_email(
        links=(plain(f"https://evil.test/#{token}"),),
        cc=(EmailAddress(address="Priya@Larkspur.test"), EmailAddress(display_name="x")),
    )
    (indicator,) = LinkCheck(SETTINGS).run(email)
    assert "priya@larkspur.test" in indicator.evidence


def test_unparseable_url_in_link_text_is_skipped() -> None:
    found = run(anchor("https://portal.larkspur.test/", "http://[bad.test then larkspur.test"))
    assert found == []
