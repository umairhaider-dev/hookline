import pytest

from hookline.checks import AuthenticationCheck
from hookline.models import AuthResult, IndicatorSource, IndicatorType, Severity
from tests.factories import make_email


def result(method: str, outcome: str, index: int = 0, **properties: str) -> AuthResult:
    return AuthResult(
        method=method,
        result=outcome,
        properties={key.replace("_", "."): value for key, value in properties.items()},
        authserv_id="mx1.larkspur.test" if index == 0 else "forged.test",
        header_index=index,
    )


def run(
    *results: AuthResult, trusted: tuple[str, ...] = ()
) -> list[tuple[IndicatorType, Severity]]:
    email = make_email(authentication_results=results)
    return [(i.type, i.severity) for i in AuthenticationCheck(trusted).run(email)]


def test_all_passing_is_quiet() -> None:
    assert run(result("spf", "pass"), result("dkim", "pass"), result("dmarc", "pass")) == []


@pytest.mark.parametrize(
    ("method", "outcome", "expected"),
    [
        ("spf", "fail", (IndicatorType.SPF_FAIL, Severity.MEDIUM)),
        ("spf", "softfail", (IndicatorType.SPF_FAIL, Severity.LOW)),
        ("spf", "permerror", (IndicatorType.SPF_FAIL, Severity.LOW)),
        ("dkim", "fail", (IndicatorType.DKIM_FAIL, Severity.MEDIUM)),
        ("dkim", "permerror", (IndicatorType.DKIM_FAIL, Severity.LOW)),
        ("dmarc", "fail", (IndicatorType.DMARC_FAIL, Severity.HIGH)),
        ("dmarc", "permerror", (IndicatorType.DMARC_FAIL, Severity.LOW)),
    ],
)
def test_failures(method: str, outcome: str, expected: tuple[IndicatorType, Severity]) -> None:
    assert run(result(method, outcome)) == [expected]


@pytest.mark.parametrize("outcome", ["none", "neutral", "temperror", "policy"])
def test_inconclusive_results_are_not_failures(outcome: str) -> None:
    assert run(result("spf", outcome), result("dkim", outcome)) == []


def test_evidence_names_the_server_and_domain() -> None:
    email = make_email(
        authentication_results=(result("spf", "fail", smtp_mailfrom="bounce@evil.test"),)
    )
    (indicator,) = AuthenticationCheck().run(email)
    assert indicator.value == "spf=fail (evil.test)"
    assert indicator.source is IndicatorSource.HEADERS
    assert indicator.evidence.startswith("mx1.larkspur.test recorded spf=fail (evil.test): ")


def test_result_without_domain_or_server() -> None:
    email = make_email(authentication_results=(AuthResult(method="dmarc", result="fail"),))
    (indicator,) = AuthenticationCheck().run(email)
    assert indicator.value == "dmarc=fail"
    assert indicator.evidence.startswith("the receiving server recorded dmarc=fail: ")


def test_one_passing_dkim_signature_is_enough() -> None:
    assert run(result("dkim", "fail"), result("dkim", "pass")) == []


def test_topmost_header_wins_over_forged_lower_header() -> None:
    found = run(result("spf", "fail", index=0), result("spf", "pass", index=1))
    assert found == [(IndicatorType.SPF_FAIL, Severity.MEDIUM)]
    found = run(result("dmarc", "pass", index=0), result("dmarc", "fail", index=1))
    assert found == []


def test_untrusted_servers_are_ignored() -> None:
    results = (result("spf", "pass", index=1), result("dmarc", "fail", index=0))
    found = run(*results, trusted=("mx1.larkspur.test",))
    assert found == [(IndicatorType.DMARC_FAIL, Severity.HIGH)]


def test_missing_header() -> None:
    (indicator,) = AuthenticationCheck().run(make_email())
    assert indicator.type is IndicatorType.AUTH_RESULTS_MISSING
    assert indicator.severity is Severity.LOW
    assert indicator.value == "no Authentication-Results header"


def test_only_untrusted_headers() -> None:
    email = make_email(authentication_results=(result("spf", "pass", index=1),))
    (indicator,) = AuthenticationCheck(["MX1.larkspur.test"]).run(email)
    assert indicator.value == "untrusted Authentication-Results only"
    assert "forged.test" in indicator.evidence
    assert "mx1.larkspur.test" in indicator.evidence


def test_trusted_header_without_relevant_methods() -> None:
    email = make_email(authentication_results=(result("arc", "none"),))
    (indicator,) = AuthenticationCheck(["mx1.larkspur.test"]).run(email)
    assert indicator.value == "no SPF, DKIM or DMARC results"
