"""SPF, DKIM and DMARC results recorded by the receiving mail server.

Only results from trusted servers are used. Anyone can add an
Authentication-Results header to a message before sending it, so when no
trusted servers are configured the topmost header for each method wins: that
is the one added last, by the receiving side.
"""

from collections.abc import Iterator, Sequence

from hookline.models.email import AuthResult, ParsedEmail
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity

_METHODS = ("spf", "dkim", "dmarc")

# (indicator type, severity, explanation) per method and result.
_FINDINGS: dict[tuple[str, str], tuple[IndicatorType, Severity, str]] = {
    ("spf", "fail"): (
        IndicatorType.SPF_FAIL,
        Severity.MEDIUM,
        "the sending server is not authorised to send mail for this domain",
    ),
    ("spf", "softfail"): (
        IndicatorType.SPF_FAIL,
        Severity.LOW,
        "the domain does not fully authorise the sending server",
    ),
    ("spf", "permerror"): (
        IndicatorType.SPF_FAIL,
        Severity.LOW,
        "the domain publishes an SPF record that cannot be evaluated",
    ),
    ("dkim", "fail"): (
        IndicatorType.DKIM_FAIL,
        Severity.MEDIUM,
        "the signature did not verify, so the message was altered or not signed by that domain",
    ),
    ("dkim", "permerror"): (
        IndicatorType.DKIM_FAIL,
        Severity.LOW,
        "the signature or its published key is broken",
    ),
    ("dmarc", "fail"): (
        IndicatorType.DMARC_FAIL,
        Severity.HIGH,
        "neither SPF nor DKIM passed for the domain shown in the From header",
    ),
    ("dmarc", "permerror"): (
        IndicatorType.DMARC_FAIL,
        Severity.LOW,
        "the From domain publishes a DMARC record that cannot be evaluated",
    ),
}

# The property that names the domain each method checked.
_DOMAIN_PROPERTIES = {
    "spf": ("smtp.mailfrom", "smtp.helo"),
    "dkim": ("header.d", "header.i"),
    "dmarc": ("header.from",),
}


class AuthenticationCheck:
    """Reports failed or missing sender authentication."""

    name = "authentication"

    def __init__(self, trusted_authserv_ids: Sequence[str] = ()) -> None:
        self._trusted = frozenset(item.lower() for item in trusted_authserv_ids)

    def run(self, email: ParsedEmail) -> Iterator[Indicator]:
        """Yield one indicator per failed method, or one if no results can be trusted."""
        results = [
            result
            for result in email.authentication_results
            if result.method in _METHODS and self._is_trusted(result)
        ]
        if not results:
            yield self._missing(email)
            return
        for method in _METHODS:
            chosen = _topmost(results, method)
            if chosen:
                yield from _evaluate(method, chosen)

    def _is_trusted(self, result: AuthResult) -> bool:
        return not self._trusted or (result.authserv_id or "") in self._trusted

    def _missing(self, email: ParsedEmail) -> Indicator:
        if not email.authentication_results:
            value = "no Authentication-Results header"
            evidence = (
                "The message has no Authentication-Results header, so its SPF, DKIM and DMARC "
                "results are unknown. Copies saved from a mail client sometimes lose this "
                "header; check the original in the mail system."
            )
        elif not any(self._is_trusted(result) for result in email.authentication_results):
            servers = sorted({r.authserv_id or "(unnamed)" for r in email.authentication_results})
            value = "untrusted Authentication-Results only"
            evidence = (
                f"Authentication-Results headers were added by {', '.join(servers)}, none of "
                f"which is a trusted server ({', '.join(sorted(self._trusted))}). Headers from "
                "other servers can be written by the sender and are ignored."
            )
        else:
            value = "no SPF, DKIM or DMARC results"
            evidence = (
                "The Authentication-Results headers contain no SPF, DKIM or DMARC result, so "
                "the sender could not be verified."
            )
        return Indicator(
            type=IndicatorType.AUTH_RESULTS_MISSING,
            value=value,
            severity=Severity.LOW,
            evidence=evidence,
            source=IndicatorSource.HEADERS,
        )


def _topmost(results: list[AuthResult], method: str) -> list[AuthResult]:
    """Results for ``method`` from the topmost header that reports it."""
    matching = [result for result in results if result.method == method]
    if not matching:
        return []
    first = min(result.header_index for result in matching)
    return [result for result in matching if result.header_index == first]


def _evaluate(method: str, results: list[AuthResult]) -> Iterator[Indicator]:
    # A message can carry several DKIM signatures; one valid signature is enough.
    if any(result.result == "pass" for result in results):
        return
    for result in results:
        finding = _FINDINGS.get((method, result.result))
        if finding is None:
            continue
        indicator_type, severity, explanation = finding
        domain = _checked_domain(result)
        value = f"{method}={result.result}" + (f" ({domain})" if domain else "")
        recorded_by = result.authserv_id or "the receiving server"
        yield Indicator(
            type=indicator_type,
            value=value,
            severity=severity,
            evidence=f"{recorded_by} recorded {value}: {explanation}.",
            source=IndicatorSource.HEADERS,
        )
        return


def _checked_domain(result: AuthResult) -> str:
    for key in _DOMAIN_PROPERTIES[result.method]:
        if result.properties.get(key):
            return result.properties[key].rpartition("@")[2]
    return ""
