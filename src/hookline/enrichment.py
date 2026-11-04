"""What the report adds on top of the verdict: IOCs, ATT&CK mapping and next steps.

All of it is derived deterministically from the parsed email, the indicators
and the verdict, so the same email always yields the same enrichment.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from hookline.domains import is_internal_ip, parse_ip, registrable_domain
from hookline.models.email import ParsedEmail
from hookline.models.indicator import Indicator, IndicatorType, Severity
from hookline.models.report import IOCSet, MitreTechnique
from hookline.models.verdict import Verdict, VerdictLabel
from hookline.reporting.defang import defang
from hookline.urls import parse_url

MAX_IOCS_PER_KIND = 100
MAX_NAMED_IN_ACTIONS = 3
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_LINK_TYPES = frozenset(
    {
        IndicatorType.LINK_TEXT_MISMATCH,
        IndicatorType.IP_ADDRESS_URL,
        IndicatorType.URL_SHORTENER,
        IndicatorType.OBFUSCATED_URL,
        IndicatorType.CREDENTIAL_LOGIN_PATH,
    }
)
_ATTACHMENT_TYPES = frozenset(
    {
        IndicatorType.RISKY_ATTACHMENT,
        IndicatorType.DOUBLE_EXTENSION,
        IndicatorType.FILE_TYPE_MISMATCH,
    }
)
_IMPERSONATION_TYPES = frozenset(
    {
        IndicatorType.DISPLAY_NAME_SPOOFING,
        IndicatorType.LOOKALIKE_DOMAIN,
        IndicatorType.HOMOGLYPH_DOMAIN,
        IndicatorType.PAYMENT_REQUEST,
        IndicatorType.GIFT_CARD_REQUEST,
    }
)
_CREDENTIAL_TYPES = frozenset(
    {
        IndicatorType.CREDENTIAL_REQUEST,
        IndicatorType.CREDENTIAL_LOGIN_PATH,
        IndicatorType.LINK_TEXT_MISMATCH,
    }
)
_FRAUD_TYPES = frozenset({IndicatorType.PAYMENT_REQUEST, IndicatorType.GIFT_CARD_REQUEST})


@dataclass(frozen=True)
class _Technique:
    technique_id: str
    name: str
    tactic: str
    types: frozenset[IndicatorType]


# Sub-techniques are listed with the indicator types that show them. T1566
# itself is added whenever the verdict is suspicious or malicious.
_TECHNIQUES = (
    _Technique(
        "T1566.001", "Phishing: Spearphishing Attachment", "Initial Access", _ATTACHMENT_TYPES
    ),
    _Technique("T1566.002", "Phishing: Spearphishing Link", "Initial Access", _LINK_TYPES),
    _Technique(
        "T1598.003",
        "Phishing for Information: Spearphishing Link",
        "Reconnaissance",
        frozenset({IndicatorType.CREDENTIAL_REQUEST}),
    ),
    _Technique("T1656", "Impersonation", "Defense Evasion", _IMPERSONATION_TYPES),
    _Technique(
        "T1036.007",
        "Masquerading: Double File Extension",
        "Defense Evasion",
        frozenset({IndicatorType.DOUBLE_EXTENSION}),
    ),
    _Technique(
        "T1036.008",
        "Masquerading: Masquerade File Type",
        "Defense Evasion",
        frozenset({IndicatorType.FILE_TYPE_MISMATCH}),
    ),
)


def extract_iocs(email: ParsedEmail, protected_domains: Iterable[str]) -> IOCSet:
    """Collect the URLs, domains, IPs, addresses and hashes worth blocking or hunting.

    The organisation's own domains (the protected domains and the recipients'
    domains) and internal IP addresses are left out: blocking them would hurt,
    and they say nothing about the sender.
    """
    protected = {registrable_domain(domain) for domain in protected_domains}
    protected |= {
        registrable_domain(recipient.domain)
        for recipient in (*email.to, *email.cc)
        if recipient.domain
    }
    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    addresses: list[str] = []

    def add_domain(host: str) -> None:
        domain = registrable_domain(host)
        if domain and domain not in protected:
            domains.append(domain)

    def add_address(address: str) -> None:
        _, at, host = address.rpartition("@")
        if at and host and registrable_domain(host) not in protected:
            addresses.append(address.lower())
            add_domain(host)

    if email.from_address:
        add_address(email.from_address.address)
    for reply_to in email.reply_to:
        add_address(reply_to.address)
    if email.return_path:
        add_address(email.return_path)
    for hop in email.received:
        if hop.from_ip is not None and not is_internal_ip(hop.from_ip):
            ips.append(str(hop.from_ip))
    for link in email.links:
        url = parse_url(link.url)
        if url is None or not url.is_web:
            continue
        if url.ip is not None:
            if not is_internal_ip(url.ip):
                urls.append(link.url)
                ips.append(str(url.ip))
        elif registrable_domain(url.host) not in protected:
            urls.append(link.url)
            add_domain(url.host)
    hashes = [item.sha256 for item in email.attachments if item.size > 0]

    def unique(values: list[str]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(value for value in values if value))[:MAX_IOCS_PER_KIND]

    return IOCSet(
        urls=unique(urls),
        domains=unique([domain for domain in domains if parse_ip(domain) is None]),
        ip_addresses=unique(ips),
        email_addresses=unique(addresses),
        sha256_hashes=unique(hashes),
    )


def map_mitre(verdict: Verdict, indicators: Sequence[Indicator]) -> tuple[MitreTechnique, ...]:
    """Map the findings to MITRE ATT&CK techniques, for suspicious or malicious mail only."""
    if verdict.label is VerdictLabel.LIKELY_SAFE:
        return ()
    scoring = [item for item in indicators if item.severity is not Severity.INFO]
    techniques = [
        MitreTechnique(
            technique_id="T1566",
            name="Phishing",
            tactic="Initial Access",
            indicator_ids=tuple(
                contribution.indicator_id
                for contribution in verdict.contributions
                if contribution.indicator_id
            ),
        )
    ]
    for technique in _TECHNIQUES:
        ids = [item.id for item in scoring if item.type in technique.types]
        ids += [item.id for item in scoring if _intel_kind(item) == technique.technique_id]
        if ids:
            techniques.append(
                MitreTechnique(
                    technique_id=technique.technique_id,
                    name=technique.name,
                    tactic=technique.tactic,
                    indicator_ids=tuple(dict.fromkeys(ids)),
                )
            )
    return tuple(techniques)


def recommend_actions(
    verdict: Verdict, indicators: Sequence[Indicator], iocs: IOCSet
) -> tuple[str, ...]:
    """Concrete next steps for the analyst, from the verdict and what was found."""
    if verdict.label is VerdictLabel.LIKELY_SAFE:
        return (
            "No action needed; if the message was quarantined it can be released.",
            "If the recipient is still unsure, confirm with the sender through a known channel.",
        )
    found = {item.type for item in indicators if item.severity is not Severity.INFO}
    actions = []
    if verdict.label is VerdictLabel.MALICIOUS:
        actions.append(
            "Quarantine the message and remove other copies from all mailboxes "
            "(search by sender, subject and Message-ID)."
        )
        if iocs.domains:
            actions.append(f"Block the sender and link domains: {_named(iocs.domains)}.")
        if iocs.urls or iocs.ip_addresses:
            actions.append(
                "Block the URLs and IP addresses listed as IOCs at the proxy and firewall."
            )
    else:
        actions.append(
            "Hold the message and confirm with the claimed sender through a known phone number "
            "or address, not the contact details in the email."
        )
        actions.append("Search other mailboxes for the same sender or links before deciding.")
    if found & _CREDENTIAL_TYPES:
        actions.append(
            "Ask recipients whether they clicked or entered credentials; for anyone who did, "
            "reset the password, revoke active sessions and review MFA registrations."
        )
    if found & _ATTACHMENT_TYPES:
        actions.append(
            "Find out whether the attachment was opened; if it was, isolate the device and scan it."
        )
        if iocs.sha256_hashes:
            actions.append(
                f"Block the attachment hashes in endpoint protection: {_named(iocs.sha256_hashes)}."
            )
    if found & _FRAUD_TYPES:
        actions.append(
            "Do not act on payment, bank-detail or gift card requests; verify by phone using a "
            "known number and alert the finance team."
        )
    if IndicatorType.PROMPT_INJECTION in found:
        actions.append(
            "The email tries to manipulate AI tools; check any AI-assisted mail tools that "
            "processed it."
        )
    return tuple(actions)


def _named(values: Sequence[str]) -> str:
    shown = ", ".join(defang(value) for value in values[:MAX_NAMED_IN_ACTIONS])
    more = len(values) - MAX_NAMED_IN_ACTIONS
    return shown + (f" and {more} more" if more > 0 else "")


def _intel_kind(indicator: Indicator) -> str | None:
    """Which sub-technique a threat intelligence match supports, from its value."""
    if indicator.type is not IndicatorType.THREAT_INTEL_MATCH:
        return None
    if _SHA256.match(indicator.value):
        return "T1566.001"
    if indicator.value.startswith(("http://", "https://")):
        return "T1566.002"
    return None
