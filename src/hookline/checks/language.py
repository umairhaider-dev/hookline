"""Social-engineering language: pressure, credential and payment requests, gift cards.

Phrases are matched on normalised text, so invisible characters, fullwidth
letters and odd spacing cannot split a phrase to dodge the patterns. Only the
subject and the first part of the body are read: social-engineering lines sit
near the top, and scanning megabytes of padding would let a sender slow the
analysis down. The patterns are English only.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass

from hookline.models.email import ParsedEmail
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity
from hookline.textnorm import normalize_text

MAX_PHRASES_SHOWN = 5
MAX_TEXT_CHARS = 200_000


@dataclass(frozen=True)
class _Category:
    indicator_type: IndicatorType
    description: str
    severity: Severity
    patterns: tuple[re.Pattern[str], ...]


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern) for pattern in patterns)


_CATEGORIES = (
    _Category(
        IndicatorType.URGENCY_LANGUAGE,
        "pressure or secrecy",
        Severity.LOW,
        _compile(
            r"\burgent(?:ly)?\b",
            r"\bimmediate(?:ly)?\b",
            r"\bas soon as possible\b|\basap\b",
            r"\bright away\b",
            r"\bwithin (?:the next )?\d+ (?:hours?|hrs?|minutes?|days?)\b",
            r"\b(?:expires?|expiring|expired) (?:today|tonight|soon|in \d+ \w+)\b",
            r"\b(?:final|last) (?:notice|warning|reminder|attempt)\b",
            r"\bact now\b",
            r"\baction required\b",
            r"\b(?:account|mailbox|access|service|email) (?:will be|has been|is being) "
            r"(?:suspended|closed|locked|disabled|deactivated|terminated|deleted|restricted)\b",
            r"\b(?:avoid|prevent) (?:losing access|suspension|deactivation|interruption)\b",
            r"\btime[- ]sensitive\b",
            r"\bfailure to (?:respond|comply|verify|act|update)\b",
            r"\bkeep (?:this|it) (?:confidential|between us|private|quiet)\b",
            r"\b(?:are you|r u) (?:available|around|at your desk)\b",
            r"\bi need (?:you to do )?a (?:quick )?favou?r\b",
        ),
    ),
    _Category(
        IndicatorType.CREDENTIAL_REQUEST,
        "credential request",
        Severity.MEDIUM,
        _compile(
            r"\b(?:confirm|verify|validate|re-?enter|update|provide|submit) your "
            r"(?:current |existing |old )?(?:password|passcode|credentials|login details|"
            r"sign-?in details|username and password)\b",
            r"\b(?:verify|confirm|validate) your (?:account|identity|mailbox|email address)\b",
            r"\bpassword (?:expires|will expire|is expiring|has expired)\b",
            r"\b(?:mailbox|storage|inbox) (?:is )?(?:full|almost full|over quota)\b",
            r"\b(?:unusual|suspicious|unauthori[sz]ed) (?:sign-?in|login|log-?in) "
            r"(?:activity|attempts?)\b",
            r"\b(?:send|share|forward|tell|give) (?:me|us) (?:the|your) "
            r"(?:code|passcode|pin|otp|verification code)\b",
            r"\bsign in (?:to|and) (?:verify|confirm|restore|unlock|keep)\b",
        ),
    ),
    _Category(
        IndicatorType.PAYMENT_REQUEST,
        "payment request",
        Severity.MEDIUM,
        _compile(
            r"\b(?:wire|bank|swift|ach|international) (?:transfer|payment)\b",
            r"\bwire (?:the )?(?:funds|money|payment)\b",
            r"\b(?:update|change|new|updated|changed) (?:our |my |the )?(?:bank(?:ing)?|payment|"
            r"remittance) (?:details|information|info|account|instructions)\b",
            r"\b(?:outstanding|overdue|unpaid|past[- ]due) (?:invoice|payment|balance|amount)s?\b",
            r"\b(?:invoice|payment) (?:is )?(?:overdue|past due|due today|due immediately)\b",
            r"\b(?:routing|iban|swift|bic|sort) (?:number|code)\b",
            r"\b(?:process|make|send|approve|release) (?:a |the |this )?(?:urgent )?"
            r"(?:wire |bank )?(?:payment|transfer)\b",
            r"\b(?:bitcoin|btc|ethereum|usdt|crypto(?:currency)?) (?:wallet|address|payment)\b",
        ),
    ),
    _Category(
        IndicatorType.GIFT_CARD_REQUEST,
        "gift card request",
        Severity.MEDIUM,
        _compile(
            r"\bgift ?cards?\b",
            r"\b(?:itunes|apple|google play|steam|amazon|ebay|razer gold) cards?\b",
            r"\bscratch (?:off )?(?:the )?(?:back|silver|panel|code)\b",
            r"\b(?:card|redemption|claim) (?:codes?|numbers?|pins?)\b",
            r"\b(?:pictures?|photos?|images?|snapshots?) of (?:the )?(?:cards?|codes?|back)\b",
        ),
    ),
)


class LanguageCheck:
    """Looks for phrases typical of phishing and fraud in the subject and body."""

    name = "language"

    def run(self, email: ParsedEmail) -> Iterator[Indicator]:
        """Yield one indicator per category with matching phrases.

        A single phrase gives the category's base severity; two or more distinct
        phrases raise it by one level.
        """
        combined = "\n".join((email.subject, email.text_body, email.html_text))
        text = normalize_text(combined[:MAX_TEXT_CHARS])
        for category in _CATEGORIES:
            phrases = _matches(category, text)
            if not phrases:
                continue
            severity = category.severity
            if len(phrases) > 1:
                severity = list(Severity)[min(severity.rank + 1, Severity.HIGH.rank)]
            shown = phrases[:MAX_PHRASES_SHOWN]
            quoted = ", ".join(f"'{phrase}'" for phrase in shown)
            more = len(phrases) - len(shown)
            evidence = f"Found {len(phrases)} {category.description} phrase(s): {quoted}"
            evidence += f" and {more} more." if more > 0 else "."
            yield Indicator(
                type=category.indicator_type,
                value="; ".join(shown),
                severity=severity,
                evidence=evidence,
                source=IndicatorSource.LANGUAGE,
            )


def _matches(category: _Category, text: str) -> list[str]:
    """The first match of each pattern, as found in the text."""
    found = []
    for pattern in category.patterns:
        match = pattern.search(text)
        if match is not None:
            found.append(match.group(0))
    return list(dict.fromkeys(found))
