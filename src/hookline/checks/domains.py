"""Lookalike, internationalised and high-risk domains in sender headers and links."""

import unicodedata
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field

from hookline.config import CheckSettings
from hookline.domains import (
    GENERIC_LABELS,
    DomainParts,
    decode_punycode,
    edit_distance,
    encode_punycode,
    has_punycode,
    normalize_host,
    parse_ip,
    registrable_domain,
    skeleton,
    split_domain,
    top_level_domain,
)
from hookline.models.email import ParsedEmail
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity
from hookline.urls import parse_url

# Shortest protected label compared by edit distance. Shorter names sit one
# edit away from too many ordinary words ("apple" and "apply"); they are still
# covered by the homoglyph, combination and suffix checks.
MIN_TYPO_LENGTH = 6
# Shortest protected label matched as a prefix or suffix of a longer label.
MIN_AFFIX_LENGTH = 6
MAX_NON_ASCII_SHOWN = 5


@dataclass(frozen=True)
class _Finding:
    severity: Severity
    evidence: str


@dataclass
class _Sighting:
    """The hosts under one registrable domain, and where in the message they appeared."""

    hosts: set[str] = field(default_factory=set)
    places: set[str] = field(default_factory=set)

    def describe(self, domain: str) -> str:
        text = f"{domain} (in the {', '.join(sorted(self.places))}"
        others = sorted(self.hosts - {domain})
        if others:
            text += f"; as {', '.join(others)}"
        return text + ")"


class DomainCheck:
    """Compares every sender and link domain with the protected domains.

    Findings are reported once per registrable domain, so a fake domain used in
    both the From address and its ``mailer.`` Return-Path counts once.
    """

    name = "domains"

    def __init__(self, settings: CheckSettings) -> None:
        self._protected = [split_domain(domain) for domain in settings.protected_domains]
        self._protected_names = {parts.registrable for parts in self._protected}
        self._suspicious_tlds = frozenset(settings.suspicious_tlds)

    def run(self, email: ParsedEmail) -> Iterator[Indicator]:
        """Yield findings for each distinct registrable domain."""
        for domain, sighting in _collect_domains(email).items():
            yield from self._check(domain, sighting)

    def _check(self, domain: str, sighting: _Sighting) -> Iterator[Indicator]:
        readable = decode_punycode(domain)
        parts = split_domain(readable)
        if readable in self._protected_names or domain in self._protected_names:
            return
        described = sighting.describe(domain)
        if has_punycode(domain) or not domain.isascii():
            ascii_form = encode_punycode(readable)
            also = f" (ASCII form {ascii_form})" if ascii_form != domain else ""
            yield _indicator(
                IndicatorType.PUNYCODE_DOMAIN,
                domain,
                Severity.MEDIUM,
                f"{described} is an internationalised domain that displays as "
                f"'{readable}'{also}. Lookalike letters from other alphabets can make it pass "
                f"for a familiar name.{_letters_note(readable)}",
            )
        for host in sorted(sighting.hosts):
            embedded = self._embedded_protected(host)
            if embedded is not None:
                yield _indicator(
                    IndicatorType.LOOKALIKE_DOMAIN,
                    host,
                    Severity.HIGH,
                    f"{host} starts with {embedded} but belongs to {domain}; the protected "
                    "name is only a subdomain prefix.",
                )
        homoglyph, lookalike = self._compare(parts)
        if homoglyph is not None:
            yield _indicator(
                IndicatorType.HOMOGLYPH_DOMAIN,
                domain,
                homoglyph.severity,
                f"{described} {homoglyph.evidence}",
            )
        if lookalike is not None:
            yield _indicator(
                IndicatorType.LOOKALIKE_DOMAIN,
                domain,
                lookalike.severity,
                f"{described} {lookalike.evidence}",
            )
        tld = top_level_domain(readable)
        if tld in self._suspicious_tlds:
            yield _indicator(
                IndicatorType.SUSPICIOUS_TLD,
                domain,
                Severity.LOW,
                f"{described} uses .{tld}, a top-level domain that appears "
                "disproportionately often in phishing and abuse reports.",
            )

    def _embedded_protected(self, host: str) -> str | None:
        """The protected domain written into the subdomain part of ``host``, if any."""
        subdomain = f".{split_domain(decode_punycode(host)).subdomain}."
        for protected in self._protected:
            if f".{protected.registrable}." in subdomain:
                return protected.registrable
        return None

    def _compare(self, parts: DomainParts) -> tuple[_Finding | None, _Finding | None]:
        """Return the strongest homoglyph and lookalike findings across protected domains."""
        homoglyph: _Finding | None = None
        lookalike: _Finding | None = None
        for protected in self._protected:
            found = _homoglyph(parts, protected)
            if found is not None:
                homoglyph = _stronger(homoglyph, found)
                continue
            lookalike = _stronger(lookalike, _lookalike(parts, protected))
        return homoglyph, lookalike


def _homoglyph(parts: DomainParts, protected: DomainParts) -> _Finding | None:
    if parts.label == protected.label or skeleton(parts.label) != skeleton(protected.label):
        return None
    if parts.label.isascii():
        return _Finding(
            Severity.HIGH,
            f"reads as {protected.registrable}: '{parts.label}' differs from "
            f"'{protected.label}' only by characters that are easy to confuse, such as "
            "1 and l, 0 and o, or rn and m.",
        )
    return _Finding(
        Severity.CRITICAL,
        f"is visually identical to {protected.registrable}: '{parts.label}' uses letters "
        f"from another alphabet in place of Latin ones.{_letters_note(parts.label)}",
    )


def _lookalike(parts: DomainParts, protected: DomainParts) -> _Finding | None:
    label, target = parts.label, protected.label
    if target in GENERIC_LABELS:
        # Ordinary words: only exact visual imitation is meaningful for these.
        return None
    if label == target:
        # Same name, different suffix (the same registrable domain returned earlier).
        return _Finding(
            Severity.MEDIUM,
            f"uses the name of {protected.registrable} under a different suffix "
            f"(.{parts.suffix}). If the organisation owns it, add it to protected_domains.",
        )
    if len(target) >= MIN_TYPO_LENGTH:
        limit = 1 if len(target) < 9 else 2
        distance = edit_distance(label, target, limit=limit)
        if distance <= limit:
            return _Finding(
                Severity.HIGH,
                f"is {distance} edit(s) away from {protected.registrable} "
                f"('{label}' versus '{target}'), a typical typosquat.",
            )
    tokens = label.split("-")
    affixed = len(target) >= MIN_AFFIX_LENGTH and (
        label.startswith(target) or label.endswith(target)
    )
    if (len(tokens) > 1 and target in tokens) or affixed:
        return _Finding(
            Severity.MEDIUM,
            f"combines the protected name '{target}' ({protected.registrable}) with other "
            "words, a common way to make a fake domain look official.",
        )
    return None


def _stronger(current: _Finding | None, candidate: _Finding | None) -> _Finding | None:
    if candidate is None:
        return current
    if current is None or candidate.severity.rank > current.severity.rank:
        return candidate
    return current


def _letters_note(text: str) -> str:
    unusual = list(dict.fromkeys(char for char in text if not char.isascii()))
    if not unusual:
        return ""
    names = [f"U+{ord(char):04X} {unicodedata.name(char, 'UNKNOWN')}" for char in unusual]
    shown = ", ".join(names[:MAX_NON_ASCII_SHOWN])
    if len(names) > MAX_NON_ASCII_SHOWN:
        shown += f" and {len(names) - MAX_NON_ASCII_SHOWN} more"
    return f" Non-ASCII characters: {shown}."


def _indicator(kind: IndicatorType, host: str, severity: Severity, evidence: str) -> Indicator:
    return Indicator(
        type=kind, value=host, severity=severity, evidence=evidence, source=IndicatorSource.DOMAINS
    )


def _collect_domains(email: ParsedEmail) -> dict[str, _Sighting]:
    """Group every sender and link host by registrable domain."""
    sightings: defaultdict[str, _Sighting] = defaultdict(_Sighting)

    def add(host: str, place: str) -> None:
        host = normalize_host(host)
        if host and parse_ip(host) is None:
            sighting = sightings[registrable_domain(host)]
            sighting.hosts.add(host)
            sighting.places.add(place)

    if email.from_address and email.from_address.domain:
        add(email.from_address.domain, "From address")
    for address in email.reply_to:
        if address.domain:
            add(address.domain, "Reply-To")
    if email.return_path and "@" in email.return_path:
        add(email.return_path.rpartition("@")[2], "Return-Path")
    for link in email.links:
        parsed = parse_url(link.url)
        if parsed is not None and parsed.is_web and parsed.ip is None:
            add(parsed.host, "links")
    return dict(sightings)
