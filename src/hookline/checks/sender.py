"""Consistency between the From address and the other sender headers."""

import re
from collections.abc import Iterator

from hookline.config import CheckSettings
from hookline.domains import (
    GENERIC_LABELS,
    looks_like_domain,
    registrable_domain,
    skeleton,
    split_domain,
)
from hookline.models.email import EmailAddress, ParsedEmail
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity

MIN_BRAND_LENGTH = 4

_ADDRESS_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_DOMAIN_IN_TEXT = re.compile(r"(?<![\w@.-])((?:[\w-]+\.)+[^\W\d_]{2,})(?![\w-])")
_WORDS = re.compile(r"[a-z0-9]+")


class SenderCheck:
    """Compares Reply-To, Return-Path and the display name against the From address."""

    name = "sender"

    def __init__(self, settings: CheckSettings) -> None:
        self._protected = frozenset(registrable_domain(d) for d in settings.protected_domains)
        self._freemail = frozenset(settings.freemail_domains)
        self._brands: dict[str, str] = {}
        for domain in settings.protected_domains:
            label = split_domain(domain).label
            # Generic labels would match ordinary names such as "Office Manager".
            if len(label) >= MIN_BRAND_LENGTH and label not in GENERIC_LABELS:
                self._brands.setdefault(skeleton(label), domain)

    def run(self, email: ParsedEmail) -> Iterator[Indicator]:
        """Yield mismatches between the From address and the other sender fields."""
        sender = email.from_address
        if sender is None or not sender.domain:
            return
        from_domain = registrable_domain(sender.domain)
        yield from self._reply_to(email.reply_to, sender, from_domain)
        if email.return_path:
            yield from _return_path(email.return_path, from_domain)
        display = self._display_name(sender, from_domain)
        if display is not None:
            yield display

    def _reply_to(
        self, reply_to: tuple[EmailAddress, ...], sender: EmailAddress, from_domain: str
    ) -> Iterator[Indicator]:
        for address in reply_to:
            if not address.domain:
                continue
            domain = registrable_domain(address.domain)
            if domain == from_domain:
                continue
            evidence = (
                f"Replies go to {address.address}, at {domain}, not to the sender's domain "
                f"{from_domain} ({sender.address})."
            )
            severity = Severity.MEDIUM
            if domain in self._freemail and from_domain not in self._freemail:
                severity = Severity.HIGH
                evidence += (
                    f" {domain} is a free webmail provider, a common way to take over a "
                    "conversation in invoice and payroll fraud."
                )
            yield Indicator(
                type=IndicatorType.REPLY_TO_MISMATCH,
                value=address.address,
                severity=severity,
                evidence=evidence,
                source=IndicatorSource.HEADERS,
            )

    def _display_name(self, sender: EmailAddress, from_domain: str) -> Indicator | None:
        name = sender.display_name
        if not name:
            return None
        reason, severity = self._claimed_identity(name, from_domain)
        if reason is None:
            return None
        if severity is Severity.MEDIUM and from_domain in self._freemail:
            severity = Severity.HIGH
            reason += f" The real address is at {from_domain}, a free webmail provider."
        return Indicator(
            type=IndicatorType.DISPLAY_NAME_SPOOFING,
            value=str(sender),
            severity=severity,
            evidence=reason,
            source=IndicatorSource.HEADERS,
        )

    def _claimed_identity(self, name: str, from_domain: str) -> tuple[str | None, Severity]:
        """Explain what the display name claims that the address does not back up."""
        for match in _ADDRESS_IN_TEXT.finditer(name):
            if registrable_domain(match.group(1)) != from_domain:
                return (
                    f"The display name shows the address {match.group(0)}, but the message "
                    f"was sent from {from_domain}.",
                    Severity.HIGH,
                )
        for match in _DOMAIN_IN_TEXT.finditer(name):
            shown = match.group(1)
            if looks_like_domain(shown) and registrable_domain(shown) != from_domain:
                return (
                    f"The display name shows the domain {shown}, but the message was sent "
                    f"from {from_domain}.",
                    Severity.HIGH,
                )
        if from_domain in self._protected:
            return None, Severity.INFO
        words = set(_WORDS.findall(skeleton(name)))
        for brand, domain in self._brands.items():
            if brand in words:
                return (
                    f"The display name '{name}' suggests {domain}, but the message was sent "
                    f"from {from_domain}.",
                    Severity.MEDIUM,
                )
        return None, Severity.INFO


def _return_path(return_path: str, from_domain: str) -> Iterator[Indicator]:
    _, at, host = return_path.rpartition("@")
    if not at or not host:
        return
    domain = registrable_domain(host)
    if domain == from_domain:
        return
    yield Indicator(
        type=IndicatorType.RETURN_PATH_MISMATCH,
        value=return_path,
        severity=Severity.LOW,
        evidence=(
            f"The envelope sender (Return-Path) is at {domain}, while the From address uses "
            f"{from_domain}. Bulk-mail services do this legitimately; it matters more when "
            "SPF or DMARC also fail."
        ),
        source=IndicatorSource.HEADERS,
    )
