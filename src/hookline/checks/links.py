"""Suspicious links: mismatched text, raw IPs, shorteners, obfuscation and login pages.

URLs are only parsed as text. They are never resolved or fetched.
"""

import base64
import binascii
import re
from collections.abc import Iterator
from urllib.parse import unquote

from hookline.config import CheckSettings
from hookline.domains import looks_like_domain, registrable_domain
from hookline.models.email import Link, LinkOrigin, ParsedEmail
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity
from hookline.urls import ParsedURL, parse_url

LONG_URL_LENGTH = 300
MIN_ENCODED_CHARACTERS = 10
ENCODED_RATIO = 0.3

_ACTIVE_SCHEMES = frozenset({"javascript", "vbscript", "data"})
_PERCENT_ESCAPE = re.compile(r"%[0-9a-f]{2}", re.I)
_EMBEDDED_URL = re.compile(r"https?://[^\s&#]+", re.I)
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_URLSAFE_ALPHABET = str.maketrans("-_", "+/")
_LOGIN_WORDS = re.compile(
    r"(?<![a-z])(?:log[-_]?in|log[-_]?on|sign[-_]?in|signon|verify|verification|validate|"
    r"confirm|account|password|passwd|reset|auth|authenticate|sso|owa|webmail|session|"
    r"unlock|recover|credential|credentials|mfa)(?![a-z])"
)
_SHOWN_URL = re.compile(r"(?:https?://)?[^\s/<>\"'()]+\.[^\s/<>\"'()]+[^\s<>\"'()]*", re.I)


class LinkCheck:
    """Inspects every link found in the message body."""

    name = "links"

    def __init__(self, settings: CheckSettings) -> None:
        self._shorteners = frozenset(settings.url_shorteners)
        self._protected = frozenset(registrable_domain(d) for d in settings.protected_domains)

    def run(self, email: ParsedEmail) -> Iterator[Indicator]:
        """Yield findings for each link. One indicator per link and finding type."""
        recipients = {
            address.address.lower() for address in (*email.to, *email.cc) if address.address
        }
        for link in email.links:
            parsed = parse_url(link.url)
            if parsed is None:
                continue
            if parsed.scheme in _ACTIVE_SCHEMES:
                yield _indicator(
                    IndicatorType.OBFUSCATED_URL,
                    link.url,
                    Severity.HIGH,
                    f"A link uses the {parsed.scheme}: scheme, which runs code or carries a "
                    "whole page inside the link instead of pointing to a website.",
                )
                continue
            if parsed.is_web:
                yield from self._check_web_link(link, parsed, recipients)

    def _check_web_link(
        self, link: Link, url: ParsedURL, recipients: set[str]
    ) -> Iterator[Indicator]:
        if url.ip is not None:
            evidence = (
                f"The link goes straight to the IP address {url.ip} instead of a domain name. "
                "Legitimate services almost always use names."
            )
            if url.ip_is_disguised:
                evidence += (
                    f" The address is written as '{url.host}', an unusual numeric form that "
                    "browsers still accept and that hides it from a quick look."
                )
            yield _indicator(IndicatorType.IP_ADDRESS_URL, link.url, Severity.HIGH, evidence)

        mismatch = _text_mismatch(link, url)
        if mismatch is not None:
            yield _indicator(IndicatorType.LINK_TEXT_MISMATCH, link.url, Severity.HIGH, mismatch)

        registrable = _site(url)
        if url.host in self._shorteners or registrable in self._shorteners:
            yield _indicator(
                IndicatorType.URL_SHORTENER,
                link.url,
                Severity.MEDIUM,
                f"{url.host} is a URL shortener, which hides the real destination until the "
                "link is opened.",
            )

        obfuscation = _obfuscation(url, recipients)
        if obfuscation is not None:
            severity, reasons = obfuscation
            evidence = "The link " + "; ".join(reasons) + "."
            yield _indicator(IndicatorType.OBFUSCATED_URL, link.url, severity, evidence)

        if registrable not in self._protected:
            login = _login_evidence(link, url)
            if login is not None:
                yield _indicator(
                    IndicatorType.CREDENTIAL_LOGIN_PATH, link.url, Severity.MEDIUM, login
                )


def _site(url: ParsedURL) -> str:
    """The registrable domain of a URL, or its IP address."""
    return str(url.ip) if url.ip is not None else registrable_domain(url.host)


def _text_mismatch(link: Link, url: ParsedURL) -> str | None:
    """Explain how the visible link text disagrees with the real destination."""
    if link.origin is not LinkOrigin.HTML_ANCHOR or not link.text:
        return None
    for match in _SHOWN_URL.finditer(link.text):
        text = match.group(0)
        shown = parse_url(text if "://" in text else f"http://{text}")
        if shown is None or not shown.host:
            continue
        if shown.ip is None and not looks_like_domain(shown.host):
            continue
        if _site(shown) == _site(url):
            return None
        destination = str(url.ip) if url.ip is not None else url.host
        return (
            f"The link text shows {shown.host}, but clicking it goes to {destination}. "
            "Showing one address and linking to another is a core phishing technique."
        )
    return None


def _obfuscation(url: ParsedURL, recipients: set[str]) -> tuple[Severity, list[str]] | None:
    findings: list[tuple[Severity, str]] = []
    if url.userinfo:
        findings.append(
            (
                Severity.HIGH,
                f"puts '{url.userinfo}' before an @ sign; browsers ignore that part, so the "
                f"real host is {url.host}",
            )
        )
    netloc = url.raw.split("//", 1)[-1].split("/", 1)[0]
    if "%" in netloc and _PERCENT_ESCAPE.search(netloc):
        findings.append((Severity.HIGH, "percent-encodes its host name to disguise it"))
    path_and_query = url.path + url.query
    escapes = len(_PERCENT_ESCAPE.findall(path_and_query))
    if escapes >= MIN_ENCODED_CHARACTERS and escapes * 3 >= ENCODED_RATIO * len(path_and_query):
        findings.append((Severity.MEDIUM, f"is heavily percent-encoded ({escapes} escapes)"))
    embedded = _EMBEDDED_URL.search(unquote(url.query + "&" + url.fragment))
    if embedded is not None:
        findings.append(
            (
                Severity.LOW,
                f"passes another address ({embedded.group(0)}) as a parameter, as redirectors do",
            )
        )
    recipient = _encoded_recipient(url, recipients)
    if recipient is not None:
        findings.append(
            (
                Severity.MEDIUM,
                f"carries the recipient's address ({recipient}) in base64 form, which "
                "phishing kits use to pre-fill a fake login page",
            )
        )
    if len(url.raw) > LONG_URL_LENGTH:
        findings.append((Severity.LOW, f"is {len(url.raw)} characters long"))
    if not findings:
        return None
    severity = max((severity for severity, _ in findings), key=lambda item: item.rank)
    return severity, [reason for _, reason in findings]


def _encoded_recipient(url: ParsedURL, recipients: set[str]) -> str | None:
    if not recipients:
        return None
    for token in _BASE64_TOKEN.findall(url.path + "?" + url.query + "#" + url.fragment):
        decoded = _decode_base64(token)
        for recipient in recipients:
            if recipient in decoded:
                return recipient
    return None


def _decode_base64(token: str) -> str:
    """Decode standard or URL-safe base64, returning an empty string for non-base64."""
    padded = token.translate(_URLSAFE_ALPHABET) + "=" * (-len(token) % 4)
    try:
        return base64.b64decode(padded).decode("utf-8", errors="ignore").lower()
    except binascii.Error:
        return ""


def _login_evidence(link: Link, url: ParsedURL) -> str | None:
    if link.origin is LinkOrigin.HTML_FORM:
        return (
            f"The message contains an HTML form that submits to {url.host}. Legitimate email "
            "almost never asks you to type information into the message itself."
        )
    words = sorted(set(_LOGIN_WORDS.findall(unquote(f"{url.path}?{url.query}").lower())))
    if not words:
        return None
    return (
        f"The link leads to a page whose address suggests a login or account check "
        f"({', '.join(words)}) on {url.host}, which is not one of the protected domains."
    )


def _indicator(kind: IndicatorType, url: str, severity: Severity, evidence: str) -> Indicator:
    return Indicator(
        type=kind, value=url, severity=severity, evidence=evidence, source=IndicatorSource.LINKS
    )
