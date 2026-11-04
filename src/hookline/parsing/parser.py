"""Turn raw RFC 5322 bytes into a :class:`ParsedEmail`.

The parser never raises on malformed input. Whatever it cannot make sense of
is recorded in ``ParsedEmail.defects``, because a broken message is itself a
useful signal for the checks.
"""

import hashlib
import logging
import re
from datetime import datetime
from email import policy
from email.errors import HeaderParseError, MessageDefect
from email.headerregistry import AddressHeader, BaseHeader, DateHeader
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from hookline.models.email import AuthResult, EmailAddress, Header, Link, ParsedEmail, ReceivedHop
from hookline.parsing.auth_results import parse_authentication_results
from hookline.parsing.html import extract_html
from hookline.parsing.links import extract_text_links
from hookline.parsing.mime import walk_body
from hookline.parsing.received import parse_received
from hookline.parsing.text import repair_text

logger = logging.getLogger(__name__)

MAX_RECEIVED_HOPS = 100
MAX_LINKS = 500

# The standard library's header parser can raise any of these on hostile input
# instead of registering a defect (OverflowError comes from absurd time zones).
_HEADER_ERRORS = (
    HeaderParseError,
    ValueError,
    IndexError,
    TypeError,
    AttributeError,
    OverflowError,
)

_FOLDING = re.compile(r"\r?\n[ \t]+")


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse ``raw`` message bytes. Never raises on malformed content."""
    message = BytesParser(policy=policy.default).parsebytes(raw)
    # Walk the body first: decoding a single-part message's payload adds
    # transfer-encoding problems to the message's own defects.
    body = walk_body(message)
    defects = [_describe_defect(defect) for defect in message.defects]

    headers: list[Header] = []
    first: dict[str, str] = {}
    for raw_name, raw_value in message.raw_items():
        name = repair_text(raw_name)
        value = _decode_header(message, name, repair_text(raw_value), defects)
        headers.append(Header(name=name, value=str(value)))
        first.setdefault(name.lower(), value)

    from_addresses = _mailboxes(first.get("from"), "From", defects)
    if len(from_addresses) > 1:
        defects.append(f"From header lists {len(from_addresses)} addresses")

    defects.extend(body.defects)
    text_body = "\n\n".join(body.text_parts)
    html_body = "\n".join(body.html_parts)
    html = extract_html(html_body, max_links=MAX_LINKS)
    defects.extend(html.problems)
    # One extra link per source is enough to know whether the cap was hit.
    links = _unique_links(
        [
            *html.links,
            *extract_text_links(text_body, limit=MAX_LINKS + 1),
            *extract_text_links(html.text, limit=MAX_LINKS + 1),
        ]
    )
    if html.links_dropped or len(links) > MAX_LINKS:
        defects.append(
            f"Message has more than {MAX_LINKS} distinct links; only the first {MAX_LINKS} "
            "were analysed"
        )
        links = links[:MAX_LINKS]

    parsed = ParsedEmail(
        message_id=_strip_brackets(first.get("message-id")),
        subject=str(first.get("subject", "")),
        date=_date(first.get("date"), defects),
        from_address=from_addresses[0] if from_addresses else None,
        reply_to=_mailboxes(first.get("reply-to"), "Reply-To", defects),
        return_path=_strip_brackets(first.get("return-path")),
        to=_mailboxes(first.get("to"), "To", defects),
        cc=_mailboxes(first.get("cc"), "Cc", defects),
        headers=tuple(headers),
        authentication_results=_authentication_results(headers, defects),
        received=_received_hops(headers, defects),
        text_body=text_body,
        html_body=html_body,
        html_text=html.text,
        hidden_text=html.hidden,
        links=tuple(links),
        attachments=tuple(body.attachments),
        defects=tuple(repair_text(defect) for defect in defects),
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    logger.debug(
        "Parsed message: %d headers, %d links, %d attachments, %d defects, %d bytes",
        len(parsed.headers),
        len(parsed.links),
        len(parsed.attachments),
        len(parsed.defects),
        parsed.size_bytes,
    )
    return parsed


def _decode_header(message: EmailMessage, name: str, raw_value: str, defects: list[str]) -> str:
    """Decode one header, falling back to its raw text if decoding fails.

    On success the result is a header object from the policy's registry (a
    ``str`` subclass), which still carries parsed addresses and dates.
    """
    try:
        value = message.policy.header_fetch_parse(name, raw_value)
    except _HEADER_ERRORS as exc:
        logger.debug("Could not decode %s header: %s", name, exc)
        defects.append(f"{name} header could not be decoded: {exc}")
        return _FOLDING.sub(" ", raw_value).strip()
    if isinstance(value, BaseHeader):
        defects.extend(f"{name} header: {_describe_defect(defect)}" for defect in value.defects)
    return value


def _authentication_results(headers: list[Header], defects: list[str]) -> tuple[AuthResult, ...]:
    values = [h.value for h in headers if h.name.lower() == "authentication-results"]
    results: list[AuthResult] = []
    for index, value in enumerate(values):
        parsed = parse_authentication_results(value, header_index=index)
        results.extend(parsed.results)
        if parsed.unreadable:
            defects.append(
                f"Authentication-Results header {index + 1} has "
                f"{parsed.unreadable} unreadable result(s)"
            )
    return tuple(results)


def _received_hops(headers: list[Header], defects: list[str]) -> tuple[ReceivedHop, ...]:
    values = [h.value for h in headers if h.name.lower() == "received"]
    if len(values) > MAX_RECEIVED_HOPS:
        defects.append(
            f"Message has {len(values)} Received headers; only {MAX_RECEIVED_HOPS} were read"
        )
    return tuple(parse_received(value) for value in values[:MAX_RECEIVED_HOPS])


def _unique_links(links: list[Link]) -> list[Link]:
    return list(dict.fromkeys(links))


def _mailboxes(header: str | None, name: str, defects: list[str]) -> tuple[EmailAddress, ...]:
    if header is None:
        return ()
    if isinstance(header, AddressHeader):
        try:
            return tuple(
                EmailAddress(display_name=item.display_name, address=item.addr_spec)
                for item in header.addresses
            )
        except _HEADER_ERRORS as exc:
            defects.append(f"{name} header addresses could not be parsed: {exc}")
    # Fall back to the older, more lenient tuple parser.
    return tuple(
        EmailAddress(display_name=display, address=address)
        for display, address in getaddresses([str(header)])
        if display or address
    )


def _date(header: str | None, defects: list[str]) -> datetime | None:
    if header is None:
        return None
    if isinstance(header, DateHeader):
        # Invalid dates were already recorded as header defects.
        return header.datetime
    try:
        return parsedate_to_datetime(str(header))
    except (TypeError, ValueError, IndexError, OverflowError):
        defects.append("Date header could not be parsed")
        return None


def _strip_brackets(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip().removeprefix("<").removesuffix(">").strip()
    return cleaned or None


def _describe_defect(defect: MessageDefect) -> str:
    detail = str(defect)
    name = type(defect).__name__
    return f"{name}: {detail}" if detail else name
