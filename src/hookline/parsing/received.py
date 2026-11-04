"""Parse Received headers into hops.

Received headers have no strict grammar in practice. Typical forms::

    from mail.example.test (mail.example.test [192.0.2.10]) by mx1.example.test
        (Postfix) with ESMTPS id 1B7C; Mon, 02 Nov 2026 15:02:11 +0000
    from EXCH01.corp.test (10.1.1.5) by EXCH02.corp.test (10.1.1.6) with
        Microsoft SMTP Server id 15.2.1118.40; Mon, 2 Nov 2026 15:02:11 +0000

The connecting IP is taken from the ``from`` clause: a bracketed address first,
then any IPv4 address written inside a comment, then the host itself.
"""

import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from ipaddress import IPv4Address, IPv6Address

from hookline.domains import parse_ip
from hookline.models.email import ReceivedHop
from hookline.parsing.auth_results import strip_comments

_WHITESPACE = re.compile(r"\s+")
_FROM_HOST = re.compile(r"^\s*from\s+([^\s;()]+)", re.I)
# "by" as a whole word, not the end of a host name such as "relay.by".
_BY_KEYWORD = re.compile(r"(?<![\w.-])by\s+([^\s;()]+)", re.I)
_BRACKETED_IP = re.compile(r"\[(?:ipv6:)?([0-9a-f:.]+)\]", re.I)
_BARE_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def parse_received(value: str) -> ReceivedHop:
    """Parse one Received header value. Fields that cannot be found are None."""
    raw = _WHITESPACE.sub(" ", value).strip()
    clauses, semicolon, date_text = raw.rpartition(";")
    if not semicolon:
        clauses, date_text = raw, ""
    top_level = strip_comments(clauses)

    from_match = _FROM_HOST.match(top_level)
    from_host = from_match.group(1).strip("[]") if from_match else None
    by_match = _BY_KEYWORD.search(top_level)
    by_host = by_match.group(1) if by_match else None

    from_ip = None
    if from_match:
        from_ip = _connecting_ip(_from_clause(clauses), from_host)
    return ReceivedHop(
        raw=raw,
        from_host=from_host,
        from_ip=from_ip,
        by_host=by_host,
        timestamp=_timestamp(date_text),
    )


def _from_clause(clauses: str) -> str:
    """Return the text between ``from`` and the top-level ``by``, comments included."""
    depth = 0
    for index, char in enumerate(clauses):
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        elif depth == 0 and _BY_KEYWORD.match(clauses, index):
            return clauses[:index]
    return clauses


def _connecting_ip(clause: str, from_host: str | None) -> IPv4Address | IPv6Address | None:
    for match in _BRACKETED_IP.finditer(clause):
        address = parse_ip(match.group(1))
        if address is not None:
            return address
    for match in _BARE_IPV4.finditer(clause):
        address = parse_ip(match.group(1))
        if address is not None:
            return address
    return parse_ip(from_host) if from_host else None


def _timestamp(text: str) -> datetime | None:
    text = strip_comments(text).strip()
    if not text:
        return None
    try:
        return parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
