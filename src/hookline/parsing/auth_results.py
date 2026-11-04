"""Parse Authentication-Results headers (RFC 8601).

Example::

    mx1.example.test; spf=fail smtp.mailfrom=bad.test; dkim=none;
        dmarc=fail (p=reject) header.from=bad.test

Comments in parentheses are dropped first, because they may contain
semicolons. Entries that do not look like ``method=result`` are skipped and
counted so the caller can record a defect.
"""

import re
from dataclasses import dataclass

from hookline.models.email import AuthResult

MAX_RESULTS_PER_HEADER = 50

_METHOD_RESULT = re.compile(r"^\s*([a-z0-9][a-z0-9_-]*)\s*(?:/\s*\d+\s*)?=\s*([a-z0-9_-]+)", re.I)
# Properties such as smtp.mailfrom=..., header.d=..., reason="..." or action=none.
_PROPERTY = re.compile(r'([a-z0-9_.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s;]+)', re.I)


@dataclass(frozen=True)
class ParsedAuthHeader:
    """Results from one header, plus how many entries could not be read."""

    results: tuple[AuthResult, ...]
    unreadable: int


def parse_authentication_results(value: str, *, header_index: int = 0) -> ParsedAuthHeader:
    """Parse one Authentication-Results header value."""
    segments = _split_outside_quotes(strip_comments(value))
    authserv_id = segments[0].strip().split(maxsplit=1)[0].lower() if segments[0].strip() else None
    results: list[AuthResult] = []
    unreadable = 0
    for segment in segments[1:]:
        if not segment.strip() or segment.strip().lower() == "none":
            continue
        match = _METHOD_RESULT.match(segment)
        if match is None:
            unreadable += 1
            continue
        if len(results) >= MAX_RESULTS_PER_HEADER:
            unreadable += 1
            continue
        properties = {
            key.lower(): _unquote(item) for key, item in _PROPERTY.findall(segment[match.end() :])
        }
        results.append(
            AuthResult(
                method=match.group(1).lower(),
                result=match.group(2).lower(),
                properties=properties,
                authserv_id=authserv_id,
                header_index=header_index,
            )
        )
    return ParsedAuthHeader(results=tuple(results), unreadable=unreadable)


def strip_comments(value: str) -> str:
    """Remove (possibly nested) parenthesised comments, leaving quoted strings alone."""
    output: list[str] = []
    depth = 0
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            escaped = False
            if depth == 0:
                output.append(char)
            continue
        if char == "\\":
            escaped = True
            if depth == 0:
                output.append(char)
            continue
        if quoted:
            quoted = char != '"'
            output.append(char)
        elif char == '"' and depth == 0:
            quoted = True
            output.append(char)
        elif char == "(":
            depth += 1
        elif char == ")" and depth > 0:
            depth -= 1
            if depth == 0:
                output.append(" ")
        elif depth == 0:
            output.append(char)
    return "".join(output)


def _split_outside_quotes(value: str) -> list[str]:
    """Split on semicolons that are not inside a quoted string."""
    segments: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == ";" and not quoted:
            segments.append("".join(current))
            current = []
            continue
        current.append(char)
    segments.append("".join(current))
    return segments


def _unquote(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value
