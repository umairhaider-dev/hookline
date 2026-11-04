"""Parse URLs found in emails without ever fetching them."""

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import unquote, urlsplit

from hookline.domains import normalize_host, parse_ip

# Browsers drop these from URLs before parsing (WHATWG URL standard).
_URL_WHITESPACE = str.maketrans("", "", "\t\n\r")

_IPV4_PART = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")


@dataclass(frozen=True)
class ParsedURL:
    """The pieces of a URL that the link checks look at."""

    raw: str
    scheme: str
    host: str
    userinfo: str
    path: str
    query: str
    fragment: str
    ip: IPv4Address | IPv6Address | None
    ip_is_disguised: bool

    @property
    def is_web(self) -> bool:
        """True for http and https URLs with a host."""
        return self.scheme in {"http", "https"} and bool(self.host)


def clean_url(url: str) -> str:
    """Strip the whitespace a browser would ignore, so checks see the real URL."""
    return url.strip().translate(_URL_WHITESPACE)


def parse_url(url: str) -> ParsedURL | None:
    """Split ``url`` into parts. Returns None if it cannot be parsed at all.

    ``www.`` addresses without a scheme are treated as ``http``. Hosts are
    normalised and percent-decoded, and IPv4 addresses written in decimal,
    hexadecimal or octal form (which browsers still accept) are recognised.
    """
    text = clean_url(url)
    if text.lower().startswith("www."):
        text = "http://" + text
    try:
        # Raises on unbalanced IPv6 brackets and on netlocs that change under
        # Unicode normalisation.
        parts = urlsplit(text)
    except ValueError:
        return None
    hostname = parts.hostname or ""
    userinfo, _, _ = parts.netloc.rpartition("@")
    host = normalize_host(unquote(hostname))
    ip = parse_ip(host)
    disguised = False
    if ip is None and host:
        ip = _parse_numeric_ipv4(host)
        disguised = ip is not None
    return ParsedURL(
        raw=url,
        scheme=parts.scheme.lower(),
        host=host,
        userinfo=userinfo,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
        ip=ip,
        ip_is_disguised=disguised,
    )


def _parse_numeric_ipv4(host: str) -> IPv4Address | None:
    """Parse the non-standard IPv4 forms browsers accept, like ``3325256839``.

    Follows the WHATWG rules: one to four dot-separated parts, each decimal,
    ``0x`` hexadecimal or zero-prefixed octal, with the last part filling the
    remaining bytes.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(_IPV4_PART.match(part) for part in parts):
        return None
    numbers = [_parse_ipv4_number(part) for part in parts]
    last = numbers.pop()
    if any(number > 255 for number in numbers) or last >= 256 ** (4 - len(numbers)):
        return None
    value = last
    for index, number in enumerate(numbers):
        value += number * 256 ** (3 - index)
    return IPv4Address(value)


def _parse_ipv4_number(part: str) -> int:
    if part.startswith("0x"):
        return int(part[2:] or "0", 16)
    if len(part) > 1 and part.startswith("0"):
        # Not valid octal (contains 8 or 9): browsers reject the host.
        return int(part, 8) if set(part) <= set("01234567") else 256**4
    return int(part)
