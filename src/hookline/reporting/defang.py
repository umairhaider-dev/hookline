"""Defang indicators so they cannot be clicked or resolved by accident.

``http://evil.test/x`` becomes ``hxxp://evil[.]test/x``, ``198.51.100.23``
becomes ``198.51.100[.]23`` and ``a@evil.test`` becomes ``a[@]evil[.]test``,
the conventions most threat intelligence tools understand.
"""

import re

from hookline.domains import looks_like_domain, parse_ip

_SCHEME = re.compile(r"^http(s?)://", re.I)
_ANGLE_ADDRESS = re.compile(r"<([^<>\s@]+@[^<>\s@]+)>")
_LAST_DOT = re.compile(r"\.(?=[^.]*$)")


def defang(value: str) -> str:
    """Return a defanged copy of a URL, domain, IP address or email address."""
    text = _SCHEME.sub(lambda match: f"hxxp{match.group(1).lower()}://", value)
    rest = text
    prefix = ""
    if "://" in text:
        prefix, _, rest = text.partition("://")
        prefix += "://"
    host, slash, path = _split_host(rest)
    host = host.replace("@", "[@]")
    host = _LAST_DOT.sub("[.]", host, count=1)
    return f"{prefix}{host}{slash}{path}"


def defang_if_indicator(value: str) -> str:
    """Defang ``value`` only if it is a URL, domain, IP or email address.

    Indicator values are often free text (matched phrases, header results);
    those are returned unchanged so sentences keep their full stops.
    """
    text = value.strip()
    if _SCHEME.match(text) or parse_ip(text) is not None or looks_like_domain(text):
        return defang(value)
    _, at, host = text.rpartition("@")
    if at and " " not in text and looks_like_domain(host):
        return defang(value)
    # "Display Name" <user@example.com>
    return _ANGLE_ADDRESS.sub(lambda match: f"<{defang(match.group(1))}>", value)


def _split_host(text: str) -> tuple[str, str, str]:
    for index, char in enumerate(text):
        if char in "/?#":
            return text[:index], char, text[index + 1 :]
    return text, "", ""
