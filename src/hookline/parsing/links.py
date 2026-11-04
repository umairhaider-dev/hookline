"""Find URLs written out in plain text."""

import re

from hookline.models.email import Link, LinkOrigin

_URL = re.compile(r"(?:\bhttps?://|\bwww\.)[^\s<>\"'\x00-\x1f\x7f]+", re.I)
_TRAILING = ".,;:!?'\")]}>*"


def extract_text_links(text: str, *, limit: int | None = None) -> list[Link]:
    """Return the ``http(s)://`` and ``www.`` URLs in ``text``, in order, without duplicates.

    Stops after ``limit`` distinct URLs when a limit is given.
    """
    seen: set[str] = set()
    links: list[Link] = []
    for match in _URL.finditer(text):
        url = _trim(match.group(0))
        if url and url not in seen:
            if limit is not None and len(links) >= limit:
                break
            seen.add(url)
            links.append(Link(url=url, origin=LinkOrigin.PLAIN_TEXT))
    return links


def _trim(url: str) -> str:
    """Drop sentence punctuation after a URL, keeping balanced closing parentheses."""
    while url and url[-1] in _TRAILING:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url
