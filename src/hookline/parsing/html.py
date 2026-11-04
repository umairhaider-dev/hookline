"""Extract readable text and links from an HTML body.

Uses the standard library's tolerant HTML tokenizer. Nothing is rendered,
no resources are loaded and scripts are never run; script and style content is
simply dropped from the text. Text a reader would not see (see
:mod:`hookline.parsing.visibility`) and HTML comments are kept apart from the
visible text, so they can be reported without being mistaken for content. The
tokenizer is pure Python, so very large bodies are cut off and the cut is
reported rather than silently ignored.
"""

import logging
import re
from dataclasses import dataclass
from html.parser import HTMLParser

from hookline.models.email import HiddenText, Link, LinkOrigin
from hookline.parsing.visibility import ROOT, Frame, child_frame
from hookline.urls import clean_url

logger = logging.getLogger(__name__)

MAX_LINK_TEXT = 500
MAX_HTML_CHARS = 2_000_000
DEFAULT_MAX_LINKS = 500
MAX_HIDDEN_SEGMENTS = 50
MAX_HIDDEN_CHARS = 2000
COMMENT = "HTML comment"

_SKIPPED_ELEMENTS = frozenset({"script", "style"})
_BLOCK_ELEMENTS = frozenset(
    {
        "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt",
        "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li",
        "main", "nav", "ol", "p", "pre", "section", "table", "tr", "ul",
    }
)  # fmt: skip
_CELL_ELEMENTS = frozenset({"td", "th"})
# Elements that never have content or an end tag.
_VOID_ELEMENTS = frozenset(
    {
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
        "source", "track", "wbr",
    }
)  # fmt: skip

_SPACES = re.compile(r"[ \t\f\v]+")
_BLANK_LINES = re.compile(r"\n{3,}")


@dataclass(frozen=True)
class HtmlContent:
    """What an HTML body yields: its readable text and the links it contains."""

    text: str
    links: tuple[Link, ...]
    hidden: tuple[HiddenText, ...] = ()
    problems: tuple[str, ...] = ()
    links_dropped: int = 0


def extract_html(html: str, *, max_links: int = DEFAULT_MAX_LINKS) -> HtmlContent:
    """Return the text and distinct links of ``html``. Never raises on malformed markup."""
    problems = []
    if len(html) > MAX_HTML_CHARS:
        problems.append(
            f"HTML body has {len(html):,} characters; only the first {MAX_HTML_CHARS:,} "
            "were analysed"
        )
        html = html[:MAX_HTML_CHARS]
    extractor = _Extractor(max_links)
    try:
        extractor.feed(html)
        extractor.close()
    except AssertionError as exc:
        # The tokenizer has one internal assertion for states it believes are
        # unreachable; keep whatever was extracted before it fired.
        logger.debug("HTML tokenizer stopped early: %s", exc)
        problems.append(f"HTML body could not be fully parsed: {exc}")
    extractor.finish_anchor()
    return HtmlContent(
        text=_tidy(extractor.text()),
        links=tuple(extractor.links),
        hidden=extractor.hidden_text(),
        problems=tuple(problems),
        links_dropped=extractor.links_dropped,
    )


def collapse_whitespace(text: str) -> str:
    """Collapse every run of whitespace into one space."""
    return " ".join(text.split())


class _Extractor(HTMLParser):
    def __init__(self, max_links: int = DEFAULT_MAX_LINKS) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.links_dropped = 0
        self._max_links = max_links
        self._seen: set[tuple[str, str, LinkOrigin]] = set()
        self._chunks: list[str] = []
        self._hidden: list[tuple[str, list[str]]] = []
        self._hidden_open = False
        self._stack: list[Frame] = [ROOT]
        self._skipping: str | None = None
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def text(self) -> str:
        return "".join(self._chunks)

    def hidden_text(self) -> tuple[HiddenText, ...]:
        segments = []
        for reason, parts in self._hidden:
            text = collapse_whitespace("".join(parts))[:MAX_HIDDEN_CHARS]
            if text:
                segments.append(HiddenText(text=text, reason=reason))
        return tuple(segments[:MAX_HIDDEN_SEGMENTS])

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIPPED_ELEMENTS:
            self._skipping = tag
            return
        values = {name: value for name, value in attrs if value is not None}
        if tag == "a":
            self.finish_anchor()
            href = values.get("href")
            if href:
                self._anchor_href = clean_url(href)
        elif tag == "area" and values.get("href"):
            self._add_link(values["href"], "", LinkOrigin.HTML_ANCHOR)
        elif tag == "form" and values.get("action"):
            self._add_link(values["action"], "", LinkOrigin.HTML_FORM)
        elif tag == "img" and values.get("alt") and self._anchor_href is not None:
            self._anchor_text.append(f" {values['alt']} ")
        if tag not in _VOID_ELEMENTS:
            attributes = {name: value or "" for name, value in attrs}
            self._stack.append(child_frame(tag, attributes, self._stack[-1]))
        self._break(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Browsers ignore the slash on non-void elements ("<div/>" opens a div),
        # so this is treated exactly like a start tag.
        if tag not in _SKIPPED_ELEMENTS:
            self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if self._skipping is not None:
            if tag == self._skipping:
                self._skipping = None
            return
        if tag == "a":
            self.finish_anchor()
        # Close back to the matching element; stray end tags are ignored.
        for depth in range(len(self._stack) - 1, 0, -1):
            if self._stack[depth].tag == tag:
                del self._stack[depth:]
                break
        self._break(tag)

    def handle_data(self, data: str) -> None:
        if self._skipping is not None:
            return
        if self._anchor_href is not None:
            self._anchor_text.append(data)
        reason = self._stack[-1].hidden
        if reason is None:
            self._chunks.append(data)
            if data.strip():
                self._hidden_open = False
        elif self._hidden_open and self._hidden[-1][0] == reason:
            self._hidden[-1][1].append(data)
        else:
            self._hidden.append((reason, [data]))
            self._hidden_open = True

    def handle_comment(self, data: str) -> None:
        # Outlook's conditional comments carry layout markup, not text.
        stripped = data.strip()
        if stripped and not stripped.startswith(("[if", "<![endif]", "[endif]")):
            self._hidden.append((COMMENT, [stripped]))
            self._hidden_open = False

    def finish_anchor(self) -> None:
        """Record the open anchor, if any. Also called for unclosed anchors."""
        if self._anchor_href is not None:
            self._add_link(self._anchor_href, "".join(self._anchor_text), LinkOrigin.HTML_ANCHOR)
        self._anchor_href = None
        self._anchor_text = []

    def _add_link(self, url: str, text: str, origin: LinkOrigin) -> None:
        url = clean_url(url)
        if not url:
            return
        text = collapse_whitespace(text)[:MAX_LINK_TEXT]
        key = (url, text, origin)
        if key in self._seen:
            return
        if len(self.links) >= self._max_links:
            self.links_dropped += 1
            return
        self._seen.add(key)
        self.links.append(Link(url=url, text=text, origin=origin))

    def _break(self, tag: str) -> None:
        if tag not in _BLOCK_ELEMENTS and tag not in _CELL_ELEMENTS:
            return
        self._chunks.append("\n" if tag in _BLOCK_ELEMENTS else " ")
        if self._hidden_open:
            self._hidden[-1][1].append(" ")


def _tidy(text: str) -> str:
    lines = (_SPACES.sub(" ", line).strip() for line in text.splitlines())
    return _BLANK_LINES.sub("\n\n", "\n".join(lines)).strip()
