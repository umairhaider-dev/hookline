"""Decide whether HTML text would be invisible to the reader.

Only inline styles and presentational attributes are considered; style sheets
and scripts are not evaluated. That covers the tricks phishing kits use to hide
text from people while keeping it for filters and language models:
``display:none``, zero sizes, transparent or background-coloured text,
Outlook's ``mso-hide:all`` and the ``hidden`` attribute.
"""

import re
from dataclasses import dataclass

DEFAULT_TEXT = "#000000"
DEFAULT_BACKGROUND = "#ffffff"
TRANSPARENT = "transparent"

_NAMED_COLOURS = {
    "white": "#ffffff",
    "black": "#000000",
    "snow": "#fffafa",
    "ivory": "#fffff0",
    "whitesmoke": "#f5f5f5",
    "transparent": TRANSPARENT,
}
_HEX = re.compile(r"^#(?:[0-9a-f]{3}|[0-9a-f]{6})$")
_RGB = re.compile(r"^rgba?\((\d{1,3}),(\d{1,3}),(\d{1,3})(?:,([\d.]+%?))?\)$")
_ZERO_LENGTH = re.compile(r"^0+(?:\.0+)?(?:px|pt|em|rem|%|cm|mm|in)?$")
_TINY_FONT = re.compile(r"^(?:0+(?:\.\d+)?|1)(?:px|pt)?$")


@dataclass(frozen=True)
class Frame:
    """The visibility state of one open element."""

    tag: str
    hidden_by: str | None = None
    colour: str | None = None
    background: str | None = None

    @property
    def hidden(self) -> str | None:
        """Why text in this element is invisible, or None if it is visible."""
        if self.hidden_by is not None:
            return self.hidden_by
        text = self.colour or DEFAULT_TEXT
        if text == TRANSPARENT:
            return "transparent text"
        if text == (self.background or DEFAULT_BACKGROUND):
            return "text the same colour as its background"
        return None


ROOT = Frame(tag="")


def child_frame(tag: str, attributes: dict[str, str], parent: Frame) -> Frame:
    """The frame for an element opened inside ``parent``."""
    style = parse_style(attributes.get("style", ""))
    hidden_by = parent.hidden_by or _structural_reason(attributes, style)
    colour = normalize_colour(style.get("color") or attributes.get("color", "")) or parent.colour
    background = _background(style, attributes) or parent.background
    return Frame(tag=tag, hidden_by=hidden_by, colour=colour, background=background)


def parse_style(style: str) -> dict[str, str]:
    """Parse an inline ``style`` attribute into lower-cased property values."""
    declarations: dict[str, str] = {}
    for declaration in style.split(";"):
        name, colon, value = declaration.partition(":")
        if colon:
            cleaned = value.lower().replace("!important", "").strip()
            declarations[name.strip().lower()] = cleaned
    return declarations


def normalize_colour(value: str) -> str | None:
    """Return a colour as ``#rrggbb`` (or ``transparent``), or None if not understood."""
    text = value.strip().lower().replace(" ", "")
    if not text:
        return None
    if text in _NAMED_COLOURS:
        return _NAMED_COLOURS[text]
    if _HEX.match(text):
        if len(text) == 4:
            return "#" + "".join(digit * 2 for digit in text[1:])
        return text
    match = _RGB.match(text)
    if match:
        alpha = match.group(4)
        if alpha is not None and _is_zero(alpha.rstrip("%")):
            return TRANSPARENT
        channels = [min(int(part), 255) for part in match.groups()[:3]]
        return "#" + "".join(f"{channel:02x}" for channel in channels)
    return None


def _structural_reason(attributes: dict[str, str], style: dict[str, str]) -> str | None:
    if "hidden" in attributes:
        return "hidden attribute"
    if style.get("display") == "none":
        return "display:none"
    if style.get("visibility") in {"hidden", "collapse"}:
        return "visibility:hidden"
    if style.get("mso-hide") == "all":
        return "mso-hide:all"
    if _is_zero(style.get("opacity", "1").rstrip("%")):
        return "opacity:0"
    if _TINY_FONT.match(style.get("font-size", "")):
        return "zero or one pixel font size"
    collapsed = any(
        _ZERO_LENGTH.match(style.get(name, "")) for name in ("height", "max-height", "width")
    )
    if collapsed and style.get("overflow") == "hidden":
        return "zero size with overflow hidden"
    return None


def _background(style: dict[str, str], attributes: dict[str, str]) -> str | None:
    for candidate in (style.get("background-color", ""), attributes.get("bgcolor", "")):
        colour = normalize_colour(candidate)
        if colour is not None and colour != TRANSPARENT:
            return colour
    # The shorthand may mix a colour with images and positions.
    for token in style.get("background", "").split():
        colour = normalize_colour(token)
        if colour is not None and colour != TRANSPARENT:
            return colour
    return None


def _is_zero(value: str) -> bool:
    try:
        return float(value) == 0
    except ValueError:
        return False
