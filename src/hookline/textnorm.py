"""Text normalisation shared by the checks and the language model prompt.

Characters are referred to by code point so this file contains no invisible
characters itself.
"""

import re
import unicodedata

# Invisible characters that can be slipped inside words to break up phrases.
# The soft hyphen is excluded from in-word counting because long words use it
# legitimately for line breaking.
ZERO_WIDTH_CODE_POINTS = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)
_INVISIBLE_CODE_POINTS = (
    *ZERO_WIDTH_CODE_POINTS,
    0x00AD,
    0x034F,
    0x180E,
    0x2061,
    0x2062,
    0x2063,
    0x2064,
)

_FOLD_TABLE: dict[int, str | None] = {
    **dict.fromkeys(_INVISIBLE_CODE_POINTS),
    0x2018: "'",
    0x2019: "'",
}
_SPACES = re.compile(r"\s+")
_ZERO_WIDTH_CLASS = "".join(chr(code) for code in ZERO_WIDTH_CODE_POINTS)
_ZERO_WIDTH_IN_WORDS = re.compile(f"(?<=\\w)[{_ZERO_WIDTH_CLASS}]+(?=\\w)")
_KEPT_CONTROLS = frozenset("\n\t")


def normalize_text(text: str) -> str:
    """Fold text for phrase matching: compatibility forms, case, invisibles, whitespace."""
    folded = unicodedata.normalize("NFKC", text).translate(_FOLD_TABLE).casefold()
    return _SPACES.sub(" ", folded)


def count_zero_width_in_words(text: str) -> int:
    """How many zero-width characters sit between two word characters."""
    return sum(len(match.group(0)) for match in _ZERO_WIDTH_IN_WORDS.finditer(text))


def strip_invisible(text: str) -> str:
    """Remove control and format characters (keeping newlines and tabs).

    Used for text shown to the language model, so that bidirectional overrides
    and zero-width characters cannot hide or reorder words.
    """
    return "".join(
        char
        for char in text
        if char in _KEPT_CONTROLS or unicodedata.category(char) not in {"Cc", "Cf", "Cs"}
    )
