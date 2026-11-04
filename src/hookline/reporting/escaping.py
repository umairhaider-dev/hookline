"""Make untrusted text safe to display."""

import unicodedata

# Control characters, format characters (zero-width and bidirectional
# overrides), lone surrogates, and line/paragraph separators.
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def escape_control_chars(text: str, *, keep_newlines: bool = False) -> str:
    r"""Replace invisible and control characters with visible escapes.

    Email content is attacker-controlled. Terminal escape sequences could
    rewrite what an analyst sees, and right-to-left overrides or zero-width
    characters can disguise file names and URLs (``invoice\u202efdp.exe``).
    Each such character becomes a ``\xNN`` or ``\uNNNN`` escape instead.

    Args:
        text: The untrusted text.
        keep_newlines: Leave ``\n`` and ``\t`` as they are, for multi-line bodies.
    """
    if text.isprintable():
        return text
    out: list[str] = []
    for char in text:
        if keep_newlines and char in "\n\t":
            out.append(char)
        elif unicodedata.category(char) in _INVISIBLE_CATEGORIES:
            code = ord(char)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(char)
    return "".join(out)
