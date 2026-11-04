"""Repair text that the email package decoded with ``surrogateescape``.

Raw 8-bit bytes in headers (common in badly built or deliberately broken
messages) come back from the standard library as lone surrogate characters.
Those cannot be encoded, validated or written to JSON, so every header string is
repaired on the way in: bytes that form valid UTF-8 are decoded, anything else
becomes U+FFFD.
"""

_SURROGATES = range(0xD800, 0xE000)


def repair_text(text: str) -> str:
    """Return ``text`` with surrogate-escaped bytes decoded or replaced."""
    if not any(ord(char) in _SURROGATES for char in text):
        return text
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        # Surrogates outside the escape range cannot map back to bytes.
        return text.encode("utf-8", "replace").decode("utf-8")
