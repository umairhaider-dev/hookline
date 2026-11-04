import pytest

from hookline.reporting.escaping import escape_control_chars


@pytest.mark.parametrize("text", ["plain ascii", "caf\u00e9 \u26a0 \u4f60\u597d", ""])
def test_printable_text_is_unchanged(text: str) -> None:
    assert escape_control_chars(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("\x1b[31mred", "\\x1b[31mred"),
        ("nul\x00", "nul\\x00"),
        ("bell\x07", "bell\\x07"),
        ("invoice\u202efdp.exe", "invoice\\u202efdp.exe"),
        ("pay\u200bpal", "pay\\u200bpal"),
        ("line\u2028break", "line\\u2028break"),
        ("lone\udc80surrogate", "lone\\udc80surrogate"),
        ("a\nb\tc", "a\\x0ab\\x09c"),
    ],
)
def test_invisible_characters_are_escaped(text: str, expected: str) -> None:
    assert escape_control_chars(text) == expected


def test_newlines_and_tabs_can_be_kept() -> None:
    assert escape_control_chars("a\nb\tc\x1b", keep_newlines=True) == "a\nb\tc\\x1b"
