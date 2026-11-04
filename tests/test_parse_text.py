from hookline.parsing.text import repair_text


def test_clean_text_is_returned_unchanged() -> None:
    text = "caf\xe9 \N{CYRILLIC SMALL LETTER A}"
    assert repair_text(text) is text


def test_escaped_utf8_bytes_are_decoded() -> None:
    escaped = b"caf\xc3\xa9".decode("ascii", "surrogateescape")
    assert repair_text(escaped) == "caf\xe9"


def test_escaped_invalid_bytes_are_replaced() -> None:
    escaped = b"bad \xff byte".decode("ascii", "surrogateescape")
    assert repair_text(escaped) == "bad \ufffd byte"


def test_other_lone_surrogates_are_replaced() -> None:
    assert repair_text("x\ud800y") == "x?y"
