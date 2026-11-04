from ipaddress import IPv4Address, IPv6Address

import pytest

from hookline.domains import (
    DomainParts,
    decode_punycode,
    edit_distance,
    encode_punycode,
    has_public_suffix,
    has_punycode,
    looks_like_domain,
    normalize_host,
    parse_ip,
    registrable_domain,
    skeleton,
    split_domain,
    top_level_domain,
)

CYRILLIC_A = "\N{CYRILLIC SMALL LETTER A}"
CYRILLIC_IE = "\N{CYRILLIC SMALL LETTER IE}"


def test_normalize_host() -> None:
    assert normalize_host("  WWW.PayPal.COM. ") == "www.paypal.com"
    assert normalize_host("[2001:db8::1]") == "2001:db8::1"


def test_parse_ip() -> None:
    assert parse_ip("198.51.100.23") == IPv4Address("198.51.100.23")
    assert parse_ip("[2001:db8::1]") == IPv6Address("2001:db8::1")
    assert parse_ip("larkspur.test") is None


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("mail.example.co.uk", DomainParts("mail", "example", "co.uk")),
        ("WWW.PayPal.COM.", DomainParts("www", "paypal", "com")),
        ("portal.larkspur.test", DomainParts("portal", "larkspur", "test")),
        ("a.b.larkspur.test", DomainParts("a.b", "larkspur", "test")),
        ("localhost", DomainParts("", "localhost", "")),
        ("198.51.100.23", DomainParts("", "198.51.100.23", "")),
        ("", DomainParts("", "", "")),
    ],
)
def test_split_domain(host: str, expected: DomainParts) -> None:
    assert split_domain(host) == expected


def test_registrable_domain() -> None:
    assert registrable_domain("mailer.larkspur-helpdesk.test") == "larkspur-helpdesk.test"
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("localhost") == "localhost"


def test_top_level_domain() -> None:
    assert top_level_domain("mail.example.co.uk") == "uk"
    assert top_level_domain("Invoice.ZIP.") == "zip"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("paypal.com", True),
        ("portal.larkspur.test", True),
        ("invoice.pdf", False),
        ("198.51.100.23", False),
        ("nodot", False),
        ("bad_label.com", False),
        ("double..dot.com", False),
    ],
)
def test_looks_like_domain(text: str, expected: bool) -> None:
    assert looks_like_domain(text) is expected


def test_punycode_round_trip() -> None:
    unicode_host = f"f{CYRILLIC_IE}rnhill-bank.test"
    ascii_host = "xn--frnhill-bank-sck.test"
    assert encode_punycode(unicode_host) == ascii_host
    assert decode_punycode(ascii_host) == unicode_host
    assert has_punycode(ascii_host)
    assert not has_punycode("larkspur.test")


def test_invalid_punycode_label_is_kept() -> None:
    assert decode_punycode("xn--99999999999.test") == "xn--99999999999.test"


@pytest.mark.parametrize(
    "lookalike",
    [
        f"p{CYRILLIC_A}yp{CYRILLIC_A}l",
        "paypa1",
        "PAYPAL",
        "p\N{LATIN SMALL LETTER A WITH ACUTE}ypal",
        "\N{FULLWIDTH LATIN SMALL LETTER P}aypal",
        "paypaI",
    ],
)
def test_skeleton_folds_lookalikes(lookalike: str) -> None:
    assert skeleton(lookalike) == skeleton("paypal")


def test_skeleton_folds_letter_pairs() -> None:
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert skeleton("vvebmail") == skeleton("webmail")
    assert skeleton("larkspur") != skeleton("larkspar")


@pytest.mark.parametrize(
    ("first", "second", "distance"),
    [
        ("paypal", "paypal", 0),
        ("paypal", "paypa", 1),
        ("paypal", "paypall", 1),
        ("paypal", "paypol", 1),
        ("paypal", "papyal", 1),
        ("larkspur", "larksupr", 1),
        ("", "abc", 3),
        ("microsoft", "micrsoft", 1),
    ],
)
def test_edit_distance(first: str, second: str, distance: int) -> None:
    assert edit_distance(first, second, limit=5) == distance


def test_edit_distance_stops_at_limit() -> None:
    assert edit_distance("paypal", "larkspur", limit=1) == 2
    assert edit_distance("abcdefgh", "zyxwvuts", limit=2) == 3
    assert edit_distance("a", "abcdef", limit=2) == 3


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("paypal.com", True),
        ("mail.example.co.uk", True),
        ("portal.larkspur.test", False),
        ("intranet.corp.internal", False),
        ("localhost", False),
        ("198.51.100.23", False),
        ("", False),
    ],
)
def test_has_public_suffix(host: str, expected: bool) -> None:
    assert has_public_suffix(host) is expected
