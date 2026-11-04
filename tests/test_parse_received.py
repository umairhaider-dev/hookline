from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

from hookline.parsing.received import parse_received


def test_postfix_style() -> None:
    hop = parse_received(
        "from mail.larkspur.test (mail.larkspur.test [192.0.2.10])\r\n"
        "\tby mx1.larkspur.test (Postfix) with ESMTPS id 1B7C\r\n"
        "\tfor <sam.ortega@larkspur.test>; Mon, 02 Nov 2026 15:02:11 +0000 (UTC)"
    )
    assert hop.from_host == "mail.larkspur.test"
    assert hop.from_ip == IPv4Address("192.0.2.10")
    assert hop.by_host == "mx1.larkspur.test"
    assert hop.timestamp == datetime(2026, 11, 2, 15, 2, 11, tzinfo=UTC)
    assert "\n" not in hop.raw


def test_exchange_style_with_bare_ip_in_comment() -> None:
    hop = parse_received(
        "from EXCH01.corp.test (10.1.1.5) by EXCH02.corp.test (10.1.1.6) with Microsoft SMTP "
        "Server id 15.2.1118.40; Mon, 2 Nov 2026 15:02:11 +0000"
    )
    assert hop.from_ip == IPv4Address("10.1.1.5")
    assert hop.by_host == "EXCH02.corp.test"


def test_ipv6_literal() -> None:
    hop = parse_received("from [IPv6:2001:db8::25] by mx.test; Mon, 2 Nov 2026 15:02:11 +0000")
    assert hop.from_host == "IPv6:2001:db8::25"
    assert hop.from_ip == IPv6Address("2001:db8::25")


def test_bare_ip_as_host() -> None:
    hop = parse_received("from 203.0.113.9 by mx.test")
    assert hop.from_ip == IPv4Address("203.0.113.9")
    assert hop.timestamp is None


def test_by_inside_a_comment_or_host_name_is_ignored() -> None:
    hop = parse_received(
        "from relay.test (authenticated by someone [198.51.100.4]) by mx.test; "
        "Mon, 2 Nov 2026 15:02:11 +0000"
    )
    assert hop.by_host == "mx.test"
    assert hop.from_ip == IPv4Address("198.51.100.4")
    nearby = parse_received("from host.by (x [192.0.2.1]) by mx.test")
    assert nearby.by_host == "mx.test"


def test_invalid_bracketed_value_falls_back_to_comment_ip() -> None:
    hop = parse_received("from x ([unknown] 203.0.113.5) by mx.test")
    assert hop.from_ip == IPv4Address("203.0.113.5")


def test_local_delivery_without_from_clause() -> None:
    hop = parse_received("by mx.test (Postfix, from userid 1000) id 99; Mon, 2 Nov 2026 15:02:11")
    assert hop.from_host is None
    assert hop.from_ip is None
    assert hop.by_host == "mx.test"


def test_unparseable_date() -> None:
    hop = parse_received("from a.test by b.test; sometime yesterday")
    assert hop.timestamp is None


def test_garbage() -> None:
    hop = parse_received("((((;;;")
    assert hop.from_host is None
    assert hop.by_host is None


def test_from_clause_without_by() -> None:
    hop = parse_received("from relay.test (relay.test [203.0.113.8])")
    assert hop.from_ip == IPv4Address("203.0.113.8")
    assert hop.by_host is None


def test_invalid_addresses_are_skipped() -> None:
    hop = parse_received("from x ([999.1.1.1] 999.0.0.1 203.0.113.5) by y")
    assert hop.from_ip == IPv4Address("203.0.113.5")
