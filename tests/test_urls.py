from ipaddress import IPv4Address, IPv6Address

import pytest

from hookline.urls import clean_url, parse_url


def test_parse_simple_url() -> None:
    url = parse_url("https://Portal.Larkspur.test:8443/a/b?x=1#frag")
    assert url is not None
    assert (url.scheme, url.host, url.path, url.query, url.fragment) == (
        "https",
        "portal.larkspur.test",
        "/a/b",
        "x=1",
        "frag",
    )
    assert url.ip is None
    assert url.is_web


def test_www_without_scheme_is_http() -> None:
    url = parse_url("www.larkspur.test/news")
    assert url is not None
    assert url.scheme == "http"
    assert url.host == "www.larkspur.test"


def test_userinfo_is_split_from_host() -> None:
    url = parse_url("https://portal.larkspur.test@198.51.100.23/login")
    assert url is not None
    assert url.userinfo == "portal.larkspur.test"
    assert url.host == "198.51.100.23"
    assert url.ip == IPv4Address("198.51.100.23")
    assert not url.ip_is_disguised


def test_ipv6_host() -> None:
    url = parse_url("http://[2001:db8::1]/x")
    assert url is not None
    assert url.ip == IPv6Address("2001:db8::1")


def test_unparseable_url_returns_none() -> None:
    assert parse_url("http://[::1/") is None


def test_non_web_schemes() -> None:
    mail = parse_url("mailto:sam.ortega@larkspur.test")
    assert mail is not None
    assert not mail.is_web
    script = parse_url("JavaScript:alert(1)")
    assert script is not None
    assert script.scheme == "javascript"


def test_percent_encoded_host_is_decoded() -> None:
    url = parse_url("http://%6c%61rkspur.test/")
    assert url is not None
    assert url.host == "larkspur.test"


@pytest.mark.parametrize(
    ("host", "address"),
    [
        ("3325256727", "198.51.100.23"),
        ("0xc6336417", "198.51.100.23"),
        ("0306.0063.0144.0027", "198.51.100.23"),
        ("198.51.25623", "198.51.100.23"),
        ("198.051.100.023", "198.41.100.19"),
        ("198.51.100.23.", "198.51.100.23"),
    ],
)
def test_disguised_ipv4_forms(host: str, address: str) -> None:
    url = parse_url(f"http://{host}/login")
    assert url is not None
    assert url.ip == IPv4Address(address)
    assert url.ip_is_disguised is (host.rstrip(".") != address)


@pytest.mark.parametrize(
    "host",
    ["1.2.3.4.5", "256.1.1.1", "09.1.1.1", "1e100.test", "1.2.3.4294967296", "0x.1.2.3a"],
)
def test_hosts_that_are_not_ip_addresses(host: str) -> None:
    url = parse_url(f"http://{host}/")
    assert url is not None
    assert url.ip is None


def test_clean_url_drops_whitespace_browsers_ignore() -> None:
    assert clean_url("  https://larkspur.test/\tpa\nth\r  ") == "https://larkspur.test/path"
