from ipaddress import IPv4Address, IPv6Address

import pytest
from pydantic import ValidationError

from hookline.models import Attachment, EmailAddress, Header, ReceivedHop
from tests.factories import make_email


@pytest.mark.parametrize(
    ("address", "domain"),
    [
        ("dana@Larkspur.TEST", "larkspur.test"),
        ("dana@larkspur.test.", "larkspur.test"),
        ("odd@local@evil.test", "evil.test"),
        ("no-at-sign", ""),
        ("", ""),
    ],
)
def test_email_address_domain(address: str, domain: str) -> None:
    assert EmailAddress(address=address).domain == domain


def test_email_address_str() -> None:
    assert str(EmailAddress(address="a@b.test")) == "a@b.test"
    named = EmailAddress(display_name="Dana Whitfield", address="dana@larkspur.test")
    assert str(named) == '"Dana Whitfield" <dana@larkspur.test>'


def test_header_values_match_case_insensitively_and_keep_order() -> None:
    email = make_email(
        headers=(
            Header(name="Received", value="first"),
            Header(name="From", value="x@y.test"),
            Header(name="received", value="second"),
        )
    )
    assert email.header_values("RECEIVED") == ["first", "second"]
    assert email.header_values("X-Missing") == []


@pytest.mark.parametrize("digest", ["ABC", "A" * 64, "g" * 64, "a" * 63])
def test_sha256_must_be_lowercase_hex(digest: str) -> None:
    with pytest.raises(ValidationError):
        make_email(sha256=digest)


def test_received_hop_accepts_v4_and_v6() -> None:
    v4 = ReceivedHop.model_validate({"raw": "from x", "from_ip": "203.0.113.45"})
    v6 = ReceivedHop.model_validate({"raw": "from y", "from_ip": "2001:db8::1"})
    assert v4.from_ip == IPv4Address("203.0.113.45")
    assert v6.from_ip == IPv6Address("2001:db8::1")


def test_received_hop_rejects_invalid_ip() -> None:
    with pytest.raises(ValidationError):
        ReceivedHop.model_validate({"raw": "from x", "from_ip": "not-an-ip"})


def test_attachment_size_cannot_be_negative() -> None:
    with pytest.raises(ValidationError):
        Attachment(content_type="application/pdf", size=-1, sha256="0" * 64)
