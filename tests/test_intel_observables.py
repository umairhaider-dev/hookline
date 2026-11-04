import hashlib
from ipaddress import ip_address

from hookline.config import ThreatIntelSettings
from hookline.intel.observables import collect_observables
from hookline.models import (
    Attachment,
    EmailAddress,
    Link,
    LinkOrigin,
    Observable,
    ObservableKind,
    ReceivedHop,
)
from tests.factories import make_email

SHA = hashlib.sha256(b"payload").hexdigest()


def link(url: str) -> Link:
    return Link(url=url, origin=LinkOrigin.HTML_ANCHOR)


def hop(address: str) -> ReceivedHop:
    return ReceivedHop(raw="from x", from_ip=ip_address(address))


EMAIL = make_email(
    from_address=EmailAddress(address="billing@mail.example.org"),
    attachments=(
        Attachment(filename="a.pdf", content_type="application/pdf", size=7, sha256=SHA),
        Attachment(
            filename="empty.txt",
            content_type="text/plain",
            size=0,
            sha256=hashlib.sha256(b"").hexdigest(),
        ),
    ),
    received=(hop("8.8.8.8"), hop("10.0.0.1"), hop("203.0.113.5"), hop("8.8.8.8")),
    links=(
        link("https://login.example.net/verify"),
        link("https://login.example.net/verify"),
        link("http://8.8.4.4/x"),
        link("http://198.51.100.23/x"),
        link("https://portal.larkspur.test/reset"),
        link("https://intranet.corp.internal/"),
        link("https://www.protected.example.com/"),
        link("mailto:help@example.net"),
        link("http://[bad"),
    ),
)


def test_only_public_values_are_collected_most_decisive_first() -> None:
    found = collect_observables(EMAIL, ThreatIntelSettings(), ["example.com"])
    assert found == [
        Observable(kind=ObservableKind.SHA256, value=SHA),
        Observable(kind=ObservableKind.URL, value="https://login.example.net/verify"),
        Observable(kind=ObservableKind.URL, value="http://8.8.4.4/x"),
        Observable(kind=ObservableKind.IP, value="8.8.8.8"),
        Observable(kind=ObservableKind.IP, value="8.8.4.4"),
        Observable(kind=ObservableKind.DOMAIN, value="example.org"),
        Observable(kind=ObservableKind.DOMAIN, value="example.net"),
    ]


def test_kinds_can_be_turned_off() -> None:
    settings = ThreatIntelSettings(
        lookup_hashes=False, lookup_urls=False, lookup_domains=False, lookup_ips=True
    )
    found = collect_observables(EMAIL, settings, [])
    assert {item.kind for item in found} == {ObservableKind.IP}


def test_protected_or_reserved_sender_is_not_looked_up() -> None:
    for address in ("x@mail.example.com", "x@larkspur.test", "x@[8.8.8.8]", "nodomain"):
        email = make_email(from_address=EmailAddress(address=address))
        assert collect_observables(email, ThreatIntelSettings(), ["example.com"]) == []
