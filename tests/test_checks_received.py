from ipaddress import IPv4Address, IPv6Address, ip_address

import pytest

from hookline.checks import ReceivedChainCheck
from hookline.checks import received as received_module
from hookline.checks.received import is_internal
from hookline.models import IndicatorType, ReceivedHop, Severity
from tests.factories import make_email


def hop(address: str | None, from_host: str | None = "relay.test") -> ReceivedHop:
    return ReceivedHop(
        raw="from ...",
        from_host=from_host,
        from_ip=ip_address(address) if address else None,
        by_host="mx1.larkspur.test",
    )


@pytest.mark.parametrize(
    ("address", "internal"),
    [
        ("10.1.2.3", True),
        ("172.20.0.1", True),
        ("192.168.1.1", True),
        ("127.0.0.1", True),
        ("100.64.0.9", True),
        ("169.254.0.1", True),
        ("0.1.2.3", True),
        ("224.0.0.1", True),
        ("::1", True),
        ("fd00::5", True),
        ("fe80::1", True),
        ("203.0.113.45", False),
        ("8.8.8.8", False),
        ("2001:db8::1", False),
    ],
)
def test_is_internal(address: str, internal: bool) -> None:
    parsed: IPv4Address | IPv6Address = ip_address(address)
    assert is_internal(parsed) is internal


def test_external_ips_are_reported_newest_first() -> None:
    email = make_email(
        received=(
            hop("203.0.113.45", "edge.sender.test"),
            hop("10.0.0.5"),
            hop("203.0.113.45"),
            hop("198.51.100.7", "origin.sender.test"),
            hop(None),
        )
    )
    found = list(ReceivedChainCheck().run(email))
    assert [i.value for i in found] == ["203.0.113.45", "198.51.100.7"]
    assert {i.type for i in found} == {IndicatorType.SENDING_IP}
    assert {i.severity for i in found} == {Severity.INFO}
    assert found[0].evidence.startswith(
        "Received header 1 of 5: edge.sender.test [203.0.113.45] handed the message to "
        "mx1.larkspur.test."
    )
    assert "delivered the message into the receiving mail system" in found[0].evidence
    assert "earliest external hop" in found[1].evidence


def test_single_and_intermediate_hops() -> None:
    (only,) = ReceivedChainCheck().run(make_email(received=(hop("198.51.100.7", None),)))
    assert "an unnamed host [198.51.100.7]" in only.evidence
    assert "only external address" in only.evidence
    middle = list(
        ReceivedChainCheck().run(
            make_email(received=(hop("203.0.113.1"), hop("203.0.113.2"), hop("203.0.113.3")))
        )
    )
    assert "intermediate relay" in middle[1].evidence


def test_unnamed_receiver() -> None:
    unnamed = ReceivedHop(raw="x", from_ip=ip_address("203.0.113.1"))
    (indicator,) = ReceivedChainCheck().run(make_email(received=(unnamed,)))
    assert "to an unnamed server" in indicator.evidence


def test_number_of_reported_ips_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(received_module, "MAX_SENDING_IPS", 2)
    hops = tuple(hop(f"203.0.113.{n}") for n in range(1, 6))
    assert len(list(ReceivedChainCheck().run(make_email(received=hops)))) == 2
