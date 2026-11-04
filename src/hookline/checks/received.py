"""Sending IP addresses from the Received chain."""

from collections.abc import Iterator
from ipaddress import IPv4Address, IPv6Address, ip_network

from hookline.models.email import ParsedEmail, ReceivedHop
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity

MAX_SENDING_IPS = 10

# Addresses that never identify an outside sender. Documentation ranges such
# as 192.0.2.0/24 are deliberately not listed: they stand in for public
# addresses in examples and test data.
_INTERNAL_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def is_internal(address: IPv4Address | IPv6Address) -> bool:
    """True for loopback, private, carrier-grade NAT, link-local and similar addresses."""
    if address.is_multicast or address.is_unspecified:
        return True
    return any(address.version == net.version and address in net for net in _INTERNAL_NETWORKS)


class ReceivedChainCheck:
    """Lists the external IP addresses that handled the message.

    These are informational: they carry no points on their own, but they are
    the addresses to block or look up in threat intelligence.
    """

    name = "received_chain"

    def run(self, email: ParsedEmail) -> Iterator[Indicator]:
        """Yield one indicator per distinct external sending IP, newest first."""
        external = [
            (position, hop)
            for position, hop in enumerate(email.received, start=1)
            if hop.from_ip is not None and not is_internal(hop.from_ip)
        ]
        seen: set[str] = set()
        total = len(email.received)
        for position, hop in external:
            address = str(hop.from_ip)
            if address in seen:
                continue
            seen.add(address)
            if len(seen) > MAX_SENDING_IPS:
                return
            role = _role(position == external[0][0], position == external[-1][0])
            yield Indicator(
                type=IndicatorType.SENDING_IP,
                value=address,
                severity=Severity.INFO,
                evidence=f"Received header {position} of {total}: {_describe(hop)}. {role}",
                source=IndicatorSource.HEADERS,
            )


def _describe(hop: ReceivedHop) -> str:
    sender = hop.from_host or "an unnamed host"
    receiver = hop.by_host or "an unnamed server"
    return f"{sender} [{hop.from_ip}] handed the message to {receiver}"


def _role(newest: bool, oldest: bool) -> str:
    if newest and oldest:
        return "This is the only external address in the chain."
    if newest:
        return "This server delivered the message into the receiving mail system."
    if oldest:
        return "This is the earliest external hop, the closest to the original sender."
    return "This is an intermediate relay."
