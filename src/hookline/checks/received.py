"""Sending IP addresses from the Received chain."""

from collections.abc import Iterator

from hookline.domains import is_internal_ip
from hookline.models.email import ParsedEmail, ReceivedHop
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity

MAX_SENDING_IPS = 10


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
            if hop.from_ip is not None and not is_internal_ip(hop.from_ip)
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
