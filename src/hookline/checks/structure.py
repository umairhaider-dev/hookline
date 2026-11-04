"""Checks on the structure of the message itself."""

from collections.abc import Iterator

from hookline.models.email import ParsedEmail
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity

MAX_DEFECTS_IN_EVIDENCE = 5


class MessageStructureCheck:
    """Flags messages the parser found to be malformed.

    Legitimate mail servers rarely produce broken MIME or invalid headers, while
    hand-rolled phishing kits and spam tools often do. On its own this is a weak
    signal, so it is reported at low severity.
    """

    name = "message_structure"

    def run(self, email: ParsedEmail) -> Iterator[Indicator]:
        """Report one indicator summarising all parser defects, if there were any."""
        if not email.defects:
            return
        shown = list(email.defects[:MAX_DEFECTS_IN_EVIDENCE])
        hidden = len(email.defects) - len(shown)
        evidence = "The parser found structural problems: " + "; ".join(shown)
        if hidden:
            evidence += f"; and {hidden} more"
        yield Indicator(
            type=IndicatorType.MALFORMED_MESSAGE,
            value=f"{len(email.defects)} defect(s)",
            severity=Severity.LOW,
            evidence=evidence,
            source=IndicatorSource.PARSER,
        )
