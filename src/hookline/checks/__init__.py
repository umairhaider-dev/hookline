"""Deterministic checks. Each one inspects a parsed email and returns indicators."""

from hookline.checks.attachments import AttachmentCheck
from hookline.checks.authentication import AuthenticationCheck
from hookline.checks.base import Check
from hookline.checks.content import ContentCheck
from hookline.checks.domains import DomainCheck
from hookline.checks.language import LanguageCheck
from hookline.checks.links import LinkCheck
from hookline.checks.received import ReceivedChainCheck
from hookline.checks.sender import SenderCheck
from hookline.checks.structure import MessageStructureCheck
from hookline.config import CheckSettings


def build_checks(settings: CheckSettings) -> list[Check]:
    """Return the checks to run, in order, configured from ``settings``."""
    return [
        MessageStructureCheck(),
        AuthenticationCheck(settings.trusted_authserv_ids),
        SenderCheck(settings),
        ReceivedChainCheck(),
        DomainCheck(settings),
        LinkCheck(settings),
        AttachmentCheck(),
        LanguageCheck(),
        ContentCheck(),
    ]


__all__ = [
    "AttachmentCheck",
    "AuthenticationCheck",
    "Check",
    "ContentCheck",
    "DomainCheck",
    "LanguageCheck",
    "LinkCheck",
    "MessageStructureCheck",
    "ReceivedChainCheck",
    "SenderCheck",
    "build_checks",
]
