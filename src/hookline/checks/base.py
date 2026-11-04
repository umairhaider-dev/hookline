"""The interface every deterministic check implements."""

from collections.abc import Iterable
from typing import Protocol

from hookline.models.email import ParsedEmail
from hookline.models.indicator import Indicator


class Check(Protocol):
    """A deterministic check over a parsed email.

    Checks must be pure: they read the parsed email and return indicators,
    without network access and without touching attachment payloads.
    """

    name: str

    def run(self, email: ParsedEmail) -> Iterable[Indicator]:
        """Return the indicators found in ``email``. Empty means nothing was found."""
        ...
