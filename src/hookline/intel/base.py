"""The interface every threat intelligence provider implements."""

from dataclasses import dataclass
from typing import Protocol

from hookline.config import ProviderLimits
from hookline.models.intel import IntelVerdict, Observable, ObservableKind

MAX_TAGS_SHOWN = 5


@dataclass(frozen=True)
class ProviderAnswer:
    """What a provider said about one observable."""

    verdict: IntelVerdict
    summary: str
    reference: str | None = None


class IntelProvider(Protocol):
    """A reputation service that can be asked about observables.

    Providers only look values up. They never submit URLs or files for
    scanning, and they never contact the URLs themselves.
    """

    name: str
    kinds: frozenset[ObservableKind]
    limits: ProviderLimits

    def lookup(self, observable: Observable) -> ProviderAnswer:
        """Ask the provider about ``observable``.

        Raises:
            IntelLookupError: If this lookup failed but others may still work.
            ProviderUnavailableError: If the provider should not be used again this run.
        """
        ...

    def close(self) -> None:
        """Release network resources."""
        ...


def join_tags(tags: list[str] | None) -> str:
    """Format a provider's tag list for a summary, keeping it short."""
    if not tags:
        return ""
    shown = ", ".join(tag.strip()[:40] for tag in tags[:MAX_TAGS_SHOWN] if tag.strip())
    more = len(tags) - MAX_TAGS_SHOWN
    return shown + (f" and {more} more" if more > 0 else "")
