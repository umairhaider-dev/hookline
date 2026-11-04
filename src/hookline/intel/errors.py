"""Errors raised by threat intelligence providers."""


class IntelLookupError(Exception):
    """One lookup failed. The provider can still be asked about other values."""


class ProviderUnavailableError(IntelLookupError):
    """The provider cannot be used for the rest of this analysis.

    Raised for timeouts, connection failures and rejected API keys, so that one
    unreachable service costs a single timeout rather than one per lookup.
    """


class QuotaExceededError(ProviderUnavailableError):
    """The provider refused the request because a rate limit or quota was reached."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after
