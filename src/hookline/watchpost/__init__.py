"""Push analysed emails to Watchpost, the self-hosted SOC platform."""

from hookline.watchpost.client import (
    Credentials,
    WatchpostClient,
    WatchpostError,
    resolve_url,
    tls_verification,
)
from hookline.watchpost.events import events_jsonl, meets, report_event

__all__ = [
    "Credentials",
    "WatchpostClient",
    "WatchpostError",
    "events_jsonl",
    "meets",
    "report_event",
    "resolve_url",
    "tls_verification",
]
