"""Optional threat intelligence lookups with URLhaus, AbuseIPDB and VirusTotal.

Nothing here runs unless at least one API key is set. Without keys, or with
the feature turned off, Hookline stays fully offline.
"""

import time
from collections.abc import Callable

import httpx

from hookline.config import Settings
from hookline.intel.abuseipdb import AbuseIPDBProvider
from hookline.intel.base import IntelProvider, ProviderAnswer
from hookline.intel.errors import IntelLookupError, ProviderUnavailableError, QuotaExceededError
from hookline.intel.service import ThreatIntel
from hookline.intel.store import IntelStore
from hookline.intel.urlhaus import URLhausProvider
from hookline.intel.virustotal import VirusTotalProvider

HOURS = 3600.0


def disabled_reason(settings: Settings) -> str | None:
    """Why threat intelligence will not run with ``settings``, or None if it will."""
    if not settings.threat_intel.enabled:
        return "Threat intelligence is turned off."
    if not any(
        (settings.urlhaus_auth_key, settings.abuseipdb_api_key, settings.virustotal_api_key)
    ):
        return (
            "No threat intelligence API keys are set (URLHAUS_AUTH_KEY, ABUSEIPDB_API_KEY, "
            "VIRUSTOTAL_API_KEY)."
        )
    return None


def build_threat_intel(
    settings: Settings,
    *,
    transport: httpx.BaseTransport | None = None,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> ThreatIntel | None:
    """Create the lookup service for the providers that have keys, or None if none do."""
    if disabled_reason(settings) is not None:
        return None
    config = settings.threat_intel
    providers: list[IntelProvider] = []
    if settings.urlhaus_auth_key is not None:
        providers.append(
            URLhausProvider(
                settings.urlhaus_auth_key.get_secret_value(),
                limits=config.urlhaus,
                timeout=config.timeout_seconds,
                transport=transport,
            )
        )
    if settings.abuseipdb_api_key is not None:
        providers.append(
            AbuseIPDBProvider(
                settings.abuseipdb_api_key.get_secret_value(),
                limits=config.abuseipdb,
                timeout=config.timeout_seconds,
                transport=transport,
            )
        )
    if settings.virustotal_api_key is not None:
        providers.append(
            VirusTotalProvider(
                settings.virustotal_api_key.get_secret_value(),
                limits=config.virustotal,
                timeout=config.timeout_seconds,
                transport=transport,
            )
        )
    store = IntelStore(config.cache_dir, ttl_seconds=config.cache_ttl_hours * HOURS, clock=clock)
    return ThreatIntel(
        providers,
        store,
        config,
        protected_domains=settings.checks.protected_domains,
        clock=clock,
        sleep=sleep,
    )


__all__ = [
    "AbuseIPDBProvider",
    "IntelLookupError",
    "IntelProvider",
    "IntelStore",
    "ProviderAnswer",
    "ProviderUnavailableError",
    "QuotaExceededError",
    "ThreatIntel",
    "URLhausProvider",
    "VirusTotalProvider",
    "build_threat_intel",
    "disabled_reason",
]
