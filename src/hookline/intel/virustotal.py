"""VirusTotal: multi-engine verdicts for files, URLs, domains and IP addresses.

API v3: https://docs.virustotal.com/reference/overview . Only GET report
endpoints are used, so nothing is ever submitted for scanning. A 404 means
VirusTotal has never seen the value.
"""

import base64
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field

from hookline.config import ProviderLimits
from hookline.intel.base import ProviderAnswer
from hookline.intel.http import build_client, parse_json, send
from hookline.models.intel import IntelVerdict, Observable, ObservableKind

BASE_URL = "https://www.virustotal.com/api/v3/"
GUI_URL = "https://www.virustotal.com/gui/"
NAME = "VirusTotal"
MALICIOUS_ENGINES = 3

# Observable kind -> (API collection, GUI section).
_COLLECTIONS = {
    ObservableKind.SHA256: ("files", "file"),
    ObservableKind.URL: ("urls", "url"),
    ObservableKind.DOMAIN: ("domains", "domain"),
    ObservableKind.IP: ("ip_addresses", "ip-address"),
}


class _Stats(BaseModel):
    model_config = ConfigDict(extra="ignore")

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0


class _ThreatClassification(BaseModel):
    model_config = ConfigDict(extra="ignore")

    suggested_threat_label: str | None = None


class _Attributes(BaseModel):
    model_config = ConfigDict(extra="ignore")

    last_analysis_stats: _Stats = Field(default_factory=_Stats)
    reputation: int | None = None
    popular_threat_classification: _ThreatClassification | None = None


class _Object(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    attributes: _Attributes


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="ignore")

    data: _Object


class VirusTotalProvider:
    """Looks up file hashes, URLs, domains and IP addresses on VirusTotal."""

    name = NAME
    kinds = frozenset(ObservableKind)

    def __init__(
        self,
        api_key: str,
        *,
        limits: ProviderLimits,
        timeout: float,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.limits = limits
        self._client = build_client(
            base_url=BASE_URL, headers={"x-apikey": api_key}, timeout=timeout, transport=transport
        )

    def lookup(self, observable: Observable) -> ProviderAnswer:
        """Fetch VirusTotal's existing report for one observable."""
        collection, section = _COLLECTIONS[observable.kind]
        identifier = (
            url_identifier(observable.value)
            if observable.kind is ObservableKind.URL
            else (observable.value)
        )
        request = self._client.build_request("GET", f"{collection}/{quote(identifier, safe='')}")
        response = send(self._client, NAME, request)
        if response.status_code == 404:
            return ProviderAnswer(IntelVerdict.UNKNOWN, "VirusTotal has no record of it.")
        report = parse_json(response, _Envelope, NAME).data
        return ProviderAnswer(
            _verdict(report.attributes.last_analysis_stats),
            _summary(report.attributes),
            f"{GUI_URL}{section}/{quote(report.id, safe='')}",
        )

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


def url_identifier(url: str) -> str:
    """VirusTotal's identifier for a URL: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _verdict(stats: _Stats) -> IntelVerdict:
    if stats.malicious >= MALICIOUS_ENGINES:
        return IntelVerdict.MALICIOUS
    if stats.malicious or stats.suspicious:
        return IntelVerdict.SUSPICIOUS
    return IntelVerdict.CLEAN


def _summary(attributes: _Attributes) -> str:
    stats = attributes.last_analysis_stats
    engines = stats.malicious + stats.suspicious + stats.harmless + stats.undetected
    text = (
        f"{stats.malicious} of {engines} engines flag it as malicious and "
        f"{stats.suspicious} as suspicious"
    )
    label = (
        attributes.popular_threat_classification.suggested_threat_label
        if attributes.popular_threat_classification
        else None
    )
    if label:
        text += f"; threat label {label[:80]}"
    if attributes.reputation is not None:
        text += f"; community reputation {attributes.reputation}"
    return text + "."
