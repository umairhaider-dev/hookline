"""AbuseIPDB: crowd-sourced reports of abusive IP addresses.

API: https://docs.abuseipdb.com/ . Uses the v2 ``check`` endpoint with the key
in the ``Key`` header.
"""

import httpx
from pydantic import BaseModel, ConfigDict, Field

from hookline.config import ProviderLimits
from hookline.intel.base import ProviderAnswer
from hookline.intel.errors import IntelLookupError
from hookline.intel.http import build_client, parse_json, send
from hookline.models.intel import IntelVerdict, Observable, ObservableKind

BASE_URL = "https://api.abuseipdb.com/api/v2/"
NAME = "AbuseIPDB"
MAX_AGE_DAYS = 90
MALICIOUS_SCORE = 75
SUSPICIOUS_SCORE = 25


class _Report(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    score: int = Field(alias="abuseConfidenceScore", ge=0, le=100)
    total_reports: int = Field(default=0, alias="totalReports")
    distinct_users: int = Field(default=0, alias="numDistinctUsers")
    last_reported_at: str | None = Field(default=None, alias="lastReportedAt")
    country_code: str | None = Field(default=None, alias="countryCode")
    isp: str | None = None
    usage_type: str | None = Field(default=None, alias="usageType")
    is_tor: bool | None = Field(default=None, alias="isTor")


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="ignore")

    data: _Report


class AbuseIPDBProvider:
    """Looks up IP addresses on AbuseIPDB."""

    name = NAME
    kinds = frozenset({ObservableKind.IP})

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
            base_url=BASE_URL, headers={"Key": api_key}, timeout=timeout, transport=transport
        )

    def lookup(self, observable: Observable) -> ProviderAnswer:
        """Ask AbuseIPDB how often an IP address has been reported."""
        request = self._client.build_request(
            "GET", "check", params={"ipAddress": observable.value, "maxAgeInDays": MAX_AGE_DAYS}
        )
        response = send(self._client, NAME, request)
        if response.status_code == 404:
            raise IntelLookupError(f"{NAME} answered HTTP 404 for the check endpoint")
        report = parse_json(response, _Envelope, NAME).data
        return ProviderAnswer(
            _verdict(report),
            _summary(report),
            f"https://www.abuseipdb.com/check/{observable.value}",
        )

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


def _verdict(report: _Report) -> IntelVerdict:
    if report.score >= MALICIOUS_SCORE:
        return IntelVerdict.MALICIOUS
    if report.score >= SUSPICIOUS_SCORE:
        return IntelVerdict.SUSPICIOUS
    return IntelVerdict.CLEAN


def _summary(report: _Report) -> str:
    text = (
        f"Abuse confidence {report.score}% from {report.total_reports} report(s) by "
        f"{report.distinct_users} user(s) in the last {MAX_AGE_DAYS} days"
    )
    if report.last_reported_at:
        text += f", last on {report.last_reported_at[:10]}"
    details = [
        part
        for part in (
            report.isp and f"ISP {report.isp[:80]}",
            report.usage_type and f"usage {report.usage_type[:60]}",
            report.country_code and f"country {report.country_code[:3]}",
            "Tor exit node" if report.is_tor else "",
        )
        if part
    ]
    if details:
        text += f" ({'; '.join(details)})"
    return text + "."
