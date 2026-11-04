import base64
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from hookline.config import AbuseIPDBLimits, ProviderLimits, VirusTotalLimits
from hookline.intel import (
    AbuseIPDBProvider,
    IntelLookupError,
    URLhausProvider,
    VirusTotalProvider,
)
from hookline.intel.base import join_tags
from hookline.intel.virustotal import url_identifier
from hookline.models import IntelVerdict, Observable, ObservableKind
from tests.intel_helpers import recording_transport

SHA = "a" * 64
URL = "https://login.example.net/verify?u=1"


def json_reply(body: Any, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(status, json=body)


def urlhaus(body: Any) -> tuple[URLhausProvider, list[httpx.Request]]:
    transport, requests = recording_transport(json_reply(body))
    provider = URLhausProvider("uh-key", limits=ProviderLimits(), timeout=5, transport=transport)
    return provider, requests


def form(request: httpx.Request) -> dict[str, list[str]]:
    return parse_qs(request.content.decode())


# --- URLhaus ------------------------------------------------------------------


def test_urlhaus_listed_url() -> None:
    provider, requests = urlhaus(
        {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["emotet", "doc", "heodo", "epoch4", "x", "y", "z"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
        }
    )
    answer = provider.lookup(Observable(kind=ObservableKind.URL, value=URL))
    provider.close()
    assert answer.verdict is IntelVerdict.MALICIOUS
    assert answer.summary == (
        "Listed on URLhaus as a malware distribution URL (status online; threat "
        "malware_download; tags emotet, doc, heodo, epoch4, x and 2 more)."
    )
    assert answer.reference == "https://urlhaus.abuse.ch/url/1/"
    (request,) = requests
    assert request.method == "POST"
    assert request.url.path == "/v1/url/"
    assert request.headers["Auth-Key"] == "uh-key"
    assert form(request) == {"url": [URL]}


@pytest.mark.parametrize("status", ["no_results", "invalid_url", "invalid_host"])
def test_urlhaus_not_listed(status: str) -> None:
    provider, _ = urlhaus({"query_status": status})
    for kind, value in ((ObservableKind.URL, URL), (ObservableKind.DOMAIN, "example.net")):
        answer = provider.lookup(Observable(kind=kind, value=value))
        assert (answer.verdict, answer.summary) == (IntelVerdict.UNKNOWN, "Not listed on URLhaus.")
    provider.close()


def test_urlhaus_unexpected_status() -> None:
    provider, _ = urlhaus({"query_status": "http_post_expected"})
    with pytest.raises(IntelLookupError, match="status 'http_post_expected'"):
        provider.lookup(Observable(kind=ObservableKind.URL, value=URL))
    provider.close()


def test_urlhaus_payload() -> None:
    provider, requests = urlhaus(
        {
            "query_status": "ok",
            "file_type": "exe",
            "signature": "AgentTesla",
            "url_count": 3,
            "urlhaus_download": "https://urlhaus-api.abuse.ch/v1/download/x/",
        }
    )
    answer = provider.lookup(Observable(kind=ObservableKind.SHA256, value=SHA))
    provider.close()
    assert answer.verdict is IntelVerdict.MALICIOUS
    assert answer.summary == (
        "Known malware sample on URLhaus (file type exe; family AgentTesla; served from 3 URL(s))."
    )
    assert answer.reference is None
    assert "download" not in answer.summary
    assert requests[0].url.path == "/v1/payload/"
    assert form(requests[0]) == {"sha256_hash": [SHA]}


def test_urlhaus_payload_without_details() -> None:
    provider, _ = urlhaus({"query_status": "ok"})
    answer = provider.lookup(Observable(kind=ObservableKind.SHA256, value=SHA))
    provider.close()
    assert answer.summary == "Known malware sample on URLhaus (file type unknown)."


def test_urlhaus_host() -> None:
    provider, requests = urlhaus(
        {
            "query_status": "ok",
            "url_count": 12,
            "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"},
            "urlhaus_reference": "https://urlhaus.abuse.ch/host/example.net/",
        }
    )
    answer = provider.lookup(Observable(kind=ObservableKind.IP, value="8.8.8.8"))
    provider.close()
    assert answer.verdict is IntelVerdict.SUSPICIOUS
    assert answer.summary == (
        "URLhaus has recorded 12 malware URL(s) on this host; also on spamhaus_dbl "
        "abused_legit_malware."
    )
    assert requests[0].url.path == "/v1/host/"
    assert form(requests[0]) == {"host": ["8.8.8.8"]}


def test_urlhaus_url_without_details() -> None:
    provider, _ = urlhaus({"query_status": "ok"})
    answer = provider.lookup(Observable(kind=ObservableKind.URL, value=URL))
    host = provider.lookup(Observable(kind=ObservableKind.DOMAIN, value="example.net"))
    provider.close()
    assert answer.summary == "Listed on URLhaus as a malware distribution URL (status unknown)."
    assert host.summary == "URLhaus has recorded 0 malware URL(s) on this host."


# --- AbuseIPDB ----------------------------------------------------------------


def abuseipdb(body: Any, status: int = 200) -> tuple[AbuseIPDBProvider, list[httpx.Request]]:
    transport, requests = recording_transport(json_reply(body, status))
    provider = AbuseIPDBProvider("ab-key", limits=AbuseIPDBLimits(), timeout=5, transport=transport)
    return provider, requests


@pytest.mark.parametrize(
    ("score", "verdict"),
    [
        (100, IntelVerdict.MALICIOUS),
        (75, IntelVerdict.MALICIOUS),
        (74, IntelVerdict.SUSPICIOUS),
        (25, IntelVerdict.SUSPICIOUS),
        (24, IntelVerdict.CLEAN),
        (0, IntelVerdict.CLEAN),
    ],
)
def test_abuseipdb_verdicts(score: int, verdict: IntelVerdict) -> None:
    provider, _ = abuseipdb({"data": {"abuseConfidenceScore": score}})
    answer = provider.lookup(Observable(kind=ObservableKind.IP, value="8.8.8.8"))
    provider.close()
    assert answer.verdict is verdict


def test_abuseipdb_request_and_summary() -> None:
    provider, requests = abuseipdb(
        {
            "data": {
                "abuseConfidenceScore": 92,
                "totalReports": 40,
                "numDistinctUsers": 12,
                "lastReportedAt": "2026-11-01T10:00:00+00:00",
                "countryCode": "NL",
                "isp": "Example Hosting",
                "usageType": "Data Center/Web Hosting/Transit",
                "isTor": True,
            }
        }
    )
    answer = provider.lookup(Observable(kind=ObservableKind.IP, value="8.8.8.8"))
    provider.close()
    assert answer.summary == (
        "Abuse confidence 92% from 40 report(s) by 12 user(s) in the last 90 days, last on "
        "2026-11-01 (ISP Example Hosting; usage Data Center/Web Hosting/Transit; country NL; "
        "Tor exit node)."
    )
    assert answer.reference == "https://www.abuseipdb.com/check/8.8.8.8"
    (request,) = requests
    assert request.method == "GET"
    assert request.url.path == "/api/v2/check"
    assert dict(request.url.params) == {"ipAddress": "8.8.8.8", "maxAgeInDays": "90"}
    assert request.headers["Key"] == "ab-key"


def test_abuseipdb_minimal_summary() -> None:
    provider, _ = abuseipdb({"data": {"abuseConfidenceScore": 0}})
    answer = provider.lookup(Observable(kind=ObservableKind.IP, value="8.8.8.8"))
    provider.close()
    assert (
        answer.summary == "Abuse confidence 0% from 0 report(s) by 0 user(s) in the last 90 days."
    )


def test_abuseipdb_not_found_is_an_error() -> None:
    provider, _ = abuseipdb({}, status=404)
    with pytest.raises(IntelLookupError, match="HTTP 404"):
        provider.lookup(Observable(kind=ObservableKind.IP, value="8.8.8.8"))
    provider.close()


# --- VirusTotal ---------------------------------------------------------------


def virustotal(body: Any, status: int = 200) -> tuple[VirusTotalProvider, list[httpx.Request]]:
    transport, requests = recording_transport(json_reply(body, status))
    provider = VirusTotalProvider(
        "vt-key", limits=VirusTotalLimits(), timeout=5, transport=transport
    )
    return provider, requests


def vt_object(identifier: str, **attributes: Any) -> dict[str, Any]:
    return {"data": {"id": identifier, "type": "x", "attributes": attributes}}


def test_url_identifier_is_unpadded_urlsafe_base64() -> None:
    identifier = url_identifier(URL)
    assert "=" not in identifier
    padded = identifier + "=" * (-len(identifier) % 4)
    assert base64.urlsafe_b64decode(padded).decode() == URL


@pytest.mark.parametrize(
    ("kind", "value", "path", "gui"),
    [
        (ObservableKind.SHA256, SHA, f"/api/v3/files/{SHA}", f"file/{SHA}"),
        (ObservableKind.URL, URL, f"/api/v3/urls/{url_identifier(URL)}", "url/obj-id"),
        (ObservableKind.DOMAIN, "example.net", "/api/v3/domains/example.net", "domain/obj-id"),
        (ObservableKind.IP, "8.8.8.8", "/api/v3/ip_addresses/8.8.8.8", "ip-address/obj-id"),
    ],
)
def test_virustotal_paths_and_references(
    kind: ObservableKind, value: str, path: str, gui: str
) -> None:
    identifier = SHA if kind is ObservableKind.SHA256 else "obj-id"
    provider, requests = virustotal(vt_object(identifier))
    answer = provider.lookup(Observable(kind=kind, value=value))
    provider.close()
    (request,) = requests
    assert request.method == "GET"
    assert request.url.path == path
    assert request.headers["x-apikey"] == "vt-key"
    assert answer.reference == f"https://www.virustotal.com/gui/{gui}"


@pytest.mark.parametrize(
    ("stats", "verdict"),
    [
        ({"malicious": 3}, IntelVerdict.MALICIOUS),
        ({"malicious": 2}, IntelVerdict.SUSPICIOUS),
        ({"suspicious": 1}, IntelVerdict.SUSPICIOUS),
        ({"harmless": 60, "undetected": 10}, IntelVerdict.CLEAN),
    ],
)
def test_virustotal_verdicts(stats: dict[str, int], verdict: IntelVerdict) -> None:
    provider, _ = virustotal(vt_object(SHA, last_analysis_stats=stats))
    answer = provider.lookup(Observable(kind=ObservableKind.SHA256, value=SHA))
    provider.close()
    assert answer.verdict is verdict


def test_virustotal_summary() -> None:
    provider, _ = virustotal(
        vt_object(
            SHA,
            last_analysis_stats={"malicious": 40, "suspicious": 2, "harmless": 0, "undetected": 30},
            reputation=-55,
            popular_threat_classification={"suggested_threat_label": "trojan.agenttesla/msil"},
        )
    )
    answer = provider.lookup(Observable(kind=ObservableKind.SHA256, value=SHA))
    provider.close()
    assert answer.summary == (
        "40 of 72 engines flag it as malicious and 2 as suspicious; threat label "
        "trojan.agenttesla/msil; community reputation -55."
    )


def test_virustotal_unknown() -> None:
    provider, _ = virustotal({"error": {"code": "NotFoundError"}}, status=404)
    answer = provider.lookup(Observable(kind=ObservableKind.URL, value=URL))
    provider.close()
    assert answer.verdict is IntelVerdict.UNKNOWN
    assert answer.reference is None


def test_virustotal_malformed_response() -> None:
    provider, _ = virustotal({"data": {"unexpected": True}})
    with pytest.raises(IntelLookupError, match="unexpected format"):
        provider.lookup(Observable(kind=ObservableKind.IP, value="8.8.8.8"))
    provider.close()


def test_join_tags() -> None:

    assert join_tags(None) == ""
    assert join_tags([]) == ""
    assert join_tags([" a ", "", "b" * 50]) == "a, " + "b" * 40
