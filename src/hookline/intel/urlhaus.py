"""URLhaus (abuse.ch): known malware distribution URLs, hosts and payloads.

API: https://urlhaus-api.abuse.ch/ . Every request is a POST with form data
and an ``Auth-Key`` header. Only the lookup endpoints are used.
"""

import httpx
from pydantic import BaseModel, ConfigDict

from hookline.config import ProviderLimits
from hookline.intel.base import ProviderAnswer, join_tags
from hookline.intel.errors import IntelLookupError
from hookline.intel.http import build_client, parse_json, send
from hookline.models.intel import IntelVerdict, Observable, ObservableKind

BASE_URL = "https://urlhaus-api.abuse.ch/v1/"
NAME = "URLhaus"

# query_status values meaning "valid question, nothing on record".
_NOT_LISTED = frozenset({"no_results", "invalid_url", "invalid_host"})


class _Answer(BaseModel):
    model_config = ConfigDict(extra="ignore")

    query_status: str
    urlhaus_reference: str | None = None
    url_status: str | None = None
    threat: str | None = None
    tags: list[str] | None = None
    url_count: int | None = None
    signature: str | None = None
    file_type: str | None = None
    blacklists: dict[str, str] | None = None


class URLhausProvider:
    """Looks up URLs, hosts and file hashes on URLhaus."""

    name = NAME
    kinds = frozenset(ObservableKind)

    def __init__(
        self,
        auth_key: str,
        *,
        limits: ProviderLimits,
        timeout: float,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.limits = limits
        self._client = build_client(
            base_url=BASE_URL, headers={"Auth-Key": auth_key}, timeout=timeout, transport=transport
        )

    def lookup(self, observable: Observable) -> ProviderAnswer:
        """Ask URLhaus about one URL, host or SHA-256 hash."""
        if observable.kind is ObservableKind.URL:
            answer = self._post("url/", {"url": observable.value})
            return _url_answer(answer) if answer.query_status == "ok" else _not_listed()
        if observable.kind is ObservableKind.SHA256:
            answer = self._post("payload/", {"sha256_hash": observable.value})
            return _payload_answer(answer) if answer.query_status == "ok" else _not_listed()
        answer = self._post("host/", {"host": observable.value})
        return _host_answer(answer) if answer.query_status == "ok" else _not_listed()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def _post(self, path: str, form: dict[str, str]) -> _Answer:
        request = self._client.build_request("POST", path, data=form)
        response = send(self._client, NAME, request)
        answer = parse_json(response, _Answer, NAME)
        if answer.query_status != "ok" and answer.query_status not in _NOT_LISTED:
            raise IntelLookupError(f"{NAME} answered with status '{answer.query_status[:40]}'")
        return answer


def _not_listed() -> ProviderAnswer:
    return ProviderAnswer(IntelVerdict.UNKNOWN, "Not listed on URLhaus.")


def _url_answer(answer: _Answer) -> ProviderAnswer:
    details = [f"status {answer.url_status or 'unknown'}"]
    if answer.threat:
        details.append(f"threat {answer.threat}")
    if answer.tags:
        details.append(f"tags {join_tags(answer.tags)}")
    return ProviderAnswer(
        IntelVerdict.MALICIOUS,
        f"Listed on URLhaus as a malware distribution URL ({'; '.join(details)}).",
        answer.urlhaus_reference,
    )


def _payload_answer(answer: _Answer) -> ProviderAnswer:
    details = [f"file type {answer.file_type or 'unknown'}"]
    if answer.signature:
        details.append(f"family {answer.signature}")
    if answer.url_count is not None:
        details.append(f"served from {answer.url_count} URL(s)")
    # The response also holds a download link for the sample; it is deliberately not kept.
    return ProviderAnswer(
        IntelVerdict.MALICIOUS,
        f"Known malware sample on URLhaus ({'; '.join(details)}).",
    )


def _host_answer(answer: _Answer) -> ProviderAnswer:
    listings = [
        f"{name} {value}"
        for name, value in (answer.blacklists or {}).items()
        if value and value != "not listed"
    ]
    summary = f"URLhaus has recorded {answer.url_count or 0} malware URL(s) on this host"
    if listings:
        summary += f"; also on {', '.join(listings)}"
    return ProviderAnswer(IntelVerdict.SUSPICIOUS, summary + ".", answer.urlhaus_reference)
