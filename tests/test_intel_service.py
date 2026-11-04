import hashlib
from pathlib import Path

import httpx
from pydantic import SecretStr

from hookline.config import ProviderLimits, Settings, ThreatIntelSettings
from hookline.intel import (
    IntelLookupError,
    ProviderAnswer,
    ProviderUnavailableError,
    QuotaExceededError,
    build_threat_intel,
    disabled_reason,
)
from hookline.intel.service import NOTHING_TO_LOOK_UP, matches_to_indicators
from hookline.intel.store import DATABASE_NAME, now_utc
from hookline.models import (
    Attachment,
    EmailAddress,
    IndicatorSource,
    IndicatorType,
    IntelResult,
    IntelStatus,
    IntelVerdict,
    Link,
    LinkOrigin,
    Observable,
    ObservableKind,
    ParsedEmail,
    Severity,
)
from tests.factories import make_email
from tests.intel_helpers import FakeClock, FakeProvider, make_service

SHA = hashlib.sha256(b"payload").hexdigest()
URL = "https://login.example.net/verify"
MALICIOUS = ProviderAnswer(IntelVerdict.MALICIOUS, "Known bad.", "https://intel.example.org/1")
SUSPICIOUS = ProviderAnswer(IntelVerdict.SUSPICIOUS, "Somewhat bad.")
UNKNOWN = ProviderAnswer(IntelVerdict.UNKNOWN, "Never seen.")


def email_with(*urls: str, attachment: bool = False) -> ParsedEmail:
    attachments = (
        (Attachment(filename="a.pdf", content_type="application/pdf", size=7, sha256=SHA),)
        if attachment
        else ()
    )
    return make_email(
        links=tuple(Link(url=url, origin=LinkOrigin.HTML_ANCHOR) for url in urls),
        attachments=attachments,
    )


def test_nothing_public_to_look_up() -> None:
    provider = FakeProvider()
    service = make_service(provider)
    indicators, run = service.investigate(make_email(from_address=EmailAddress(address="a@b.test")))
    service.close()
    assert indicators == ()
    assert run.status is IntelStatus.COMPLETED
    assert run.note == NOTHING_TO_LOOK_UP
    assert run.providers == ("Fake",)
    assert provider.calls == []
    assert provider.closed


def test_malicious_answer_becomes_a_critical_indicator() -> None:
    provider = FakeProvider(answers={URL: MALICIOUS})
    other = FakeProvider("Other", answers={URL: ProviderAnswer(IntelVerdict.CLEAN, "Fine.")})
    service = make_service(provider, other)
    indicators, run = service.investigate(email_with(URL))
    service.close()
    (indicator,) = indicators
    assert indicator.type is IndicatorType.THREAT_INTEL_MATCH
    assert indicator.source is IndicatorSource.THREAT_INTEL
    assert indicator.severity is Severity.CRITICAL
    assert indicator.value == URL
    assert indicator.evidence == (
        "Fake (malicious): Known bad. See https://intel.example.org/1 Rated clean by Other."
    )
    assert run.status is IntelStatus.COMPLETED
    assert {(r.provider, r.observable.kind) for r in run.results} == {
        ("Fake", ObservableKind.URL),
        ("Fake", ObservableKind.DOMAIN),
        ("Other", ObservableKind.URL),
        ("Other", ObservableKind.DOMAIN),
    }


def test_suspicious_answer_is_medium() -> None:
    service = make_service(FakeProvider(answers={"example.net": SUSPICIOUS}))
    (indicator,), _ = service.investigate(email_with(URL))
    service.close()
    assert indicator.severity is Severity.MEDIUM
    assert indicator.value == "example.net"


def test_providers_only_get_kinds_they_support() -> None:
    ip_only = FakeProvider("IPs", kinds=[ObservableKind.IP])
    service = make_service(ip_only)
    service.investigate(email_with(URL, "http://8.8.4.4/x"))
    service.close()
    assert [call.value for call in ip_only.calls] == ["8.8.4.4"]


def test_answers_are_cached_between_runs(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider(answers={URL: MALICIOUS})
    service = make_service(provider, clock=clock, cache_dir=tmp_path)
    service.investigate(email_with(URL))
    service.close()
    again = FakeProvider(answers={URL: UNKNOWN})
    second = make_service(again, clock=clock, cache_dir=tmp_path)
    indicators, run = second.investigate(email_with(URL))
    second.close()
    assert again.calls == []
    assert all(result.from_cache for result in run.results)
    assert indicators[0].severity is Severity.CRITICAL


def test_unavailable_provider_is_not_asked_again() -> None:
    provider = FakeProvider(default=ProviderUnavailableError("could not reach Fake (ConnectError)"))
    service = make_service(provider)
    indicators, run = service.investigate(email_with(URL, attachment=True))
    service.close()
    assert len(provider.calls) == 1
    assert indicators == ()
    assert run.status is IntelStatus.PARTIAL
    assert run.problems == ("could not reach Fake (ConnectError); 3 lookup(s) not made",)


def test_quota_refusal_pauses_the_provider(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider(
        default=QuotaExceededError("Fake reported that its quota was reached", retry_after=90)
    )
    service = make_service(provider, clock=clock, cache_dir=tmp_path, max_wait_seconds=0)
    _, run = service.investigate(email_with(URL))
    service.close()
    assert run.problems[0].startswith("Fake reported that its quota was reached")
    later = FakeProvider()
    second = make_service(later, clock=clock, cache_dir=tmp_path, max_wait_seconds=0)
    _, second_run = second.investigate(email_with(URL))
    second.close()
    assert later.calls == []
    assert second_run.problems == ("Fake: the provider asked for a pause; 2 lookup(s) not made",)


def test_quota_refusal_without_retry_after_uses_default_pause(tmp_path: Path) -> None:
    clock = FakeClock()
    service = make_service(
        FakeProvider(default=QuotaExceededError("quota")), clock=clock, cache_dir=tmp_path
    )
    service.investigate(email_with(URL))
    service.close()
    clock.now += 61
    later = FakeProvider()
    second = make_service(later, clock=clock, cache_dir=tmp_path)
    second.investigate(email_with(URL))
    second.close()
    assert len(later.calls) == 2


def test_single_lookup_failure_does_not_stop_the_provider() -> None:
    provider = FakeProvider(answers={URL: IntelLookupError("Fake had a server error (HTTP 502)")})
    service = make_service(provider)
    _, run = service.investigate(email_with(URL))
    service.close()
    assert len(provider.calls) == 2
    assert run.problems == ("url lookup failed: Fake had a server error (HTTP 502)",)


def test_lookups_per_message_are_capped() -> None:
    provider = FakeProvider()
    service = make_service(provider, max_lookups_per_provider=2)
    urls = [f"https://site{n}.example.net/" for n in range(3)]
    _, run = service.investigate(email_with(*urls))
    service.close()
    assert len(provider.calls) == 2
    assert run.problems == ("Fake: only 2 lookups are made per message; 2 skipped",)


def test_rate_limit_without_waiting_skips_the_rest() -> None:
    provider = FakeProvider(limits=ProviderLimits(requests_per_minute=1))
    service = make_service(provider, max_wait_seconds=0)
    _, run = service.investigate(email_with(URL))
    service.close()
    assert len(provider.calls) == 1
    assert run.problems == ("Fake: the per-minute request limit was reached; 1 lookup(s) not made",)


def test_long_answers_are_trimmed() -> None:
    long = ProviderAnswer(IntelVerdict.MALICIOUS, "x" * 5000, "https://r.example.org/" + "y" * 900)
    service = make_service(FakeProvider(answers={URL: long}))
    _, run = service.investigate(email_with(URL))
    service.close()
    result = next(r for r in run.results if r.observable.value == URL)
    assert len(result.summary) == 1000
    assert result.reference is not None
    assert len(result.reference) == 500


def test_cache_problem_is_reported(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    service = make_service(FakeProvider(), cache_dir=blocker / "cache")
    _, run = service.investigate(make_email())
    service.close()
    assert run.status is IntelStatus.PARTIAL
    assert run.problems[0].startswith("Threat intelligence: the cache in ")


def test_matches_to_indicators_ignores_clean_and_unknown() -> None:
    clock = FakeClock()
    observable = Observable(kind=ObservableKind.IP, value="8.8.8.8")
    results = [
        IntelResult(
            provider=name,
            observable=observable,
            verdict=verdict,
            summary="s",
            checked_at=now_utc(clock),
        )
        for name, verdict in (("A", IntelVerdict.CLEAN), ("B", IntelVerdict.UNKNOWN))
    ]
    assert matches_to_indicators(results) == ()


# --- building from settings ---------------------------------------------------


def settings_with(**keys: str) -> Settings:
    return Settings.model_validate({name: SecretStr(value) for name, value in keys.items()})


def test_disabled_reasons() -> None:
    assert "No threat intelligence API keys" in (disabled_reason(Settings()) or "")
    off = Settings(threat_intel=ThreatIntelSettings(enabled=False), urlhaus_auth_key=SecretStr("k"))
    assert disabled_reason(off) == "Threat intelligence is turned off."
    assert disabled_reason(settings_with(urlhaus_auth_key="k")) is None
    assert build_threat_intel(Settings()) is None
    assert build_threat_intel(off) is None


def test_only_providers_with_keys_are_built(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 90}})

    settings = settings_with(abuseipdb_api_key="ab").model_copy(
        update={"threat_intel": ThreatIntelSettings(cache_dir=tmp_path / "c")}
    )
    service = build_threat_intel(settings, transport=httpx.MockTransport(handler))
    assert service is not None
    assert service.provider_names == ("AbuseIPDB",)
    email = make_email(links=(Link(url="http://8.8.4.4/", origin=LinkOrigin.PLAIN_TEXT),))
    (indicator,), run = service.investigate(email)
    service.close()
    assert indicator.value == "8.8.4.4"
    assert run.results[0].provider == "AbuseIPDB"
    assert (tmp_path / "c" / DATABASE_NAME).is_file()


def test_all_providers_in_lookup_order(tmp_path: Path) -> None:
    keys = settings_with(urlhaus_auth_key="u", abuseipdb_api_key="a", virustotal_api_key="v")
    settings = keys.model_copy(update={"threat_intel": ThreatIntelSettings(cache_dir=tmp_path)})
    service = build_threat_intel(
        settings, transport=httpx.MockTransport(lambda r: httpx.Response(500))
    )
    assert service is not None
    assert service.provider_names == ("URLhaus", "AbuseIPDB", "VirusTotal")
    service.close()
