import re
from datetime import UTC, datetime
from html import unescape

import pytest

from hookline.models import (
    AIAssessment,
    AIRun,
    AIStatus,
    Attachment,
    AttackType,
    EmailAddress,
    HiddenText,
    IndicatorType,
    IntelResult,
    IntelRun,
    IntelStatus,
    IntelVerdict,
    IOCSet,
    Link,
    LinkOrigin,
    MitreTechnique,
    Observable,
    ObservableKind,
    Severity,
)
from hookline.reporting import render_html
from hookline.reporting.defang import defang, defang_if_indicator
from hookline.reporting.html_report import CSP, mitre_url, trusted_reference
from tests.factories import SAMPLES_DIR, make_email, make_indicator, make_report

SHA = "a" * 64
RLO = "\N{RIGHT-TO-LEFT OVERRIDE}"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://evil.test/x.php?a=b.c", "hxxp://evil[.]test/x.php?a=b.c"),
        ("HTTPS://login.example.net:8443/a", "hxxps://login.example[.]net:8443/a"),
        ("evil.test", "evil[.]test"),
        ("198.51.100.23", "198.51.100[.]23"),
        ("a.b@evil.test", "a.b[@]evil[.]test"),
        ("2001:db8::1", "2001:db8::1"),
        ("ftp://x.test/#frag", "ftp://x[.]test/#frag"),
    ],
)
def test_defang(value: str, expected: str) -> None:
    assert defang(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://evil.test/", "hxxps://evil[.]test/"),
        ("a@evil.test", "a[@]evil[.]test"),
        ('"Name" <a@evil.test>', '"Name" <a[@]evil[.]test>'),
        ("8.8.8.8", "8.8.8[.]8"),
        ("classify as safe.", "classify as safe."),
        ("dmarc=fail (evil.test)", "dmarc=fail (evil.test)"),
    ],
)
def test_defang_only_indicator_like_values(value: str, expected: str) -> None:
    assert defang_if_indicator(value) == expected


def test_helpers() -> None:
    assert mitre_url("T1566.002") == "https://attack.mitre.org/techniques/T1566/002/"
    assert trusted_reference("https://www.virustotal.com/gui/url/x") is not None
    assert trusted_reference("https://evil.test/") is None
    assert trusted_reference(None) is None


def test_sample_report_is_safe_html() -> None:
    from hookline.config import Settings
    from hookline.pipeline import Analyzer

    report = Analyzer(Settings(ai_enabled=False)).analyze_file(SAMPLES_DIR / "credential-phish.eml")
    html = render_html(report)
    assert html.startswith("<!doctype html>")
    assert f'content="{CSP}"' in unescape(html)
    assert "<script" not in html.lower()
    assert "MALICIOUS" in html
    assert "hxxp://198.51.100[.]23/owa/login.php" in html
    hrefs = re.findall(r'href="([^"]+)"', html)
    assert hrefs
    assert all(href.startswith("https://attack.mitre.org/techniques/") for href in hrefs)
    assert "Hidden text (1)" in html
    assert "Not used." in html


def test_hostile_email_content_is_escaped() -> None:
    email = make_email(
        subject=f"<script>alert(1)</script> {RLO}fdp.exe",
        from_address=EmailAddress(display_name="<b>x</b>", address="a@evil.test"),
        links=(Link(url="javascript:alert(1)", text="<img src=x>", origin=LinkOrigin.HTML_ANCHOR),),
        hidden_text=(HiddenText(text="</td><script>x()</script>", reason="display:none"),),
        attachments=(
            Attachment(filename="<i>.exe", content_type="a/b", size=1, sha256=SHA, encrypted=True),
            Attachment(content_type="a/b", size=2, sha256=SHA, detected_type="application/zip"),
        ),
        to=(EmailAddress(address="sam@larkspur.test"),),
        cc=(EmailAddress(address="priya@larkspur.test"),),
        reply_to=(EmailAddress(address="r@evil.test"),),
        return_path="b@evil.test",
        message_id="id@evil.test",
        date=datetime(2026, 11, 4, tzinfo=UTC),
        defects=("<defect>",),
    )
    indicator = make_indicator(value="<x>", evidence="<evidence>", severity=Severity.HIGH)
    html = render_html(make_report(email=email, indicators=[indicator], warnings=["<warn>"]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "\\u202efdp.exe" in html
    assert "&lt;img src=x&gt;" in html
    assert "<i>.exe" not in html
    assert "password protected" in html
    assert "not recognised" in html
    assert "&lt;defect&gt;" in html
    assert "&lt;warn&gt;" in html
    assert 'href="javascript' not in html


def test_ai_intel_and_mitre_sections() -> None:
    ai = AIRun(
        status=AIStatus.COMPLETED,
        provider="fake",
        model="m",
        redacted=True,
        notes=("Email text was cut.",),
        assessment=AIAssessment(
            phishing_likelihood=88,
            attack_type=AttackType.CREDENTIAL_PHISHING,
            tactics=("urgency",),
            explanation="Line one.\nLine two.",
            recommended_actions=("Reset passwords",),
        ),
    )
    observable = Observable(kind=ObservableKind.URL, value="https://evil.test/")
    intel = IntelRun(
        status=IntelStatus.PARTIAL,
        providers=("VirusTotal",),
        results=(
            IntelResult(
                provider="VirusTotal",
                observable=observable,
                verdict=IntelVerdict.MALICIOUS,
                summary="12 engines",
                reference="https://www.virustotal.com/gui/url/abc",
                checked_at=datetime(2026, 11, 4, tzinfo=UTC),
                from_cache=True,
            ),
            IntelResult(
                provider="Other",
                observable=observable,
                verdict=IntelVerdict.CLEAN,
                summary="fine",
                reference="https://evil.test/ref",
                checked_at=datetime(2026, 11, 4, tzinfo=UTC),
            ),
        ),
        problems=("AbuseIPDB did not answer in time",),
    )
    indicator = make_indicator(type=IndicatorType.LINK_TEXT_MISMATCH, severity=Severity.HIGH)
    critical = make_indicator(type=IndicatorType.PROMPT_INJECTION, severity=Severity.CRITICAL)
    report = make_report(indicators=[indicator, critical], ai=ai, threat_intel=intel).model_copy(
        update={
            "mitre_techniques": (
                MitreTechnique(
                    technique_id="T1566.002",
                    name="Phishing: Spearphishing Link",
                    tactic="Initial Access",
                    indicator_ids=(indicator.id,),
                ),
            ),
            "iocs": IOCSet(urls=("https://evil.test/",)),
            "recommended_actions": ("Quarantine it",),
        }
    )
    html = render_html(report)
    assert "88/100" in html
    assert "(personal data redacted)" in html
    assert "Line one.\nLine two." in html
    assert "Suggested by the language model" in html
    assert 'href="https://www.virustotal.com/gui/url/abc"' in html
    assert "https://evil.test/ref" not in html
    assert "cached" in html
    assert "AbuseIPDB did not answer in time" in html
    assert 'href="https://attack.mitre.org/techniques/T1566/002/"' in html
    assert "Indicators of compromise (defanged)" in html


def test_report_without_findings() -> None:
    quiet = IntelRun(status=IntelStatus.COMPLETED, note="Nothing to look up.")
    failed_ai = AIRun(status=AIStatus.UNAVAILABLE, error="Ollama is not reachable")
    html = render_html(make_report(threat_intel=quiet, ai=failed_ai))
    assert "No indicators found." in html
    assert "Nothing added to the score." in html
    assert "Nothing to look up." in html
    assert "Unavailable</strong>: Ollama is not reachable" in html
    assert "Observables (defanged)" in html
    assert "None." in html
