import hashlib
from ipaddress import ip_address

from hookline.config import ScoringSettings
from hookline.enrichment import extract_iocs, map_mitre, recommend_actions
from hookline.models import (
    Attachment,
    EmailAddress,
    Indicator,
    IndicatorType,
    IOCSet,
    Link,
    LinkOrigin,
    ReceivedHop,
    Severity,
    Verdict,
    VerdictLabel,
)
from hookline.scoring import score_verdict
from tests.factories import make_email, make_indicator

SHA = hashlib.sha256(b"x").hexdigest()


def link(url: str) -> Link:
    return Link(url=url, origin=LinkOrigin.HTML_ANCHOR)


def test_iocs_leave_out_own_domains_and_internal_addresses() -> None:
    email = make_email(
        from_address=EmailAddress(address="it@Helpdesk-Fake.test"),
        reply_to=(EmailAddress(address="review@verify.test"), EmailAddress(address="noat")),
        return_path="bounce@larkspur.test",
        to=(EmailAddress(address="sam@larkspur.test"), EmailAddress(display_name="x")),
        received=(
            ReceivedHop(raw="a", from_ip=ip_address("203.0.113.5")),
            ReceivedHop(raw="b", from_ip=ip_address("10.0.0.5")),
            ReceivedHop(raw="c"),
        ),
        links=(
            link("http://198.51.100.23/login"),
            link("http://192.168.1.1/admin"),
            link("https://portal.larkspur.test/reset"),
            link("https://www.partner.example.com/"),
            link("https://evil.test/a"),
            link("https://evil.test/a"),
            link("mailto:x@evil.test"),
            link("http://[bad"),
        ),
        attachments=(
            Attachment(filename="a.exe", content_type="x/y", size=4, sha256=SHA),
            Attachment(
                filename="empty",
                content_type="x/y",
                size=0,
                sha256=hashlib.sha256(b"").hexdigest(),
            ),
        ),
    )
    iocs = extract_iocs(email, ["example.com"])
    assert iocs == IOCSet(
        urls=("http://198.51.100.23/login", "https://evil.test/a"),
        domains=("helpdesk-fake.test", "verify.test", "evil.test"),
        ip_addresses=("203.0.113.5", "198.51.100.23"),
        email_addresses=("it@helpdesk-fake.test", "review@verify.test"),
        sha256_hashes=(SHA,),
    )


def test_empty_email_has_no_iocs() -> None:
    assert extract_iocs(make_email(), []) == IOCSet()


def verdict_for(*indicators: Indicator) -> Verdict:
    return score_verdict(list(indicators), ScoringSettings())


def test_likely_safe_mail_maps_to_no_techniques() -> None:
    low = make_indicator(type=IndicatorType.URGENCY_LANGUAGE, severity=Severity.LOW)
    assert verdict_for(low).label is VerdictLabel.LIKELY_SAFE
    assert map_mitre(verdict_for(low), [low]) == ()


def test_techniques_follow_the_findings() -> None:
    indicators = [
        make_indicator(type=IndicatorType.LINK_TEXT_MISMATCH, severity=Severity.HIGH, value="l"),
        make_indicator(type=IndicatorType.CREDENTIAL_REQUEST, severity=Severity.HIGH, value="c"),
        make_indicator(type=IndicatorType.DOUBLE_EXTENSION, severity=Severity.CRITICAL, value="d"),
        make_indicator(type=IndicatorType.FILE_TYPE_MISMATCH, severity=Severity.HIGH, value="f"),
        make_indicator(type=IndicatorType.DISPLAY_NAME_SPOOFING, value="n"),
        make_indicator(
            type=IndicatorType.THREAT_INTEL_MATCH, severity=Severity.CRITICAL, value=SHA
        ),
        make_indicator(
            type=IndicatorType.THREAT_INTEL_MATCH,
            severity=Severity.CRITICAL,
            value="https://evil.test/a",
        ),
        make_indicator(
            type=IndicatorType.THREAT_INTEL_MATCH, severity=Severity.CRITICAL, value="8.8.8.8"
        ),
        make_indicator(type=IndicatorType.SENDING_IP, severity=Severity.INFO, value="203.0.113.5"),
    ]
    techniques = {t.technique_id: t for t in map_mitre(verdict_for(*indicators), indicators)}
    assert list(techniques) == [
        "T1566",
        "T1566.001",
        "T1566.002",
        "T1598.003",
        "T1656",
        "T1036.007",
        "T1036.008",
    ]
    assert techniques["T1566"].tactic == "Initial Access"
    assert len(techniques["T1566.001"].indicator_ids) == 3
    assert len(techniques["T1566.002"].indicator_ids) == 2
    assert techniques["T1656"].name == "Impersonation"


def test_actions_for_likely_safe_mail() -> None:
    actions = recommend_actions(verdict_for(), [], IOCSet())
    assert actions[0].startswith("No action needed")


def test_actions_for_malicious_mail_name_defanged_iocs() -> None:
    indicators = [
        make_indicator(type=IndicatorType.PROMPT_INJECTION, severity=Severity.CRITICAL),
        make_indicator(type=IndicatorType.CREDENTIAL_REQUEST, severity=Severity.HIGH),
        make_indicator(type=IndicatorType.RISKY_ATTACHMENT, severity=Severity.HIGH),
        make_indicator(type=IndicatorType.GIFT_CARD_REQUEST, severity=Severity.MEDIUM),
    ]
    iocs = IOCSet(
        urls=("https://evil.test/",),
        domains=("a.test", "b.test", "c.test", "d.test"),
        sha256_hashes=(SHA,),
    )
    actions = recommend_actions(verdict_for(*indicators), indicators, iocs)
    text = "\n".join(actions)
    assert actions[0].startswith("Quarantine the message")
    assert "a[.]test, b[.]test, c[.]test and 1 more" in text
    assert "reset the password" in text
    assert f"endpoint protection: {SHA}" in text
    assert "gift card" in text
    assert "AI-assisted mail tools" in text


def test_actions_for_suspicious_mail() -> None:
    indicators = [make_indicator(type=IndicatorType.RISKY_ATTACHMENT, severity=Severity.HIGH)]
    indicators.append(make_indicator(type=IndicatorType.SPF_FAIL, severity=Severity.LOW))
    verdict = verdict_for(*indicators)
    assert verdict.label is VerdictLabel.SUSPICIOUS
    actions = recommend_actions(verdict, indicators, IOCSet())
    assert actions[0].startswith("Hold the message")
    assert not any("Block the attachment hashes" in action for action in actions)
    assert any("isolate the device" in action for action in actions)
