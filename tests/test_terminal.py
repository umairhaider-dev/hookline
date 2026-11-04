import io

from rich.console import Console

from hookline.models import AIAssessment, AIRun, AIStatus, AttackType, EmailAddress, Severity
from hookline.models.report import Report
from hookline.reporting import render_terminal
from hookline.reporting.terminal import safe_text
from tests.factories import make_email, make_indicator, make_report


def render(report: Report) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, width=150, color_system=None, legacy_windows=False)
    render_terminal(report, console)
    return buffer.getvalue()


def test_shows_verdict_message_and_ai_status() -> None:
    email = make_email(
        subject="Quarterly invoice",
        from_address=EmailAddress(display_name="Billing", address="billing@larkspur.test"),
    )
    output = render(make_report(email=email, ai=AIRun(status=AIStatus.UNAVAILABLE, error="down")))
    assert "LIKELY SAFE" in output
    assert "Quarterly invoice" in output
    assert '"Billing" <billing@larkspur.test>' in output
    assert "No indicators found." in output
    assert "Unavailable: down" in output
    assert "deterministic checks only" in output


def test_shows_indicators_and_score_breakdown() -> None:
    indicators = [
        make_indicator(value="198.51.100.23", severity=Severity.HIGH),
        make_indicator(value="low-thing", severity=Severity.LOW),
    ]
    output = render(make_report(indicators=indicators))
    assert "Indicators (2)" in output
    assert "198.51.100.23" in output
    assert "Score breakdown" in output
    assert "+30" in output
    assert "high severity" in output


def test_control_characters_in_email_content_are_escaped() -> None:
    email = make_email(subject="Invoice\x1b[2J\x1b[31mPAID")
    indicator = make_indicator(value="invoice\u202efdp.exe")
    output = render(make_report(email=email, indicators=[indicator]))
    assert "\x1b" not in output
    assert "\\x1b[2J" in output
    assert "invoice\\u202efdp.exe" in output


def test_rich_markup_in_email_content_is_shown_literally() -> None:
    output = render(make_report(email=make_email(subject="[bold red]URGENT[/bold red]")))
    assert "[bold red]URGENT[/bold red]" in output


def test_completed_ai_assessment() -> None:
    assessment = AIAssessment(
        phishing_likelihood=92,
        attack_type=AttackType.CREDENTIAL_PHISHING,
        tactics=("urgency", "impersonation"),
        explanation="Impersonates the IT desk.\nLink goes to a raw IP address.",
    )
    run = AIRun(
        status=AIStatus.COMPLETED,
        provider="ollama",
        model="llama3.1:8b",
        attempts=1,
        assessment=assessment,
    )
    output = render(make_report(ai=run))
    assert "92/100" in output
    assert "credential_phishing" in output
    assert "Impersonates the IT desk." in output
    assert "urgency, impersonation" in output
    assert "ollama / llama3.1:8b" in output


def test_warnings_are_shown() -> None:
    output = render(make_report(warnings=["Check 'links' failed and was skipped: boom"]))
    assert "Warning: Check 'links' failed" in output


def test_safe_text_truncates_long_values() -> None:
    shortened = safe_text("x" * 500, limit=20)
    assert len(shortened) == 20
    assert shortened.endswith("...")
    assert safe_text("short") == "short"
