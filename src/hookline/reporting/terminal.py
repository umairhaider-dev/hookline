"""Rich terminal summary of a report.

Every value taken from the email is wrapped in ``Text`` (so Rich never treats
it as markup) after passing through :func:`escape_control_chars`.
"""

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hookline.models.ai import AIRun, AIStatus
from hookline.models.email import EmailAddress
from hookline.models.indicator import Severity
from hookline.models.intel import IntelRun, IntelStatus, IntelVerdict
from hookline.models.report import IOCSet, MitreTechnique, Report
from hookline.models.verdict import Verdict, VerdictLabel
from hookline.reporting.defang import defang
from hookline.reporting.escaping import escape_control_chars

MAX_CELL_CHARS = 160
MAX_IOCS_SHOWN = 15

_VERDICT_STYLES = {
    VerdictLabel.MALICIOUS: "bold white on red",
    VerdictLabel.SUSPICIOUS: "bold black on yellow",
    VerdictLabel.LIKELY_SAFE: "bold white on green",
}

_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_terminal(report: Report, console: Console) -> None:
    """Print a human-readable summary of ``report``."""
    console.print(_verdict_panel(report.verdict))
    console.print(_message_table(report))
    console.print(_indicator_table(report))
    console.print(_intel_panel(report.threat_intel))
    console.print(_ai_panel(report.ai))
    if report.verdict.contributions:
        console.print(_score_table(report.verdict))
    if report.recommended_actions:
        console.print(_actions(report.recommended_actions))
    if report.mitre_techniques:
        console.print(_mitre_table(report.mitre_techniques))
    iocs = _ioc_table(report.iocs)
    if iocs is not None:
        console.print(iocs)
    for warning in report.warnings:
        console.print(Text(f"Warning: {safe_text(warning)}", style="yellow"))


def safe_text(value: str, limit: int = MAX_CELL_CHARS) -> str:
    """Escape control characters and shorten ``value`` for display."""
    text = escape_control_chars(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _verdict_panel(verdict: Verdict) -> Panel:
    label = verdict.label.value.replace("_", " ").upper()
    body = Text.assemble(
        (f" {label} ", _VERDICT_STYLES[verdict.label]),
        f"  score {verdict.score:.0f}/100\n",
        (verdict.summary, "dim"),
    )
    return Panel(body, title="Hookline verdict", title_align="left", expand=False)


def _addresses(addresses: tuple[EmailAddress, ...]) -> str:
    return ", ".join(str(address) for address in addresses)


def _message_table(report: Report) -> Table:
    email = report.email
    table = Table(title="Message", title_justify="left", show_header=False, expand=False)
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value", overflow="fold")
    rows = [
        ("File", report.source_file or ""),
        ("Subject", email.subject),
        ("From", str(email.from_address) if email.from_address else ""),
        ("Reply-To", _addresses(email.reply_to)),
        ("Return-Path", email.return_path or ""),
        ("To", _addresses(email.to)),
        ("Date", email.date.isoformat() if email.date else ""),
        ("Message-ID", email.message_id or ""),
        ("SHA-256", email.sha256),
    ]
    for field, value in rows:
        if value:
            table.add_row(field, Text(safe_text(value)))
    return table


def _indicator_table(report: Report) -> RenderableType:
    indicators = report.indicators_by_severity()
    if not indicators:
        return Text("No indicators found.", style="dim")
    table = Table(title=f"Indicators ({len(indicators)})", title_justify="left")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Value", overflow="fold", max_width=40)
    table.add_column("Evidence", overflow="fold")
    for indicator in indicators:
        table.add_row(
            Text(indicator.severity.value, style=_SEVERITY_STYLES[indicator.severity]),
            indicator.type.value,
            Text(safe_text(indicator.value)),
            Text(safe_text(indicator.evidence, limit=400)),
        )
    return table


def _intel_panel(run: IntelRun) -> Panel:
    title = "Threat intelligence"
    subtitle = ", ".join(run.providers) or None
    if run.status is IntelStatus.DISABLED:
        body = Text(f"Not used. {run.note or ''}".strip(), style="dim")
        return Panel(body, title=title, title_align="left")

    lines: list[RenderableType] = []
    if run.results:
        counts = dict.fromkeys(IntelVerdict, 0)
        for result in run.results:
            counts[result.verdict] += 1
        cached = sum(result.from_cache for result in run.results)
        summary = f"{len(run.results)} answer(s)"
        if cached:
            summary += f", {cached} from cache"
        summary += (
            f": {counts[IntelVerdict.MALICIOUS]} malicious, "
            f"{counts[IntelVerdict.SUSPICIOUS]} suspicious, {counts[IntelVerdict.CLEAN]} clean, "
            f"{counts[IntelVerdict.UNKNOWN]} not on record."
        )
        lines.append(Text(summary))
    elif run.status is not IntelStatus.FAILED:
        lines.append(Text(run.note or "No answers.", style="dim"))
    lines.extend(Text(safe_text(problem, limit=300), style="yellow") for problem in run.problems)
    return Panel(Group(*lines), title=title, title_align="left", subtitle=subtitle)


def _ai_panel(run: AIRun) -> Panel:
    if run.status is AIStatus.COMPLETED and run.assessment is not None:
        assessment = run.assessment
        parts: list[RenderableType] = [
            Text.assemble(
                ("Likelihood ", "bold"),
                f"{assessment.phishing_likelihood}/100   ",
                ("Attack type ", "bold"),
                assessment.attack_type.value,
            ),
            Text(escape_control_chars(assessment.explanation, keep_newlines=True)),
        ]
        if assessment.tactics:
            tactics = ", ".join(safe_text(tactic) for tactic in assessment.tactics)
            parts.append(Text.assemble(("Tactics ", "bold"), tactics))
        for action in assessment.recommended_actions:
            parts.append(Text(f"- {safe_text(action)}"))
        parts.extend(Text(safe_text(note, limit=300), style="dim") for note in run.notes)
        parts.append(Text("The model can add to the score but never lower it.", style="dim"))
        subtitle = f"{run.provider} / {run.model}" if run.provider else None
        return Panel(Group(*parts), title="AI assessment", title_align="left", subtitle=subtitle)

    body = Text(run.status.value.replace("_", " ").capitalize(), style="bold")
    if run.error:
        body.append(f": {safe_text(run.error, limit=300)}", style="")
    for note in run.notes:
        body.append(f"\n{safe_text(note, limit=300)}", style="dim")
    body.append("\nThe verdict is based on deterministic checks only.", style="dim")
    return Panel(body, title="AI assessment", title_align="left")


def _actions(actions: tuple[str, ...]) -> Panel:
    lines = Text("\n".join(f"- {safe_text(action, limit=400)}" for action in actions))
    return Panel(lines, title="Recommended actions", title_align="left")


def _mitre_table(techniques: tuple[MitreTechnique, ...]) -> Table:
    table = Table(title="MITRE ATT&CK", title_justify="left")
    table.add_column("Technique", no_wrap=True)
    table.add_column("Name")
    table.add_column("Tactic")
    table.add_column("Evidence", justify="right")
    for technique in techniques:
        table.add_row(
            technique.technique_id,
            technique.name,
            technique.tactic,
            f"{len(technique.indicator_ids)} indicator(s)",
        )
    return table


def _ioc_table(iocs: IOCSet) -> Table | None:
    rows = [
        (kind, value)
        for kind, values in (
            ("URL", iocs.urls),
            ("Domain", iocs.domains),
            ("IP", iocs.ip_addresses),
            ("Email", iocs.email_addresses),
            ("SHA-256", iocs.sha256_hashes),
        )
        for value in values
    ]
    if not rows:
        return None
    table = Table(title=f"IOCs ({len(rows)}, defanged)", title_justify="left")
    table.add_column("Type", no_wrap=True)
    table.add_column("Value", overflow="fold")
    for kind, value in rows[:MAX_IOCS_SHOWN]:
        table.add_row(kind, Text(safe_text(defang(value), limit=200)))
    if len(rows) > MAX_IOCS_SHOWN:
        table.add_row("", Text(f"and {len(rows) - MAX_IOCS_SHOWN} more in the JSON report"))
    return table


def _score_table(verdict: Verdict) -> Table:
    table = Table(title="Score breakdown", title_justify="left")
    table.add_column("Points", justify="right")
    table.add_column("Factor")
    table.add_column("Note", style="dim")
    for item in verdict.contributions:
        table.add_row(f"{item.points:+g}", item.label, item.note)
    return table
