"""Turn reports into the JSON events Watchpost's generic ``json`` parser reads.

One event per analysed email. The ECS fields Watchpost indexes carry what
analysts filter on (the recipient as ``user.name``, the sending IP as
``source.ip``, the first IOC URL, and the verdict as ``event.action``, which
starts with ``hookline_`` because the parser keeps no provider field), and the
``hookline`` object keeps the findings, IOCs, ATT&CK techniques and actions in
the stored event. The bundled Watchpost rules turn these events into alerts,
one per email (grouped by its SHA-256 in ``event.code``).

The event holds nothing that changes between runs of the same analysis, so
pushing the same report twice stores it once.
"""

import json
from collections.abc import Sequence
from datetime import UTC
from typing import Any

from hookline.domains import is_internal_ip
from hookline.models.indicator import Severity
from hookline.models.report import Report
from hookline.models.verdict import VerdictLabel

PROVIDER = "hookline"
ACTION_PREFIX = "hookline_email_"
MAX_INDICATORS = 50
MAX_MESSAGE_CHARS = 500
VERDICT_ORDER = (VerdictLabel.LIKELY_SAFE, VerdictLabel.SUSPICIOUS, VerdictLabel.MALICIOUS)


def meets(report: Report, minimum: VerdictLabel) -> bool:
    """Whether the report's verdict is at least ``minimum``."""
    return VERDICT_ORDER.index(report.verdict.label) >= VERDICT_ORDER.index(minimum)


def report_event(report: Report) -> dict[str, Any]:
    """The Watchpost event for one report."""
    email = report.email
    when = email.date or report.generated_at
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    recipients = [item.address for item in (*email.to, *email.cc) if item.address]
    sending_ip = next(
        (
            str(hop.from_ip)
            for hop in email.received
            if hop.from_ip is not None and not is_internal_ip(hop.from_ip)
        ),
        None,
    )
    label = report.verdict.label
    sender = email.from_address.address if email.from_address else "an unknown sender"
    message = (
        f"Hookline: {label.value.replace('_', ' ')} email (score {report.verdict.score:g}/100) "
        f"from {sender}: {email.subject}"
    )[:MAX_MESSAGE_CHARS]
    indicators = [
        item for item in report.indicators_by_severity() if item.severity is not Severity.INFO
    ]

    event: dict[str, Any] = {
        "@timestamp": when.astimezone(UTC).isoformat(),
        "event.provider": PROVIDER,
        "event.kind": "alert",
        "event.category": "intrusion_detection",
        "event.action": f"{ACTION_PREFIX}{label.value}",
        "event.outcome": "unknown",
        "event.code": email.sha256,
        "message": message,
        "user.name": recipients[0] if recipients else None,
        "source.ip": sending_ip,
        "url.original": report.iocs.urls[0] if report.iocs.urls else None,
        PROVIDER: {
            "verdict": label.value,
            "score": report.verdict.score,
            "mode": report.verdict.mode.value,
            "summary": report.verdict.summary,
            "subject": email.subject,
            "from": str(email.from_address) if email.from_address else None,
            "reply_to": [item.address for item in email.reply_to],
            "return_path": email.return_path,
            "to": recipients,
            "message_id": email.message_id,
            "email_sha256": email.sha256,
            "indicators": [
                {
                    "type": item.type.value,
                    "severity": item.severity.value,
                    "value": item.value,
                    "evidence": item.evidence,
                }
                for item in indicators[:MAX_INDICATORS]
            ],
            "iocs": report.iocs.model_dump(mode="json"),
            "mitre": [
                {"id": item.technique_id, "name": item.name, "tactic": item.tactic}
                for item in report.mitre_techniques
            ],
            "recommended_actions": list(report.recommended_actions),
            "ai": _ai_summary(report),
            "tool_version": report.tool_version,
        },
    }
    return {key: value for key, value in event.items() if value is not None}


def events_jsonl(reports: Sequence[Report], *, ascii_only: bool = False) -> bytes:
    """One JSON event per line, ready to upload. ``ascii_only`` escapes non-ASCII text."""
    lines = [
        json.dumps(report_event(report), ensure_ascii=ascii_only, sort_keys=True)
        for report in reports
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _ai_summary(report: Report) -> dict[str, Any]:
    summary: dict[str, Any] = {"status": report.ai.status.value}
    if report.ai.assessment is not None:
        summary.update(
            phishing_likelihood=report.ai.assessment.phishing_likelihood,
            attack_type=report.ai.assessment.attack_type.value,
        )
    return summary
