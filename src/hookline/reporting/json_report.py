"""JSON rendering of reports."""

import json

from hookline.models.report import Report


def render_json(report: Report, *, ascii_only: bool = False) -> str:
    """Serialize ``report`` as indented JSON.

    Args:
        report: The report to serialize.
        ascii_only: Escape every non-ASCII character. Use this when writing to a
            stream whose encoding is unknown, such as a redirected Windows console.
    """
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=ascii_only)
