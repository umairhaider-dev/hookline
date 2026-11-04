"""Rendering reports for people and machines."""

from hookline.reporting.json_report import render_json
from hookline.reporting.terminal import render_terminal

__all__ = ["render_json", "render_terminal"]
