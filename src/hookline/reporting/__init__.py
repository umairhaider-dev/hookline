"""Rendering reports for people and machines."""

from hookline.reporting.html_report import render_html
from hookline.reporting.json_report import render_json
from hookline.reporting.terminal import render_terminal

__all__ = ["render_html", "render_json", "render_terminal"]
