"""Command line interface.

Reports go to stdout; diagnostics and errors go to stderr. Exit codes:
0 on success, 1 when an email could not be analyzed, 2 for usage or
configuration errors.
"""

import io
import json
import logging
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from hookline import __version__
from hookline.config import Settings, load_settings
from hookline.errors import ConfigError, HooklineError
from hookline.logging_config import configure_logging
from hookline.pipeline import Analyzer
from hookline.reporting import render_json, render_terminal

logger = logging.getLogger(__name__)

EXIT_ANALYSIS_ERROR = 1
EXIT_USAGE_ERROR = 2

app = typer.Typer(
    name="hookline",
    help="Analyze suspicious emails and explain the verdict.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


class OutputFormat(StrEnum):
    """Report formats ``analyze`` can produce."""

    TERMINAL = "terminal"
    JSON = "json"


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"hookline {__version__}")
        raise typer.Exit


def _harden_output_streams() -> None:
    """Stop unencodable characters from crashing output.

    Subjects and addresses are attacker-controlled. When stdout is redirected
    on Windows it uses a legacy code page, and a single emoji in a subject
    would otherwise raise UnicodeEncodeError halfway through a report.
    """
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")


def _error(message: str) -> None:
    typer.echo(f"Error: {message}", err=True)


def _settings_from(ctx: typer.Context) -> Settings:
    settings = ctx.obj
    if not isinstance(settings, Settings):  # pragma: no cover - set by main()
        raise RuntimeError("Settings were not initialised")
    return settings


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="TOML config file.", dir_okay=False),
    ] = None,
    verbose: Annotated[
        int,
        typer.Option(
            "--verbose", "-v", count=True, help="Log to stderr (-v for info, -vv for debug)."
        ),
    ] = 0,
    _version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_show_version, is_eager=True, help="Show the version and exit."
        ),
    ] = False,
) -> None:
    """Hookline analyzes suspicious emails and explains the verdict."""
    _harden_output_streams()
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_USAGE_ERROR) from exc
    level = {0: settings.log_level, 1: "INFO"}.get(verbose, "DEBUG")
    configure_logging(level, settings.log_format)
    ctx.obj = settings


@app.command()
def analyze(
    ctx: typer.Context,
    email_file: Annotated[Path, typer.Argument(help="The .eml file to analyze.")],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Report format.")
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Write the report to this file (JSON only).", dir_okay=False
        ),
    ] = None,
    no_ai: Annotated[
        bool, typer.Option("--no-ai", help="Skip the language model; use rules only.")
    ] = False,
) -> None:
    """Analyze one email file and report the verdict."""
    settings = _settings_from(ctx)
    if output is not None and output_format is OutputFormat.TERMINAL:
        raise typer.BadParameter("use --format json to write a report file", param_hint="--output")
    if no_ai:
        settings = settings.model_copy(update={"ai_enabled": False})

    try:
        report = Analyzer(settings).analyze_file(email_file)
    except HooklineError as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ANALYSIS_ERROR) from exc

    if output_format is OutputFormat.TERMINAL:
        render_terminal(report, Console())
        return
    if output is None:
        typer.echo(render_json(report, ascii_only=True))
        return
    try:
        output.write_text(render_json(report) + "\n", encoding="utf-8")
    except OSError as exc:
        _error(f"Could not write {output}: {exc.strerror or exc}")
        raise typer.Exit(code=EXIT_ANALYSIS_ERROR) from exc
    logger.info("Report written to %s", output)
    typer.echo(f"Report written to {output}", err=True)


@app.command("config")
def show_config(ctx: typer.Context) -> None:
    """Print the effective configuration as JSON, with API keys masked."""
    settings = _settings_from(ctx)
    typer.echo(json.dumps(settings.model_dump(mode="json"), indent=2))
