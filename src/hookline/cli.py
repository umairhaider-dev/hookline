"""Command line interface.

Reports go to stdout; diagnostics and errors go to stderr. Exit codes:
0 on success, 1 when an email could not be analyzed, 2 for usage or
configuration errors.
"""

import io
import json
import logging
import secrets
import sys
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console

from hookline import __version__
from hookline.ai.assessor import recipient_names, should_redact
from hookline.ai.prompt import build_prompt
from hookline.ai.redaction import NoRedaction, Redactor
from hookline.config import LLMProvider, Settings, load_settings
from hookline.errors import ConfigError, HooklineError
from hookline.intel.store import DATABASE_NAME
from hookline.logging_config import configure_logging
from hookline.models.report import Report
from hookline.models.verdict import VerdictLabel
from hookline.pipeline import Analyzer
from hookline.reporting import render_html, render_json, render_terminal
from hookline.watchpost import (
    Credentials,
    WatchpostClient,
    events_jsonl,
    meets,
    resolve_url,
    tls_verification,
)

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
    HTML = "html"


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
            "--output", "-o", help="Write the report to this file (JSON or HTML).", dir_okay=False
        ),
    ] = None,
    no_ai: Annotated[
        bool, typer.Option("--no-ai", help="Skip the language model; use rules only.")
    ] = False,
    no_intel: Annotated[
        bool,
        typer.Option("--no-intel", help="Skip threat intelligence lookups (no network use)."),
    ] = False,
) -> None:
    """Analyze one email file and report the verdict."""
    settings = _settings_from(ctx)
    if output is not None and output_format is OutputFormat.TERMINAL:
        raise typer.BadParameter(
            "use --format json or --format html to write a report file", param_hint="--output"
        )
    if no_ai:
        settings = settings.model_copy(update={"ai_enabled": False})
    if no_intel:
        intel = settings.threat_intel.model_copy(update={"enabled": False})
        settings = settings.model_copy(update={"threat_intel": intel})

    try:
        with Analyzer(settings) as analyzer:
            report = analyzer.analyze_file(email_file)
    except HooklineError as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ANALYSIS_ERROR) from exc

    if output_format is OutputFormat.TERMINAL:
        render_terminal(report, Console())
        return
    if output_format is OutputFormat.HTML:
        rendered = render_html(report)
    else:
        rendered = render_json(report, ascii_only=output is None) + "\n"
    if output is None:
        typer.echo(rendered, nl=False)
        return
    try:
        output.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        _error(f"Could not write {output}: {exc.strerror or exc}")
        raise typer.Exit(code=EXIT_ANALYSIS_ERROR) from exc
    logger.info("Report written to %s", output)
    typer.echo(f"Report written to {output}", err=True)


@app.command("show-prompt")
def show_prompt(
    ctx: typer.Context,
    email_file: Annotated[Path, typer.Argument(help="The .eml file to build the prompt for.")],
) -> None:
    """Print the exact prompt the language model would receive for an email.

    Runs the deterministic checks (no lookups, no model) and applies the same
    redaction the configured provider would get.
    """
    settings = _settings_from(ctx)
    offline = settings.model_copy(
        update={
            "ai_enabled": False,
            "threat_intel": settings.threat_intel.model_copy(update={"enabled": False}),
        }
    )
    try:
        with Analyzer(offline) as analyzer:
            report = analyzer.analyze_file(email_file)
    except HooklineError as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ANALYSIS_ERROR) from exc
    cloud = settings.llm.provider is LLMProvider.ANTHROPIC
    redact = should_redact(settings.llm.redaction, cloud=cloud)
    prompt = build_prompt(
        report.email,
        report.indicators,
        max_email_chars=settings.llm.max_email_chars,
        redactor=Redactor(recipient_names(report.email)) if redact else NoRedaction(),
        nonce=secrets.token_hex(8),
    )
    typer.echo(
        f"=== system ({settings.llm.provider.value}, redaction {'on' if redact else 'off'}) ==="
    )
    typer.echo(prompt.system)
    typer.echo("=== user ===")
    typer.echo(prompt.user)
    for note in prompt.notes:
        typer.echo(f"Note: {note}", err=True)


@app.command("clear-cache")
def clear_cache(ctx: typer.Context) -> None:
    """Delete cached threat intelligence answers and the request log."""
    path = _settings_from(ctx).threat_intel.cache_dir / DATABASE_NAME
    if not path.exists():
        typer.echo(f"No cache at {path}", err=True)
        return
    try:
        path.unlink()
    except OSError as exc:
        _error(f"Could not delete {path}: {exc.strerror or exc}")
        raise typer.Exit(code=EXIT_ANALYSIS_ERROR) from exc
    typer.echo(f"Deleted {path}", err=True)


class Verdict(StrEnum):
    """Verdict thresholds for ``push``."""

    LIKELY_SAFE = "likely_safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@app.command()
def push(
    ctx: typer.Context,
    sources: Annotated[
        list[Path],
        typer.Argument(help=".eml files to analyze, or JSON reports from 'analyze -f json'."),
    ],
    url: Annotated[str | None, typer.Option("--url", help="Watchpost base URL.")] = None,
    min_verdict: Annotated[
        Verdict | None,
        typer.Option("--min-verdict", help="Push only emails with at least this verdict."),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the events instead of sending them.")
    ] = False,
    wait: Annotated[
        bool, typer.Option("--wait", help="Wait for Watchpost to ingest them and report alerts.")
    ] = False,
) -> None:
    """Send analysed emails to Watchpost as events that its Hookline rules turn into alerts."""
    settings = _settings_from(ctx)
    minimum = VerdictLabel(min_verdict or settings.watchpost.min_verdict)
    try:
        reports = _load_reports(sources, settings)
    except HooklineError as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ANALYSIS_ERROR) from exc
    selected = [report for report in reports if meets(report, minimum)]
    skipped = len(reports) - len(selected)
    if skipped:
        typer.echo(f"Skipped {skipped} email(s) below the {minimum.value} verdict.", err=True)
    if not selected:
        typer.echo("Nothing to push.", err=True)
        return
    if dry_run:
        typer.echo(events_jsonl(selected, ascii_only=True).decode("ascii"), nl=False)
        return
    content = events_jsonl(selected)
    try:
        target = resolve_url(url, settings.watchpost)
        with WatchpostClient(
            target,
            Credentials.from_settings(settings),
            timeout=settings.watchpost.timeout_seconds,
            max_retries=settings.watchpost.max_retries,
            verify=tls_verification(settings.watchpost),
        ) as client:
            filename = f"hookline-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.jsonl"
            job = client.upload(content, filename=filename, host_name=settings.watchpost.host_name)
            typer.echo(
                f"Sent {len(selected)} email(s) to {target} as ingestion job {job.get('id')} "
                f"({job.get('status')})."
            )
            if wait:
                _report_job(client.wait_for_job(int(job.get("id", 0))))
    except HooklineError as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ANALYSIS_ERROR) from exc


def _load_reports(sources: list[Path], settings: Settings) -> list[Report]:
    reports = []
    with Analyzer(settings) as analyzer:
        for source in sources:
            if source.suffix.lower() == ".json":
                try:
                    reports.append(Report.model_validate_json(source.read_bytes()))
                except OSError as exc:
                    raise HooklineError(f"Could not read {source}: {exc.strerror or exc}") from exc
                except ValidationError as exc:
                    raise HooklineError(f"{source} is not a Hookline JSON report") from exc
            else:
                reports.append(analyzer.analyze_file(source))
    return reports


def _report_job(job: dict[str, object]) -> None:
    status = job.get("status")
    if status not in {"completed", "failed"}:
        typer.echo(f"Watchpost is still processing the job ({status}).")
        return
    if status == "failed":
        raise HooklineError(f"Watchpost could not ingest the events: {job.get('error')}")
    typer.echo(
        f"Watchpost stored {job.get('events_inserted')} new event(s) "
        f"({job.get('events_duplicate')} already known)."
    )
    detection = job.get("detection")
    if isinstance(detection, dict):
        typer.echo(
            f"Detection: {detection.get('alerts_created')} alert(s) created, "
            f"{detection.get('alerts_updated')} updated."
        )


@app.command()
def serve(
    ctx: typer.Context,
    host: Annotated[str, typer.Option(help="Interface to listen on.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to listen on.", min=1, max=65535)] = 8000,
) -> None:
    """Run the web upload page and JSON API (needs: pip install "hookline[web]")."""
    settings = _settings_from(ctx)
    try:
        import uvicorn

        from hookline.web import create_app
    except ImportError as exc:
        _error('the web interface needs extra packages; run: pip install "hookline[web]"')
        raise typer.Exit(code=EXIT_USAGE_ERROR) from exc
    if host not in {"127.0.0.1", "localhost", "::1"} and settings.web_token is None:
        typer.echo(
            "Warning: listening beyond this machine without HOOKLINE_WEB_TOKEN; anyone who can "
            "reach the port can submit emails.",
            err=True,
        )
    uvicorn.run(create_app(settings), host=host, port=port, log_level="warning")


@app.command("config")
def show_config(ctx: typer.Context) -> None:
    """Print the effective configuration as JSON, with API keys masked."""
    settings = _settings_from(ctx)
    typer.echo(json.dumps(settings.model_dump(mode="json"), indent=2))
