"""Self-contained HTML report.

Safety properties, since every string from the email is attacker-controlled:

* Jinja2 autoescaping is on for every value, and control characters are made
  visible, so nothing from the email becomes markup.
* A Content-Security-Policy forbids scripts, external styles, images, frames
  and form submissions; the page loads nothing from anywhere.
* URLs, domains, IPs and addresses from the email are shown defanged and never
  as links. The only links are ones Hookline builds itself: MITRE ATT&CK pages
  and threat intelligence references on the providers' own sites.
"""

from datetime import UTC
from functools import lru_cache

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from hookline.models.intel import IntelVerdict
from hookline.models.report import Report
from hookline.models.verdict import VerdictLabel
from hookline.reporting.defang import defang, defang_if_indicator
from hookline.reporting.escaping import escape_control_chars

TRUSTED_REFERENCE_PREFIXES = (
    "https://www.virustotal.com/",
    "https://urlhaus.abuse.ch/",
    "https://www.abuseipdb.com/",
)
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)


def render_html(report: Report) -> str:
    """Render ``report`` as a complete HTML document."""
    template = _environment().get_template("report.html.j2")
    return template.render(
        report=report,
        csp=CSP,
        generated=report.generated_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        verdict_title=report.verdict.label.value.replace("_", " ").upper(),
        flagged_verdicts={IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS},
        is_safe=report.verdict.label is VerdictLabel.LIKELY_SAFE,
    )


def mitre_url(technique_id: str) -> str:
    """The ATT&CK page for a technique or sub-technique."""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def trusted_reference(url: str | None) -> str | None:
    """``url`` if it points at a known provider's site, otherwise None."""
    if url and url.startswith(TRUSTED_REFERENCE_PREFIXES):
        return url
    return None


def _clean(value: object, keep_newlines: bool = False) -> str:
    return escape_control_chars(str(value), keep_newlines=keep_newlines)


@lru_cache(maxsize=1)
def _environment() -> Environment:
    environment = Environment(
        loader=PackageLoader("hookline.reporting", "templates"),
        autoescape=select_autoescape(["html", "j2"], default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters.update(
        clean=_clean,
        defang=lambda value: defang(_clean(value)),
        defang_value=lambda value: defang_if_indicator(_clean(value)),
        number=lambda value: f"{value:g}",
        mitre_url=mitre_url,
        trusted_reference=trusted_reference,
    )
    return environment
