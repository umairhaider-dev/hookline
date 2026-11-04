"""Choose which values from an email are worth sending to reputation services.

Only public values leave the machine. Private and reserved IP addresses,
internal or reserved host names (``.local``, ``.test`` and so on) and the
protected domains themselves are never looked up. Attachment hashes come
first because they are the most decisive, then URLs, IPs and domains.
"""

from collections.abc import Iterable

from hookline.config import ThreatIntelSettings
from hookline.domains import has_public_suffix, parse_ip, registrable_domain
from hookline.models.email import ParsedEmail
from hookline.models.intel import Observable, ObservableKind
from hookline.urls import parse_url


def collect_observables(
    email: ParsedEmail, settings: ThreatIntelSettings, protected_domains: Iterable[str]
) -> list[Observable]:
    """Return the distinct observables to look up, most decisive first."""
    protected = {registrable_domain(domain) for domain in protected_domains}
    hashes: list[str] = []
    urls: list[str] = []
    ips: list[str] = []
    domains: list[str] = []

    for attachment in email.attachments:
        if attachment.size > 0:
            hashes.append(attachment.sha256)

    for hop in email.received:
        # is_global excludes private, shared, loopback and documentation ranges.
        if hop.from_ip is not None and hop.from_ip.is_global:
            ips.append(str(hop.from_ip))

    for link in email.links:
        url = parse_url(link.url)
        if url is None or not url.is_web:
            continue
        if url.ip is not None:
            if url.ip.is_global:
                urls.append(link.url)
                ips.append(str(url.ip))
        elif has_public_suffix(url.host) and registrable_domain(url.host) not in protected:
            urls.append(link.url)
            domains.append(registrable_domain(url.host))

    sender = email.from_address.domain if email.from_address else ""
    if sender and parse_ip(sender) is None and has_public_suffix(sender):
        sender_domain = registrable_domain(sender)
        if sender_domain not in protected:
            domains.insert(0, sender_domain)

    wanted = (
        (settings.lookup_hashes, ObservableKind.SHA256, hashes),
        (settings.lookup_urls, ObservableKind.URL, urls),
        (settings.lookup_ips, ObservableKind.IP, ips),
        (settings.lookup_domains, ObservableKind.DOMAIN, domains),
    )
    observables: list[Observable] = []
    for enabled, kind, values in wanted:
        if enabled:
            observables.extend(
                Observable(kind=kind, value=value) for value in dict.fromkeys(values)
            )
    return observables
