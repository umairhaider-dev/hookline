"""Domain name helpers shared by the checks.

Covers normalisation, registrable domains (via the public suffix list), punycode,
lookalike-character folding and edit distance. Nothing here touches the network:
the public suffix list is the snapshot bundled with ``tldextract``.
"""

import contextlib
import ipaddress
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import IPv4Address, IPv6Address, ip_network

import tldextract

# An empty URL list plus no cache directory means the bundled snapshot is used
# as-is: no download and no cache files written.
_EXTRACT = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())

# Reserved and internal top-level names (RFC 2606, RFC 6761 and common practice).
# They are not on the public suffix list but still name real hosts.
_RESERVED_TLDS = frozenset({"test", "example", "invalid", "localhost", "local", "internal"})

# Addresses that never identify an outside sender. Documentation ranges such
# as 192.0.2.0/24 are deliberately not listed: they stand in for public
# addresses in examples and test data.
_INTERNAL_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

# Labels of protected domains that are also ordinary words ("office.com").
# Fuzzy matching on them would flag far too many unrelated names.
GENERIC_LABELS = frozenset(
    {"office", "mail", "email", "online", "account", "support", "service", "secure", "login"}
)

# Characters that look like ASCII letters in common fonts, mapped to the letter
# they imitate. Code points are used instead of literals so this file contains
# no lookalike characters itself.
_CONFUSABLES: dict[int, str] = {
    # Cyrillic
    0x0430: "a",
    0x0431: "b",
    0x0432: "b",
    0x0433: "r",
    0x0435: "e",
    0x0437: "3",
    0x043A: "k",
    0x043D: "h",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0442: "t",
    0x0443: "y",
    0x0445: "x",
    0x0455: "s",
    0x0456: "i",
    0x0457: "i",
    0x0458: "j",
    0x04BB: "h",
    0x04CF: "l",
    0x0501: "d",
    0x051B: "q",
    0x051D: "w",
    # Greek
    0x03B1: "a",
    0x03B5: "e",
    0x03B9: "i",
    0x03BA: "k",
    0x03BD: "v",
    0x03BF: "o",
    0x03C1: "p",
    0x03C4: "t",
    0x03C5: "u",
    0x03C7: "x",
    0x03C9: "w",
    # Armenian
    0x0570: "h",
    0x0578: "n",
    0x057D: "u",
    0x0585: "o",
    # Latin letters that are not plain ASCII
    0x0131: "i",
    0x0261: "g",
    0x0269: "i",
    0x026A: "i",
    0x1D0F: "o",
}

# Pure-ASCII tricks, applied after the table above. Both sides of a comparison
# are folded the same way, so "paypa1" and "paypal" end up identical.
_ASCII_SEQUENCES = (("rn", "m"), ("vv", "w"))
_ASCII_CHARACTERS = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l"})


@dataclass(frozen=True)
class DomainParts:
    """A host split at the registrable boundary, for example ``mail`` + ``paypal`` + ``com``."""

    subdomain: str
    label: str
    suffix: str

    @property
    def registrable(self) -> str:
        """The domain an organisation registers, such as ``paypal.com`` or ``bbc.co.uk``."""
        return f"{self.label}.{self.suffix}" if self.suffix else self.label


def normalize_host(host: str) -> str:
    """Lower-case a host and drop surrounding whitespace, brackets and trailing dots."""
    return host.strip().removeprefix("[").removesuffix("]").rstrip(".").lower()


def parse_ip(host: str) -> IPv4Address | IPv6Address | None:
    """Return the IP address a host is written as, or None for a name."""
    try:
        return ipaddress.ip_address(normalize_host(host))
    except ValueError:
        return None


def is_internal_ip(address: IPv4Address | IPv6Address) -> bool:
    """True for loopback, private, carrier-grade NAT, link-local and similar addresses."""
    if address.is_multicast or address.is_unspecified:
        return True
    return any(address.version == net.version and address in net for net in _INTERNAL_NETWORKS)


def has_public_suffix(host: str) -> bool:
    """True if ``host`` is a name under a public suffix (so not ``.test`` or ``.internal``)."""
    host = normalize_host(host)
    return bool(host) and parse_ip(host) is None and bool(_EXTRACT(host).suffix)


@lru_cache(maxsize=4096)
def split_domain(host: str) -> DomainParts:
    """Split ``host`` into subdomain, registrable label and public suffix.

    Hosts outside the public suffix list, such as reserved ``.test`` names or
    internal ones, are treated as if their last label were the suffix.
    """
    host = normalize_host(host)
    if not host or parse_ip(host) is not None:
        return DomainParts(subdomain="", label=host, suffix="")
    result = _EXTRACT(host)
    if result.suffix and result.domain:
        return DomainParts(subdomain=result.subdomain, label=result.domain, suffix=result.suffix)
    labels = host.split(".")
    if len(labels) < 2:
        return DomainParts(subdomain="", label=host, suffix="")
    return DomainParts(subdomain=".".join(labels[:-2]), label=labels[-2], suffix=labels[-1])


def looks_like_domain(text: str) -> bool:
    """True if ``text`` is a dotted host name under a public suffix or a reserved TLD."""
    host = normalize_host(text)
    labels = host.split(".")
    if len(labels) < 2 or parse_ip(host) is not None:
        return False
    if not all(label and all(c.isalnum() or c == "-" for c in label) for label in labels):
        return False
    return bool(_EXTRACT(host).suffix) or labels[-1] in _RESERVED_TLDS


def registrable_domain(host: str) -> str:
    """Shortcut for ``split_domain(host).registrable``."""
    return split_domain(host).registrable


def top_level_domain(host: str) -> str:
    """The last label of a host name, such as ``uk`` for ``mail.example.co.uk``."""
    return normalize_host(host).rpartition(".")[2]


def decode_punycode(host: str) -> str:
    """Return ``host`` with every ``xn--`` label decoded to Unicode.

    Labels that are not valid punycode are left as they are.
    """
    labels = []
    for label in normalize_host(host).split("."):
        if label.startswith("xn--"):
            # An invalid label is kept as it is; it is still worth reporting.
            with contextlib.suppress(UnicodeError, ValueError):
                label = label[4:].encode("ascii").decode("punycode")
        labels.append(label)
    return ".".join(labels)


def encode_punycode(host: str) -> str:
    """Return the ASCII (``xn--``) form of a host that contains Unicode labels."""
    labels = []
    for label in normalize_host(host).split("."):
        if not label.isascii():
            label = "xn--" + label.encode("punycode").decode("ascii")
        labels.append(label)
    return ".".join(labels)


def has_punycode(host: str) -> bool:
    """True if any label of ``host`` is punycode-encoded."""
    return any(label.startswith("xn--") for label in normalize_host(host).split("."))


def skeleton(text: str) -> str:
    """Fold ``text`` so that strings which look alike compare equal.

    The result is only meant for comparisons. Accents are removed, compatibility
    forms (fullwidth letters and so on) are unified, common Cyrillic, Greek and
    Armenian lookalikes become their Latin twins, and ASCII swaps such as ``rn``
    for ``m`` or ``1`` for ``l`` are folded.
    """
    folded = unicodedata.normalize("NFKC", text).lower().translate(_CONFUSABLES)
    folded = "".join(
        char for char in unicodedata.normalize("NFKD", folded) if unicodedata.category(char) != "Mn"
    )
    for sequence, replacement in _ASCII_SEQUENCES:
        folded = folded.replace(sequence, replacement)
    return folded.translate(_ASCII_CHARACTERS)


def edit_distance(first: str, second: str, *, limit: int) -> int:
    """Damerau-Levenshtein distance (optimal string alignment), capped at ``limit + 1``.

    Adjacent swaps count as one edit, which matches how typosquats are made
    ("paypla" for "paypal"). Returns ``limit + 1`` as soon as the distance is
    known to exceed ``limit``, so long unrelated strings stay cheap.
    """
    if abs(len(first) - len(second)) > limit:
        return limit + 1
    previous_previous: list[int] = []
    previous = list(range(len(second) + 1))
    for i, char_a in enumerate(first, start=1):
        current = [i] + [0] * len(second)
        for j, char_b in enumerate(second, start=1):
            cost = 0 if char_a == char_b else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and char_a == second[j - 2] and first[i - 2] == char_b:
                current[j] = min(current[j], previous_previous[j - 2] + 1)
        if min(current) > limit:
            return limit + 1
        previous_previous, previous = previous, current
    return min(previous[-1], limit + 1)
