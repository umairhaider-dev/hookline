"""Attachment hashes, disguised file types and risky formats.

Works purely from the metadata the parser recorded: names, declared and
detected types, hashes and ZIP member lists. Payloads are never opened.
"""

import re
import unicodedata
from collections.abc import Iterator

from hookline.filetypes import (
    ACTIVE_CONTENT_TYPES,
    DECLARED_TYPES,
    EXPECTED_TYPES,
    file_extension,
)
from hookline.models.email import Attachment, ParsedEmail
from hookline.models.indicator import Indicator, IndicatorSource, IndicatorType, Severity

# Extension -> (severity, what it is). The severity applies to the extension alone.
_RISKY_EXTENSIONS: dict[str, tuple[Severity, str]] = {
    **dict.fromkeys(
        ("exe", "scr", "com", "pif", "cpl", "dll", "msi", "msp", "msc", "gadget", "application",
         "appx", "appxbundle", "msix", "msixbundle", "xll"),
        (Severity.HIGH, "a Windows program or installer"),
    ),
    **dict.fromkeys(
        ("bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "wsc", "hta",
         "sct", "reg", "inf", "scf", "sh", "jar", "chm"),
        (Severity.HIGH, "a script or program that runs when opened"),
    ),
    **dict.fromkeys(
        ("lnk", "settingcontent-ms", "library-ms"),
        (Severity.HIGH, "a shortcut that can launch commands"),
    ),
    **dict.fromkeys(
        ("iso", "img", "vhd", "vhdx"),
        (Severity.HIGH, "a disk image, often used to get files past Mark-of-the-Web protection"),
    ),
    **dict.fromkeys(
        ("docm", "dotm", "xlsm", "xltm", "xlsb", "xlam", "pptm", "potm", "ppsm", "ppam", "sldm"),
        (Severity.HIGH, "an Office file that can carry macros"),
    ),
    **dict.fromkeys(
        ("html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"),
        (Severity.MEDIUM, "a web page that opens locally, often a fake login page"),
    ),
    **dict.fromkeys(
        ("one", "onepkg"), (Severity.MEDIUM, "a OneNote file, which can embed runnable files")
    ),
    **dict.fromkeys(
        ("url", "iqy", "slk"), (Severity.MEDIUM, "a file that makes Windows or Excel fetch content")
    ),
    **dict.fromkeys(
        ("zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace", "arj", "lzh", "bz2", "xz"),
        (Severity.LOW, "an archive, which hides its contents from a quick look"),
    ),
}  # fmt: skip

# Extensions people trust at a glance, used as the decoy in "invoice.pdf.exe".
_DECOY_EXTENSIONS = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg",
     "png", "gif", "bmp", "mp3", "mp4", "wav", "mov"}
)  # fmt: skip

# Bidirectional controls make "invoice<RLO>fdp.exe" display as "invoiceexe.pdf".
_BIDI_CONTROLS = frozenset(
    {0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E} | set(range(0x2066, 0x206A))
)
_PADDING = re.compile(r"\s{3,}|_{5,}")

MAX_MEMBERS_SHOWN = 5


class AttachmentCheck:
    """Reports attachment hashes and anything that makes an attachment dangerous."""

    name = "attachments"

    def run(self, email: ParsedEmail) -> Iterator[Indicator]:
        """Yield a hash indicator for every attachment plus any risk findings."""
        for attachment in email.attachments:
            yield _hash_indicator(attachment)
            yield from _check(attachment)


def _label(attachment: Attachment) -> str:
    return attachment.filename or f"unnamed attachment {attachment.sha256[:12]}"


def _hash_indicator(attachment: Attachment) -> Indicator:
    detected = attachment.detected_type or "not recognised"
    return Indicator(
        type=IndicatorType.ATTACHMENT_HASH,
        value=attachment.sha256,
        severity=Severity.INFO,
        evidence=(
            f"SHA-256 of {_label(attachment)} ({attachment.size:,} bytes; declared "
            f"{attachment.content_type}; content {detected})."
        ),
        source=IndicatorSource.ATTACHMENTS,
    )


def _check(attachment: Attachment) -> Iterator[Indicator]:
    label = _label(attachment)
    disguise = _disguised_name(attachment.filename)
    if disguise is not None:
        severity, evidence = disguise
        yield _indicator(IndicatorType.DOUBLE_EXTENSION, label, severity, evidence)
    mismatch = _type_mismatch(attachment)
    if mismatch is not None:
        severity, evidence = mismatch
        yield _indicator(IndicatorType.FILE_TYPE_MISMATCH, label, severity, evidence)
    risks = _risks(attachment)
    if risks:
        severity = max((item for item, _ in risks), key=lambda item: item.rank)
        evidence = " ".join(reason for _, reason in risks)
        yield _indicator(IndicatorType.RISKY_ATTACHMENT, label, severity, evidence)


def _disguised_name(filename: str | None) -> tuple[Severity, str] | None:
    """Detect names built to hide the real extension."""
    if not filename:
        return None
    real = file_extension(filename)
    real_risk = _RISKY_EXTENSIONS.get(real, (Severity.INFO, ""))[0]
    if any(ord(char) in _BIDI_CONTROLS for char in filename):
        severity = Severity.CRITICAL if real_risk.rank >= Severity.HIGH.rank else Severity.HIGH
        return severity, (
            f"The file name contains invisible text-direction characters, which make it display "
            f"with a different extension than its real one (.{real or 'none'})."
        )
    stem = filename.rstrip(". ")
    stem = stem[: -len(real) - 1] if real else stem
    decoy = file_extension(stem)
    if decoy not in _DECOY_EXTENSIONS or real_risk is Severity.INFO:
        return None
    padded = bool(_PADDING.search(filename))
    if real_risk.rank >= Severity.HIGH.rank:
        severity = Severity.CRITICAL
    elif real_risk is Severity.MEDIUM:
        severity = Severity.HIGH
    else:
        severity = Severity.LOW
    evidence = (
        f"The name ends in .{decoy}.{real}: it looks like a .{decoy} file but is really a "
        f".{real} file."
    )
    if padded:
        evidence += " Extra spaces push the real extension out of view."
    return severity, evidence


def _type_mismatch(attachment: Attachment) -> tuple[Severity, str] | None:
    """Compare the detected content type with the extension and the declared type."""
    detected = attachment.detected_type
    if detected is None:
        return None
    extension = file_extension(attachment.filename)
    problems = []
    expected = EXPECTED_TYPES.get(extension)
    if expected is not None and detected not in expected:
        problems.append(f"its .{extension} extension")
    declared = DECLARED_TYPES.get(attachment.content_type)
    if declared is not None and detected not in declared:
        problems.append(f"its declared type {attachment.content_type}")
    if not problems:
        return None
    severity = Severity.HIGH if detected in ACTIVE_CONTENT_TYPES else Severity.MEDIUM
    return severity, (f"The content is {detected}, which does not match {' or '.join(problems)}.")


def _risks(attachment: Attachment) -> list[tuple[Severity, str]]:
    risks: list[tuple[Severity, str]] = []
    extension = file_extension(attachment.filename)
    if extension in _RISKY_EXTENSIONS:
        severity, description = _RISKY_EXTENSIONS[extension]
        risks.append((severity, f"A .{extension} file is {description}."))
    elif attachment.detected_type in ACTIVE_CONTENT_TYPES:
        risks.append(
            (
                Severity.HIGH,
                f"Its content is {attachment.detected_type}, which can run code or open a "
                "web page.",
            )
        )
    dangerous = [
        name for name in attachment.archive_members if _member_risk(name).rank >= Severity.HIGH.rank
    ]
    if dangerous:
        shown = ", ".join(_printable(name) for name in dangerous[:MAX_MEMBERS_SHOWN])
        more = len(dangerous) - MAX_MEMBERS_SHOWN
        more_text = f" and {more} more" if more > 0 else ""
        risks.append(
            (Severity.HIGH, f"The archive contains {shown}{more_text}, which can run when opened.")
        )
    if attachment.encrypted:
        risks.append(
            (
                Severity.MEDIUM,
                "It is password-protected, so mail scanners cannot look inside; the password "
                "is usually given in the message.",
            )
        )
    return risks


def _member_risk(name: str) -> Severity:
    return _RISKY_EXTENSIONS.get(file_extension(name), (Severity.INFO, ""))[0]


def _printable(name: str) -> str:
    return "".join(char for char in name if unicodedata.category(char)[0] != "C")


def _indicator(kind: IndicatorType, value: str, severity: Severity, evidence: str) -> Indicator:
    return Indicator(
        type=kind,
        value=value,
        severity=severity,
        evidence=evidence,
        source=IndicatorSource.ATTACHMENTS,
    )
