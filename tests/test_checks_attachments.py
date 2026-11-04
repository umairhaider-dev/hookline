import hashlib
from typing import Any

import pytest

from hookline import filetypes
from hookline.checks import AttachmentCheck
from hookline.models import Attachment, Indicator, IndicatorType, Severity
from tests.factories import make_email

RLO = "\N{RIGHT-TO-LEFT OVERRIDE}"


def attachment(filename: str | None, **fields: Any) -> Attachment:
    values: dict[str, Any] = {
        "filename": filename,
        "content_type": "application/octet-stream",
        "size": 4,
        "sha256": hashlib.sha256(b"test").hexdigest(),
    }
    values.update(fields)
    return Attachment(**values)


def run(*attachments: Attachment) -> list[Indicator]:
    return list(AttachmentCheck().run(make_email(attachments=attachments)))


def findings(item: Attachment) -> dict[IndicatorType, Indicator]:
    return {i.type: i for i in run(item) if i.type is not IndicatorType.ATTACHMENT_HASH}


def test_every_attachment_gets_a_hash_indicator() -> None:
    found = run(
        attachment("report.pdf", content_type="application/pdf", detected_type=filetypes.PDF),
        attachment(None, content_type="image/png"),
    )
    hashes = [i for i in found if i.type is IndicatorType.ATTACHMENT_HASH]
    assert [i.severity for i in hashes] == [Severity.INFO, Severity.INFO]
    assert hashes[0].value == hashlib.sha256(b"test").hexdigest()
    assert "report.pdf (4 bytes; declared application/pdf; content application/pdf)" in (
        hashes[0].evidence
    )
    assert "unnamed attachment" in hashes[1].evidence
    assert "content not recognised" in hashes[1].evidence
    assert len(found) == 2


@pytest.mark.parametrize(
    ("filename", "severity"),
    [
        ("setup.exe", Severity.HIGH),
        ("run.PS1", Severity.HIGH),
        ("shortcut.lnk", Severity.HIGH),
        ("disk.iso", Severity.HIGH),
        ("budget.xlsm", Severity.HIGH),
        ("login.html", Severity.MEDIUM),
        ("notes.one", Severity.MEDIUM),
        ("query.iqy", Severity.MEDIUM),
        ("photos.zip", Severity.LOW),
    ],
)
def test_risky_extensions(filename: str, severity: Severity) -> None:
    risky = findings(attachment(filename))[IndicatorType.RISKY_ATTACHMENT]
    assert risky.severity is severity
    assert risky.value == filename


def test_safe_attachment_has_no_findings() -> None:
    assert findings(attachment("q4.pdf", content_type="application/pdf")) == {}


def test_active_content_without_risky_extension() -> None:
    found = findings(attachment(None, detected_type=filetypes.PE))
    assert found[IndicatorType.RISKY_ATTACHMENT].severity is Severity.HIGH
    assert "application/x-dosexec" in found[IndicatorType.RISKY_ATTACHMENT].evidence


@pytest.mark.parametrize(
    ("filename", "severity"),
    [
        ("invoice.pdf.exe", Severity.CRITICAL),
        ("scan.jpg.lnk", Severity.CRITICAL),
        ("payment.pdf.html", Severity.HIGH),
        ("report.pdf.zip", Severity.LOW),
    ],
)
def test_double_extensions(filename: str, severity: Severity) -> None:
    double = findings(attachment(filename))[IndicatorType.DOUBLE_EXTENSION]
    assert double.severity is severity


def test_padded_double_extension() -> None:
    double = findings(attachment("invoice.pdf          .exe"))[IndicatorType.DOUBLE_EXTENSION]
    assert "Extra spaces" in double.evidence


@pytest.mark.parametrize("filename", ["archive.tar.gz", "v1.2.pdf", "report.final.docx"])
def test_ordinary_dotted_names_are_not_double_extensions(filename: str) -> None:
    assert IndicatorType.DOUBLE_EXTENSION not in findings(attachment(filename))


def test_right_to_left_override_in_name() -> None:
    name = f"invoice{RLO}fdp.exe"
    double = findings(attachment(name))[IndicatorType.DOUBLE_EXTENSION]
    assert double.severity is Severity.CRITICAL
    assert "text-direction" in double.evidence
    quieter = findings(attachment(f"photo{RLO}gpj.txt"))[IndicatorType.DOUBLE_EXTENSION]
    assert quieter.severity is Severity.HIGH


def test_extension_mismatch() -> None:
    mismatch = findings(attachment("invoice.pdf", detected_type=filetypes.PE))[
        IndicatorType.FILE_TYPE_MISMATCH
    ]
    assert mismatch.severity is Severity.HIGH
    assert "does not match its .pdf extension" in mismatch.evidence


def test_declared_type_mismatch() -> None:
    item = attachment(None, content_type="image/png", detected_type=filetypes.PDF)
    mismatch = findings(item)[IndicatorType.FILE_TYPE_MISMATCH]
    assert mismatch.severity is Severity.MEDIUM
    assert "its declared type image/png" in mismatch.evidence


def test_macro_document_disguised_as_docx() -> None:
    found = findings(attachment("contract.docx", detected_type=filetypes.DOCM))
    assert found[IndicatorType.FILE_TYPE_MISMATCH].severity is Severity.HIGH


def test_text_file_with_binary_content() -> None:
    found = findings(attachment("readme.txt", detected_type=filetypes.ZIP))
    assert found[IndicatorType.FILE_TYPE_MISMATCH].severity is Severity.MEDIUM


def test_matching_and_unknown_types_are_not_mismatches() -> None:
    assert findings(attachment("logo.png", detected_type=filetypes.PNG)) == {}
    assert findings(attachment("data.bin", detected_type=filetypes.PDF)) == {}
    assert findings(attachment("notes.txt", detected_type=None)) == {}


def test_archive_with_dangerous_members() -> None:
    members = (*(f"part{n}.exe" for n in range(7)), "readme.txt", f"x{RLO}.js")
    risky = findings(attachment("files.zip", archive_members=members))[
        IndicatorType.RISKY_ATTACHMENT
    ]
    assert risky.severity is Severity.HIGH
    assert "part0.exe, part1.exe, part2.exe, part3.exe, part4.exe and 3 more" in risky.evidence


def test_member_names_are_printed_without_control_characters() -> None:
    risky = findings(attachment("files.zip", archive_members=(f"x{RLO}y.vbs",)))[
        IndicatorType.RISKY_ATTACHMENT
    ]
    assert "xy.vbs" in risky.evidence


def test_encrypted_archive() -> None:
    risky = findings(attachment("secure.zip", encrypted=True))[IndicatorType.RISKY_ATTACHMENT]
    assert risky.severity is Severity.MEDIUM
    assert "password-protected" in risky.evidence
