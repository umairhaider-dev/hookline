import io
import zipfile

import pytest

from hookline import filetypes
from hookline.filetypes import detect_type, file_extension, list_zip_archive


def make_zip(*names: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, "test")
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"MZ\x90\x00", filetypes.PE),
        (b"\x7fELF\x02\x01", filetypes.ELF),
        (b"\xcf\xfa\xed\xfe", filetypes.MACHO),
        (b"%PDF-1.7\n", filetypes.PDF),
        (b"PK\x03\x04rest", filetypes.ZIP),
        (bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 8, filetypes.OLE),
        (b"Rar!\x1a\x07\x01\x00", filetypes.RAR),
        (b"7z\xbc\xaf\x27\x1c", filetypes.SEVEN_ZIP),
        (b"\x1f\x8b\x08", filetypes.GZIP),
        (b"MSCF\x00\x00", filetypes.CAB),
        (bytes.fromhex("4c0000000114020000000000c000000000000046"), filetypes.LNK),
        (bytes.fromhex("e4525c7b8cd8a74daeb15359de61a9b9"), filetypes.ONENOTE),
        (b"vhdxfile", filetypes.VHDX),
        (b"{\\rtf1\\ansi", filetypes.RTF),
        (b"\x89PNG\r\n\x1a\n", filetypes.PNG),
        (b"\xff\xd8\xff\xe0", filetypes.JPEG),
        (b"GIF89a", filetypes.GIF),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", filetypes.WEBP),
        (b"#!/bin/sh\n", filetypes.SHELL_SCRIPT),
        (b"\x00" * 0x8001 + b"CD001", filetypes.ISO),
        (b"\xef\xbb\xbf  <!DOCTYPE html><html>", filetypes.HTML),
        (b"\r\n<script>alert(1)</script>", filetypes.HTML),
        (b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg">', filetypes.SVG),
        (b"plain text, nothing special", None),
        (b"", None),
        (b"<?xml version='1.0'?><note/>", None),
    ],
)
def test_detect_type(data: bytes, expected: str | None) -> None:
    assert detect_type(data) == expected


@pytest.mark.parametrize(
    ("filename", "extension"),
    [
        ("invoice.PDF", "pdf"),
        ("invoice.pdf.exe", "exe"),
        ("invoice.exe. . ", "exe"),
        ("C:\\Users\\x\\report.docx", "docx"),
        ("folder/archive.tar.gz", "gz"),
        ("README", ""),
        ("", ""),
        (None, ""),
    ],
)
def test_file_extension(filename: str | None, extension: str) -> None:
    assert file_extension(filename) == extension


@pytest.mark.parametrize(
    ("members", "expected"),
    [
        (("[Content_Types].xml", "word/document.xml"), filetypes.DOCX),
        (("[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"), filetypes.DOCM),
        (("[Content_Types].xml", "xl/workbook.xml"), filetypes.XLSX),
        (("[Content_Types].xml", "xl/workbook.xml", "xl/vbaProject.bin"), filetypes.XLSM),
        (("[Content_Types].xml", "ppt/presentation.xml"), filetypes.PPTX),
        (("[Content_Types].xml", "ppt/vbaProject.bin", "ppt/x.xml"), filetypes.PPTM),
        (("[Content_Types].xml", "other/thing.xml"), filetypes.ZIP),
        (("META-INF/MANIFEST.MF", "App.class"), filetypes.JAR),
        (("AndroidManifest.xml", "classes.dex", "META-INF/MANIFEST.MF"), filetypes.APK),
        (("photos/one.jpg", "notes.txt"), filetypes.ZIP),
    ],
)
def test_zip_containers_are_told_apart(members: tuple[str, ...], expected: str) -> None:
    listing = list_zip_archive(make_zip(*members))
    assert listing is not None
    assert listing.content_type == expected
    assert listing.members == members
    assert not listing.encrypted


def test_encrypted_zip_is_flagged() -> None:
    data = bytearray(make_zip("secret.exe"))
    # Set the "encrypted" bit in the central directory entry's flags.
    central = data.index(b"PK\x01\x02")
    data[central + 8] |= 0x1
    listing = list_zip_archive(bytes(data))
    assert listing is not None
    assert listing.encrypted


def test_member_list_is_capped() -> None:
    names = [f"file{n}.txt" for n in range(filetypes.MAX_ARCHIVE_MEMBERS + 5)]
    listing = list_zip_archive(make_zip(*names))
    assert listing is not None
    assert len(listing.members) == filetypes.MAX_ARCHIVE_MEMBERS


def test_corrupt_zip_returns_none() -> None:
    assert list_zip_archive(b"PK\x03\x04 truncated") is None


def test_archives_with_too_many_entries_are_not_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(filetypes, "MAX_ARCHIVE_ENTRIES", 2)
    assert list_zip_archive(make_zip("a", "b")) is not None
    assert list_zip_archive(make_zip("a", "b", "c")) is None
