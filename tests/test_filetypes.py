import io
import logging
import sys
import zipfile
from collections.abc import Callable, Iterator

import pytest

from hookline import filetypes
from hookline.filetypes import _load_libmagic, detect_type, file_extension, list_zip_archive

Identify = Callable[[bytes], str | None]


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


# --- libmagic -----------------------------------------------------------------


def use_libmagic(monkeypatch: pytest.MonkeyPatch, answers: dict[bytes, str | None]) -> list[int]:
    """Stand in for libmagic with fixed answers; returns the sizes it was asked about."""
    asked: list[int] = []

    def identify(data: bytes) -> str | None:
        asked.append(len(data))
        return answers.get(data[:8])

    monkeypatch.setattr(filetypes, "_load_libmagic", lambda: identify)
    return asked


def test_libmagic_names_only_types_the_checks_understand(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = use_libmagic(
        monkeypatch,
        {
            b"<!-- x -": " TEXT/HTML ",
            b"\x00\x01pe\x00\x00\x00\x00": "application/vnd.microsoft.portable-executable",
            b"BEGIN:VC": "text/calendar",
            b"\x00\x02\x00\x00\x00\x00\x00\x00": None,
        },
    )
    assert detect_type(b"<!-- x --><html><body>Sign in</body></html>") == filetypes.HTML
    assert detect_type(b"\x00\x01pe\x00\x00\x00\x00" + b"\x00" * 200_000) == filetypes.PE
    assert detect_type(b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n") is None
    assert detect_type(b"\x00\x02" + b"\x00" * 6) is None
    assert max(asked) == filetypes.LIBMAGIC_SNIFF_BYTES
    asked.clear()
    assert detect_type(b"%PDF-1.7\n") == filetypes.PDF
    assert detect_type(b"") is None
    assert asked == []


class FakeMagicError(Exception):
    """Stands in for magic.MagicException."""


class FakeMagic:
    """Stands in for magic.Magic."""

    broken = False

    def __init__(self, mime: bool = False) -> None:
        if self.broken:
            raise FakeMagicError("no magic database")
        assert mime

    def from_buffer(self, buf: bytes) -> str:
        if buf.startswith(b"bad"):
            raise FakeMagicError("cannot read")
        return "application/pdf"


class FakeMagicModule(type(sys)):  # type: ignore[misc]
    """Stands in for the magic module."""

    MagicException = FakeMagicError
    Magic = FakeMagic


@pytest.fixture
def fresh_loader() -> Iterator[Callable[[], Identify | None]]:
    _load_libmagic.cache_clear()
    yield _load_libmagic
    _load_libmagic.cache_clear()


def test_libmagic_is_loaded_once_where_it_is_safe(
    monkeypatch: pytest.MonkeyPatch,
    fresh_loader: Callable[[], Identify | None],
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(filetypes, "LIBMAGIC_PLATFORMS", frozenset({sys.platform}))
    monkeypatch.setitem(sys.modules, "magic", FakeMagicModule("magic"))
    identify = fresh_loader()
    assert identify is not None
    assert fresh_loader() is identify
    assert identify(b"anything") == "application/pdf"
    with caplog.at_level(logging.WARNING, logger="hookline"):
        assert identify(b"bad bytes") is None
    assert "could not identify" in caplog.text


def test_libmagic_is_skipped_when_unsafe_missing_or_broken(
    monkeypatch: pytest.MonkeyPatch,
    fresh_loader: Callable[[], Identify | None],
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setitem(sys.modules, "magic", FakeMagicModule("magic"))
    monkeypatch.setattr(filetypes, "LIBMAGIC_PLATFORMS", frozenset())
    assert fresh_loader() is None
    _load_libmagic.cache_clear()
    monkeypatch.setattr(filetypes, "LIBMAGIC_PLATFORMS", frozenset({sys.platform}))
    monkeypatch.setitem(sys.modules, "magic", None)
    assert fresh_loader() is None
    _load_libmagic.cache_clear()
    monkeypatch.setitem(sys.modules, "magic", FakeMagicModule("magic"))
    monkeypatch.setattr(FakeMagic, "broken", True)
    with caplog.at_level(logging.WARNING, logger="hookline"):
        assert fresh_loader() is None
    assert "could not be loaded" in caplog.text


@pytest.mark.skipif(
    sys.platform not in filetypes.LIBMAGIC_PLATFORMS,
    reason="python-magic is only used on Linux and macOS",
)
def test_real_libmagic(
    monkeypatch: pytest.MonkeyPatch, fresh_loader: Callable[[], Identify | None]
) -> None:
    if fresh_loader() is None:
        pytest.skip("libmagic is not installed")
    monkeypatch.setattr(filetypes, "_load_libmagic", fresh_loader)
    page = b"<!-- saved page -->\n<HTML><body><form>Password</form></body></HTML>\n"
    assert detect_type(page) == filetypes.HTML
    assert detect_type(b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n") is None
    assert detect_type(bytes(range(256)) * 8) is None
