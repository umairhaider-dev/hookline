"""File type detection from content bytes, and what each file extension should hold.

Detection reads the leading bytes of a payload and, for ZIP containers, the
archive's central directory (the list of member names). Nothing is extracted,
decompressed, rendered or executed.

A built-in signature table comes first, so a file gets the same answer on
every platform. For content it does not recognise, libmagic (through
python-magic) is asked as well, on Linux and macOS only: on Windows,
python-magic's loader also tries a ``libmagic.dll`` in the current directory,
where a planted DLL would run, and MSYS builds found on PATH, such as the one
Git for Windows ships, which hang a native Python process. Only libmagic
answers that name a type the checks understand are kept.
"""

import io
import logging
import sys
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePosixPath

logger = logging.getLogger(__name__)

PE = "application/x-dosexec"
ELF = "application/x-executable"
MACHO = "application/x-mach-binary"
SHELL_SCRIPT = "text/x-shellscript"
PDF = "application/pdf"
ZIP = "application/zip"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
DOCM = "application/vnd.ms-word.document.macroenabled.12"
XLSM = "application/vnd.ms-excel.sheet.macroenabled.12"
PPTM = "application/vnd.ms-powerpoint.presentation.macroenabled.12"
JAR = "application/java-archive"
APK = "application/vnd.android.package-archive"
OLE = "application/x-ole-storage"
RAR = "application/vnd.rar"
SEVEN_ZIP = "application/x-7z-compressed"
GZIP = "application/gzip"
BZIP2 = "application/x-bzip2"
XZ = "application/x-xz"
CAB = "application/vnd.ms-cab-compressed"
LNK = "application/x-ms-shortcut"
ONENOTE = "application/onenote"
ISO = "application/x-iso9660-image"
VHD = "application/x-vhd"
VHDX = "application/x-vhdx"
RTF = "text/rtf"
HTML = "text/html"
SVG = "image/svg+xml"
PNG = "image/png"
JPEG = "image/jpeg"
GIF = "image/gif"
TIFF = "image/tiff"
WEBP = "image/webp"

# Content that can run code or open a web page as soon as it is opened.
ACTIVE_CONTENT_TYPES = frozenset(
    {PE, ELF, MACHO, SHELL_SCRIPT, JAR, APK, LNK, ONENOTE, ISO, VHD, VHDX, HTML, SVG}
    | {DOCM, XLSM, PPTM}
)

# Platforms where python-magic loads the system libmagic and nothing else.
LIBMAGIC_PLATFORMS = frozenset({"linux", "darwin"})
# libmagic is a native parser of hostile bytes, so it sees no more than this.
LIBMAGIC_SNIFF_BYTES = 64 * 1024

MAX_ARCHIVE_MEMBERS = 200
# Listing builds one object per entry, so archives declaring more are skipped.
MAX_ARCHIVE_ENTRIES = 10_000
_END_OF_DIRECTORY = b"PK\x05\x06"
_END_OF_DIRECTORY_SEARCH = 22 + 65_535  # fixed record plus the longest comment
_MAX_MEMBER_NAME = 255
_TEXT_SNIFF_BYTES = 2048

_ONENOTE_GUID = bytes.fromhex("e4525c7b8cd8a74daeb15359de61a9b9")
_LNK_HEADER = bytes.fromhex("4c0000000114020000000000c000000000000046")

# (offset, magic bytes, type). Longer and more specific signatures come first.
_SIGNATURES: tuple[tuple[int, bytes, str], ...] = (
    (0, _LNK_HEADER, LNK),
    (0, _ONENOTE_GUID, ONENOTE),
    (0, bytes.fromhex("d0cf11e0a1b11ae1"), OLE),
    (0, b"\x89PNG\r\n\x1a\n", PNG),
    (0, b"Rar!\x1a\x07", RAR),
    (0, b"7z\xbc\xaf\x27\x1c", SEVEN_ZIP),
    (0, b"\xfd7zXZ\x00", XZ),
    (0, b"vhdxfile", VHDX),
    (0, b"conectix", VHD),
    (0, b"GIF87a", GIF),
    (0, b"GIF89a", GIF),
    (0, b"%PDF-", PDF),
    (0, b"{\\rtf", RTF),
    (0, b"\x7fELF", ELF),
    (0, b"\xcf\xfa\xed\xfe", MACHO),
    (0, b"\xce\xfa\xed\xfe", MACHO),
    (0, b"\xfe\xed\xfa\xcf", MACHO),
    (0, b"\xfe\xed\xfa\xce", MACHO),
    (0, b"PK\x03\x04", ZIP),
    (0, b"PK\x05\x06", ZIP),
    (0, b"PK\x07\x08", ZIP),
    (0, b"MSCF", CAB),
    (0, b"II*\x00", TIFF),
    (0, b"MM\x00*", TIFF),
    (0, b"\xff\xd8\xff", JPEG),
    (0, b"BZh", BZIP2),
    (0, b"\x1f\x8b", GZIP),
    (0, b"MZ", PE),
    (0, b"#!", SHELL_SCRIPT),
    (0x8001, b"CD001", ISO),
    (0x8801, b"CD001", ISO),
    (0x9001, b"CD001", ISO),
)

_HTML_STARTS = ("<!doctype html", "<html", "<head", "<body", "<script", "<meta", "<iframe")

# Every type the checks reason about; libmagic answers outside it are dropped,
# so a CSV or calendar file is never reported as a mismatch for its extension.
_KNOWN_TYPES = frozenset(
    {PE, ELF, MACHO, SHELL_SCRIPT, PDF, ZIP, DOCX, XLSX, PPTX, DOCM, XLSM, PPTM, JAR, APK}
    | {OLE, RAR, SEVEN_ZIP, GZIP, BZIP2, XZ, CAB, LNK, ONENOTE, ISO, VHD, VHDX, RTF, HTML}
    | {SVG, PNG, JPEG, GIF, TIFF, WEBP}
)
# Other names libmagic uses for those types, depending on its version.
_LIBMAGIC_ALIASES = {
    "application/vnd.microsoft.portable-executable": PE,
    "application/x-msdownload": PE,
    "application/x-sharedlib": ELF,
    "application/x-pie-executable": ELF,
    "application/x-object": ELF,
    "application/cdfv2": OLE,
    "application/x-msi": OLE,
    "application/msword": OLE,
    "application/vnd.ms-excel": OLE,
    "application/vnd.ms-powerpoint": OLE,
    "application/vnd.ms-office": OLE,
    "application/x-rar": RAR,
    "application/x-gzip": GZIP,
    "application/rtf": RTF,
    "application/xhtml+xml": HTML,
}

# Extension -> content types it may legitimately hold. An empty set means a
# text format with no signature: any recognised binary type is a mismatch.
EXPECTED_TYPES: dict[str, frozenset[str]] = {
    "pdf": frozenset({PDF}),
    **dict.fromkeys(
        ("doc", "dot", "xls", "xlt", "ppt", "pps", "pot", "msg", "msi"), frozenset({OLE})
    ),
    **dict.fromkeys(("docx", "dotx"), frozenset({DOCX})),
    **dict.fromkeys(("xlsx", "xltx"), frozenset({XLSX})),
    **dict.fromkeys(("pptx", "ppsx", "potx"), frozenset({PPTX})),
    **dict.fromkeys(("docm", "dotm"), frozenset({DOCM})),
    **dict.fromkeys(("xlsm", "xltm"), frozenset({XLSM})),
    **dict.fromkeys(("pptm", "ppsm", "potm"), frozenset({PPTM})),
    **dict.fromkeys(("zip", "odt", "ods", "odp"), frozenset({ZIP})),
    "jar": frozenset({JAR, ZIP}),
    "apk": frozenset({APK, JAR, ZIP}),
    "rar": frozenset({RAR}),
    "7z": frozenset({SEVEN_ZIP}),
    **dict.fromkeys(("gz", "tgz"), frozenset({GZIP})),
    "bz2": frozenset({BZIP2}),
    "xz": frozenset({XZ}),
    "cab": frozenset({CAB}),
    "png": frozenset({PNG}),
    **dict.fromkeys(("jpg", "jpeg", "jfif"), frozenset({JPEG})),
    "gif": frozenset({GIF}),
    **dict.fromkeys(("tif", "tiff"), frozenset({TIFF})),
    "webp": frozenset({WEBP}),
    "rtf": frozenset({RTF}),
    **dict.fromkeys(("html", "htm", "shtml", "xhtml", "hta"), frozenset({HTML})),
    "svg": frozenset({SVG}),
    **dict.fromkeys(("exe", "dll", "scr", "cpl", "ocx", "sys"), frozenset({PE})),
    "lnk": frozenset({LNK}),
    "one": frozenset({ONENOTE}),
    "iso": frozenset({ISO}),
    "vhd": frozenset({VHD}),
    "vhdx": frozenset({VHDX}),
    **dict.fromkeys(("txt", "csv", "ics", "vcf", "log", "md"), frozenset()),
}

# Declared MIME types worth comparing with the detected type. Generic types
# such as application/octet-stream say nothing and are left out.
DECLARED_TYPES: dict[str, frozenset[str]] = {
    "application/pdf": frozenset({PDF}),
    "application/msword": frozenset({OLE}),
    "application/vnd.ms-excel": frozenset({OLE}),
    "application/vnd.ms-powerpoint": frozenset({OLE}),
    DOCX: frozenset({DOCX}),
    XLSX: frozenset({XLSX}),
    PPTX: frozenset({PPTX}),
    "application/zip": frozenset({ZIP, DOCX, XLSX, PPTX, JAR}),
    "application/x-zip-compressed": frozenset({ZIP, DOCX, XLSX, PPTX, JAR}),
    "image/png": frozenset({PNG}),
    "image/jpeg": frozenset({JPEG}),
    "image/jpg": frozenset({JPEG}),
    "image/gif": frozenset({GIF}),
    "text/plain": frozenset(),
    "text/csv": frozenset(),
    "text/calendar": frozenset(),
}


@dataclass(frozen=True)
class ArchiveListing:
    """What a ZIP container's central directory says about its members."""

    content_type: str
    members: tuple[str, ...]
    encrypted: bool


def file_extension(filename: str | None) -> str:
    """The lower-cased final extension, ignoring the trailing dots and spaces Windows drops."""
    if not filename:
        return ""
    name = PurePosixPath(filename.replace("\\", "/")).name.rstrip(". ")
    _, dot, extension = name.rpartition(".")
    return extension.strip().lower() if dot else ""


def detect_type(data: bytes) -> str | None:
    """Identify a payload from its leading bytes. Returns None if unrecognised."""
    for offset, signature, content_type in _SIGNATURES:
        if data.startswith(signature, offset):
            return content_type
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return WEBP
    return _detect_markup(data[:_TEXT_SNIFF_BYTES]) or _libmagic_type(data)


def _detect_markup(head: bytes) -> str | None:
    text = head.decode("latin-1").lstrip("\xef\xbb\xbf \t\r\n").lower()
    if text.startswith(_HTML_STARTS):
        return HTML
    if "<svg" in text and text.startswith(("<?xml", "<svg", "<!doctype svg")):
        return SVG
    return None


def _libmagic_type(data: bytes) -> str | None:
    """The type libmagic names for ``data``, if it is one the checks understand."""
    identify = _load_libmagic()
    if identify is None or not data:
        return None
    answer = identify(data[:LIBMAGIC_SNIFF_BYTES])
    if answer is None:
        return None
    content_type = answer.strip().lower()
    content_type = _LIBMAGIC_ALIASES.get(content_type, content_type)
    return content_type if content_type in _KNOWN_TYPES else None


@lru_cache(maxsize=1)
def _load_libmagic() -> Callable[[bytes], str | None] | None:
    """python-magic's MIME detector, or None where it is missing or not used."""
    if sys.platform not in LIBMAGIC_PLATFORMS:
        return None
    try:
        import magic
    except ImportError as exc:  # python-magic or the libmagic library is missing
        logger.debug("libmagic is not available: %s", exc)
        return None
    try:
        detector = magic.Magic(mime=True)
    except magic.MagicException as exc:
        logger.warning("libmagic could not be loaded: %s", exc)
        return None

    def identify(data: bytes) -> str | None:
        try:
            return detector.from_buffer(data)
        except magic.MagicException as exc:
            logger.warning("libmagic could not identify an attachment: %s", exc)
            return None

    return identify


def list_zip_archive(data: bytes) -> ArchiveListing | None:
    """Read a ZIP archive's member list and refine its type. None if it is not readable.

    Only the central directory is parsed. Office Open XML, Java and Android
    packages are told apart by their well-known member names, and documents
    carrying a ``vbaProject.bin`` are reported as macro-enabled. Archives that
    declare more than ``MAX_ARCHIVE_ENTRIES`` entries are not listed.
    """
    declared = _declared_entries(data)
    if declared is not None and declared > MAX_ARCHIVE_ENTRIES:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        NotImplementedError,
        ValueError,
        EOFError,
        OSError,
    ):
        return None
    names = [entry.filename for entry in entries]
    lowered = {name.lower() for name in names}
    return ArchiveListing(
        content_type=_zip_content_type(lowered),
        members=tuple(name[:_MAX_MEMBER_NAME] for name in names[:MAX_ARCHIVE_MEMBERS]),
        encrypted=any(entry.flag_bits & 0x1 for entry in entries),
    )


def _declared_entries(data: bytes) -> int | None:
    """The total entry count in the end-of-central-directory record, if there is one."""
    position = data.rfind(_END_OF_DIRECTORY, max(0, len(data) - _END_OF_DIRECTORY_SEARCH))
    if position < 0 or position + 22 > len(data):
        return None
    return int.from_bytes(data[position + 10 : position + 12], "little")


def _zip_content_type(names: set[str]) -> str:
    if "[content_types].xml" in names:
        for folder, plain, macro in (
            ("word/", DOCX, DOCM),
            ("xl/", XLSX, XLSM),
            ("ppt/", PPTX, PPTM),
        ):
            if any(name.startswith(folder) for name in names):
                return macro if f"{folder}vbaproject.bin" in names else plain
    if "androidmanifest.xml" in names and "classes.dex" in names:
        return APK
    if "meta-inf/manifest.mf" in names:
        return JAR
    return ZIP
