"""Walk a message's MIME tree, separating body text from attachments.

Attachment payloads are decoded only to hash them and sniff their type, then
discarded. Attached emails (``message/rfc822``) are treated as attachments and
not descended into, so their content is never mistaken for the outer body.
"""

import codecs
import hashlib
import logging
from dataclasses import dataclass, field
from email.errors import HeaderParseError
from email.message import EmailMessage, Message

from hookline.filetypes import ZIP, detect_type, list_zip_archive
from hookline.models.email import Attachment
from hookline.parsing.text import repair_text

logger = logging.getLogger(__name__)

MAX_PARTS = 1000
MAX_DEPTH = 30

# Raised by the standard library's header and serialisation code on hostile input.
_SERIALISE_ERRORS = (
    HeaderParseError,
    ValueError,
    IndexError,
    TypeError,
    AttributeError,
    LookupError,
)
_BODY_TYPES = frozenset({"text/plain", "text/html"})


@dataclass
class MessageBody:
    """Decoded body text and attachment metadata collected from all parts."""

    text_parts: list[str] = field(default_factory=list)
    html_parts: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)
    parts_seen: int = 0


def walk_body(message: EmailMessage) -> MessageBody:
    """Collect body text and attachments from ``message`` and all its parts."""
    body = MessageBody()
    _visit(message, body, depth=0)
    return body


def _visit(part: Message, body: MessageBody, depth: int) -> None:
    body.parts_seen += 1
    if body.parts_seen > MAX_PARTS:
        if body.parts_seen == MAX_PARTS + 1:
            body.defects.append(f"More than {MAX_PARTS} MIME parts; the rest were skipped")
        return
    if depth > MAX_DEPTH:
        body.defects.append(f"MIME parts nested deeper than {MAX_DEPTH} levels were skipped")
        return
    content_type = repair_text(part.get_content_type())
    # is_multipart() only checks the payload's shape. get_payload() on a text
    # part would re-decode it with the declared charset, which can raise.
    if part.is_multipart():
        _record_defects(part, body, depth)
        children = [child for child in part.get_payload() if isinstance(child, Message)]
        if part.get_content_maintype() == "message":
            data = _serialise(children, body)
            _add_attachment(body, part, data, content_type, _filename(part, body))
            return
        for child in children:
            _visit(child, body, depth + 1)
        return

    data = _decode_payload(part, body)
    # Decoding registers transfer-encoding defects, so collect them afterwards.
    _record_defects(part, body, depth)
    filename = _filename(part, body)
    is_multipart_without_parts = part.get_content_maintype() == "multipart"
    if is_multipart_without_parts or (
        content_type in _BODY_TYPES
        and filename is None
        and part.get_content_disposition() != "attachment"
    ):
        text = _decode_text(data, part, body)
        if content_type == "text/html":
            body.html_parts.append(text)
        else:
            body.text_parts.append(text)
        return
    _add_attachment(body, part, data, content_type, filename)


def _record_defects(part: Message, body: MessageBody, depth: int) -> None:
    # The top-level message's own defects are collected by the parser.
    if depth > 0:
        body.defects.extend(f"MIME part: {type(defect).__name__}" for defect in part.defects)


def _add_attachment(
    body: MessageBody,
    part: Message,
    data: bytes,
    content_type: str,
    filename: str | None = None,
) -> None:
    detected = detect_type(data)
    members: tuple[str, ...] = ()
    encrypted = False
    if detected == ZIP:
        listing = list_zip_archive(data)
        if listing is None:
            name = filename or "(unnamed)"
            body.defects.append(
                f"Attachment {name} looks like a ZIP archive but could not be listed "
                "(damaged, or too many entries)"
            )
        else:
            detected, members, encrypted = listing.content_type, listing.members, listing.encrypted
    disposition = part.get_content_disposition()
    body.attachments.append(
        Attachment(
            filename=filename,
            content_type=content_type,
            detected_type=detected,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            inline=disposition == "inline" or (disposition is None and "Content-ID" in part),
            archive_members=members,
            encrypted=encrypted,
        )
    )


def _decode_payload(part: Message, body: MessageBody) -> bytes:
    try:
        data = part.get_payload(decode=True)
    except (ValueError, LookupError) as exc:
        body.defects.append(f"MIME part could not be decoded: {exc}")
        return b""
    return data if isinstance(data, bytes) else b""


def _decode_text(data: bytes, part: Message, body: MessageBody) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        codecs.lookup(charset)
        return data.decode(charset, errors="replace")
    except (LookupError, ValueError):
        body.defects.append(f"Unknown charset {charset!r}; decoded as UTF-8")
        return data.decode("utf-8", errors="replace")


def _filename(part: Message, body: MessageBody) -> str | None:
    try:
        name = part.get_filename()
    except _SERIALISE_ERRORS as exc:
        body.defects.append(f"Attachment filename could not be decoded: {exc}")
        return None
    return repair_text(str(name)) if name else None


def _serialise(messages: list[Message], body: MessageBody) -> bytes:
    """Bytes of an attached message, for hashing. Empty if it cannot be rebuilt."""
    try:
        return b"".join(message.as_bytes() for message in messages)
    except (*_SERIALISE_ERRORS, UnicodeError) as exc:
        body.defects.append(f"Attached message could not be serialised: {exc}")
        return b""
