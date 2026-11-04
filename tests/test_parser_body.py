"""Parser behaviour for bodies, links, attachments and hostile MIME structures."""

import hashlib
import io
import zipfile
from email.errors import HeaderParseError
from email.message import EmailMessage, Message

import pytest

from hookline.models import LinkOrigin
from hookline.parsing import mime, parse_email, parser
from hookline.parsing.html import HtmlContent
from tests.factories import SAMPLES_DIR, build_eml


def mime_message() -> EmailMessage:
    message = EmailMessage()
    message["From"] = "dana.whitfield@larkspur.test"
    message["To"] = "sam.ortega@larkspur.test"
    message["Subject"] = "Bodies and attachments"
    return message


def add_binary(message: EmailMessage, data: bytes, filename: str | None = None) -> None:
    message.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)


def test_sample_bodies_links_auth_and_hops() -> None:
    email = parse_email((SAMPLES_DIR / "credential-phish.eml").read_bytes())
    assert "confirm your current password now" in email.text_body
    assert "<div style=" in email.html_body
    assert "expires in 2 hours" in email.html_text
    assert "<p>" not in email.html_text
    assert [(link.url, link.origin) for link in email.links] == [
        ("http://198.51.100.23/owa/login.php?session=7f3a9c", LinkOrigin.HTML_ANCHOR),
        ("https://portal.larkspur.test/password-renewal", LinkOrigin.PLAIN_TEXT),
    ]
    assert email.links[0].text == "https://portal.larkspur.test/password-renewal"
    assert [(r.method, r.result) for r in email.authentication_results] == [
        ("spf", "fail"),
        ("dkim", "none"),
        ("dmarc", "fail"),
    ]
    (hop,) = email.received
    assert str(hop.from_ip) == "203.0.113.45"
    assert email.attachments == ()


def test_attachments_are_hashed_and_typed() -> None:
    message = mime_message()
    message.set_content("See attached.")
    payload = b"MZ\x90\x00 inert test bytes"
    message.add_attachment(payload, maintype="application", subtype="pdf", filename="invoice.pdf")
    message.add_attachment(
        b"\x89PNG\r\n\x1a\n...",
        maintype="image",
        subtype="png",
        filename="logo.png",
        disposition="inline",
    )
    email = parse_email(message.as_bytes())
    assert email.text_body.strip() == "See attached."
    invoice, logo = email.attachments
    assert invoice.filename == "invoice.pdf"
    assert invoice.content_type == "application/pdf"
    assert invoice.detected_type == "application/x-dosexec"
    assert invoice.size == len(payload)
    assert invoice.sha256 == hashlib.sha256(payload).hexdigest()
    assert not invoice.inline
    assert logo.inline


def test_part_with_content_id_and_no_disposition_is_inline() -> None:
    raw = (
        b"Content-Type: multipart/related; boundary=X\r\n\r\n--X\r\n"
        b"Content-Type: text/html\r\n\r\n<img src=cid:logo>\r\n--X\r\n"
        b"Content-Type: image/png\r\nContent-ID: <logo>\r\n\r\nPNG\r\n--X--\r\n"
    )
    (attachment,) = parse_email(raw).attachments
    assert attachment.inline
    assert attachment.filename is None


def test_zip_attachment_members_are_listed() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("statement.pdf.js", "// inert")
    message = mime_message()
    message.set_content("Statement attached.")
    add_binary(message, buffer.getvalue(), "statement.zip")
    (attachment,) = parse_email(message.as_bytes()).attachments
    assert attachment.detected_type == "application/zip"
    assert attachment.archive_members == ("statement.pdf.js",)


@pytest.mark.parametrize(("filename", "label"), [("broken.zip", "broken.zip"), (None, "(unnamed)")])
def test_unreadable_zip_is_a_defect(filename: str | None, label: str) -> None:
    message = mime_message()
    message.set_content("x")
    add_binary(message, b"PK\x03\x04 broken", filename)
    email = parse_email(message.as_bytes())
    assert email.attachments[0].archive_members == ()
    assert (
        f"Attachment {label} looks like a ZIP archive but could not be listed "
        "(damaged, or too many entries)"
    ) in email.defects


def test_attached_email_is_not_mistaken_for_the_body() -> None:
    inner = EmailMessage()
    inner["Subject"] = "Inner"
    inner.set_content("Inner body with https://inner.test/link")
    message = mime_message()
    message.set_content("Outer body.")
    message.add_attachment(inner, filename="forwarded.eml")
    email = parse_email(message.as_bytes())
    assert "Inner body" not in email.text_body
    assert email.links == ()
    (attachment,) = email.attachments
    assert attachment.content_type == "message/rfc822"
    assert attachment.filename == "forwarded.eml"
    assert attachment.size > 0


def test_attached_email_that_cannot_be_serialised(monkeypatch: pytest.MonkeyPatch) -> None:
    inner = EmailMessage()
    inner.set_content("Inner")
    message = mime_message()
    message.set_content("Outer")
    message.add_attachment(inner)
    raw = message.as_bytes()

    def broken(self: Message, *args: object, **kwargs: object) -> bytes:
        raise ValueError("cannot serialise")

    monkeypatch.setattr(Message, "as_bytes", broken)
    email = parse_email(raw)
    assert email.attachments[0].size == 0
    assert "Attached message could not be serialised: cannot serialise" in email.defects


def test_text_attachment_with_filename_is_not_body() -> None:
    message = mime_message()
    message.set_content("Body text.")
    message.add_attachment("notes", filename="notes.txt")
    email = parse_email(message.as_bytes())
    assert email.text_body.strip() == "Body text."
    assert email.attachments[0].filename == "notes.txt"


def test_unknown_charset_falls_back_to_utf8() -> None:
    email = parse_email(
        build_eml([("Content-Type", "text/plain; charset=klingon")], body="caf\xe9\r\n")
    )
    assert email.text_body.startswith("caf")
    assert "Unknown charset 'klingon'; decoded as UTF-8" in email.defects


def test_non_text_codec_charset_is_rejected() -> None:
    email = parse_email(build_eml([("Content-Type", "text/plain; charset=rot13")], body="uryyb"))
    assert email.text_body.strip() == "uryyb"
    assert "Unknown charset 'rot13'; decoded as UTF-8" in email.defects


def test_invalid_base64_is_recorded() -> None:
    raw = (
        b"Content-Type: multipart/mixed; boundary=X\r\n\r\n--X\r\n"
        b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n"
        b'Content-Disposition: attachment; filename="a.bin"\r\n\r\nTVqQ!!!AAMAAAA\r\n--X--\r\n'
    )
    email = parse_email(raw)
    assert email.attachments[0].detected_type == "application/x-dosexec"
    assert any(defect.startswith("MIME part: InvalidBase64") for defect in email.defects)


def test_payload_decoding_error_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Message.get_payload

    def broken(self: Message, *args: object, **kwargs: object) -> object:
        if kwargs.get("decode"):
            raise ValueError("bad payload")
        return original(self, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(Message, "get_payload", broken)
    email = parse_email(build_eml(body="hello"))
    assert email.text_body == ""
    assert "MIME part could not be decoded: bad payload" in email.defects


def test_filename_decoding_error_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(self: Message, failobj: object = None) -> str:
        raise HeaderParseError("bad filename")

    message = mime_message()
    message.set_content("x")
    add_binary(message, b"data", "data.bin")
    monkeypatch.setattr(Message, "get_filename", broken)
    email = parse_email(message.as_bytes())
    assert "Attachment filename could not be decoded: bad filename" in email.defects


def test_multipart_without_boundary_is_read_as_text() -> None:
    email = parse_email(build_eml([("Content-Type", "multipart/mixed")], body="raw parts here"))
    assert "raw parts here" in email.text_body


def test_too_many_parts_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mime, "MAX_PARTS", 3)
    message = mime_message()
    message.set_content("x")
    for number in range(5):
        add_binary(message, b"data", f"{number}.bin")
    email = parse_email(message.as_bytes())
    assert len(email.attachments) == 1
    assert email.defects.count("More than 3 MIME parts; the rest were skipped") == 1


def test_deep_nesting_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mime, "MAX_DEPTH", 2)
    head = b"".join(
        f"Content-Type: multipart/mixed; boundary=b{n}\r\n\r\n--b{n}\r\n".encode() for n in range(4)
    )
    email = parse_email(head + b"Content-Type: text/plain\r\n\r\ndeep text\r\n")
    assert "deep text" not in email.text_body
    assert "MIME parts nested deeper than 2 levels were skipped" in email.defects


def test_links_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parser, "MAX_LINKS", 2)
    body = " ".join(f"https://x{n}.test/" for n in range(4))
    email = parse_email(build_eml(body=body))
    assert len(email.links) == 2
    assert "Message has more than 2 distinct links; only the first 2 were analysed" in email.defects


def test_received_headers_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parser, "MAX_RECEIVED_HOPS", 2)
    email = parse_email(build_eml([("Received", f"from h{n}.test by mx.test") for n in range(3)]))
    assert len(email.received) == 2
    assert "Message has 3 Received headers; only 2 were read" in email.defects


def test_several_auth_headers_keep_their_position() -> None:
    email = parse_email(
        build_eml(
            [
                ("Authentication-Results", "mx1.larkspur.test; spf=fail"),
                ("Authentication-Results", "forged.test; spf=pass; nonsense"),
            ]
        )
    )
    assert [(r.authserv_id, r.header_index) for r in email.authentication_results] == [
        ("mx1.larkspur.test", 0),
        ("forged.test", 1),
    ]
    assert "Authentication-Results header 2 has 1 unreadable result(s)" in email.defects


def test_html_parse_error_becomes_a_defect(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(html: str, *, max_links: int) -> HtmlContent:
        return HtmlContent(text="", links=(), problems=("boom",))

    monkeypatch.setattr(parser, "extract_html", failing)
    assert "boom" in parse_email(build_eml()).defects


def test_single_part_decoding_problems_are_recorded() -> None:
    email = parse_email(build_eml([("Content-Transfer-Encoding", "base64")], body="aGVsbG8!!!\r\n"))
    assert any(defect.startswith("Invalid") for defect in email.defects)


def test_raw_8bit_headers_are_repaired() -> None:
    raw = (
        b'From: "Ren\xc3\xa9e \x9c Ortiz" <renee@larkspur-helpdesk.test>\r\n'
        b"Reply-To: <x@elsewhere.test>\r\nSubject: caf\xc3\xa9 \xff\r\n\r\nbody\r\n"
    )
    email = parse_email(raw)
    assert email.subject == "caf\xe9 \ufffd"
    assert email.from_address is not None
    assert email.from_address.display_name == "Ren\xe9e \ufffd Ortiz"
    # Every string must survive validation and JSON encoding downstream.
    email.model_dump_json()


def test_charset_with_nul_byte_and_8bit_body() -> None:
    raw = b'Content-Type: text/plain; charset="a\x00b"\r\n\r\nbody \xff\r\n'
    email = parse_email(raw)
    assert email.text_body.startswith("body ")
    assert "Unknown charset 'a\\x00b'; decoded as UTF-8" in email.defects


def test_html_link_overflow_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parser, "MAX_LINKS", 1)
    message = mime_message()
    message.set_content("x")
    message.add_alternative(
        '<a href="https://a.test">a</a><a href="https://b.test">b</a>', subtype="html"
    )
    email = parse_email(message.as_bytes())
    assert [link.url for link in email.links] == ["https://a.test"]
    assert any(defect.startswith("Message has more than 1 distinct") for defect in email.defects)
