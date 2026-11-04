import hashlib
from datetime import UTC, datetime
from email.errors import HeaderParseError
from email.headerregistry import AddressHeader
from email.policy import EmailPolicy

import pytest

from hookline.models import EmailAddress
from hookline.parsing import parse_email
from tests.factories import SAMPLES_DIR, build_eml


def test_sample_envelope_fields() -> None:
    email = parse_email((SAMPLES_DIR / "credential-phish.eml").read_bytes())
    assert email.subject == "\u26a0 Action required: your password expires today"
    assert email.from_address == EmailAddress(
        display_name="Larkspur IT Service Desk", address="it-support@larkspur-helpdesk.test"
    )
    assert [item.address for item in email.reply_to] == ["account-review@mailbox-verify.test"]
    assert email.return_path == "bounce-7731@mailer.larkspur-helpdesk.test"
    assert email.to == (
        EmailAddress(display_name="Sam Ortega", address="sam.ortega@larkspur.test"),
    )
    assert email.message_id == "20261103081419.5521@mailer.larkspur-helpdesk.test"
    assert email.date == datetime(2026, 11, 3, 8, 14, 19, tzinfo=UTC)
    assert email.defects == ()


def test_headers_keep_order_and_are_unfolded() -> None:
    email = parse_email((SAMPLES_DIR / "credential-phish.eml").read_bytes())
    assert [h.name for h in email.headers[:3]] == [
        "Return-Path",
        "Received",
        "Authentication-Results",
    ]
    (auth,) = email.header_values("authentication-results")
    assert "\n" not in auth
    assert "spf=fail" in auth


def test_cc_recipients() -> None:
    email = parse_email((SAMPLES_DIR / "benign-meeting.eml").read_bytes())
    assert [item.address for item in email.cc] == ["priya.raman@larkspur.test"]


def test_hash_and_size_describe_the_raw_bytes() -> None:
    raw = build_eml()
    email = parse_email(raw)
    assert email.sha256 == hashlib.sha256(raw).hexdigest()
    assert email.size_bytes == len(raw)


def test_encoded_display_name_with_comma_stays_one_address() -> None:
    email = parse_email(build_eml([("From", "=?utf-8?q?Doe,_John?= <john.doe@larkspur.test>")]))
    assert email.from_address == EmailAddress(
        display_name="Doe, John", address="john.doe@larkspur.test"
    )


def test_several_from_addresses_are_a_defect() -> None:
    email = parse_email(build_eml([("From", "a@larkspur.test, b@elsewhere.test")]))
    assert email.from_address is not None
    assert email.from_address.address == "a@larkspur.test"
    assert "From header lists 2 addresses" in email.defects


def test_invalid_date_becomes_none_with_defect() -> None:
    email = parse_email(build_eml([("Date", "sometime last week")]))
    assert email.date is None
    assert any("Date header" in defect for defect in email.defects)


def test_invalid_address_is_recorded() -> None:
    email = parse_email(build_eml([("To", 'ok@larkspur.test, "Bad" <<<>>>')]))
    assert email.to[0].address == "ok@larkspur.test"
    assert any(defect.startswith("To header") for defect in email.defects)


def test_bounce_return_path_is_empty() -> None:
    email = parse_email(build_eml([("Return-Path", "<>")]))
    assert email.return_path is None


def test_message_without_headers() -> None:
    email = parse_email(b"\r\njust a body\r\n")
    assert email.subject == ""
    assert email.from_address is None
    assert email.to == ()
    assert email.date is None


@pytest.mark.parametrize(
    "raw",
    [
        bytes(range(256)) * 4,
        b"",
        b"Subject: caf\xe9 \xff\xfe\r\nFrom: \x00\x01@\x02\r\n\r\nbody",
        b"Content-Type: multipart/mixed; boundary=\r\n\r\n--\r\n",
        b"From: " + b"<" * 5000 + b"\r\n\r\n",
    ],
)
def test_hostile_input_never_raises(raw: bytes) -> None:
    email = parse_email(raw)
    assert email.size_bytes == len(raw)


def test_falls_back_to_raw_text_when_decoding_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(self: EmailPolicy, name: str, value: str) -> str:
        raise HeaderParseError("simulated parser bug")

    monkeypatch.setattr(EmailPolicy, "header_fetch_parse", broken)
    email = parse_email(
        build_eml(
            [
                ("From", '"Dana Whitfield" <dana.whitfield@larkspur.test>'),
                ("Subject", "Folded\r\n subject"),
                ("Date", "Mon, 02 Nov 2026 15:02:08 +0000"),
            ]
        )
    )
    assert email.from_address == EmailAddress(
        display_name="Dana Whitfield", address="dana.whitfield@larkspur.test"
    )
    assert email.subject == "Folded subject"
    assert email.date == datetime(2026, 11, 2, 15, 2, 8, tzinfo=UTC)
    assert any("could not be decoded" in defect for defect in email.defects)


def test_unparseable_date_in_fallback_path(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(self: EmailPolicy, name: str, value: str) -> str:
        raise HeaderParseError("simulated parser bug")

    monkeypatch.setattr(EmailPolicy, "header_fetch_parse", broken)
    email = parse_email(build_eml([("Date", "not a date")]))
    assert email.date is None
    assert "Date header could not be parsed" in email.defects


def test_address_extraction_failure_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(self: AddressHeader) -> tuple[object, ...]:
        raise IndexError("simulated parser bug")

    monkeypatch.setattr(AddressHeader, "addresses", property(broken))
    email = parse_email(build_eml([("From", "dana.whitfield@larkspur.test")]))
    assert email.from_address == EmailAddress(address="dana.whitfield@larkspur.test")
    assert any("addresses could not be parsed" in defect for defect in email.defects)


def test_plain_string_header_values_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    def plain(self: EmailPolicy, name: str, value: str) -> str:
        return value.strip()

    monkeypatch.setattr(EmailPolicy, "header_fetch_parse", plain)
    email = parse_email(build_eml([("Subject", "Plain")]))
    assert email.subject == "Plain"
    assert email.defects == ()
