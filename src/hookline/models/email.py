"""Models describing a parsed email message.

Every string here comes from the email and is untrusted. Values are stored as
found, even when malformed, so checks can reason about the malformation.
"""

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from pydantic import Field

from hookline.models.base import FrozenModel

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class EmailAddress(FrozenModel):
    """A mailbox taken from an address header such as From or Reply-To."""

    display_name: str = ""
    address: str = ""

    @property
    def domain(self) -> str:
        """Lower-cased domain part, or an empty string if there is none."""
        _, at, domain = self.address.rpartition("@")
        return domain.strip().rstrip(".").lower() if at else ""

    def __str__(self) -> str:
        if self.display_name:
            return f'"{self.display_name}" <{self.address}>'
        return self.address


class Header(FrozenModel):
    """A single header, decoded where possible, in its original position."""

    name: str
    value: str


class AuthResult(FrozenModel):
    """One method result from an Authentication-Results header (RFC 8601)."""

    method: str = Field(description="spf, dkim, dmarc, arc and so on, lower-cased.")
    result: str = Field(description="pass, fail, softfail, neutral, none, temperror, permerror.")
    properties: dict[str, str] = Field(
        default_factory=dict,
        description="Method properties such as smtp.mailfrom or header.d.",
    )
    authserv_id: str | None = Field(
        default=None, description="The server that recorded the result."
    )
    header_index: int = Field(
        default=0,
        ge=0,
        description="Which Authentication-Results header this came from; 0 is the topmost.",
    )


class ReceivedHop(FrozenModel):
    """One Received header. Hops are kept in message order, newest first."""

    raw: str
    from_host: str | None = None
    from_ip: IPv4Address | IPv6Address | None = None
    by_host: str | None = None
    timestamp: datetime | None = None


class LinkOrigin(StrEnum):
    """Where in the message a link was found."""

    HTML_ANCHOR = "html_anchor"
    HTML_FORM = "html_form"
    PLAIN_TEXT = "plain_text"


class Link(FrozenModel):
    """A URL found in the message body. Links are never fetched."""

    url: str
    text: str = Field(default="", description="Visible anchor text, for HTML links.")
    origin: LinkOrigin


class Attachment(FrozenModel):
    """Metadata about an attachment. The payload itself is never kept or opened."""

    filename: str | None = None
    content_type: str = Field(description="MIME type as declared by the sender.")
    detected_type: str | None = Field(
        default=None, description="MIME type detected from the content bytes."
    )
    size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    inline: bool = False
    archive_members: tuple[str, ...] = Field(
        default=(),
        description="File names inside a ZIP-based attachment, read from its directory only.",
    )
    encrypted: bool = Field(
        default=False, description="True for password-protected archives, which scanners skip."
    )


class ParsedEmail(FrozenModel):
    """Everything extracted from one message, ready for the checks."""

    message_id: str | None = None
    subject: str = ""
    date: datetime | None = None
    from_address: EmailAddress | None = None
    reply_to: tuple[EmailAddress, ...] = ()
    return_path: str | None = None
    to: tuple[EmailAddress, ...] = ()
    cc: tuple[EmailAddress, ...] = ()
    headers: tuple[Header, ...] = ()
    authentication_results: tuple[AuthResult, ...] = ()
    received: tuple[ReceivedHop, ...] = ()
    text_body: str = ""
    html_body: str = ""
    html_text: str = Field(
        default="", description="Readable text of the HTML body, without tags, scripts or styles."
    )
    links: tuple[Link, ...] = ()
    attachments: tuple[Attachment, ...] = ()
    defects: tuple[str, ...] = Field(
        default=(), description="Structural problems noticed while parsing."
    )
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN, description="Hash of the raw message.")

    def header_values(self, name: str) -> list[str]:
        """Return every value of header ``name``, matched case-insensitively."""
        wanted = name.lower()
        return [header.value for header in self.headers if header.name.lower() == wanted]
