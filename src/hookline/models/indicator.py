"""Indicators: individual pieces of evidence produced by deterministic checks."""

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import Field, computed_field, field_validator, model_validator

from hookline.models.base import FrozenModel

MAX_VALUE_LENGTH = 2048
_TRUNCATION_MARK = "...[truncated]"


class Severity(StrEnum):
    """How strongly an indicator points towards a malicious email."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Position in ascending order of severity, for sorting."""
        return list(Severity).index(self)


class IndicatorSource(StrEnum):
    """The component that produced an indicator."""

    PARSER = "parser"
    HEADERS = "headers"
    DOMAINS = "domains"
    LINKS = "links"
    ATTACHMENTS = "attachments"
    LANGUAGE = "language"
    CONTENT = "content"
    THREAT_INTEL = "threat_intel"


class IndicatorType(StrEnum):
    """What kind of evidence an indicator represents."""

    # Message structure
    MALFORMED_MESSAGE = "malformed_message"

    # Sender authentication and header consistency
    SPF_FAIL = "spf_fail"
    DKIM_FAIL = "dkim_fail"
    DMARC_FAIL = "dmarc_fail"
    AUTH_RESULTS_MISSING = "auth_results_missing"
    REPLY_TO_MISMATCH = "reply_to_mismatch"
    RETURN_PATH_MISMATCH = "return_path_mismatch"
    DISPLAY_NAME_SPOOFING = "display_name_spoofing"
    SENDING_IP = "sending_ip"

    # Domains
    LOOKALIKE_DOMAIN = "lookalike_domain"
    HOMOGLYPH_DOMAIN = "homoglyph_domain"
    PUNYCODE_DOMAIN = "punycode_domain"
    SUSPICIOUS_TLD = "suspicious_tld"

    # Links
    LINK_TEXT_MISMATCH = "link_text_mismatch"
    IP_ADDRESS_URL = "ip_address_url"
    URL_SHORTENER = "url_shortener"
    OBFUSCATED_URL = "obfuscated_url"
    CREDENTIAL_LOGIN_PATH = "credential_login_path"

    # Attachments
    ATTACHMENT_HASH = "attachment_hash"
    FILE_TYPE_MISMATCH = "file_type_mismatch"
    DOUBLE_EXTENSION = "double_extension"
    RISKY_ATTACHMENT = "risky_attachment"

    # Language
    URGENCY_LANGUAGE = "urgency_language"
    PAYMENT_REQUEST = "payment_request"
    CREDENTIAL_REQUEST = "credential_request"
    GIFT_CARD_REQUEST = "gift_card_request"

    # Content aimed at automated analysis
    PROMPT_INJECTION = "prompt_injection"
    HIDDEN_TEXT = "hidden_text"

    # Threat intelligence
    THREAT_INTEL_MATCH = "threat_intel_match"


class Indicator(FrozenModel):
    """A single finding, with the evidence an analyst needs to verify it.

    Indicators are immutable. Later stages (threat intelligence, the language
    model, scoring) can add context around them but never edit or drop one.
    """

    type: IndicatorType
    value: str = Field(
        min_length=1,
        description="The observed artifact: a domain, URL, header value, hash and so on.",
    )
    severity: Severity
    evidence: str = Field(
        min_length=1,
        description="Why this was flagged, phrased so an analyst can check it.",
    )
    source: IndicatorSource

    @model_validator(mode="before")
    @classmethod
    def _accept_serialized_id(cls, data: Any) -> Any:
        # Serialized reports include the computed id. It is derived from the
        # other fields, so drop it when loading a report back in.
        if isinstance(data, dict) and "id" in data:
            return {key: item for key, item in data.items() if key != "id"}
        return data

    @field_validator("value", mode="before")
    @classmethod
    def _truncate_value(cls, value: Any) -> Any:
        # Attackers control these values; cap them rather than failing the analysis.
        if isinstance(value, str) and len(value) > MAX_VALUE_LENGTH:
            keep = MAX_VALUE_LENGTH - len(_TRUNCATION_MARK)
            return value[:keep] + _TRUNCATION_MARK
        return value

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        """Short, stable identifier derived from source, type and value."""
        key = f"{self.source.value}|{self.type.value}|{self.value}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
