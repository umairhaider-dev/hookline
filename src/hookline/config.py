"""Runtime configuration.

Settings are read from these sources, highest precedence first:

1. Environment variables prefixed with ``HOOKLINE_``. Nested sections use a
   double underscore, for example ``HOOKLINE_LLM__OLLAMA_MODEL``.
2. A ``.env`` file in the working directory.
3. A TOML config file: the path given with ``--config``, the path in
   ``HOOKLINE_CONFIG``, or ``hookline.toml`` in the working directory.
4. Built-in defaults.

API keys are only accepted from the environment or ``.env``. They are held as
``SecretStr`` so they never appear in logs or in ``hookline config`` output.
"""

import logging
import os
import tomllib
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeFloat,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from hookline.errors import ConfigError
from hookline.models.indicator import Severity

logger = logging.getLogger(__name__)

CONFIG_ENV_VAR = "HOOKLINE_CONFIG"
DEFAULT_CONFIG_FILENAME = "hookline.toml"

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]

# Commonly impersonated brands. Replace or extend these with your own
# organisation's domains in the config file.
DEFAULT_PROTECTED_DOMAINS = (
    "microsoft.com",
    "office.com",
    "outlook.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "docusign.com",
    "dropbox.com",
    "linkedin.com",
)

# TLDs that show up disproportionately in phishing and abuse reports.
DEFAULT_SUSPICIOUS_TLDS = (
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "link",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
    "work",
    "rest",
    "cam",
    "icu",
    "sbs",
    "cfd",
    "quest",
)

DEFAULT_URL_SHORTENERS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
    "t.ly",
    "s.id",
)

# Free webmail providers. A business sender replying through one of these is a
# classic sign of business email compromise.
DEFAULT_FREEMAIL_DOMAINS = (
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "gmx.net",
    "mail.com",
    "yandex.com",
    "zoho.com",
)

DEFAULT_SEVERITY_POINTS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 5.0,
    Severity.MEDIUM: 15.0,
    Severity.HIGH: 30.0,
    Severity.CRITICAL: 50.0,
}

# Fields that hold credentials and must never be read from the config file.
_SECRET_FIELDS = frozenset({"anthropic_api_key"})


class LogFormat(StrEnum):
    """How log records are written to stderr."""

    TEXT = "text"
    JSON = "json"


class LLMProvider(StrEnum):
    """Language model backends."""

    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"


class RedactionMode(StrEnum):
    """When to redact personal data before sending email content to a model."""

    AUTO = "auto"  # only for cloud providers
    ALWAYS = "always"
    NEVER = "never"


class _Section(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class LLMSettings(_Section):
    """Language model provider settings."""

    provider: LLMProvider = LLMProvider.OLLAMA
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = Field(default="llama3.1:8b", min_length=1)
    anthropic_model: str = Field(default="claude-opus-5-5", min_length=1)
    timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    max_retries: int = Field(default=2, ge=0, le=5)
    max_email_chars: int = Field(default=12_000, ge=500, le=200_000)
    redaction: RedactionMode = RedactionMode.AUTO

    @field_validator("ollama_url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("must start with http:// or https://")
        return value.rstrip("/")


class CheckSettings(_Section):
    """Lists the deterministic checks compare against."""

    protected_domains: tuple[str, ...] = DEFAULT_PROTECTED_DOMAINS
    suspicious_tlds: tuple[str, ...] = DEFAULT_SUSPICIOUS_TLDS
    url_shorteners: tuple[str, ...] = DEFAULT_URL_SHORTENERS
    freemail_domains: tuple[str, ...] = DEFAULT_FREEMAIL_DOMAINS
    trusted_authserv_ids: tuple[str, ...] = Field(
        default=(),
        description=(
            "Mail servers whose Authentication-Results headers are trusted. When empty, "
            "the topmost header for each method is used."
        ),
    )

    @field_validator(
        "protected_domains",
        "suspicious_tlds",
        "url_shorteners",
        "freemail_domains",
        "trusted_authserv_ids",
    )
    @classmethod
    def _normalize_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = (value.strip().strip(".").lower() for value in values)
        return tuple(dict.fromkeys(value for value in cleaned if value))


class ScoringSettings(_Section):
    """Points per severity and the thresholds that turn a score into a verdict."""

    severity_points: dict[Severity, NonNegativeFloat] = Field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_POINTS)
    )
    suspicious_threshold: float = Field(default=35.0, gt=0, lt=100)
    malicious_threshold: float = Field(default=70.0, gt=0, le=100)

    @field_validator("severity_points")
    @classmethod
    def _fill_missing_severities(cls, value: dict[Severity, float]) -> dict[Severity, float]:
        # Lets a config file override a single level without restating the rest.
        return {**DEFAULT_SEVERITY_POINTS, **value}

    @model_validator(mode="after")
    def _thresholds_in_order(self) -> Self:
        if self.suspicious_threshold >= self.malicious_threshold:
            raise ValueError("suspicious_threshold must be lower than malicious_threshold")
        return self


class Settings(BaseSettings):
    """All runtime settings. Build instances with :func:`load_settings`."""

    model_config = SettingsConfigDict(
        env_prefix="HOOKLINE_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        # .env files often hold variables for other tools. Unknown keys in the
        # TOML file are caught separately in _read_config_file.
        extra="ignore",
        populate_by_name=True,
        frozen=True,
    )

    log_level: LogLevel = "WARNING"
    log_format: LogFormat = LogFormat.TEXT
    max_email_bytes: int = Field(default=25 * 1024 * 1024, gt=0)
    ai_enabled: bool = True
    llm: LLMSettings = Field(default_factory=LLMSettings)
    checks: CheckSettings = Field(default_factory=CheckSettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)

    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("HOOKLINE_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper_log_level(cls, value: Any) -> Any:
        return value.strip().upper() if isinstance(value, str) else value

    @classmethod
    def settings_customise_sources(
        cls,
        # pydantic-settings passes these by keyword, so the names are fixed.
        settings_cls: type[BaseSettings],  # noqa: ARG003
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,  # noqa: ARG003
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Rank the environment above init arguments.

        load_settings passes the TOML file's values as init arguments, so this
        ordering is what lets environment variables override the config file.
        """
        return env_settings, dotenv_settings, init_settings


def load_settings(config_file: Path | None = None) -> Settings:
    """Load settings from the environment, ``.env`` and an optional TOML file.

    Args:
        config_file: Explicit TOML file. When omitted, ``HOOKLINE_CONFIG`` or
            ``./hookline.toml`` is used if present.

    Raises:
        ConfigError: If the file is missing, unreadable or contains invalid values.
    """
    path = _resolve_config_file(config_file)
    file_values = _read_config_file(path) if path is not None else {}
    try:
        settings = Settings(**file_values)
    except ValidationError as exc:
        where = f" (config file: {path})" if path is not None else ""
        raise ConfigError(f"Invalid configuration{where}:\n{exc}") from exc
    logger.debug("Settings loaded; config file: %s", path or "none")
    return settings


def _resolve_config_file(explicit: Path | None) -> Path | None:
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"Config file not found: {explicit}")
        return explicit
    from_env = os.environ.get(CONFIG_ENV_VAR)
    if from_env:
        path = Path(from_env)
        if not path.is_file():
            raise ConfigError(f"Config file named in {CONFIG_ENV_VAR} not found: {path}")
        return path
    default = Path(DEFAULT_CONFIG_FILENAME)
    return default if default.is_file() else None


def _read_config_file(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Could not parse {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not read {path}: {exc}") from exc

    secrets = sorted(set(data) & _SECRET_FIELDS)
    if secrets:
        raise ConfigError(
            f"{path} contains {', '.join(secrets)}. API keys must be set through "
            "environment variables or .env, never the config file."
        )
    unknown = sorted(set(data) - set(Settings.model_fields))
    if unknown:
        raise ConfigError(f"Unknown setting(s) in {path}: {', '.join(unknown)}")
    return data
