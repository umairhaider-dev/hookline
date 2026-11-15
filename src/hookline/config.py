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
from hookline.models.indicator import IndicatorType, Severity

logger = logging.getLogger(__name__)

CONFIG_ENV_VAR = "HOOKLINE_CONFIG"
DEFAULT_CONFIG_FILENAME = "hookline.toml"

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
Effort = Literal["low", "medium", "high"]

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
_SECRET_FIELDS = frozenset(
    {
        "anthropic_api_key",
        "virustotal_api_key",
        "abuseipdb_api_key",
        "urlhaus_auth_key",
        "web_token",
        "watchpost_token",
        "watchpost_username",
        "watchpost_password",
    }
)


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
    anthropic_effort: Effort = Field(
        default="medium", description="How much the model reasons before answering."
    )
    timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    max_retries: int = Field(default=2, ge=0, le=5)
    max_email_chars: int = Field(
        default=12_000,
        ge=500,
        le=200_000,
        description="Email text sent to the model is cut to this many characters.",
    )
    max_output_tokens: int = Field(
        default=16_000,
        ge=512,
        le=64_000,
        description="Upper bound on the model's answer, including any reasoning it does.",
    )
    ollama_num_ctx: int = Field(
        default=8192,
        ge=2048,
        le=262_144,
        description="Context window to request from Ollama, so long prompts are not cut.",
    )
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
    type_points: dict[IndicatorType, NonNegativeFloat] = Field(
        default_factory=dict,
        description="Points for specific indicator types, overriding their severity's points.",
    )
    suspicious_threshold: float = Field(default=35.0, gt=0, lt=100)
    malicious_threshold: float = Field(default=70.0, gt=0, le=100)
    ai_max_points: float = Field(
        default=40.0,
        ge=0,
        le=100,
        description=(
            "Most points the AI assessment can add. It adds nothing at a likelihood of 50 or "
            "below and can never subtract."
        ),
    )

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


class ProviderLimits(_Section):
    """Request budget for one threat intelligence provider.

    The defaults match the providers' free tiers. Raise them for paid plans.
    """

    requests_per_minute: int = Field(default=60, gt=0)
    requests_per_day: int | None = Field(default=None, gt=0)


class AbuseIPDBLimits(ProviderLimits):
    """AbuseIPDB's free tier allows 1,000 checks a day."""

    requests_per_day: int | None = Field(default=1000, gt=0)


class VirusTotalLimits(ProviderLimits):
    """VirusTotal's public API allows 4 requests a minute and 500 a day."""

    requests_per_minute: int = Field(default=4, gt=0)
    requests_per_day: int | None = Field(default=500, gt=0)


class ThreatIntelSettings(_Section):
    """Optional lookups with URLhaus, AbuseIPDB and VirusTotal.

    A provider is only used when its API key is set in the environment, so with
    no keys Hookline makes no network requests at all.
    """

    enabled: bool = True
    timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    cache_dir: Path = Path(".hookline-cache")
    cache_ttl_hours: float = Field(
        default=24.0, ge=0, description="How long answers are reused. 0 turns the cache off."
    )
    max_lookups_per_provider: int = Field(default=10, ge=1, le=200)
    max_wait_seconds: float = Field(
        default=15.0,
        ge=0,
        le=300,
        description="Longest wait for a rate-limit slot before a lookup is skipped.",
    )
    lookup_urls: bool = True
    lookup_domains: bool = True
    lookup_ips: bool = True
    lookup_hashes: bool = True
    urlhaus: ProviderLimits = Field(default_factory=ProviderLimits)
    abuseipdb: AbuseIPDBLimits = Field(default_factory=AbuseIPDBLimits)
    virustotal: VirusTotalLimits = Field(default_factory=VirusTotalLimits)


class WatchpostSettings(_Section):
    """Where and how ``hookline push`` sends analysed emails to Watchpost.

    Credentials come only from the environment: ``WATCHPOST_TOKEN``, or
    ``WATCHPOST_USERNAME`` and ``WATCHPOST_PASSWORD``.
    """

    url: str | None = Field(
        default=None, description="Watchpost base URL; --url and WATCHPOST_URL take precedence."
    )
    verify_tls: bool = True
    ca_bundle: Path | None = Field(default=None, description="Extra CA bundle for a private CA.")
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_retries: int = Field(default=2, ge=0, le=5)
    min_verdict: Literal["likely_safe", "suspicious", "malicious"] = Field(
        default="suspicious", description="Only emails with at least this verdict are pushed."
    )
    host_name: str = Field(
        default="hookline",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$",
        description="Host name Watchpost records for the pushed events.",
    )

    @field_validator("url")
    @classmethod
    def _http_url(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith(("http://", "https://")):
            raise ValueError("must start with http:// or https://")
        return value.rstrip("/") if value else value


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
    threat_intel: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    watchpost: WatchpostSettings = Field(default_factory=WatchpostSettings)

    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("HOOKLINE_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )
    virustotal_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("HOOKLINE_VIRUSTOTAL_API_KEY", "VIRUSTOTAL_API_KEY"),
    )
    abuseipdb_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("HOOKLINE_ABUSEIPDB_API_KEY", "ABUSEIPDB_API_KEY"),
    )
    urlhaus_auth_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("HOOKLINE_URLHAUS_AUTH_KEY", "URLHAUS_AUTH_KEY"),
    )
    web_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("HOOKLINE_WEB_TOKEN"),
        description="Bearer token the web interface requires for uploads, if set.",
    )
    watchpost_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("HOOKLINE_WATCHPOST_URL", "WATCHPOST_URL"),
        description="Watchpost base URL from the environment or .env; overrides [watchpost] url.",
    )
    watchpost_token: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("HOOKLINE_WATCHPOST_TOKEN", "WATCHPOST_TOKEN")
    )
    watchpost_username: str | None = Field(
        default=None,
        validation_alias=AliasChoices("HOOKLINE_WATCHPOST_USERNAME", "WATCHPOST_USERNAME"),
    )
    watchpost_password: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("HOOKLINE_WATCHPOST_PASSWORD", "WATCHPOST_PASSWORD"),
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
