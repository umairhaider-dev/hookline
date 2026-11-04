from pathlib import Path

import pytest

from hookline.config import (
    CONFIG_ENV_VAR,
    DEFAULT_CONFIG_FILENAME,
    LLMProvider,
    LogFormat,
    RedactionMode,
    load_settings,
)
from hookline.errors import ConfigError
from hookline.models import Severity
from tests.factories import PROJECT_ROOT


def write_toml(directory: Path, content: str, name: str = "custom.toml") -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


def test_defaults_when_nothing_is_configured() -> None:
    settings = load_settings()
    assert settings.log_level == "WARNING"
    assert settings.log_format is LogFormat.TEXT
    assert settings.ai_enabled
    assert settings.llm.provider is LLMProvider.OLLAMA
    assert settings.llm.redaction is RedactionMode.AUTO
    assert settings.anthropic_api_key is None
    assert "paypal.com" in settings.checks.protected_domains
    assert settings.scoring.severity_points[Severity.HIGH] == 30


def test_environment_variables_override_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOOKLINE_LOG_LEVEL", "debug")
    monkeypatch.setenv("HOOKLINE_AI_ENABLED", "false")
    monkeypatch.setenv("HOOKLINE_LLM__OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.setenv("HOOKLINE_CHECKS__PROTECTED_DOMAINS", '["Larkspur.test."]')
    settings = load_settings()
    assert settings.log_level == "DEBUG"
    assert not settings.ai_enabled
    assert settings.llm.ollama_model == "qwen2.5:7b"
    assert settings.checks.protected_domains == ("larkspur.test",)


def test_config_file_values_are_loaded(tmp_path: Path) -> None:
    path = write_toml(
        tmp_path,
        """
        log_format = "json"
        [llm]
        provider = "anthropic"
        timeout_seconds = 15
        [scoring]
        suspicious_threshold = 40
        """,
    )
    settings = load_settings(path)
    assert settings.log_format is LogFormat.JSON
    assert settings.llm.provider is LLMProvider.ANTHROPIC
    assert settings.llm.timeout_seconds == 15
    assert settings.scoring.suspicious_threshold == 40


def test_environment_beats_config_file_and_sections_merge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_toml(
        tmp_path,
        """
        log_level = "ERROR"
        [llm]
        ollama_model = "from-file"
        timeout_seconds = 15
        """,
    )
    monkeypatch.setenv("HOOKLINE_LOG_LEVEL", "INFO")
    monkeypatch.setenv("HOOKLINE_LLM__OLLAMA_MODEL", "from-env")
    settings = load_settings(path)
    assert settings.log_level == "INFO"
    assert settings.llm.ollama_model == "from-env"
    assert settings.llm.timeout_seconds == 15


def test_config_file_in_working_directory_is_picked_up(tmp_path: Path) -> None:
    write_toml(tmp_path, 'log_level = "ERROR"\n', name=DEFAULT_CONFIG_FILENAME)
    assert load_settings().log_level == "ERROR"


def test_config_path_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_toml(tmp_path, 'log_level = "ERROR"\n', name="elsewhere.toml")
    monkeypatch.setenv(CONFIG_ENV_VAR, str(path))
    assert load_settings().log_level == "ERROR"


def test_missing_config_path_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(CONFIG_ENV_VAR, "nope.toml")
    with pytest.raises(ConfigError, match=CONFIG_ENV_VAR):
        load_settings()


def test_missing_explicit_config_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "missing.toml")


def test_unreadable_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_toml(tmp_path, 'log_level = "ERROR"\n')

    def deny(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("access denied")

    monkeypatch.setattr(Path, "open", deny)
    with pytest.raises(ConfigError, match="Could not read"):
        load_settings(path)


def test_invalid_toml(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Could not parse"):
        load_settings(write_toml(tmp_path, "log_level = \n"))


def test_unknown_top_level_key(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"Unknown setting.*log_levl"):
        load_settings(write_toml(tmp_path, 'log_levl = "DEBUG"\n'))


def test_unknown_nested_key(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="ollama_modle"):
        load_settings(write_toml(tmp_path, '[llm]\nollama_modle = "x"\n'))


@pytest.mark.parametrize(
    "content",
    [
        "[scoring]\nsuspicious_threshold = 80\nmalicious_threshold = 70\n",
        "[scoring.severity_points]\nhigh = -5\n",
        '[llm]\nollama_url = "localhost:11434"\n',
        "[llm]\ntimeout_seconds = 0\n",
        'log_level = "LOUD"\n',
    ],
)
def test_invalid_values_are_reported(tmp_path: Path, content: str) -> None:
    with pytest.raises(ConfigError, match="Invalid configuration"):
        load_settings(write_toml(tmp_path, content))


def test_api_keys_are_refused_in_config_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="environment variables"):
        load_settings(write_toml(tmp_path, 'anthropic_api_key = "sk-test"\n'))


@pytest.mark.parametrize("variable", ["ANTHROPIC_API_KEY", "HOOKLINE_ANTHROPIC_API_KEY"])
def test_api_key_from_environment(monkeypatch: pytest.MonkeyPatch, variable: str) -> None:
    monkeypatch.setenv(variable, "sk-test-123")
    key = load_settings().anthropic_api_key
    assert key is not None
    assert key.get_secret_value() == "sk-test-123"


def test_api_key_from_dotenv_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "ANTHROPIC_API_KEY=sk-from-dotenv\nUNRELATED_TOOL_SETTING=1\n", encoding="utf-8"
    )
    key = load_settings().anthropic_api_key
    assert key is not None
    assert key.get_secret_value() == "sk-from-dotenv"


def test_empty_api_key_counts_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    assert load_settings().anthropic_api_key is None


def test_secrets_are_masked_when_dumped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-123")
    settings = load_settings()
    dumped = settings.model_dump(mode="json")
    assert dumped["anthropic_api_key"] == "**********"
    assert "sk-test-123" not in repr(settings)


def test_severity_points_can_be_partially_overridden(tmp_path: Path) -> None:
    settings = load_settings(write_toml(tmp_path, "[scoring.severity_points]\nhigh = 40\n"))
    assert settings.scoring.severity_points[Severity.HIGH] == 40
    assert settings.scoring.severity_points[Severity.CRITICAL] == 50


def test_domain_lists_are_normalized_and_deduplicated(tmp_path: Path) -> None:
    path = write_toml(
        tmp_path,
        "[checks]\n"
        'protected_domains = ["Larkspur.TEST", " larkspur.test. ", "", "fernhill.test"]\n',
    )
    assert load_settings(path).checks.protected_domains == ("larkspur.test", "fernhill.test")


def test_ollama_url_trailing_slash_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOOKLINE_LLM__OLLAMA_URL", "http://gpu-box.test:11434/")
    assert load_settings().llm.ollama_url == "http://gpu-box.test:11434"


def test_example_config_file_is_valid() -> None:
    settings = load_settings(PROJECT_ROOT / "hookline.example.toml")
    assert "larkspur.test" in settings.checks.protected_domains
