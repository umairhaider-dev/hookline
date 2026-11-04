import sys

import pytest
from pydantic import SecretStr

from hookline.ai import AnthropicProvider, OllamaProvider, build_assessor
from hookline.config import LLMProvider, LLMSettings, Settings
from hookline.models import AIStatus


def test_disabled() -> None:
    setup = build_assessor(Settings(ai_enabled=False))
    assert setup.assessor is None
    assert setup.status is AIStatus.DISABLED


def test_ollama_is_the_default() -> None:
    setup = build_assessor(Settings())
    assert setup.assessor is not None
    model = setup.assessor.model
    assert isinstance(model, OllamaProvider)
    assert (model.model, model.is_cloud) == ("llama3.1:8b", False)
    setup.assessor.close()


def test_anthropic_needs_a_key() -> None:
    settings = Settings(llm=LLMSettings(provider=LLMProvider.ANTHROPIC))
    setup = build_assessor(settings)
    assert setup.assessor is None
    assert setup.status is AIStatus.UNAVAILABLE
    assert setup.reason is not None
    assert "ANTHROPIC_API_KEY" in setup.reason


def test_anthropic_with_key() -> None:
    settings = Settings(
        llm=LLMSettings(provider=LLMProvider.ANTHROPIC, anthropic_effort="low"),
        anthropic_api_key=SecretStr("sk-ant-test"),
    )
    setup = build_assessor(settings)
    assert setup.assessor is not None
    model = setup.assessor.model
    assert isinstance(model, AnthropicProvider)
    assert (model.model, model.is_cloud) == ("claude-opus-5-5", True)
    setup.assessor.close()


def test_anthropic_without_the_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "anthropic", None)
    settings = Settings(
        llm=LLMSettings(provider=LLMProvider.ANTHROPIC), anthropic_api_key=SecretStr("k")
    )
    setup = build_assessor(settings)
    assert setup.status is AIStatus.UNAVAILABLE
    assert setup.reason is not None
    assert "pip install" in setup.reason
