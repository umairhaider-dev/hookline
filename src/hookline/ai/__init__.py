"""The language model layer: prompt building, redaction, providers and validation.

The model explains and assesses; it never decides alone. Its answer is
validated, and scoring only lets it add to the deterministic score.
"""

from dataclasses import dataclass

from hookline.ai.anthropic_api import AnthropicProvider
from hookline.ai.assessor import Assessor, parse_assessment, should_redact
from hookline.ai.base import (
    ChatModel,
    ModelError,
    ModelRefusalError,
    ModelRequest,
    ModelUnavailableError,
    Turn,
)
from hookline.ai.ollama import OllamaProvider
from hookline.config import LLMProvider, Settings
from hookline.models.ai import AIStatus


@dataclass(frozen=True)
class AssessorSetup:
    """The assessor to use, or why there is none."""

    assessor: Assessor | None
    status: AIStatus = AIStatus.COMPLETED
    reason: str | None = None


def build_assessor(settings: Settings) -> AssessorSetup:
    """Create the assessor for the configured provider."""
    if not settings.ai_enabled:
        return AssessorSetup(None, AIStatus.DISABLED, "AI assessment is turned off.")
    llm = settings.llm
    model: ChatModel
    if llm.provider is LLMProvider.ANTHROPIC:
        if settings.anthropic_api_key is None:
            return AssessorSetup(
                None,
                AIStatus.UNAVAILABLE,
                "ANTHROPIC_API_KEY is not set for the Anthropic provider",
            )
        try:
            model = AnthropicProvider(
                settings.anthropic_api_key.get_secret_value(),
                model=llm.anthropic_model,
                effort=llm.anthropic_effort,
                max_output_tokens=llm.max_output_tokens,
                timeout=llm.timeout_seconds,
                max_retries=llm.max_retries,
            )
        except ModelError as exc:
            return AssessorSetup(None, AIStatus.UNAVAILABLE, str(exc))
    else:
        model = OllamaProvider(
            url=llm.ollama_url,
            model=llm.ollama_model,
            timeout=llm.timeout_seconds,
            max_retries=llm.max_retries,
            num_ctx=llm.ollama_num_ctx,
            max_output_tokens=llm.max_output_tokens,
        )
    return AssessorSetup(Assessor(model, llm))


__all__ = [
    "AnthropicProvider",
    "Assessor",
    "AssessorSetup",
    "ChatModel",
    "ModelError",
    "ModelRefusalError",
    "ModelRequest",
    "ModelUnavailableError",
    "OllamaProvider",
    "Turn",
    "build_assessor",
    "parse_assessment",
    "should_redact",
]
