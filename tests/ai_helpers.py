"""A scripted language model for tests, so no test needs a real model."""

import json
from collections.abc import Sequence
from typing import Any

from hookline.ai import Assessor, ModelRequest
from hookline.config import LLMSettings, RedactionMode


def answer(**overrides: Any) -> str:
    """A valid assessment as the model would send it."""
    fields: dict[str, Any] = {
        "phishing_likelihood": 90,
        "attack_type": "credential_phishing",
        "tactics": ["urgency", "brand impersonation"],
        "explanation": "The link text and destination differ and the sender fails DMARC.",
        "recommended_actions": ["Block the sender domain", "Reset affected passwords"],
    }
    fields.update(overrides)
    return json.dumps(fields)


class FakeModel:
    """Replies with scripted text or raises scripted errors, in order."""

    def __init__(
        self,
        replies: Sequence[str | Exception] = (),
        *,
        name: str = "fake",
        model: str = "fake-model",
        is_cloud: bool = False,
    ) -> None:
        self.name = name
        self.model = model
        self.is_cloud = is_cloud
        self._replies = list(replies) or [answer()]
        self.requests: list[ModelRequest] = []
        self.closed = False

    def complete(self, request: ModelRequest) -> str:
        self.requests.append(request)
        reply = self._replies[min(len(self.requests), len(self._replies)) - 1]
        if isinstance(reply, Exception):
            raise reply
        return reply

    def close(self) -> None:
        self.closed = True


def make_assessor(
    model: FakeModel | None = None, *, redaction: RedactionMode = RedactionMode.AUTO, **llm: Any
) -> tuple[Assessor, FakeModel]:
    model = model or FakeModel()
    settings = LLMSettings.model_validate({"redaction": redaction, **llm})
    return Assessor(model, settings, nonce=lambda: "n0nce"), model
