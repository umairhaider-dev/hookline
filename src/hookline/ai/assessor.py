"""Ask the language model for an assessment and validate what comes back.

The flow for one email: build the prompt (redacting personal data for cloud
providers), call the model, parse and validate the JSON answer. An invalid
answer gets exactly one retry with a correction; a second invalid answer, an
unreachable model or a refusal all fall back to the rules-only verdict, with
the reason recorded in the report.
"""

import json
import logging
import re
import secrets
import time
from collections.abc import Callable

from pydantic import ValidationError

from hookline.ai.base import (
    ChatModel,
    ModelError,
    ModelRequest,
    ModelUnavailableError,
    Turn,
)
from hookline.ai.prompt import CORRECTION, OUTPUT_SCHEMA, build_prompt
from hookline.ai.redaction import NoRedaction, Redactor
from hookline.config import LLMSettings, RedactionMode
from hookline.models.ai import AIAssessment, AIRun, AIStatus
from hookline.models.email import ParsedEmail
from hookline.models.indicator import Indicator

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 2
MAX_REPLY_ECHO = 4000
MAX_ERRORS_SHOWN = 3

_CODE_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I)


class InvalidAnswerError(ValueError):
    """The model's reply was not a valid assessment."""


class Assessor:
    """Runs one model assessment per email."""

    def __init__(
        self,
        model: ChatModel,
        settings: LLMSettings,
        *,
        nonce: Callable[[], str] = lambda: secrets.token_hex(8),
    ) -> None:
        self._model = model
        self._settings = settings
        self._nonce = nonce

    @property
    def model(self) -> ChatModel:
        """The provider this assessor uses."""
        return self._model

    def assess(self, email: ParsedEmail, indicators: tuple[Indicator, ...]) -> AIRun:
        """Return the model's validated assessment, or why there is none."""
        started = time.perf_counter()
        redact = should_redact(self._settings.redaction, cloud=self._model.is_cloud)
        redactor = Redactor(recipient_names(email)) if redact else NoRedaction()
        prompt = build_prompt(
            email,
            indicators,
            max_email_chars=self._settings.max_email_chars,
            redactor=redactor,
            nonce=self._nonce(),
        )
        notes = list(prompt.notes)
        turns = [Turn("user", prompt.user)]
        attempts = 0
        problem = ""

        def run(status: AIStatus, **fields: object) -> AIRun:
            return AIRun.model_validate(
                {
                    "status": status,
                    "provider": self._model.name,
                    "model": self._model.model,
                    "attempts": attempts,
                    "duration_ms": (time.perf_counter() - started) * 1000,
                    "redacted": redact,
                    "notes": tuple(notes),
                    **fields,
                }
            )

        while attempts < MAX_ATTEMPTS:
            attempts += 1
            request = ModelRequest(system=prompt.system, turns=tuple(turns), schema=OUTPUT_SCHEMA)
            try:
                reply = self._model.complete(request)
            # Logged at info level: the reason is recorded in the report itself.
            except ModelUnavailableError as exc:
                logger.info("Language model unavailable: %s", exc)
                return run(AIStatus.UNAVAILABLE, error=str(exc))
            except ModelError as exc:
                logger.info("Language model failed: %s", exc)
                return run(AIStatus.FAILED, error=str(exc))
            try:
                assessment = parse_assessment(reply)
            except InvalidAnswerError as exc:
                problem = str(exc)
                logger.info("Language model answer was invalid: %s", problem)
                notes.append(f"Answer {attempts} was invalid ({problem}).")
                turns += [
                    Turn("assistant", reply[:MAX_REPLY_ECHO] or "(empty)"),
                    Turn("user", CORRECTION.format(problem=problem)),
                ]
                continue
            return run(AIStatus.COMPLETED, assessment=assessment)
        return run(
            AIStatus.INVALID_OUTPUT,
            error=f"no valid answer after {MAX_ATTEMPTS} attempts: {problem}",
        )

    def close(self) -> None:
        """Close the provider."""
        self._model.close()


def should_redact(mode: RedactionMode, *, cloud: bool) -> bool:
    """Whether personal data must be removed before the model sees the email."""
    if mode is RedactionMode.ALWAYS:
        return True
    if mode is RedactionMode.NEVER:
        return False
    return cloud


def parse_assessment(reply: str) -> AIAssessment:
    """Extract and validate the JSON assessment in ``reply``.

    Tolerates a Markdown code fence or text around the object, since local
    models sometimes add them, but nothing else.
    """
    text = _CODE_FENCE.sub("", reply.strip())
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise InvalidAnswerError("it contained no JSON object")
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise InvalidAnswerError(f"it was not valid JSON ({exc.msg})") from exc
    try:
        return AIAssessment.model_validate(data)
    except ValidationError as exc:
        problems = [
            f"{'.'.join(str(part) for part in error['loc']) or 'answer'}: {error['msg']}"
            for error in exc.errors()[:MAX_ERRORS_SHOWN]
        ]
        raise InvalidAnswerError("; ".join(problems)) from exc


def recipient_names(email: ParsedEmail) -> list[str]:
    """Display names and mailbox names of the To and Cc recipients, for redaction."""
    names = []
    for address in (*email.to, *email.cc):
        names.append(address.display_name)
        names.append(address.address.partition("@")[0])
    return names
