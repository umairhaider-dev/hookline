"""The interface language model providers implement, and their errors."""

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

Role = Literal["user", "assistant"]


class ModelError(Exception):
    """The model could not produce an answer, and retrying will not help."""


class ModelUnavailableError(ModelError):
    """The model could not be reached or did not answer in time."""


class ModelRefusalError(ModelError):
    """The model declined to answer."""


@dataclass(frozen=True)
class Turn:
    """One message in the conversation sent to the model."""

    role: Role
    text: str


@dataclass(frozen=True)
class ModelRequest:
    """Everything a provider needs for one call."""

    system: str
    turns: tuple[Turn, ...]
    schema: dict[str, Any] = field(default_factory=dict)


class ChatModel(Protocol):
    """A language model that answers one request with text.

    ``is_cloud`` decides whether personal data is redacted by default.
    """

    name: str
    model: str
    is_cloud: bool

    def complete(self, request: ModelRequest) -> str:
        """Return the model's reply text.

        Raises:
            ModelUnavailableError: If the model could not be reached in time.
            ModelRefusalError: If the model declined to answer.
            ModelError: For any other failure that retrying will not fix.
        """
        ...

    def close(self) -> None:
        """Release network resources."""
        ...
