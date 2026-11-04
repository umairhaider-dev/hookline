"""Common base class for Hookline's data models."""

from pydantic import BaseModel, ConfigDict


class FrozenModel(BaseModel):
    """An immutable model that rejects unknown fields.

    Analysis results are built once and then only read. Making them immutable
    means no later stage can quietly rewrite evidence produced by an earlier one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
