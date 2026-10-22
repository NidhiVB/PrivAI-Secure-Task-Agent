"""Context model representing metadata submitted with a prompt."""

from pydantic import BaseModel, ConfigDict
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
)


class ContextModel(BaseModel):
    """Context metadata submitted with prompt.

    Strict validation: extra fields are forbidden.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    purpose: ContextPurpose
    data_subject: ContextDataSubject
    classification: ContextClassification
