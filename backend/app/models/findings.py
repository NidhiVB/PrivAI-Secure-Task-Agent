"""Internal findings and redaction models."""

from pydantic import BaseModel, ConfigDict, Field
from backend.app.models.enums import FindingCategory


class Finding(BaseModel):
    """Detection finding for sensitive spans.

    Security Invariant: Matched raw sensitive values are strictly omitted
    from findings, responses, and log records.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    category: FindingCategory
    start: int = Field(ge=0, description="Start offset (inclusive) in Unicode code-points")
    end: int = Field(ge=0, description="End offset (exclusive) in Unicode code-points")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    severity: float = Field(ge=0.0, le=1.0, description="Severity rating between 0.0 and 1.0")


class RedactionSummary(BaseModel):
    """Safe summary of a redaction applied to a prompt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: FindingCategory
    placeholder: str
