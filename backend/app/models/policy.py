"""Policy decision and evaluation models for PrivAI."""

from pydantic import BaseModel, ConfigDict, Field
from backend.app.models.enums import FindingCategory, PolicyOutcome
from backend.app.models.findings import RedactionSummary
from backend.app.models.responses import Explanation
from backend.app.models.risk import RiskScore


class PolicyDecision(BaseModel):
    """Deterministic, structured policy decision.

    Security Invariant:
    Strictly omits raw prompt text, matched sensitive substrings, or credentials.
    Explanations and finding_categories only contain non-leaking category labels.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: PolicyOutcome = Field(
        ..., description="Authoritative policy action: ALLOW, REDACT, REVIEW, or BLOCK"
    )
    risk_score: RiskScore = Field(..., description="Explainable deterministic risk score")
    reason_codes: list[str] = Field(
        default_factory=list, description="Identifiers of matching policy rules or reason codes"
    )
    explanation: Explanation = Field(
        ..., description="Human-readable decision explanation and recommended actions"
    )
    finding_categories: list[FindingCategory] = Field(
        default_factory=list,
        description="Categories of detected sensitive findings (strictly no sensitive values)",
    )
    requires_redaction: bool = Field(
        default=False, description="Whether prompt content requires sanitization"
    )
    requires_review: bool = Field(
        default=False, description="Whether human review is required before transmission"
    )
    policy_version: str = Field(default="policy-v1", description="Policy ruleset version")
    sanitized_prompt: str | None = Field(
        default=None, description="Sanitized prompt text if redaction succeeded"
    )
    redactions: list[RedactionSummary] | None = Field(
        default=None, description="Summary of applied redactions"
    )

    @property
    def outcome(self) -> PolicyOutcome:
        """Alias for action to match logical schema."""
        return self.action
