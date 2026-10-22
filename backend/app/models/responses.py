"""Response models for PrivAI."""

from pydantic import BaseModel, ConfigDict, Field
from backend.app.models.enums import ExecutionStatus, PolicyOutcome
from backend.app.models.findings import Finding, RedactionSummary
from backend.app.models.risk import RiskScore


class HealthResponse(BaseModel):
    """Health check response.

    Security Invariant: Never exposes internal paths, credentials,
    or environment dumps.
    """

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="ok", description="Service status")
    provider_mode: str = Field(..., description="Active provider mode, e.g. 'mock'")
    policy_loaded: bool = Field(..., description="Whether policy rules are loaded and active")


class SafeErrorDetail(BaseModel):
    """Structured, sanitized error detail."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Safe user-facing error message")
    request_id: str = Field(..., description="Opaque request tracking ID")


class SafeErrorResponse(BaseModel):
    """Standardized error envelope.

    Security Invariant: Never includes raw prompts, matched values,
    credentials, internal tracebacks, or provider headers.
    """

    model_config = ConfigDict(extra="forbid")

    error: SafeErrorDetail


class Explanation(BaseModel):
    """Safe explanation of policy decision and recommended actions."""

    model_config = ConfigDict(extra="forbid")

    rule_ids: list[str] = Field(default_factory=list, description="IDs of matching policy rules")
    summary: str = Field(..., description="Non-leaking explanation of decision")
    actions: list[str] = Field(default_factory=list, description="Recommended user actions")


class ProviderInfo(BaseModel):
    """Information regarding the provider invoked."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Provider name")
    model: str = Field(..., description="Provider model identifier")


class PromptAnalyzeResponse(BaseModel):
    """Response model for POST /v1/prompts/analyze."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(..., description="Opaque analysis identifier")
    request_digest: str = Field(..., description="SHA-256 digest of canonical request")
    decision: PolicyOutcome = Field(..., description="Authoritative policy outcome")
    risk: RiskScore = Field(..., description="Risk score and explanation factors")
    findings: list[Finding] = Field(default_factory=list, description="Sanitized findings list")
    explanation: Explanation = Field(..., description="Human-readable decision explanation")
    policy_version: str = Field(..., description="Version of the evaluated policy")
    sanitized_prompt: str | None = Field(
        default=None, description="Preview of sanitized prompt when action is REDACT"
    )
    redactions: list[RedactionSummary] | None = Field(
        default=None, description="Summary of applied redactions if REDACT"
    )


class PromptExecuteResponse(BaseModel):
    """Response model for POST /v1/prompts/execute."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Opaque request identifier")
    status: ExecutionStatus = Field(..., description="Execution status")
    decision: PolicyOutcome = Field(..., description="Authoritative policy outcome")
    risk: RiskScore = Field(..., description="Risk score and explanation factors")
    redactions: list[RedactionSummary] | None = Field(
        default=None, description="Summary of applied redactions if REDACT"
    )
    provider: ProviderInfo | None = Field(
        default=None, description="Provider information (omitted if BLOCK/REVIEW)"
    )
    output: str | None = Field(
        default=None, description="Provider output (omitted if BLOCK/REVIEW)"
    )
    explanation: Explanation = Field(..., description="Human-readable decision explanation")
    policy_version: str = Field(..., description="Version of evaluated policy")
    ticket_id: str | None = Field(
        default=None, description="Identifier of created review ticket when status is review_pending"
    )
