"""Data models for Enterprise Human-Review Workflow."""

import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ReviewStatus(str, Enum):
    """Lifecycle status of a human review ticket."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ReviewRole(str, Enum):
    """Designated reviewer role."""

    COMPLIANCE_OFFICER = "compliance_officer"
    HR_ADMIN = "hr_admin"
    SECURITY_ADMIN = "security_admin"


class ReviewTicket(BaseModel):
    """Durable human-review ticket record.

    Security Invariant:
    Strictly omits raw prompt text, API credentials, or sensitive findings from header data.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    ticket_id: str = Field(..., description="Unique UUIDv4 primary identifier")
    request_digest: str = Field(
        ..., description="SHA-256 digest of canonical representation of prompt & context"
    )
    submitted_at: str = Field(..., description="UTC ISO 8601 submission timestamp")
    expires_at: str = Field(
        ..., description="Submission time plus exactly 24 hours (UTC ISO 8601)"
    )
    status: ReviewStatus = Field(..., description="Ticket status")
    assigned_role: str = Field(
        ..., description="Required reviewer role: compliance_officer, hr_admin, etc."
    )
    risk_score: int = Field(..., ge=0, le=100, description="Evaluated prompt risk score")
    triggered_rule_ids: list[str] = Field(
        default_factory=list, description="Detected rule identifiers and category metadata"
    )
    decision_rationale: str | None = Field(
        default=None, description="Reviewer justification upon approval or rejection"
    )
    decided_by: str | None = Field(
        default=None, description="Authenticated reviewer user identifier"
    )
    decided_at: str | None = Field(
        default=None, description="UTC ISO 8601 decision timestamp"
    )


class ReviewPermit(BaseModel):
    """Cryptographically signed single-use review permit authorizing provider dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(default="v1", description="Permit schema version")
    ticket_id: str = Field(..., description="Associated approved ticket identifier")
    permit_nonce: str = Field(..., description="Cryptographically secure single-use random token")
    request_digest: str = Field(
        ..., description="Cryptographic SHA-256 digest of canonical request"
    )
    issued_at: str = Field(..., description="UTC ISO 8601 issuance timestamp")
    expires_at: str = Field(..., description="Permit expiration timestamp (strict 5 min TTL)")
    approved_by: str = Field(..., description="Authenticated reviewer identity")
    assigned_role: str = Field(..., description="Reviewer role that granted approval")
    signature: str = Field(..., description="HMAC-SHA256 signature binding all permit fields")
    key_id: str | None = Field(default=None, description="Identifier of HMAC signing key in KMS")


class ReviewApprovalRequest(BaseModel):
    """Payload for POST /v1/reviews/{id}/approve."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rationale: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Non-leaking business/security justification for granting approval",
    )

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < 10:
            raise ValueError("Rationale must be at least 10 non-whitespace characters.")
        return stripped


class ReviewRejectionRequest(BaseModel):
    """Payload for POST /v1/reviews/{id}/reject."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rationale: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Reason for rejecting the prompt execution",
    )

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < 5:
            raise ValueError("Rationale must be at least 5 non-whitespace characters.")
        return stripped


class ReviewActionResponse(BaseModel):
    """Response returned upon approving or rejecting a review ticket."""

    model_config = ConfigDict(extra="forbid")

    ticket_id: str = Field(..., description="Review ticket identifier")
    status: ReviewStatus = Field(..., description="Updated ticket status")
    decided_by: str = Field(..., description="Authenticated reviewer identity")
    decided_at: str = Field(..., description="Decision timestamp")
    permit: ReviewPermit | None = Field(
        default=None, description="Cryptographic single-use permit (only present on approval)"
    )


class ReviewPendingListResponse(BaseModel):
    """Response returned by GET /v1/reviews/pending."""

    model_config = ConfigDict(extra="forbid")

    tickets: list[ReviewTicket] = Field(default_factory=list, description="Pending unexpired tickets")
    total_count: int = Field(..., ge=0, description="Total accessible pending tickets count")
