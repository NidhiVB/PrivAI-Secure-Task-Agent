"""Internal provider permit model."""

from pydantic import BaseModel, ConfigDict, Field
from backend.app.models.enums import Destination, PolicyOutcome


class ProviderPermit(BaseModel):
    """Server-generated internal authorization token for AI provider execution.

    Security Invariants:
    1. Only the central orchestration service may mint a permit.
    2. Binds exact request digest, authoritative policy outcome, policy version,
       destination, and redaction verification status.
    3. Permitted outcomes are strictly limited to ALLOW and verified REDACT.
    4. Permits are single-use and non-reusable across requests.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    permit_id: str = Field(..., description="Opaque unique permit identifier")
    request_digest: str = Field(..., description="Cryptographic SHA-256 digest of canonical request")
    outcome: PolicyOutcome = Field(..., description="Authorized policy outcome (ALLOW or REDACT)")
    policy_version: str = Field(..., description="Policy ruleset version active during evaluation")
    destination: Destination = Field(..., description="Target server-allowlisted AI destination")
    redaction_verified: bool = Field(..., description="Whether post-redaction verification passed")
    authorized_prompt: str = Field(..., description="Exact prompt authorized for transmission")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp of permit issuance")
    review_approved: bool = Field(default=False, description="Whether this permit was authorized via human review approval")
