"""Audit event data models."""

from pydantic import BaseModel, ConfigDict, Field
from backend.app.models.enums import PolicyOutcome


class AuditEvent(BaseModel):
    """Privacy-safe operational audit record.

    Security Invariant:
    Strictly omits raw prompt text, sanitized prompt contents, matched sensitive values,
    and API authentication credentials.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(..., description="Opaque audit event identifier")
    timestamp: str = Field(..., description="RFC 3339 UTC timestamp")
    request_digest: str = Field(..., description="Cryptographic SHA-256 digest of canonical request")
    destination: str = Field(..., description="Destination identifier")
    decision: PolicyOutcome = Field(..., description="Evaluated policy outcome")
    rule_ids: list[str] = Field(default_factory=list, description="IDs of matching policy rules")
    risk_score: int = Field(..., ge=0, le=100, description="Evaluated risk score")
    policy_version: str = Field(..., description="Policy version evaluated")
    detector_version: str = Field(..., description="Detector version evaluated")
    status: str = Field(..., description="Execution status: completed, blocked, review_pending, etc.")
    provider_called: bool = Field(..., description="Whether an AI provider was invoked")
    redaction_count: int = Field(default=0, ge=0, description="Number of sensitive spans sanitized")
    latency_ms: int = Field(default=0, ge=0, description="Total request execution latency in ms")
    event_type: str = Field(default="prompt_execution", description="Audit event category")
    actor_id: str | None = Field(default=None, description="Identifier of actor (e.g. reviewer ID)")
    rationale: str | None = Field(default=None, description="Reviewer rationale / explanation")
    prev_hash: str | None = Field(default=None, description="SHA-256 hash of preceding chain record")
    record_hash: str | None = Field(default=None, description="SHA-256 hash chaining this record")
    sequence_number: int | None = Field(default=None, description="Monotonically increasing sequence number")


from enum import Enum


class CheckpointAnchorStatus(str, Enum):
    """External anchor synchronization status."""

    PENDING = "PENDING"
    ANCHORED = "ANCHORED"
    FAILED = "FAILED"


class AuditCheckpoint(BaseModel):
    """Deterministic cryptographic checkpoint for an ordered range of audit events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    checkpoint_id: str = Field(..., description="Deterministic unique checkpoint identifier")
    epoch_index: int = Field(..., ge=1, description="Monotonically increasing 1-indexed epoch number")
    start_sequence: int = Field(..., ge=1, description="Inclusive starting sequence number")
    end_sequence: int = Field(..., ge=1, description="Inclusive ending sequence number")
    event_count: int = Field(..., ge=1, description="Count of contiguous audit events in range")
    merkle_root: str = Field(..., description="Cryptographic SHA-256 Merkle root over event record hashes")
    prev_checkpoint_hash: str = Field(..., description="Cryptographic hash of the preceding checkpoint")
    checkpoint_hash: str = Field(..., description="Deterministic SHA-256 hash over canonical checkpoint fields")
    anchor_status: CheckpointAnchorStatus = Field(
        default=CheckpointAnchorStatus.PENDING, description="Status of external anchoring"
    )
    anchor_reference: str | None = Field(
        default=None, description="External transaction ID, ledger UUID, or storage reference"
    )
    anchored_at: str | None = Field(
        default=None, description="ISO 8601 timestamp when external anchoring was confirmed"
    )
    created_at: str = Field(..., description="ISO 8601 UTC timestamp of checkpoint generation")
    failure_reason: str | None = Field(
        default=None, description="Sanitized error reason if external anchoring failed"
    )


class AuditAnchorReceipt(BaseModel):
    """Cryptographic confirmation receipt from external immutable anchor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    anchor_id: str = Field(..., description="External anchor transaction/ledger identifier")
    destination: str = Field(..., description="External anchor service name or URI")
    anchored_at: str = Field(..., description="ISO 8601 confirmation timestamp")
    root_hash: str = Field(..., description="Merkle root hash acknowledged by external anchor")
    external_signature: str | None = Field(default=None, description="Cryptographic signature from anchor service")


class MerkleInclusionProofResponse(BaseModel):
    """Cryptographic inclusion proof verifying an audit event's presence in an anchored checkpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    checkpoint_id: str = Field(..., description="Associated checkpoint identifier")
    epoch_index: int = Field(..., description="Associated checkpoint epoch index")
    sequence_number: int = Field(..., description="Sequence number of verified audit event")
    event_id: str = Field(..., description="Event identifier")
    record_hash: str = Field(..., description="Canonical record hash of event")
    merkle_root: str = Field(..., description="Merkle root of associated checkpoint")
    proof: list[dict[str, str]] = Field(..., description="Ordered list of sibling hashes and positions")
    verified: bool = Field(..., description="Whether inclusion proof self-verifies against root")
    anchor_status: CheckpointAnchorStatus = Field(..., description="External anchor status of checkpoint")
    anchor_reference: str | None = Field(default=None, description="External anchor reference")


class AuditCheckpointListResponse(BaseModel):
    """List of audit checkpoints matching query constraints."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    checkpoints: list[AuditCheckpoint] = Field(..., description="List of audit checkpoints")
    total_count: int = Field(..., description="Total available checkpoints")


class CheckpointCreateRequest(BaseModel):
    """Request payload for triggering checkpoint creation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    start_sequence: int | None = Field(default=None, description="Optional starting sequence number")
    end_sequence: int | None = Field(default=None, description="Optional ending sequence number")

