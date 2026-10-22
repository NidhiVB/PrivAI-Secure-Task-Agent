"""Restricted auditor API endpoints for audit checkpoints and Merkle inclusion proofs."""

from typing import Any
from fastapi import APIRouter, Depends, Query, status

from backend.app.audit.service import (
    AuditService,
    get_audit_service,
    set_audit_service as set_global_audit_service,
)
from backend.app.config import settings
from backend.app.core.auth import AuthException, ReviewerUser, get_current_auditor
from backend.app.models.audit import (
    AuditCheckpoint,
    AuditCheckpointListResponse,
    CheckpointCreateRequest,
    MerkleInclusionProofResponse,
)
from backend.app.models.responses import SafeErrorResponse

router = APIRouter(prefix="/audit", tags=["Audit Checkpoints"])

# Shared service instance
audit_service = get_audit_service()


def set_audit_service(service: AuditService) -> None:
    """Inject audit service (useful for test isolation)."""
    global audit_service
    audit_service = service
    set_global_audit_service(service)


@router.get(
    "/checkpoints",
    response_model=AuditCheckpointListResponse,
    responses={
        200: {"model": AuditCheckpointListResponse, "description": "List of anchored audit checkpoints"},
        401: {"model": SafeErrorResponse, "description": "Unauthorized / Missing or invalid token"},
        403: {"model": SafeErrorResponse, "description": "Forbidden / Insufficient auditor permissions"},
    },
    summary="List audit checkpoints with external anchor references",
)
def list_checkpoints(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: ReviewerUser = Depends(get_current_auditor),
) -> AuditCheckpointListResponse:
    """List audit checkpoints ordered chronologically.

    Security Invariant:
    Restricted to authenticated callers possessing 'auditor', 'security_admin',
    or 'compliance_officer' roles.
    """
    checkpoints = audit_service.list_checkpoints(limit=limit, offset=offset)
    return AuditCheckpointListResponse(checkpoints=checkpoints, total_count=len(checkpoints))


@router.get(
    "/checkpoints/{checkpoint_id}",
    response_model=AuditCheckpoint,
    responses={
        200: {"model": AuditCheckpoint, "description": "Audit checkpoint metadata and anchor status"},
        401: {"model": SafeErrorResponse, "description": "Unauthorized"},
        403: {"model": SafeErrorResponse, "description": "Forbidden"},
        404: {"model": SafeErrorResponse, "description": "Checkpoint not found"},
    },
    summary="Retrieve specific audit checkpoint by identifier",
)
def get_checkpoint_details(
    checkpoint_id: str,
    current_user: ReviewerUser = Depends(get_current_auditor),
) -> AuditCheckpoint:
    """Retrieve detailed metadata for an audit checkpoint."""
    return audit_service.get_checkpoint(checkpoint_id)


@router.get(
    "/checkpoints/{checkpoint_id}/proof/{sequence_number}",
    response_model=MerkleInclusionProofResponse,
    responses={
        200: {"model": MerkleInclusionProofResponse, "description": "Cryptographic Merkle inclusion proof"},
        401: {"model": SafeErrorResponse, "description": "Unauthorized"},
        403: {"model": SafeErrorResponse, "description": "Forbidden"},
        404: {"model": SafeErrorResponse, "description": "Checkpoint or sequence not found"},
        409: {"model": SafeErrorResponse, "description": "Sequence outside checkpoint range"},
    },
    summary="Generate and self-verify a Merkle inclusion proof for an audit event",
)
def get_merkle_inclusion_proof(
    checkpoint_id: str,
    sequence_number: int,
    current_user: ReviewerUser = Depends(get_current_auditor),
) -> MerkleInclusionProofResponse:
    """Generate cryptographic Merkle inclusion proof for an audit event.

    Security Invariants:
    1. Proves inclusion of the specific audit event in the externally anchored checkpoint root.
    2. Data minimization: strictly omits prompt texts, matched sensitive values, and secrets.
    """
    return audit_service.get_inclusion_proof(checkpoint_id, sequence_number)


@router.post(
    "/checkpoints",
    response_model=AuditCheckpoint,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"model": AuditCheckpoint, "description": "Checkpoint created and anchored successfully"},
        401: {"model": SafeErrorResponse, "description": "Unauthorized"},
        403: {"model": SafeErrorResponse, "description": "Forbidden / Security admin role required"},
        409: {"model": SafeErrorResponse, "description": "Sequence mismatch or integrity violation"},
        502: {"model": SafeErrorResponse, "description": "External anchor synchronization failed"},
    },
    summary="Trigger creation and immutable anchoring of an audit checkpoint",
)
def create_checkpoint(
    payload: CheckpointCreateRequest | None = None,
    current_user: ReviewerUser = Depends(get_current_auditor),
) -> AuditCheckpoint:
    """Create and anchor a new Merkle checkpoint for uncheckpointed events.

    Security Invariant:
    Requires 'security_admin' or 'auditor' role. Fails closed if remote anchor rejects root.
    """
    if "security_admin" not in current_user.roles and "auditor" not in current_user.roles:
        raise AuthException(
            message=f"Forbidden: Role '{current_user.roles}' cannot trigger audit checkpoint creation.",
            code="FORBIDDEN_CHECKPOINT_CREATION",
            status_code=403,
        )

    start_seq = payload.start_sequence if payload else None
    end_seq = payload.end_sequence if payload else None

    return audit_service.create_checkpoint(start_sequence=start_seq, end_sequence=end_seq)


@router.get(
    "/checkpoints/{checkpoint_id}/verify",
    responses={
        200: {"description": "Checkpoint verification result"},
        401: {"model": SafeErrorResponse, "description": "Unauthorized"},
        403: {"model": SafeErrorResponse, "description": "Forbidden"},
        404: {"model": SafeErrorResponse, "description": "Checkpoint not found"},
    },
    summary="Cryptographically verify integrity of a checkpoint and its event chain",
)
def verify_checkpoint(
    checkpoint_id: str,
    current_user: ReviewerUser = Depends(get_current_auditor),
) -> dict[str, Any]:
    """Verify unbroken event hash chain and Merkle root recomputation."""
    valid, reason = audit_service.verify_checkpoint_integrity(checkpoint_id)
    return {
        "checkpoint_id": checkpoint_id,
        "valid": valid,
        "failure_reason": reason,
    }
