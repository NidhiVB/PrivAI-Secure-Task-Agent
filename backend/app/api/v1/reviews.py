"""Authenticated Reviewer API endpoints for human-in-the-loop approvals."""

import datetime
import uuid
from fastapi import APIRouter, Depends, status

from backend.app.audit.service import AuditService, get_audit_service
from backend.app.core.auth import AuthException, ReviewerUser, get_current_reviewer
from backend.app.core.permits import generate_review_permit
from backend.app.models.audit import AuditEvent
from backend.app.models.enums import PolicyOutcome
from backend.app.models.responses import SafeErrorResponse
from backend.app.models.reviews import (
    ReviewActionResponse,
    ReviewApprovalRequest,
    ReviewPendingListResponse,
    ReviewRejectionRequest,
    ReviewStatus,
    ReviewTicket,
)
from backend.app.reviews.repository import ReviewRepository

router = APIRouter(prefix="/reviews", tags=["Human Review"])

# Shared service instances
review_repo = ReviewRepository()
audit_service = get_audit_service()


def set_review_services(repo: ReviewRepository, audit: AuditService) -> None:
    """Inject repositories (useful for test isolation)."""
    global review_repo, audit_service
    review_repo = repo
    audit_service = audit


@router.get(
    "/pending",
    response_model=ReviewPendingListResponse,
    responses={
        200: {"model": ReviewPendingListResponse, "description": "Active pending review tickets"},
        401: {"model": SafeErrorResponse, "description": "Unauthorized / Missing or invalid token"},
        403: {"model": SafeErrorResponse, "description": "Forbidden / Insufficient permissions"},
    },
    summary="List pending unexpired review tickets accessible to reviewer",
)
def list_pending_reviews(
    current_user: ReviewerUser = Depends(get_current_reviewer),
) -> ReviewPendingListResponse:
    """List pending unexpired review tickets matching reviewer's assigned roles."""
    # Security admin can view all pending tickets
    allowed_roles = None if "security_admin" in current_user.roles else current_user.roles
    tickets = review_repo.list_pending_tickets(allowed_roles=allowed_roles)
    return ReviewPendingListResponse(tickets=tickets, total_count=len(tickets))


@router.post(
    "/{ticket_id}/approve",
    response_model=ReviewActionResponse,
    responses={
        200: {"model": ReviewActionResponse, "description": "Ticket approved and permit issued"},
        401: {"model": SafeErrorResponse, "description": "Unauthorized"},
        403: {"model": SafeErrorResponse, "description": "Forbidden / Role mismatch"},
        404: {"model": SafeErrorResponse, "description": "Ticket not found"},
        409: {"model": SafeErrorResponse, "description": "Conflict / Ticket already decided or expired"},
    },
    summary="Approve a review ticket and generate a cryptographic single-use permit",
)
def approve_review(
    ticket_id: str,
    payload: ReviewApprovalRequest,
    current_user: ReviewerUser = Depends(get_current_reviewer),
) -> ReviewActionResponse:
    """Approve a review ticket with bounded rationale.

    Security Invariants:
    1. Enforces that the reviewer's token possesses the ticket's assigned_role (or security_admin).
    2. Atomically transitions ticket status to APPROVED (fails if expired or already decided).
    3. Records tamper-evident audit record with approver identity and rationale.
    4. Mints a single-use HMAC permit with strict 5-minute TTL.
    """
    # 1. Inspect existing ticket to verify assigned role
    ticket = review_repo.get_ticket(ticket_id)

    if "security_admin" not in current_user.roles and ticket.assigned_role not in current_user.roles:
        raise AuthException(
            message=f"Forbidden: Reviewer role '{current_user.roles}' cannot approve ticket assigned to '{ticket.assigned_role}'.",
            code="ROLE_MISMATCH",
            status_code=403,
        )

    # 2. Atomically approve ticket in repository
    approved_ticket = review_repo.approve_ticket(
        ticket_id=ticket_id,
        rationale=payload.rationale,
        reviewer_id=current_user.user_id,
    )

    # 3. Mint cryptographic single-use permit
    permit = generate_review_permit(
        ticket_id=approved_ticket.ticket_id,
        request_digest=approved_ticket.request_digest,
        approved_by=current_user.user_id,
        assigned_role=approved_ticket.assigned_role,
    )

    # 4. Record permit in database for atomic replay protection
    review_repo.record_permit(
        permit_nonce=permit.permit_nonce,
        ticket_id=permit.ticket_id,
        request_digest=permit.request_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
    )

    # 5. Tamper-evident audit log recording
    audit_service.record(
        AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=approved_ticket.decided_at or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            request_digest=approved_ticket.request_digest,
            destination="human_review",
            decision=PolicyOutcome.REVIEW,
            rule_ids=approved_ticket.triggered_rule_ids,
            risk_score=approved_ticket.risk_score,
            policy_version="policy-v1",
            detector_version="detector-v1",
            status="ticket_approved",
            provider_called=False,
            redaction_count=0,
            latency_ms=0,
            event_type="ticket_approved",
            actor_id=current_user.user_id,
            rationale=payload.rationale,
        )
    )

    return ReviewActionResponse(
        ticket_id=approved_ticket.ticket_id,
        status=approved_ticket.status,
        decided_by=current_user.user_id,
        decided_at=approved_ticket.decided_at or "",
        permit=permit,
    )


@router.post(
    "/{ticket_id}/reject",
    response_model=ReviewActionResponse,
    responses={
        200: {"model": ReviewActionResponse, "description": "Ticket rejected"},
        401: {"model": SafeErrorResponse, "description": "Unauthorized"},
        403: {"model": SafeErrorResponse, "description": "Forbidden / Role mismatch"},
        404: {"model": SafeErrorResponse, "description": "Ticket not found"},
        409: {"model": SafeErrorResponse, "description": "Conflict / Ticket already decided or expired"},
    },
    summary="Reject a review ticket",
)
def reject_review(
    ticket_id: str,
    payload: ReviewRejectionRequest,
    current_user: ReviewerUser = Depends(get_current_reviewer),
) -> ReviewActionResponse:
    """Reject a review ticket with bounded rationale.

    Security Invariants:
    1. Enforces reviewer's assigned_role (or security_admin).
    2. Atomically transitions ticket status to REJECTED.
    3. Strictly zero provider calls. Never issues a permit.
    4. Records tamper-evident audit record.
    """
    ticket = review_repo.get_ticket(ticket_id)

    if "security_admin" not in current_user.roles and ticket.assigned_role not in current_user.roles:
        raise AuthException(
            message=f"Forbidden: Reviewer role '{current_user.roles}' cannot reject ticket assigned to '{ticket.assigned_role}'.",
            code="ROLE_MISMATCH",
            status_code=403,
        )

    rejected_ticket = review_repo.reject_ticket(
        ticket_id=ticket_id,
        rationale=payload.rationale,
        reviewer_id=current_user.user_id,
    )

    audit_service.record(
        AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=rejected_ticket.decided_at or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            request_digest=rejected_ticket.request_digest,
            destination="human_review",
            decision=PolicyOutcome.REVIEW,
            rule_ids=rejected_ticket.triggered_rule_ids,
            risk_score=rejected_ticket.risk_score,
            policy_version="policy-v1",
            detector_version="detector-v1",
            status="ticket_rejected",
            provider_called=False,
            redaction_count=0,
            latency_ms=0,
            event_type="ticket_rejected",
            actor_id=current_user.user_id,
            rationale=payload.rationale,
        )
    )

    return ReviewActionResponse(
        ticket_id=rejected_ticket.ticket_id,
        status=rejected_ticket.status,
        decided_by=current_user.user_id,
        decided_at=rejected_ticket.decided_at or "",
        permit=None,
    )
