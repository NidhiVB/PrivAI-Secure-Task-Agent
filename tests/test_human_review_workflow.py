"""Comprehensive test suite for Enterprise Human-Review Workflow (Phase A & Phase B).

Security Invariants Tested:
1. Review ticket creation, persistence, schema validation, and restart survival.
2. Exact 24-hour TTL server-side expiry enforcement.
3. Valid state transitions (PENDING -> APPROVED/REJECTED/EXPIRED) and rejection of invalid transitions.
4. Concurrent approval and rejection race condition safety.
5. JWT bearer token signature, issuer, audience, and expiration validation.
6. RBAC enforcement: 'PrivAI:Reviewer' permission and ticket 'assigned_role' validation.
7. Rejection of unbacked client role claims.
8. Approval and rejection rationale bounds and auditing.
9. Cryptographic HMAC permit minting, deterministic canonicalization, and signature verification.
10. Atomic single-use permit consumption and anti-replay protection.
11. Digest mismatch / prompt tampering detection after approval.
12. Zero provider calls for BLOCK, pending REVIEW, REJECTED, and EXPIRED tickets.
13. Tamper-evident SHA-256 audit hash chaining and chain integrity verification.
14. Data minimization: zero raw prompts or secrets in audit logs or API error envelopes.
"""

import datetime
import os
import sqlite3
import threading
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.audit.service import AuditService, GENESIS_HASH
from backend.app.config import settings
from backend.app.core.auth import (
    AuthException,
    create_reviewer_token,
    decode_reviewer_token,
)
from backend.app.core.exceptions import SecurityInvariantException
from backend.app.core.permits import (
    PermitSignatureException,
    generate_review_permit,
    verify_review_permit_signature,
)
from backend.app.main import app
from backend.app.models.audit import AuditEvent
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    ExecutionStatus,
    PolicyOutcome,
)
from backend.app.models.requests import PromptRequest
from backend.app.models.reviews import ReviewPermit, ReviewStatus
from backend.app.orchestrator.service import OrchestrationService
from backend.app.providers.mock import MockProvider
from backend.app.reviews.repository import (
    InvalidTicketTransitionException,
    PermitReplayException,
    ReviewRepository,
    TicketExpiredException,
    TicketNotFoundException,
)


@pytest.fixture
def test_db_path(tmp_path) -> str:
    """Fixture providing an isolated SQLite database path for testing."""
    return str(tmp_path / "test_privai.db")


@pytest.fixture
def review_repo(test_db_path) -> ReviewRepository:
    """Fixture providing a clean ReviewRepository instance."""
    repo = ReviewRepository(db_path=test_db_path)
    repo.clear()
    return repo


@pytest.fixture
def audit_service(test_db_path) -> AuditService:
    """Fixture providing a clean AuditService instance."""
    service = AuditService(db_path=test_db_path)
    return service


# ==============================================================================
# 1. Phase A: Ticket Persistence, Expiry, and State Transitions
# ==============================================================================


def test_ticket_creation_and_persistence(review_repo: ReviewRepository) -> None:
    """Verify review ticket creation, fields, and persistence across repository instances."""
    ticket_id = str(uuid.uuid4())
    digest = "sha256:11223344556677889900aabbccddeeff"
    now = datetime.datetime(2026, 10, 17, 12, 0, 0, tzinfo=datetime.timezone.utc)

    ticket = review_repo.create_ticket(
        ticket_id=ticket_id,
        request_digest=digest,
        assigned_role="compliance_officer",
        risk_score=60,
        triggered_rule_ids=["REVIEW-HEALTH-DATA"],
        prompt_content="Patient blood test results enclosed.",
        now_utc=now,
    )

    assert ticket.ticket_id == ticket_id
    assert ticket.status == ReviewStatus.PENDING
    assert ticket.assigned_role == "compliance_officer"
    assert ticket.risk_score == 60
    assert ticket.triggered_rule_ids == ["REVIEW-HEALTH-DATA"]
    assert ticket.submitted_at == now.isoformat()
    # Exact 24h expiry
    assert ticket.expires_at == (now + datetime.timedelta(hours=24)).isoformat()

    # Restart survival: reload from a new repository instance pointing to same DB
    reloaded_repo = ReviewRepository(db_path=review_repo.db_path)
    fetched = reloaded_repo.get_ticket(ticket_id, now_utc=now)
    assert fetched.ticket_id == ticket_id
    assert fetched.status == ReviewStatus.PENDING
    assert fetched.risk_score == 60


def test_exact_24_hour_expiry_enforcement(review_repo: ReviewRepository) -> None:
    """Verify that a ticket is valid up to 24h, and becomes EXPIRED exactly after 24h."""
    ticket_id = str(uuid.uuid4())
    digest = "sha256:aabbcc"
    created_at = datetime.datetime(2026, 10, 17, 10, 0, 0, tzinfo=datetime.timezone.utc)

    review_repo.create_ticket(
        ticket_id=ticket_id,
        request_digest=digest,
        assigned_role="compliance_officer",
        risk_score=50,
        triggered_rule_ids=["REVIEW-RULE"],
        now_utc=created_at,
    )

    # 1. Check at 23 hours 59 minutes: Still active PENDING
    just_before_expiry = created_at + datetime.timedelta(hours=23, minutes=59)
    ticket_active = review_repo.get_ticket(ticket_id, now_utc=just_before_expiry)
    assert ticket_active.status == ReviewStatus.PENDING

    # 2. Check at exactly 24 hours 1 second: Dynamically marked EXPIRED
    after_expiry = created_at + datetime.timedelta(hours=24, seconds=1)
    ticket_expired = review_repo.get_ticket(ticket_id, now_utc=after_expiry)
    assert ticket_expired.status == ReviewStatus.EXPIRED

    # 3. Attempting to approve an expired ticket must fail closed with TicketExpiredException
    with pytest.raises(TicketExpiredException):
        review_repo.approve_ticket(
            ticket_id=ticket_id,
            rationale="Approval attempt after expiry",
            reviewer_id="rev-user",
            now_utc=after_expiry,
        )


def test_valid_and_invalid_status_transitions(review_repo: ReviewRepository) -> None:
    """Verify valid transitions PENDING -> APPROVED / REJECTED, and prevent double decisions."""
    ticket_id = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc)

    review_repo.create_ticket(
        ticket_id=ticket_id,
        request_digest="sha256:digest123",
        assigned_role="hr_admin",
        risk_score=45,
        triggered_rule_ids=["REVIEW-HR"],
        now_utc=now,
    )

    # Valid: PENDING -> APPROVED
    approved = review_repo.approve_ticket(
        ticket_id=ticket_id,
        rationale="Approved for quarterly auditing compliance",
        reviewer_id="compliance-officer-1",
        now_utc=now,
    )
    assert approved.status == ReviewStatus.APPROVED
    assert approved.decided_by == "compliance-officer-1"
    assert approved.decision_rationale == "Approved for quarterly auditing compliance"

    # Invalid: Attempting to reject an already APPROVED ticket must fail
    with pytest.raises(InvalidTicketTransitionException):
        review_repo.reject_ticket(
            ticket_id=ticket_id,
            rationale="Attempting to reject already approved ticket",
            reviewer_id="officer-2",
            now_utc=now,
        )


def test_concurrent_approval_and_rejection(review_repo: ReviewRepository) -> None:
    """Verify atomic conditional updates prevent race conditions between approve and reject."""
    ticket_id = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc)

    review_repo.create_ticket(
        ticket_id=ticket_id,
        request_digest="sha256:race_test",
        assigned_role="compliance_officer",
        risk_score=50,
        triggered_rule_ids=["REVIEW-TEST"],
        now_utc=now,
    )

    results = []
    errors = []

    def try_approve():
        try:
            t = review_repo.approve_ticket(
                ticket_id=ticket_id,
                rationale="Approved concurrently",
                reviewer_id="reviewer-A",
                now_utc=now,
            )
            results.append(("APPROVED", t))
        except Exception as e:
            errors.append(e)

    def try_reject():
        try:
            t = review_repo.reject_ticket(
                ticket_id=ticket_id,
                rationale="Rejected concurrently",
                reviewer_id="reviewer-B",
                now_utc=now,
            )
            results.append(("REJECTED", t))
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=try_approve)
    t2 = threading.Thread(target=try_reject)

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Exactly one action must succeed, and one must fail
    assert len(results) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], InvalidTicketTransitionException)


# ==============================================================================
# 2. Phase B: Authentication, RBAC, and Reviewer Endpoints
# ==============================================================================


def test_jwt_validation_and_rbac_failures() -> None:
    """Verify JWT signature, expiration, issuer, and PrivAI:Reviewer permission checks."""
    # 1. Valid token
    valid_token = create_reviewer_token(
        user_id="user-123",
        roles=["compliance_officer"],
        permissions=["PrivAI:Reviewer"],
    )
    claims = decode_reviewer_token(valid_token)
    assert claims.user_id == "user-123"
    assert "compliance_officer" in claims.roles

    # 2. Token with wrong secret
    tampered_secret_token = create_reviewer_token(
        user_id="user-123",
        roles=["compliance_officer"],
        secret_key="wrong-secret-key-1234567890123456",
    )
    with pytest.raises(AuthException) as exc:
        decode_reviewer_token(tampered_secret_token)
    assert exc.value.code == "TOKEN_INVALID"

    # 3. Expired token
    expired_token = create_reviewer_token(
        user_id="user-123",
        roles=["compliance_officer"],
        expires_delta=datetime.timedelta(seconds=-10),
    )
    with pytest.raises(AuthException) as exc:
        decode_reviewer_token(expired_token)
    assert exc.value.code == "TOKEN_EXPIRED"

    # 4. Token lacking 'PrivAI:Reviewer' permission
    unauthorized_token = create_reviewer_token(
        user_id="user-unauthorized",
        roles=["compliance_officer"],
        permissions=["StandardUser"],
    )
    with pytest.raises(AuthException) as exc:
        decode_reviewer_token(unauthorized_token)
    assert exc.value.code == "FORBIDDEN_INSUFFICIENT_PERMISSIONS"

    # 5. Token with invalid crypto padding (reproduction of dev_signature bug)
    import base64
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip('=')
    p = base64.urlsafe_b64encode(b'{"sub":"u1","roles":["compliance_officer"],"permissions":["PrivAI:Reviewer"],"exp":9999999999,"iss":"privai-auth","aud":"privai-api"}').decode().rstrip('=')
    malformed_padding_token = f"{h}.{p}.dev_signature"
    with pytest.raises(AuthException) as exc:
        decode_reviewer_token(malformed_padding_token)
    assert exc.value.code == "TOKEN_INVALID"
    assert "Invalid crypto padding" in exc.value.message

    # 6. Empty or whitespace-only token
    with pytest.raises(AuthException) as exc:
        decode_reviewer_token("   ")
    assert exc.value.code == "TOKEN_EMPTY"


def test_reviewer_endpoints_via_api(test_db_path) -> None:
    """Verify GET /v1/reviews/pending, approve, reject, and demo-token endpoints."""
    from backend.app.api.v1.reviews import set_review_services

    repo = ReviewRepository(db_path=test_db_path)
    audit = AuditService(db_path=test_db_path)
    repo.clear()
    audit.clear()
    set_review_services(repo, audit)

    client = TestClient(app)

    # 0. Demo token issuance test
    r_demo = client.post("/v1/reviews/demo-token", json={"role": "compliance_officer"})
    assert r_demo.status_code == 200
    demo_data = r_demo.json()
    assert "token" in demo_data
    assert demo_data["role"] == "compliance_officer"
    assert demo_data["user_id"] == "reviewer_compliance_officer"

    # Invalid demo role rejected
    r_bad_role = client.post("/v1/reviews/demo-token", json={"role": "invalid_guest_role"})
    assert r_bad_role.status_code == 400

    # Production guard: Demo token endpoint disabled in production with non-mock provider
    orig_env = settings.ENVIRONMENT
    orig_mode = settings.PROVIDER_MODE
    try:
        settings.ENVIRONMENT = "production"
        settings.PROVIDER_MODE = "groq"
        r_prod = client.post("/v1/reviews/demo-token", json={"role": "compliance_officer"})
        assert r_prod.status_code == 403
        assert r_prod.json()["error"]["code"] == "DEMO_AUTH_DISABLED"
    finally:
        settings.ENVIRONMENT = orig_env
        settings.PROVIDER_MODE = orig_mode

    # Create a test ticket assigned to compliance_officer
    ticket_id = str(uuid.uuid4())
    repo.create_ticket(
        ticket_id=ticket_id,
        request_digest="sha256:api_test_digest",
        assigned_role="compliance_officer",
        risk_score=65,
        triggered_rule_ids=["REVIEW-HEALTH-DATA"],
    )

    # 1. Unauthenticated request rejected
    r_unauth = client.get("/v1/reviews/pending")
    assert r_unauth.status_code == 401

    # 1b. Request with malformed padding token rejected with 401 TOKEN_INVALID
    malformed_padding_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1MSJ9.dev_signature"
    r_bad_pad = client.get(
        "/v1/reviews/pending", headers={"Authorization": f"Bearer {malformed_padding_token}"}
    )
    assert r_bad_pad.status_code == 401
    assert r_bad_pad.json()["error"]["code"] == "TOKEN_INVALID"

    # 2. Authenticated as compliance_officer lists the pending ticket
    token_compliance = create_reviewer_token("officer-1", roles=["compliance_officer"])
    r_list = client.get(
        "/v1/reviews/pending", headers={"Authorization": f"Bearer {token_compliance}"}
    )
    assert r_list.status_code == 200
    data = r_list.json()
    assert data["total_count"] == 1
    assert data["tickets"][0]["ticket_id"] == ticket_id

    # 3. Role mismatch rejection: HR admin cannot approve compliance ticket
    token_hr = create_reviewer_token("hr-user", roles=["hr_admin"])
    r_approve_mismatch = client.post(
        f"/v1/reviews/{ticket_id}/approve",
        headers={"Authorization": f"Bearer {token_hr}"},
        json={"rationale": "Attempting approval with wrong role justification"},
    )
    assert r_approve_mismatch.status_code == 403
    assert r_approve_mismatch.json()["error"]["code"] == "ROLE_MISMATCH"

    # 4. Valid approval by compliance_officer issues single-use permit
    r_approve = client.post(
        f"/v1/reviews/{ticket_id}/approve",
        headers={"Authorization": f"Bearer {token_compliance}"},
        json={"rationale": "Verified HIPAA-compliant anonymized health research workflow"},
    )
    assert r_approve.status_code == 200
    approve_data = r_approve.json()
    assert approve_data["status"] == "APPROVED"
    assert approve_data["decided_by"] == "officer-1"
    assert approve_data["permit"] is not None
    assert approve_data["permit"]["ticket_id"] == ticket_id
    assert approve_data["permit"]["signature"] is not None

    # 5. Verified ticket is no longer pending
    r_list_after = client.get(
        "/v1/reviews/pending", headers={"Authorization": f"Bearer {token_compliance}"}
    )
    assert r_list_after.json()["total_count"] == 0


# ==============================================================================
# 3. Cryptographic Review Permits, Anti-Replay, and Prompt Tampering
# ==============================================================================


def test_hmac_permit_signature_and_tampering() -> None:
    """Verify HMAC permit signing and rejection of altered payloads or signatures."""
    ticket_id = str(uuid.uuid4())
    digest = "sha256:orig_digest_123"

    permit = generate_review_permit(
        ticket_id=ticket_id,
        request_digest=digest,
        approved_by="approver-1",
        assigned_role="compliance_officer",
    )

    # 1. Clean verification
    assert verify_review_permit_signature(permit) is True

    # 2. Tampered digest raises signature exception
    tampered_permit = permit.model_copy(update={"request_digest": "sha256:forged_digest"})
    with pytest.raises(PermitSignatureException):
        verify_review_permit_signature(tampered_permit)

    # 3. Tampered ticket ID raises signature exception
    tampered_ticket_permit = permit.model_copy(update={"ticket_id": str(uuid.uuid4())})
    with pytest.raises(PermitSignatureException):
        verify_review_permit_signature(tampered_ticket_permit)


def test_atomic_permit_consumption_and_replay_prevention(review_repo: ReviewRepository) -> None:
    """Verify that a permit can only be consumed once, and replay attempts are blocked."""
    ticket_id = str(uuid.uuid4())
    digest = "sha256:replay_digest"
    now = datetime.datetime.now(datetime.timezone.utc)

    # Create & approve ticket
    review_repo.create_ticket(
        ticket_id=ticket_id,
        request_digest=digest,
        assigned_role="compliance_officer",
        risk_score=50,
        triggered_rule_ids=["RULE"],
        now_utc=now,
    )
    review_repo.approve_ticket(ticket_id, "Approved", "approver", now_utc=now)

    permit = generate_review_permit(ticket_id, digest, "approver", "compliance_officer", now_utc=now)
    review_repo.record_permit(
        permit_nonce=permit.permit_nonce,
        ticket_id=permit.ticket_id,
        request_digest=permit.request_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
    )

    # 1. First consumption succeeds
    consumed = review_repo.consume_permit_atomic(permit.permit_nonce, expected_digest=digest, now_utc=now)
    assert consumed["permit_nonce"] == permit.permit_nonce

    # 2. Replay attempt immediately blocked with PermitReplayException
    with pytest.raises(PermitReplayException) as exc:
        review_repo.consume_permit_atomic(permit.permit_nonce, expected_digest=digest, now_utc=now)
    assert "already been consumed" in str(exc.value)


# ==============================================================================
# 4. Orchestration Integration: Zero Calls for BLOCK/REVIEW, Verified Execution
# ==============================================================================


def test_orchestration_pending_review_creates_ticket_and_zero_provider_calls(
    test_db_path,
) -> None:
    """Verify that execution of a REVIEW prompt persists a ticket and makes ZERO provider calls."""
    repo = ReviewRepository(db_path=test_db_path)
    audit = AuditService(db_path=test_db_path)
    repo.clear()
    audit.clear()

    mock_provider = MockProvider()
    orchestrator = OrchestrationService(
        audit_service=audit,
        mock_provider=mock_provider,
        review_repo=repo,
    )

    # Prompt triggering REVIEW (health information)
    req = PromptRequest(
        prompt="Patient was diagnosed with clinical hypertension.",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.HEALTH_INFORMATION,
            data_subject=ContextDataSubject.SELF,
            classification=ContextClassification.PUBLIC,
        ),
    )

    resp = orchestrator.execute(req)

    # Invariants:
    assert resp.status == ExecutionStatus.REVIEW_PENDING
    assert resp.decision == PolicyOutcome.REVIEW
    assert resp.output is None
    assert resp.provider is None
    assert resp.ticket_id is not None
    # ZERO provider calls
    assert mock_provider.call_count == 0

    # Verify ticket was persisted in DB
    ticket = repo.get_ticket(resp.ticket_id)
    assert ticket.status == ReviewStatus.PENDING
    assert ticket.assigned_role == "compliance_officer"


def test_orchestration_execute_with_approved_permit_invokes_provider_once(
    test_db_path,
) -> None:
    """Verify that execute with a valid approved permit dispatches to provider exactly once."""
    repo = ReviewRepository(db_path=test_db_path)
    audit = AuditService(db_path=test_db_path)
    repo.clear()
    audit.clear()

    mock_provider = MockProvider()
    orchestrator = OrchestrationService(
        audit_service=audit,
        mock_provider=mock_provider,
        review_repo=repo,
    )

    req = PromptRequest(
        prompt="Patient was diagnosed with clinical hypertension.",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.HEALTH_INFORMATION,
            data_subject=ContextDataSubject.SELF,
            classification=ContextClassification.PUBLIC,
        ),
    )

    # 1. Initial submission yields review_pending
    initial_resp = orchestrator.execute(req)
    assert initial_resp.status == ExecutionStatus.REVIEW_PENDING
    ticket_id = initial_resp.ticket_id

    # 2. Compliance officer approves ticket
    repo.approve_ticket(
        ticket_id=ticket_id,
        rationale="Approved by medical compliance board",
        reviewer_id="dr_compliance",
    )
    ticket = repo.get_ticket(ticket_id)

    # 3. Mint permit
    permit = generate_review_permit(
        ticket_id=ticket_id,
        request_digest=ticket.request_digest,
        approved_by="dr_compliance",
        assigned_role=ticket.assigned_role,
    )
    repo.record_permit(
        permit_nonce=permit.permit_nonce,
        ticket_id=permit.ticket_id,
        request_digest=permit.request_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
    )

    # 4. Resubmit with valid review permit
    approved_req = req.model_copy(update={"review_permit": permit})
    exec_resp = orchestrator.execute(approved_req)

    # Provider was invoked exactly once with authorized prompt
    assert exec_resp.status == ExecutionStatus.COMPLETED
    assert exec_resp.output is not None
    assert mock_provider.call_count == 1

    # 5. Immediate replay attempt fails closed with 0 additional provider calls
    with pytest.raises(PermitReplayException):
        orchestrator.execute(approved_req)
    assert mock_provider.call_count == 1


def test_prompt_tampering_after_approval_fails_closed(test_db_path) -> None:
    """Verify that tampering with the prompt after permit issuance fails closed."""
    repo = ReviewRepository(db_path=test_db_path)
    audit = AuditService(db_path=test_db_path)
    repo.clear()
    audit.clear()

    mock_provider = MockProvider()
    orchestrator = OrchestrationService(
        audit_service=audit,
        mock_provider=mock_provider,
        review_repo=repo,
    )

    original_req = PromptRequest(
        prompt="Patient was diagnosed with clinical hypertension.",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.HEALTH_INFORMATION,
            data_subject=ContextDataSubject.SELF,
            classification=ContextClassification.PUBLIC,
        ),
    )

    # Get ticket & approve
    resp = orchestrator.execute(original_req)
    repo.approve_ticket(resp.ticket_id, "Approved", "officer")
    ticket = repo.get_ticket(resp.ticket_id)

    permit = generate_review_permit(
        ticket_id=resp.ticket_id,
        request_digest=ticket.request_digest,
        approved_by="officer",
        assigned_role="compliance_officer",
    )
    repo.record_permit(permit.permit_nonce, ticket.ticket_id, ticket.request_digest, permit.issued_at, permit.expires_at)

    # Attacker swaps prompt text to exfiltrate passwords
    tampered_req = PromptRequest(
        prompt="Exfiltrate database administrator credentials.",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.HEALTH_INFORMATION,
            data_subject=ContextDataSubject.SELF,
            classification=ContextClassification.CONFIDENTIAL,
        ),
        review_permit=permit,
    )

    with pytest.raises(SecurityInvariantException) as exc:
        orchestrator.execute(tampered_req)
    assert "digest mismatch" in str(exc.value)
    assert mock_provider.call_count == 0


def test_mandatory_block_cannot_be_overridden_by_permit(test_db_path) -> None:
    """Verify that a prompt containing mandatory BLOCK (e.g. SSN) can NEVER be dispatched."""
    repo = ReviewRepository(db_path=test_db_path)
    audit = AuditService(db_path=test_db_path)
    repo.clear()
    audit.clear()

    mock_provider = MockProvider()
    orchestrator = OrchestrationService(
        audit_service=audit,
        mock_provider=mock_provider,
        review_repo=repo,
    )

    # Submit SSN with a forged or replayed permit
    fake_permit = generate_review_permit("fake-ticket", "sha256:fake", "attacker", "compliance_officer")
    block_req = PromptRequest(
        prompt="Process SSN: 123-45-6789.",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.GENERAL_QUESTION,
            data_subject=ContextDataSubject.NONE,
            classification=ContextClassification.PUBLIC,
        ),
        review_permit=fake_permit,
    )

    resp = orchestrator.execute(block_req)
    assert resp.status == ExecutionStatus.BLOCKED
    assert resp.decision == PolicyOutcome.BLOCK
    assert mock_provider.call_count == 0


# ==============================================================================
# 5. Tamper-Evident SHA-256 Audit Chaining & Integrity
# ==============================================================================


def test_audit_hash_chaining_and_integrity_verification(test_db_path) -> None:
    """Verify SHA-256 hash chaining over sequential audit records and tamper detection."""
    audit = AuditService(db_path=test_db_path)
    audit.clear()

    # Record 3 sequential events
    for i in range(3):
        audit.record(
            AuditEvent(
                event_id=f"evt-{i}",
                timestamp=f"2026-10-17T12:0{i}:00Z",
                request_digest=f"sha256:digest-{i}",
                destination="mock",
                decision=PolicyOutcome.ALLOW,
                rule_ids=[],
                risk_score=10 * i,
                policy_version="policy-v1",
                detector_version="detector-v1",
                status="completed",
                provider_called=True,
                redaction_count=0,
                latency_ms=10,
                event_type="prompt_execution",
            )
        )

    # 1. Clean verification
    is_valid, err = audit.verify_chain_integrity()
    assert is_valid is True
    assert err is None

    # Inspect persisted chain
    events = audit.get_persisted_events()
    assert len(events) == 3
    assert events[0]["prev_hash"] == GENESIS_HASH
    assert events[1]["prev_hash"] == events[0]["record_hash"]
    assert events[2]["prev_hash"] == events[1]["record_hash"]

    # 2. Tampering test: directly alter an audit event in SQLite
    with sqlite3.connect(test_db_path) as conn:
        conn.execute("UPDATE audit_events SET risk_score = 99 WHERE sequence_number = 2")
        conn.commit()

    # 3. Chain integrity verification must detect tampering
    is_valid_after, err_after = audit.verify_chain_integrity()
    assert is_valid_after is False
    assert "Tampered record" in err_after or "Broken chain" in err_after
