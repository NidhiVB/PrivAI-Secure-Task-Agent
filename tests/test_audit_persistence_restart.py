"""Focused tests verifying durable audit persistence and survivability across service reinitialization."""

import os
import sqlite3
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.audit.service import AuditService, GENESIS_HASH
from backend.app.core.exceptions import AuditWriteException
from backend.app.models.audit import AuditEvent, CheckpointAnchorStatus
from backend.app.models.enums import PolicyOutcome


def test_audit_event_and_checkpoint_persistence_across_restart(tmp_path: Path) -> None:
    """Verify that audit events and checkpoints survive service reinitialization and restart."""
    db_file = str(tmp_path / "durable_audit_restart.db")

    # =========================================================================
    # Phase 1: Pre-restart service instance (Initial Process / Lifecycle)
    # =========================================================================
    service1 = AuditService(db_path=db_file)

    evt1 = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp="2026-10-18T10:00:00Z",
        request_digest="sha256:digest001",
        destination="groq",
        decision=PolicyOutcome.ALLOW,
        rule_ids=[],
        risk_score=10,
        policy_version="policy-v1",
        detector_version="detector-v1",
        status="completed",
        provider_called=True,
        redaction_count=0,
        latency_ms=100,
    )
    rec1 = service1.record(evt1)
    assert rec1.sequence_number == 1
    assert rec1.prev_hash == GENESIS_HASH
    assert rec1.record_hash is not None

    evt2 = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp="2026-10-18T10:01:00Z",
        request_digest="sha256:digest002",
        destination="groq",
        decision=PolicyOutcome.ALLOW,
        rule_ids=[],
        risk_score=20,
        policy_version="policy-v1",
        detector_version="detector-v1",
        status="completed",
        provider_called=True,
        redaction_count=0,
        latency_ms=115,
    )
    rec2 = service1.record(evt2)
    assert rec2.sequence_number == 2
    assert rec2.prev_hash == rec1.record_hash

    # Create Epoch 1 checkpoint spanning sequences 1 to 2
    chk1 = service1.create_checkpoint(start_sequence=1, end_sequence=2)
    assert chk1.epoch_index == 1
    assert chk1.start_sequence == 1
    assert chk1.end_sequence == 2
    assert chk1.event_count == 2
    assert chk1.anchor_status == CheckpointAnchorStatus.ANCHORED

    # Verify chain and checkpoint in Service 1
    valid1, _ = service1.verify_chain_integrity()
    assert valid1 is True
    valid_chk1, _ = service1.verify_checkpoint_integrity(chk1.checkpoint_id)
    assert valid_chk1 is True

    # Simulate full process shutdown
    del service1

    # =========================================================================
    # Phase 2: Post-restart service instance (New Process Reinitialization)
    # =========================================================================
    service2 = AuditService(db_path=db_file)

    # 1. Verify persisted events survived and match exact pre-restart content
    persisted_events = service2.get_persisted_events()
    assert len(persisted_events) == 2
    assert persisted_events[0]["event_id"] == evt1.event_id
    assert persisted_events[0]["sequence_number"] == 1
    assert persisted_events[0]["prev_hash"] == GENESIS_HASH
    assert persisted_events[0]["record_hash"] == rec1.record_hash

    assert persisted_events[1]["event_id"] == evt2.event_id
    assert persisted_events[1]["sequence_number"] == 2
    assert persisted_events[1]["prev_hash"] == rec1.record_hash
    assert persisted_events[1]["record_hash"] == rec2.record_hash

    # 2. Verify persisted checkpoint survived with exact metadata
    latest_chk = service2.get_latest_checkpoint()
    assert latest_chk is not None
    assert latest_chk.checkpoint_id == chk1.checkpoint_id
    assert latest_chk.epoch_index == 1
    assert latest_chk.start_sequence == 1
    assert latest_chk.end_sequence == 2
    assert latest_chk.merkle_root == chk1.merkle_root
    assert latest_chk.checkpoint_hash == chk1.checkpoint_hash
    assert latest_chk.anchor_reference == chk1.anchor_reference

    # 3. Verify checkpoint cryptographic integrity across restart
    valid_chk_restart, reason_chk = service2.verify_checkpoint_integrity(chk1.checkpoint_id)
    assert valid_chk_restart is True, f"Checkpoint verification failed: {reason_chk}"

    # 4. Verify historical event hash chain integrity across restart
    valid_chain_restart, reason_chain = service2.verify_chain_integrity()
    assert valid_chain_restart is True, f"Chain verification failed: {reason_chain}"

    # 5. Record new event in reinitialized service (verifies sequential continuation)
    evt3 = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp="2026-10-18T10:02:00Z",
        request_digest="sha256:digest003",
        destination="groq",
        decision=PolicyOutcome.BLOCK,
        rule_ids=["BLOCK-CRITICAL"],
        risk_score=90,
        policy_version="policy-v1",
        detector_version="detector-v1",
        status="blocked",
        provider_called=False,
        redaction_count=0,
        latency_ms=5,
    )
    rec3 = service2.record(evt3)
    assert rec3.sequence_number == 3
    # Critical Invariant: prev_hash of post-restart event must bind the last pre-restart event
    assert rec3.prev_hash == rec2.record_hash

    # 6. Verify unified pre- and post-restart chain remains unbroken
    valid_unified_chain, reason_unified = service2.verify_chain_integrity()
    assert valid_unified_chain is True, f"Unified chain broken: {reason_unified}"

    # 7. Create Epoch 2 checkpoint on reinitialized service (verifies epoch chaining)
    chk2 = service2.create_checkpoint(start_sequence=3, end_sequence=3)
    assert chk2.epoch_index == 2
    assert chk2.start_sequence == 3
    assert chk2.end_sequence == 3
    assert chk2.event_count == 1
    assert chk2.prev_checkpoint_hash == chk1.checkpoint_hash

    # Verify both checkpoints list cleanly
    all_chks = service2.list_checkpoints()
    assert len(all_chks) == 2
    assert [c.epoch_index for c in all_chks] == [1, 2]


def test_audit_service_fails_closed_on_db_storage_failure(tmp_path: Path) -> None:
    """Verify that database write failures raise AuditWriteException and fail closed."""
    db_file = str(tmp_path / "failing_audit.db")
    service = AuditService(db_path=db_file)

    # Corrupt or lock the database table to force failure
    with sqlite3.connect(db_file) as conn:
        conn.execute("DROP TABLE audit_events")
        conn.commit()

    evt = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp="2026-10-18T10:00:00Z",
        request_digest="sha256:digest",
        destination="groq",
        decision=PolicyOutcome.ALLOW,
        rule_ids=[],
        risk_score=10,
        policy_version="policy-v1",
        detector_version="detector-v1",
        status="completed",
        provider_called=True,
        redaction_count=0,
        latency_ms=50,
    )

    with pytest.raises(AuditWriteException) as exc_info:
        service.record(evt)

    assert exc_info.value.code == "AUDIT_STORAGE_FAILURE"
    assert exc_info.value.status_code == 503


def test_orchestration_and_review_durable_audit_lifecycle(tmp_path: Path) -> None:
    """Verify that end-to-end request flows, review approvals, and provider dispatch persist across restarts."""
    from backend.app.core.permits import generate_review_permit
    from backend.app.models.context import ContextModel
    from backend.app.models.enums import ContextClassification, ContextDataSubject, ContextPurpose, Destination, ExecutionStatus
    from backend.app.models.requests import PromptRequest
    from backend.app.orchestrator.service import OrchestrationService
    from backend.app.providers.mock import MockProvider
    from backend.app.reviews.repository import ReviewRepository

    db_file = str(tmp_path / "lifecycle_audit.db")

    # =========================================================================
    # Phase 1: Request creates review ticket and persists ticket_created audit event
    # =========================================================================
    audit1 = AuditService(db_path=db_file)
    repo1 = ReviewRepository(db_path=db_file)
    mock_provider = MockProvider()
    orchestrator1 = OrchestrationService(
        audit_service=audit1,
        review_repo=repo1,
        mock_provider=mock_provider,
    )

    req = PromptRequest(
        prompt="Patient blood test results enclosed for medical review.",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.HEALTH_INFORMATION,
            data_subject=ContextDataSubject.SELF,
            classification=ContextClassification.PUBLIC,
        ),
    )

    resp1 = orchestrator1.execute(req)
    assert resp1.status == ExecutionStatus.REVIEW_PENDING
    assert resp1.decision == PolicyOutcome.REVIEW
    ticket_id = resp1.ticket_id
    assert ticket_id is not None

    # Check that event was persisted in SQLite
    events1 = audit1.get_persisted_events()
    assert len(events1) == 1
    assert events1[0]["event_type"] == "ticket_created"
    assert events1[0]["sequence_number"] == 1
    assert events1[0]["prev_hash"] == GENESIS_HASH

    # Simulate Service Restart
    del orchestrator1, audit1, repo1

    # =========================================================================
    # Phase 2: Post-restart human approval records ticket_approved audit event
    # =========================================================================
    audit2 = AuditService(db_path=db_file)
    repo2 = ReviewRepository(db_path=db_file)

    # Approve ticket
    approved_ticket = repo2.approve_ticket(
        ticket_id=ticket_id,
        rationale="Approved by medical compliance officer for research.",
        reviewer_id="officer_alice",
    )

    permit = generate_review_permit(
        ticket_id=approved_ticket.ticket_id,
        request_digest=approved_ticket.request_digest,
        approved_by="officer_alice",
        assigned_role=approved_ticket.assigned_role,
    )
    repo2.record_permit(
        permit_nonce=permit.permit_nonce,
        ticket_id=permit.ticket_id,
        request_digest=permit.request_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
    )

    # Record ticket approval in audit log
    audit2.record(
        AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=approved_ticket.decided_at,
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
            actor_id="officer_alice",
            rationale="Approved by medical compliance officer for research.",
        )
    )

    # Verify event 2 persisted and chained to event 1
    events2 = audit2.get_persisted_events()
    assert len(events2) == 2
    assert events2[1]["event_type"] == "ticket_approved"
    assert events2[1]["sequence_number"] == 2
    assert events2[1]["prev_hash"] == events2[0]["record_hash"]

    # =========================================================================
    # Phase 3: Dispatch with permit records permit_consumed_and_dispatched event
    # =========================================================================
    orchestrator2 = OrchestrationService(
        audit_service=audit2,
        review_repo=repo2,
        mock_provider=mock_provider,
    )

    req_with_permit = req.model_copy(update={"review_permit": permit})
    resp2 = orchestrator2.execute(req_with_permit)
    assert resp2.status == ExecutionStatus.COMPLETED
    assert resp2.output is not None

    events3 = audit2.get_persisted_events()
    assert len(events3) == 3
    assert events3[2]["event_type"] == "permit_consumed_and_dispatched"
    assert events3[2]["sequence_number"] == 3
    assert events3[2]["prev_hash"] == events2[1]["record_hash"]

    # Checkpoint and verify across restart
    chk = audit2.create_checkpoint(start_sequence=1, end_sequence=3)
    assert chk.epoch_index == 1
    assert chk.event_count == 3

    del orchestrator2, audit2, repo2

    # Post-restart verification
    audit3 = AuditService(db_path=db_file)
    valid_chain, _ = audit3.verify_chain_integrity()
    assert valid_chain is True
    valid_chk, _ = audit3.verify_checkpoint_integrity(chk.checkpoint_id)
    assert valid_chk is True


def test_actual_api_application_path_persistence_across_restart(
    tmp_path: Path, client: TestClient
) -> None:
    """Verify that events recorded via actual FastAPI API routes persist durably and verify across restart."""
    from backend.app.api.v1 import audit as audit_module
    from backend.app.api.v1 import prompts as prompts_module
    from backend.app.api.v1 import reviews as reviews_module
    from backend.app.core.auth import create_reviewer_token
    from backend.app.orchestrator.service import OrchestrationService
    from backend.app.providers.mock import MockProvider
    from backend.app.reviews.repository import ReviewRepository

    db_file = str(tmp_path / "actual_api_durable.db")

    # Wire all actual FastAPI router modules to use the dedicated test database
    app_audit = AuditService(db_path=db_file)
    app_repo = ReviewRepository(db_path=db_file)
    app_orch = OrchestrationService(
        audit_service=app_audit,
        review_repo=app_repo,
        mock_provider=MockProvider(),
    )

    prompts_module.orchestrator = app_orch
    reviews_module.review_repo = app_repo
    reviews_module.audit_service = app_audit
    audit_module.audit_service = app_audit

    reviewer_token = create_reviewer_token(
        user_id="dr_compliance",
        roles=["compliance_officer", "auditor"],
    )
    auth_headers = {"Authorization": f"Bearer {reviewer_token}"}

    # Step 1: Prompt execute (ALLOW) via actual API route
    resp1 = client.post(
        "/v1/prompts/execute",
        json={
            "prompt": "Explain the concept of zero knowledge proofs.",
            "destination": "mock",
            "context": {
                "purpose": "general_question",
                "data_subject": "none",
                "classification": "public",
            },
        },
    )
    assert resp1.status_code == 200
    assert resp1.json()["decision"] == "ALLOW"

    # Step 2: Prompt execute (REVIEW) via actual API route -> creates ticket
    resp2 = client.post(
        "/v1/prompts/execute",
        json={
            "prompt": "Patient diagnosed with stage 2 hypertension prescribed lisinopril.",
            "destination": "mock",
            "context": {
                "purpose": "health_information",
                "data_subject": "self",
                "classification": "public",
            },
        },
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "review_pending"
    ticket_id = resp2.json()["ticket_id"]
    assert ticket_id is not None

    # Step 3: Approve review ticket via actual API route -> records ticket_approved
    resp3 = client.post(
        f"/v1/reviews/{ticket_id}/approve",
        headers=auth_headers,
        json={"rationale": "Legitimate clinical research study authorization."},
    )
    assert resp3.status_code == 200
    assert resp3.json()["status"] == "APPROVED"
    permit = resp3.json()["permit"]
    assert permit is not None

    # Step 4: Re-execute prompt with permit via actual API route -> records permit_consumed_and_dispatched
    resp4 = client.post(
        "/v1/prompts/execute",
        json={
            "prompt": "Patient diagnosed with stage 2 hypertension prescribed lisinopril.",
            "destination": "mock",
            "context": {
                "purpose": "health_information",
                "data_subject": "self",
                "classification": "public",
            },
            "review_permit": permit,
        },
    )
    assert resp4.status_code == 200
    assert resp4.json()["status"] == "completed"

    # Step 5: Verify all 4 events exist in the database
    persisted = app_audit.get_persisted_events()
    assert len(persisted) == 4
    event_types = [e["event_type"] for e in persisted]
    assert event_types == [
        "prompt_execution",
        "ticket_created",
        "ticket_approved",
        "permit_consumed_and_dispatched",
    ]

    # Cleanly release current service references
    del app_orch, app_audit, app_repo

    # =========================================================================
    # Step 6: Simulate full service restart and verify from fresh AuditService
    # =========================================================================
    fresh_audit = AuditService(db_path=db_file)

    # 1. Verify persisted events
    reloaded_events = fresh_audit.get_persisted_events()
    assert len(reloaded_events) == 4
    for i in range(4):
        assert reloaded_events[i]["sequence_number"] == i + 1

    # 2. Verify hash chain integrity across all API events
    valid_chain, reason = fresh_audit.verify_chain_integrity()
    assert valid_chain is True, f"Hash chain integrity failed: {reason}"

    # 3. Create checkpoint over API events
    chk = fresh_audit.create_checkpoint(start_sequence=1, end_sequence=4)
    assert chk.epoch_index == 1
    assert chk.event_count == 4

    # =========================================================================
    # Step 7: Simulate second restart and verify checkpoint integrity
    # =========================================================================
    fresh_audit_2 = AuditService(db_path=db_file)
    valid_chk, chk_reason = fresh_audit_2.verify_checkpoint_integrity(chk.checkpoint_id)
    assert valid_chk is True, f"Checkpoint integrity failed: {chk_reason}"

    latest = fresh_audit_2.get_latest_checkpoint()
    assert latest is not None
    assert latest.checkpoint_id == chk.checkpoint_id
    assert latest.epoch_index == 1


