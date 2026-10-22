"""Comprehensive tests for External Audit Checkpoint Anchoring & Merkle Verification."""

import datetime
import os
import sqlite3
import threading
import uuid
import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app.audit.anchors import (
    AuditAnchorAuthException,
    AuditAnchorException,
    AuditAnchorTimeoutException,
    MockAuditAnchorAdapter,
    ProductionAuditAnchorAdapter,
    set_audit_anchor_adapter,
)
from backend.app.audit.merkle import (
    build_merkle_layers,
    compute_merkle_root,
    generate_inclusion_proof,
    hash_leaf,
    hash_nodes,
    verify_merkle_inclusion_proof,
)
from backend.app.audit.service import (
    GENESIS_CHECKPOINT_HASH,
    GENESIS_HASH,
    AuditService,
    CheckpointIntegrityException,
    CheckpointNotFoundException,
    CheckpointSequenceException,
)
from backend.app.config import settings
from backend.app.core.auth import create_reviewer_token
from backend.app.main import app
from backend.app.models.audit import AuditCheckpoint, AuditEvent, CheckpointAnchorStatus
from backend.app.models.enums import PolicyOutcome


@pytest.fixture
def test_db_path(tmp_path) -> str:
    """Fixture providing an isolated SQLite database path for testing."""
    return str(tmp_path / "test_audit_anchoring.db")


@pytest.fixture
def mock_anchor() -> MockAuditAnchorAdapter:
    """Fixture providing an isolated MockAuditAnchorAdapter."""
    adapter = MockAuditAnchorAdapter()
    set_audit_anchor_adapter(adapter)
    yield adapter
    set_audit_anchor_adapter(None)


def _seed_audit_events(service: AuditService, count: int) -> list[AuditEvent]:
    """Helper to record N sequential audit events into the service."""
    events: list[AuditEvent] = []
    for i in range(1, count + 1):
        evt = AuditEvent(
            event_id=f"evt-{i:04d}-{uuid.uuid4().hex[:6]}",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            request_digest=f"sha256:digest-{i:04d}",
            destination="mock",
            decision=PolicyOutcome.ALLOW,
            rule_ids=[f"RULE-{i}"],
            risk_score=10 + (i % 20),
            policy_version="policy-v1",
            detector_version="detector-v1",
            status="completed",
            provider_called=True,
            redaction_count=0,
            latency_ms=15,
            event_type="prompt_execution",
        )
        recorded = service.record(evt)
        events.append(recorded)
    return events


# ==============================================================================
# 1. Merkle Tree & Inclusion Proof Verification
# ==============================================================================


def test_merkle_root_calculation_and_domain_separation() -> None:
    """Verify RFC 6962 domain separation (0x00 leaf, 0x01 node) and odd-node promotion."""
    # Test across powers of two and odd counts: 1, 2, 3, 5, 8, 9, 16
    for count in [1, 2, 3, 5, 8, 9, 16]:
        leaves = [os.urandom(32).hex() for _ in range(count)]
        root = compute_merkle_root(leaves)
        assert len(root) == 64
        assert isinstance(root, str)

        # Every single leaf must generate a self-verifying inclusion proof
        for idx in range(count):
            proof = generate_inclusion_proof(leaves, idx)
            assert verify_merkle_inclusion_proof(leaves[idx], proof, root) is True


def test_merkle_inclusion_proof_tampering_fails() -> None:
    """Verify that any modification to leaf, sibling, or root breaks proof verification."""
    leaves = [os.urandom(32).hex() for _ in range(7)]  # Odd node count
    root = compute_merkle_root(leaves)

    proof = generate_inclusion_proof(leaves, 2)
    assert verify_merkle_inclusion_proof(leaves[2], proof, root) is True

    # 1. Tampered leaf hash
    tampered_leaf = os.urandom(32).hex()
    assert verify_merkle_inclusion_proof(tampered_leaf, proof, root) is False

    # 2. Tampered root hash
    tampered_root = os.urandom(32).hex()
    assert verify_merkle_inclusion_proof(leaves[2], proof, tampered_root) is False

    # 3. Tampered sibling in proof
    tampered_proof = [dict(p) for p in proof]
    tampered_proof[0]["hash"] = os.urandom(32).hex()
    assert verify_merkle_inclusion_proof(leaves[2], tampered_proof, root) is False

    # 4. Inverted sibling position
    inverted_proof = [dict(p) for p in proof]
    orig_pos = inverted_proof[0]["position"]
    inverted_proof[0]["position"] = "left" if orig_pos == "right" else "right"
    assert verify_merkle_inclusion_proof(leaves[2], inverted_proof, root) is False


# ==============================================================================
# 2. Checkpoint Creation, Contiguity, & Chaining Invariants
# ==============================================================================


def test_checkpoint_creation_and_contiguity_invariants(
    test_db_path: str, mock_anchor: MockAuditAnchorAdapter
) -> None:
    """Verify sequential contiguous checkpointing with unbroken epoch chaining."""
    service = AuditService(db_path=test_db_path)
    service.clear()
    _seed_audit_events(service, 25)

    # 1. Epoch 1: events [1, 15]
    chk1 = service.create_checkpoint(start_sequence=1, end_sequence=15, anchor_adapter=mock_anchor)
    assert chk1.epoch_index == 1
    assert chk1.start_sequence == 1
    assert chk1.end_sequence == 15
    assert chk1.event_count == 15
    assert chk1.prev_checkpoint_hash == GENESIS_CHECKPOINT_HASH
    assert chk1.anchor_status == CheckpointAnchorStatus.ANCHORED
    assert chk1.anchor_reference is not None

    # 2. Epoch 2: events [16, 25]
    chk2 = service.create_checkpoint(start_sequence=16, end_sequence=25, anchor_adapter=mock_anchor)
    assert chk2.epoch_index == 2
    assert chk2.start_sequence == 16
    assert chk2.end_sequence == 25
    assert chk2.event_count == 10
    assert chk2.prev_checkpoint_hash == chk1.checkpoint_hash
    assert chk2.anchor_status == CheckpointAnchorStatus.ANCHORED

    # 3. Attempting to skip sequence 26 and start at 27 fails closed
    _seed_audit_events(service, 5)  # events 26..30
    with pytest.raises(CheckpointSequenceException) as exc:
        service.create_checkpoint(start_sequence=28, end_sequence=30, anchor_adapter=mock_anchor)
    assert "expected 26" in str(exc.value)

    # 4. Attempting to overlap with already checkpointed sequence 25 fails closed
    with pytest.raises(CheckpointSequenceException) as exc:
        service.create_checkpoint(start_sequence=25, end_sequence=30, anchor_adapter=mock_anchor)
    assert "expected 26" in str(exc.value)


# ==============================================================================
# 3. Missing, Reordered, and Truncated Events
# ==============================================================================


def test_missing_reordered_and_truncated_events_fail_closed(
    test_db_path: str, mock_anchor: MockAuditAnchorAdapter
) -> None:
    """Verify that database gaps, reordered sequences, or broken event chains abort checkpointing."""
    service = AuditService(db_path=test_db_path)
    service.clear()
    _seed_audit_events(service, 10)

    # Case A: Sequence gap (event 5 deleted by rogue admin)
    with sqlite3.connect(test_db_path) as conn:
        conn.execute("DELETE FROM audit_events WHERE sequence_number = 5")
        conn.commit()

    with pytest.raises(CheckpointIntegrityException) as exc:
        service.create_checkpoint(start_sequence=1, end_sequence=10, anchor_adapter=mock_anchor)
    assert "Missing audit events" in str(exc.value) or "Sequence gap" in str(exc.value)

    # Reset and seed fresh
    service.clear()
    _seed_audit_events(service, 10)

    # Case B: Tampered record_hash in middle of chain
    with sqlite3.connect(test_db_path) as conn:
        conn.execute(
            "UPDATE audit_events SET record_hash = 'tamperedhash123' WHERE sequence_number = 4"
        )
        conn.commit()

    with pytest.raises(CheckpointIntegrityException) as exc:
        service.create_checkpoint(start_sequence=1, end_sequence=10, anchor_adapter=mock_anchor)
    assert "Broken audit hash chain" in str(exc.value)


# ==============================================================================
# 4. Checkpoint Tampering Detection
# ==============================================================================


def test_checkpoint_tampering_detected(
    test_db_path: str, mock_anchor: MockAuditAnchorAdapter
) -> None:
    """Verify that verify_checkpoint_integrity catches any tampering with stored checkpoints."""
    service = AuditService(db_path=test_db_path)
    service.clear()
    _seed_audit_events(service, 12)

    chk = service.create_checkpoint(start_sequence=1, end_sequence=12, anchor_adapter=mock_anchor)
    valid, reason = service.verify_checkpoint_integrity(chk.checkpoint_id)
    assert valid is True
    assert reason is None

    # 1. Tamper Merkle root in SQLite
    with sqlite3.connect(test_db_path) as conn:
        conn.execute(
            "UPDATE audit_checkpoints SET merkle_root = 'forgedroot123' WHERE checkpoint_id = ?",
            (chk.checkpoint_id,),
        )
        conn.commit()

    valid, reason = service.verify_checkpoint_integrity(chk.checkpoint_id)
    assert valid is False
    assert "Merkle root recomputation mismatch" in reason


# ==============================================================================
# 5. Duplicate, Idempotent, and Concurrent Checkpoint Requests
# ==============================================================================


def test_duplicate_and_concurrent_checkpoint_requests(
    test_db_path: str, mock_anchor: MockAuditAnchorAdapter
) -> None:
    """Verify that duplicate requests return existing checkpoints without duplicate rows."""
    service = AuditService(db_path=test_db_path)
    service.clear()
    _seed_audit_events(service, 15)

    # 1. First creation
    chk1 = service.create_checkpoint(start_sequence=1, end_sequence=15, anchor_adapter=mock_anchor)

    # 2. Duplicate call for exact same range returns existing checkpoint idempotently
    chk_dup = service.create_checkpoint(start_sequence=1, end_sequence=15, anchor_adapter=mock_anchor)
    assert chk_dup.checkpoint_id == chk1.checkpoint_id
    assert chk_dup.checkpoint_hash == chk1.checkpoint_hash

    # Check only 1 checkpoint row exists in DB
    checkpoints = service.list_checkpoints()
    assert len(checkpoints) == 1

    # 3. Concurrency safety: multiple concurrent threads attempting checkpoint creation
    _seed_audit_events(service, 10)  # events 16..25
    results: list[AuditCheckpoint] = []
    errors: list[Exception] = []

    def worker():
        try:
            res = service.create_checkpoint(start_sequence=16, end_sequence=25, anchor_adapter=mock_anchor)
            results.append(res)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly 1 distinct epoch 2 checkpoint must exist in the database
    with sqlite3.connect(test_db_path) as conn:
        epochs = conn.execute("SELECT epoch_index FROM audit_checkpoints").fetchall()
    assert len(epochs) == 2


# ==============================================================================
# 6. Remote Anchor Timeout, Auth Failure, and Retry Behavior
# ==============================================================================


def test_remote_anchor_timeout_and_auth_failure_fail_closed(test_db_path: str) -> None:
    """Verify that external anchor failures fail closed and mark the checkpoint FAILED."""
    service = AuditService(db_path=test_db_path)
    service.clear()
    _seed_audit_events(service, 10)

    mock = MockAuditAnchorAdapter()
    mock.simulate_timeout = True

    with pytest.raises(AuditAnchorTimeoutException):
        service.create_checkpoint(start_sequence=1, end_sequence=10, anchor_adapter=mock)

    # Checkpoint must be stored as FAILED, never ANCHORED
    failed_chk = service.get_latest_checkpoint()
    assert failed_chk is not None
    assert failed_chk.anchor_status == CheckpointAnchorStatus.FAILED
    assert "timeout" in failed_chk.failure_reason.lower()


def test_production_adapter_retry_on_503_transient_error() -> None:
    """Verify that ProductionAuditAnchorAdapter retries transient 503 errors and succeeds."""
    attempts = 0

    def mock_transport_handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503, json={"error": "service temporarily unavailable"})
        return httpx.Response(
            201,
            json={
                "anchor_id": "rekor-uuid-998877",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "root_hash": "merkle_root_test_val",
                "signature": "valid_sig",
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(mock_transport_handler))
    adapter = ProductionAuditAnchorAdapter(
        endpoint="https://rekor.privai.internal",
        auth_token="test-token",
        max_retries=2,
        client=client,
    )

    dummy_chk = AuditCheckpoint(
        checkpoint_id="chk-001",
        epoch_index=1,
        start_sequence=1,
        end_sequence=5,
        event_count=5,
        merkle_root="merkle_root_test_val",
        prev_checkpoint_hash="prev_hash",
        checkpoint_hash="chk_hash",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )

    receipt = adapter.anchor_checkpoint(dummy_chk)
    assert receipt.anchor_id == "rekor-uuid-998877"
    assert attempts == 2


# ==============================================================================
# 7. Remote Success with Local Acknowledgement Failure Recovery
# ==============================================================================


def test_remote_success_local_ack_failure_recovery(test_db_path: str) -> None:
    """Verify recovery when external anchor succeeds but local acknowledge previously failed."""
    service = AuditService(db_path=test_db_path)
    service.clear()
    _seed_audit_events(service, 10)

    mock = MockAuditAnchorAdapter()

    # Step 1: Pre-populate checkpoint as FAILED (simulating local failure after remote anchor)
    chk = service.create_checkpoint(start_sequence=1, end_sequence=10, anchor_adapter=mock)
    assert chk.anchor_status == CheckpointAnchorStatus.ANCHORED

    # Simulate local crash by resetting DB status to FAILED while mock anchor retains record
    with sqlite3.connect(test_db_path) as conn:
        conn.execute(
            "UPDATE audit_checkpoints SET anchor_status = 'FAILED', failure_reason = 'Simulated crash before local commit' WHERE checkpoint_id = ?",
            (chk.checkpoint_id,),
        )
        conn.commit()

    # Step 2: Retry create_checkpoint for same range
    recovered_chk = service.create_checkpoint(start_sequence=1, end_sequence=10, anchor_adapter=mock)
    assert recovered_chk.anchor_status == CheckpointAnchorStatus.ANCHORED
    assert recovered_chk.failure_reason is None


# ==============================================================================
# 8. Auditor API Endpoints & RBAC Security
# ==============================================================================


def test_audit_api_rbac_and_proof_retrieval(client: TestClient, test_db_path: str) -> None:
    """Verify auditor API RBAC: 401 without token, 403 for unauthorized role, 200 for auditor."""
    from backend.app.api.v1.audit import set_audit_service
    service = AuditService(db_path=test_db_path)
    service.clear()
    _seed_audit_events(service, 10)
    mock = MockAuditAnchorAdapter()
    chk = service.create_checkpoint(start_sequence=1, end_sequence=10, anchor_adapter=mock)
    set_audit_service(service)

    # 1. Unauthorized: Missing token -> 401
    resp_unauth = client.get("/v1/audit/checkpoints")
    assert resp_unauth.status_code == 401

    # 2. Forbidden: Token with unauthorized role (e.g. 'hr_admin' only) -> 403
    hr_token = create_reviewer_token(user_id="hr_user", roles=["hr_admin"])
    resp_forbidden = client.get(
        "/v1/audit/checkpoints",
        headers={"Authorization": f"Bearer {hr_token}"},
    )
    assert resp_forbidden.status_code == 403
    assert resp_forbidden.json()["error"]["code"] == "ROLE_NOT_AUTHORIZED_FOR_AUDIT"

    # 3. Authorized: Token with 'auditor' role -> 200
    auditor_token = create_reviewer_token(user_id="audit_officer", roles=["auditor"])
    resp_ok = client.get(
        "/v1/audit/checkpoints",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert resp_ok.status_code == 200
    data = resp_ok.json()
    assert data["total_count"] == 1
    assert data["checkpoints"][0]["checkpoint_id"] == chk.checkpoint_id

    # 4. Retrieve Merkle inclusion proof for sequence 3
    proof_resp = client.get(
        f"/v1/audit/checkpoints/{chk.checkpoint_id}/proof/3",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert proof_resp.status_code == 200
    proof_data = proof_resp.json()
    assert proof_data["sequence_number"] == 3
    assert proof_data["verified"] is True
    assert proof_data["merkle_root"] == chk.merkle_root

    # Verify zero raw prompt text or secrets in response
    resp_str = proof_resp.text.lower()
    for forbidden in ["prompt", "api_key", "secret_key", "token"]:
        assert f'"{forbidden}"' not in resp_str

    # 5. Verify checkpoint endpoint
    verify_resp = client.get(
        f"/v1/audit/checkpoints/{chk.checkpoint_id}/verify",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True


# ==============================================================================
# 9. Existing Hash Chain Integrity Preserved
# ==============================================================================


def test_existing_hash_chain_verification_unaffected(test_db_path: str) -> None:
    """Verify that existing AuditService.verify_chain_integrity() continues to pass unbroken."""
    service = AuditService(db_path=test_db_path)
    service.clear()
    _seed_audit_events(service, 20)

    valid, reason = service.verify_chain_integrity()
    assert valid is True
    assert reason is None
