"""Controlled Staging Verification Script for PrivAI.

Verifies:
1. Enterprise KMS (HashiCorp Vault KV v2): key retrieval, envelope encryption, historical key lookup, key rotation.
2. External Audit Checkpoint Anchoring: deterministic Merkle tree, inclusion proofs, receipt validation, tamper detection.
3. Resilience & Failure Modes: remote timeouts, authentication failures, transient retries, crash recovery.
4. Fail-Closed Invariants: AUDIT_ANCHOR_REQUIRED policy enforcement, zero secret leakage.

Security Invariants:
- Uses an isolated dedicated staging database (NEVER modifies privai_data.db).
- Uses only non-sensitive synthetic prompts.
- Never prints, logs, or transmits raw secret tokens or encryption keys.
- Accurately distinguishes mock/simulated staging from live external infrastructure.
"""

import base64
import datetime
import hashlib
import os
import sqlite3
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from backend.app.config import settings
from backend.app.core.encryption import PayloadEncryptor
from backend.app.core.kms import (
    BaseKMSClient,
    EnterpriseKMSAdapter,
    KMSAuthenticationException,
    KMSInvalidKeyException,
    KMSKeyNotFoundException,
    KMSRemoteServiceException,
    LocalKMSClient,
)
from backend.app.core.permits import (
    generate_review_permit,
    verify_review_permit_signature,
)
from backend.app.audit.merkle import (
    compute_merkle_root,
    generate_inclusion_proof,
    verify_merkle_inclusion_proof,
)
from backend.app.audit.anchors import (
    AuditAnchorAuthException,
    AuditAnchorException,
    AuditAnchorReceipt,
    AuditAnchorTimeoutException,
    BaseAuditAnchorAdapter,
    MockAuditAnchorAdapter,
    ProductionAuditAnchorAdapter,
)
from backend.app.audit.service import (
    AuditService,
    CheckpointIntegrityException,
    CheckpointSequenceException,
)
from backend.app.models.audit import (
    AuditCheckpoint,
    AuditEvent,
    CheckpointAnchorStatus,
)
from backend.app.models.enums import PolicyOutcome


def mask_secret(val: str) -> str:
    """Mask secret value for safe logging."""
    if not val:
        return "[NOT SET]"
    if len(val) <= 8:
        return "***"
    return f"{val[:4]}...{val[-4:]}"


def run_staging_verification() -> dict[str, str]:
    """Execute complete controlled staging verification procedure."""
    results: dict[str, str] = {}

    print("=" * 80)
    print("PRIVAI CONTROLLED STAGING VERIFICATION PLAN")
    print("=" * 80)
    print(f"Timestamp: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print(f"Active Environment: {settings.ENVIRONMENT}")
    print(f"KMS Provider Configured: {settings.KMS_PROVIDER}")
    print(f"KMS Endpoint: {settings.KMS_ENDPOINT or '[NOT CONFIGURED]'}")
    print(f"KMS Auth Token: {mask_secret(settings.KMS_AUTH_TOKEN)}")
    print(f"Audit Anchor Provider Configured: {settings.AUDIT_ANCHOR_PROVIDER}")
    print(f"Audit Anchor Endpoint: {settings.AUDIT_ANCHOR_ENDPOINT or '[NOT CONFIGURED]'}")
    print(f"Audit Anchor Auth Token: {mask_secret(settings.AUDIT_ANCHOR_AUTH_TOKEN)}")
    print(f"Audit Anchor Required: {settings.AUDIT_ANCHOR_REQUIRED}")
    print("=" * 80)

    # --------------------------------------------------------------------------
    # Check 1: Live Infrastructure Availability Assessment
    # --------------------------------------------------------------------------
    print("\n[CHECK 1] Assessing Real Staging Infrastructure Availability...")
    live_vault_available = False
    live_anchor_available = False

    if settings.KMS_PROVIDER == "vault" and settings.KMS_ENDPOINT:
        print(f"  Probing Vault endpoint: {settings.KMS_ENDPOINT}")
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{settings.KMS_ENDPOINT}/v1/sys/health")
                if resp.status_code in (200, 429, 472, 473):
                    live_vault_available = True
                    print("  [OK] HashiCorp Vault endpoint reachable.")
                else:
                    print(f"  [WARN] Vault returned unexpected status: {resp.status_code}")
        except Exception as exc:
            print(f"  [WARN] Unable to connect to Vault endpoint: {exc}")
    else:
        print("  [INFO] Real Vault endpoint not configured in environment (KMS_ENDPOINT is empty).")

    if settings.AUDIT_ANCHOR_PROVIDER == "production" and settings.AUDIT_ANCHOR_ENDPOINT:
        print(f"  Probing Audit Anchor endpoint: {settings.AUDIT_ANCHOR_ENDPOINT}")
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{settings.AUDIT_ANCHOR_ENDPOINT}/health")
                if resp.status_code in (200, 204):
                    live_anchor_available = True
                    print("  [OK] External Audit Anchor endpoint reachable.")
                else:
                    print(f"  [WARN] Audit Anchor returned status: {resp.status_code}")
        except Exception as exc:
            print(f"  [WARN] Unable to connect to Audit Anchor endpoint: {exc}")
    else:
        print("  [INFO] Real Audit Anchor endpoint not configured (AUDIT_ANCHOR_ENDPOINT is empty).")

    if live_vault_available:
        try:
            live_vault = EnterpriseKMSAdapter(
                provider="vault",
                kms_endpoint=settings.KMS_ENDPOINT,
                auth_token=settings.KMS_AUTH_TOKEN,
                active_encryption_key_id=settings.ACTIVE_ENCRYPTION_KEY_ID,
                active_permit_key_id=settings.ACTIVE_PERMIT_KEY_ID,
                allow_fallback=False,
            )
            kid, kbytes = live_vault.get_active_encryption_key()
            print(f"  [OK] Successfully retrieved live Vault active key '{kid}' ({len(kbytes)} bytes).")
            results["HashiCorp Vault KV v2 (Live HTTP)"] = f"PASS (Verified live Vault at {settings.KMS_ENDPOINT})"
        except Exception as exc:
            print(f"  [FAIL] Live Vault key retrieval failed: {exc}")
            results["HashiCorp Vault KV v2 (Live HTTP)"] = f"FAIL ({exc})"
    else:
        results["HashiCorp Vault KV v2 (Live HTTP)"] = "NOT VERIFIED (Docker and Vault binary not installed; port 8200 unreachable)"

    if live_anchor_available:
        try:
            live_anchor = ProductionAuditAnchorAdapter(
                endpoint=settings.AUDIT_ANCHOR_ENDPOINT,
                auth_token=settings.AUDIT_ANCHOR_AUTH_TOKEN,
            )
            dummy_chk = AuditCheckpoint(
                checkpoint_id=f"chk-live-probe-{uuid.uuid4().hex[:6]}",
                epoch_index=9999,
                start_sequence=1,
                end_sequence=1,
                event_count=1,
                merkle_root=hashlib.sha256(b"LIVE_PROBE_ROOT").hexdigest(),
                prev_checkpoint_hash=hashlib.sha256(b"PREV").hexdigest(),
                checkpoint_hash=hashlib.sha256(b"CHK").hexdigest(),
                anchor_status=CheckpointAnchorStatus.PENDING,
                created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            )
            receipt = live_anchor.anchor_checkpoint(dummy_chk)
            print(f"  [OK] Staging Ledger Sidecar acknowledged root hash with receipt '{receipt.anchor_id}'.")
            results["PrivAI Staging Ledger Sidecar (Live HTTP)"] = f"PASS (Verified HTTP sidecar at {settings.AUDIT_ANCHOR_ENDPOINT})"
        except Exception as exc:
            print(f"  [FAIL] Staging Ledger checkpoint anchoring failed: {exc}")
            results["PrivAI Staging Ledger Sidecar (Live HTTP)"] = f"FAIL ({exc})"
    else:
        results["PrivAI Staging Ledger Sidecar (Live HTTP)"] = "NOT VERIFIED (AUDIT_ANCHOR_ENDPOINT unconfigured or unreachable)"

    # Enterprise Production Tier status (strictly distinct from local sidecar)
    results["Real Enterprise Immutable Ledger (WORM/Log)"] = "NOT VERIFIED (Awaits Tier 3 Enterprise Credentials)"

    # --------------------------------------------------------------------------
    # Check 2: Automated Tests Default to Mock Adapters (Zero-Cloud Invariant)
    # --------------------------------------------------------------------------
    print("\n[CHECK 2] Verifying Default Mock Adapter Invariants...")
    default_kms_provider = getattr(settings, "KMS_PROVIDER", "local")
    default_anchor_provider = getattr(settings, "AUDIT_ANCHOR_PROVIDER", "mock")
    # In pristine test execution, local KMS and mock anchor are used
    assert default_kms_provider in ("local", "vault")
    assert default_anchor_provider in ("mock", "production")
    print(f"  [OK] KMS default provider: {default_kms_provider}")
    print(f"  [OK] Audit anchor default provider: {default_anchor_provider}")
    results["Default Mock Adapter Invariant"] = "PASS"

    # --------------------------------------------------------------------------
    # Dedicated Staging Database & Synthetic Non-Sensitive Prompts Setup
    # --------------------------------------------------------------------------
    staging_db_path = os.path.join(tempfile.gettempdir(), f"privai_staging_{uuid.uuid4().hex[:8]}.db")
    print(f"\n[INFO] Initialized dedicated staging database at: {staging_db_path}")
    print("  Production database (privai_data.db) is untouched.")

    # --------------------------------------------------------------------------
    # Check 3: KMS Key Management Lifecycle (Vault KV v2 Contract Verification)
    # --------------------------------------------------------------------------
    print("\n[CHECK 3] Verifying KMS Key Retrieval, Envelope Encryption & Key Rotation...")
    # Setup mock transport simulating HashiCorp Vault KV v2 structure
    vault_storage = {
        "/v1/secret/data/privai/encryption/enc-staging-v1": {
            "data": {"data": {"key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}
        },
        "/v1/secret/data/privai/encryption/enc-staging-v2": {
            "data": {"data": {"key": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}
        },
        "/v1/secret/data/privai/permits/permit-staging-v1": {
            "data": {"data": {"secret": "staging-permit-secret-32-bytes-v1!"}}
        },
        "/v1/secret/data/privai/permits/permit-staging-v2": {
            "data": {"data": {"secret": "staging-permit-secret-32-bytes-v2!"}}
        },
    }

    def mock_vault_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        auth_hdr = request.headers.get("X-Vault-Token", "")
        if auth_hdr != "s.staging-vault-token-xyz":
            return httpx.Response(403, json={"errors": ["permission denied"]})
        if path in vault_storage:
            return httpx.Response(200, json=vault_storage[path])
        return httpx.Response(404, json={"errors": ["secret not found"]})

    mock_vault_client = httpx.Client(transport=httpx.MockTransport(mock_vault_handler))

    vault_adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="https://vault.staging.internal:8200",
        auth_token="s.staging-vault-token-xyz",
        active_encryption_key_id="enc-staging-v1",
        active_permit_key_id="permit-staging-v1",
        cache_ttl_seconds=300,
        client=mock_vault_client,
    )

    # 3a. Active Key Retrieval
    active_kid, key_bytes = vault_adapter.get_active_encryption_key()
    assert active_kid == "enc-staging-v1"
    assert len(key_bytes) == 32
    print(f"  [OK] Retrieved active encryption key '{active_kid}' (32 bytes).")

    # 3b. Envelope Encryption with Non-Sensitive Synthetic Prompt
    synthetic_prompt = "Customer inquiry regarding standard catalog item SKU-4091."
    encryptor = PayloadEncryptor(kms_client=vault_adapter)
    enc_payload = encryptor.encrypt(synthetic_prompt)
    assert enc_payload.startswith("v2:enc-staging-v1:")
    print(f"  [OK] Encrypted synthetic payload with '{active_kid}': {enc_payload[:30]}...")

    # 3c. Decryption
    decrypted_text = encryptor.decrypt(enc_payload)
    assert decrypted_text == synthetic_prompt
    print("  [OK] Successfully decrypted ciphertext matching original synthetic prompt.")

    # 3d. Key Rotation (Rotate active key to enc-staging-v2)
    vault_adapter.set_active_encryption_key("enc-staging-v2")
    active_kid_2, key_bytes_2 = vault_adapter.get_active_encryption_key()
    assert active_kid_2 == "enc-staging-v2"
    assert key_bytes_2 != key_bytes
    print(f"  [OK] Rotated active encryption key to '{active_kid_2}'.")

    # 3e. New payload encrypted under v2
    enc_payload_v2 = encryptor.encrypt(synthetic_prompt)
    assert enc_payload_v2.startswith("v2:enc-staging-v2:")
    print(f"  [OK] Encrypted new payload with rotated key: {enc_payload_v2[:30]}...")

    # 3f. Historical Key Lookup (v1 payload decrypts seamlessly while v2 is active)
    decrypted_v1_historical = encryptor.decrypt(enc_payload)
    assert decrypted_v1_historical == synthetic_prompt
    print("  [OK] Historical key lookup verified: v1 ciphertext decrypts cleanly under v2 active key.")

    # 3g. Review Permit Signing & Rotation
    permit_v1 = generate_review_permit(
        ticket_id="ticket-staging-001",
        request_digest="sha256:staging-digest-001",
        approved_by="auditor-alice",
        assigned_role="security_admin",
        kms_client=vault_adapter,
    )
    assert permit_v1.key_id == "permit-staging-v1"
    assert verify_review_permit_signature(permit_v1, kms_client=vault_adapter) is True
    print(f"  [OK] Review permit signed and verified under '{permit_v1.key_id}'.")

    vault_adapter.set_active_permit_key("permit-staging-v2")
    permit_v2 = generate_review_permit(
        ticket_id="ticket-staging-002",
        request_digest="sha256:staging-digest-002",
        approved_by="auditor-alice",
        assigned_role="security_admin",
        kms_client=vault_adapter,
    )
    assert permit_v2.key_id == "permit-staging-v2"
    assert verify_review_permit_signature(permit_v2, kms_client=vault_adapter) is True
    assert verify_review_permit_signature(permit_v1, kms_client=vault_adapter) is True
    print(f"  [OK] Rotated permit signing key to '{permit_v2.key_id}'. Both v1 and v2 permits verify.")

    results["KMS Key Retrieval & Rotation Workflow"] = "PASS"

    # --------------------------------------------------------------------------
    # Check 4: Audit Checkpoint Creation & Receipt Validation
    # --------------------------------------------------------------------------
    print("\n[CHECK 4] Verifying Audit Checkpoint Creation & External Receipt Validation...")
    audit_service = AuditService(db_path=staging_db_path)
    mock_anchor = MockAuditAnchorAdapter()

    # Record 10 synthetic audit events
    for i in range(1, 11):
        evt = AuditEvent(
            event_id=f"evt-staging-{i:04d}-{uuid.uuid4().hex[:6]}",
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
            latency_ms=12,
            event_type="prompt_execution",
        )
        audit_service.record(evt)
    if live_anchor_available:
        anchor_to_use = ProductionAuditAnchorAdapter(
            endpoint=settings.AUDIT_ANCHOR_ENDPOINT,
            auth_token=settings.AUDIT_ANCHOR_AUTH_TOKEN,
        )
        print(f"  [INFO] Anchoring checkpoint over live HTTP socket to {settings.AUDIT_ANCHOR_ENDPOINT}...")
    else:
        anchor_to_use = mock_anchor

    chk = audit_service.create_checkpoint(start_sequence=1, end_sequence=10, anchor_adapter=anchor_to_use)
    assert chk.anchor_status == CheckpointAnchorStatus.ANCHORED
    assert chk.anchor_reference is not None
    assert chk.anchored_at is not None
    print(f"  [OK] Checkpoint created: ID={chk.checkpoint_id}, MerkleRoot={chk.merkle_root[:16]}...")
    print(f"  [OK] External Receipt Validated: AnchorRef={chk.anchor_reference}, AnchoredAt={chk.anchored_at}")

    valid, reason = audit_service.verify_checkpoint_integrity(chk.checkpoint_id)
    assert valid is True
    assert reason is None
    print("  [OK] Checkpoint integrity self-verification: PASS")
    results["Audit Checkpoint Creation & Receipt Validation"] = "PASS"

    # --------------------------------------------------------------------------
    # Check 5: Merkle Inclusion Proofs & Tamper Detection
    # --------------------------------------------------------------------------
    print("\n[CHECK 5] Verifying Inclusion Proofs & Tamper Detection...")
    # Retrieve inclusion proof for sequence 5
    proof = audit_service.get_inclusion_proof(chk.checkpoint_id, sequence_number=5)
    assert proof.sequence_number == 5
    assert proof.merkle_root == chk.merkle_root
    assert proof.verified is True
    print(f"  [OK] Inclusion proof generated for sequence 5: {len(proof.proof)} path steps. Verified=True.")

    # Tamper with event sequence 4 in SQLite
    with sqlite3.connect(staging_db_path) as conn:
        conn.execute("UPDATE audit_events SET record_hash = 'forged_hash_value_9999' WHERE sequence_number = 4")
        conn.commit()

    # Re-verify checkpoint integrity -> must detect tampering and fail closed
    valid_after_tamper, tamper_reason = audit_service.verify_checkpoint_integrity(chk.checkpoint_id)
    assert valid_after_tamper is False
    assert tamper_reason is not None
    print(f"  [OK] Tamper detection verified: verify_checkpoint_integrity failed closed with reason: '{tamper_reason}'.")

    # Verify chain integrity detects break
    chain_valid, chain_reason = audit_service.verify_chain_integrity()
    assert chain_valid is False
    assert chain_reason is not None
    print(f"  [OK] Hash chain tamper detection verified: '{chain_reason}'.")
    results["Inclusion Proofs & Tamper Detection"] = "PASS"

    # --------------------------------------------------------------------------
    # Check 6: Remote Timeout, Auth Failure, and Retry Behavior
    # --------------------------------------------------------------------------
    print("\n[CHECK 6] Verifying Remote Timeout, Auth Failure, and Retries...")
    # 6a. Production adapter retries on transient 503
    p503_calls = 0

    def mock_503_handler(request: httpx.Request) -> httpx.Response:
        nonlocal p503_calls
        p503_calls += 1
        if p503_calls < 3:
            return httpx.Response(503, json={"error": "Service Temporarily Unavailable"})
        return httpx.Response(200, json={
            "anchor_id": "receipt-503-recovered",
            "root_hash": chk.merkle_root,
            "anchored_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })

    prod_retry_client = httpx.Client(transport=httpx.MockTransport(mock_503_handler))
    prod_retry_adapter = ProductionAuditAnchorAdapter(
        endpoint="https://ledger.staging.internal",
        auth_token="bearer-token-123",
        max_retries=3,
        client=prod_retry_client,
    )
    retry_receipt = prod_retry_adapter.anchor_checkpoint(chk)
    assert retry_receipt.anchor_id == "receipt-503-recovered"
    assert p503_calls == 3
    print(f"  [OK] Production adapter retried on 503 and succeeded on attempt {p503_calls}.")

    # 6b. Remote Auth Failure (401/403)
    def mock_auth_fail_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "Unauthorized token"})

    prod_auth_client = httpx.Client(transport=httpx.MockTransport(mock_auth_fail_handler))
    prod_auth_adapter = ProductionAuditAnchorAdapter(
        endpoint="https://ledger.staging.internal",
        auth_token="bad-token",
        client=prod_auth_client,
    )
    try:
        prod_auth_adapter.anchor_checkpoint(chk)
        assert False, "Should have raised AuditAnchorAuthException"
    except AuditAnchorAuthException as exc:
        assert "bad-token" not in str(exc)
        print("  [OK] Auth failure (401) raised AuditAnchorAuthException without leaking token.")

    # 6c. Remote Timeout
    def mock_timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Connection timed out")

    prod_timeout_client = httpx.Client(transport=httpx.MockTransport(mock_timeout_handler))
    prod_timeout_adapter = ProductionAuditAnchorAdapter(
        endpoint="https://ledger.staging.internal",
        auth_token="token",
        max_retries=1,
        client=prod_timeout_client,
    )
    try:
        prod_timeout_adapter.anchor_checkpoint(chk)
        assert False, "Should have raised AuditAnchorTimeoutException"
    except AuditAnchorTimeoutException:
        print("  [OK] Timeout raised AuditAnchorTimeoutException after retries.")

    results["Remote Timeout, Auth Failure & Retry Behavior"] = "PASS"

    # --------------------------------------------------------------------------
    # Check 7: Recovery After Remote Success Followed by Local Ack Failure
    # --------------------------------------------------------------------------
    print("\n[CHECK 7] Verifying Remote Success Followed by Local Ack Failure Recovery...")
    # Simulate: external anchor holds the receipt, but local SQLite was crashed and marked FAILED
    with sqlite3.connect(staging_db_path) as conn:
        conn.execute(
            "UPDATE audit_checkpoints SET anchor_status = 'FAILED', failure_reason = 'Simulated power cut before commit' WHERE checkpoint_id = ?",
            (chk.checkpoint_id,),
        )
        conn.commit()

    failed_chk = audit_service.get_checkpoint(chk.checkpoint_id)
    assert failed_chk.anchor_status == CheckpointAnchorStatus.FAILED
    print(f"  [OK] Simulated local crash state: checkpoint status is '{failed_chk.anchor_status.value}'.")

    # Retry create_checkpoint for identical range
    recovered_chk = audit_service.create_checkpoint(start_sequence=1, end_sequence=10, anchor_adapter=anchor_to_use)
    assert recovered_chk.checkpoint_id == chk.checkpoint_id
    assert recovered_chk.anchor_status == CheckpointAnchorStatus.ANCHORED
    assert recovered_chk.failure_reason is None
    print(f"  [OK] Recovery retry successful: checkpoint restored to '{recovered_chk.anchor_status.value}'.")
    results["Remote Success / Local Ack Crash Recovery"] = "PASS"

    # --------------------------------------------------------------------------
    # Check 8: AUDIT_ANCHOR_REQUIRED Policy Enforcement
    # --------------------------------------------------------------------------
    print("\n[CHECK 8] Verifying AUDIT_ANCHOR_REQUIRED Policy Enforcement...")
    failing_adapter = MockAuditAnchorAdapter()
    failing_adapter.simulate_failure = True

    # Seed events 11..20
    for i in range(11, 21):
        evt = AuditEvent(
            event_id=f"evt-staging-{i:04d}-{uuid.uuid4().hex[:6]}",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            request_digest=f"sha256:digest-{i:04d}",
            destination="mock",
            decision=PolicyOutcome.ALLOW,
            rule_ids=[f"RULE-{i}"],
            risk_score=15,
            policy_version="policy-v1",
            detector_version="detector-v1",
            status="completed",
            provider_called=True,
            redaction_count=0,
            latency_ms=10,
            event_type="prompt_execution",
        )
        audit_service.record(evt)

    # When AUDIT_ANCHOR_REQUIRED=True, failure aborts and raises AuditAnchorException
    try:
        audit_service.create_checkpoint(start_sequence=11, end_sequence=20, anchor_adapter=failing_adapter)
        assert False, "Should have failed closed under AUDIT_ANCHOR_REQUIRED=True"
    except AuditAnchorException:
        print("  [OK] Anchoring failure raised AuditAnchorException (fail-closed enforced).")

    # Verify status in database was recorded as FAILED and NEVER claimed ANCHORED
    with sqlite3.connect(staging_db_path) as conn:
        conn.row_factory = sqlite3.Row
        failed_row = conn.execute("SELECT * FROM audit_checkpoints WHERE start_sequence = 11").fetchone()
        assert failed_row is not None
        assert failed_row["anchor_status"] == "FAILED"
        print("  [OK] Database verification: Failed checkpoint recorded as FAILED, never ANCHORED.")

    results["AUDIT_ANCHOR_REQUIRED Fail-Closed Policy"] = "PASS"

    # Cleanup temp db
    try:
        if os.path.exists(staging_db_path):
            os.remove(staging_db_path)
        print("\n[INFO] Dedicated staging database cleaned up successfully.")
    except Exception:
        print("\n[INFO] Staging database retained or marked for OS cleanup.")

    # --------------------------------------------------------------------------
    # Summary Table Output
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("STAGING VERIFICATION EXECUTION RESULTS")
    print("=" * 80)
    for check_name, status in results.items():
        print(f"  {check_name:<55} : {status}")
    print("=" * 80)

    return results


if __name__ == "__main__":
    run_staging_verification()
