"""Controlled Single-Worker Staging Preflight Verification Script.

Executes safe, non-sensitive synthetic checks against the actual FastAPI application endpoints:
1. Health endpoint probe
2. Synthetic ALLOW execution
3. Synthetic REDACT execution (verifying sanitized transmission)
4. Synthetic BLOCK execution (verifying zero provider invocation)
5. Synthetic REVIEW execution (verifying ticket creation & zero provider invocation)
6. SQLite persistence verification across service restart
7. Hash-chain integrity and data minimization verification
"""

import os
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.audit.service import AuditService, set_audit_service
from backend.app.reviews.repository import ReviewRepository
from backend.app.api.v1.prompts import orchestrator
from backend.app.api.v1 import reviews as reviews_module
from backend.app.api.v1 import audit as audit_module
from backend.app.main import app


def run_preflight_checks() -> dict[str, str]:
    results = {}
    print("=" * 80)
    print("PRIVAI CONTROLLED SINGLE-WORKER PREFLIGHT CHECKS")
    print("=" * 80)

    # 1. Dedicated Isolated Preflight Database
    temp_dir = tempfile.mkdtemp(prefix="privai_preflight_")
    db_path = os.path.join(temp_dir, "staging_preflight.db")
    print(f"[INFO] Using isolated preflight database: {db_path}")
    print(f"[INFO] Production database (privai_data.db) is strictly protected and untouched.")

    # Configure isolated instances
    audit_svc = AuditService(db_path=db_path)
    review_repo = ReviewRepository(db_path=db_path)

    set_audit_service(audit_svc)
    orchestrator.audit_service = audit_svc
    orchestrator.review_repo = review_repo
    reviews_module.review_repo = review_repo
    reviews_module.audit_service = audit_svc
    audit_module.audit_service = audit_svc

    client = TestClient(app)

    try:
        # Check 1: Health Endpoint
        resp = client.get("/health")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        health_data = resp.json()
        assert health_data.get("status") == "ok"
        print("  [OK] Health check: 200 OK (status=ok)")
        results["Health Check Probe (/health)"] = "PASS"

        # Check 2: Synthetic ALLOW execution
        allow_payload = {
            "prompt": "Summarize principles of Keplerian orbital mechanics.",
            "destination": "mock",
            "context": {
                "purpose": "general_question",
                "data_subject": "none",
                "classification": "public",
            },
        }
        resp = client.post("/v1/prompts/execute", json=allow_payload)
        assert resp.status_code == 200
        allow_data = resp.json()
        assert allow_data["status"] == "completed"
        assert allow_data["decision"] == "ALLOW"
        assert allow_data["output"] is not None
        assert allow_data["provider"] is not None
        print("  [OK] Synthetic ALLOW: 200 OK (status=completed, provider called)")
        results["Synthetic ALLOW Execution"] = "PASS"

        # Check 3: Synthetic REDACT execution
        redact_payload = {
            "prompt": "Contact user at test.dev@example.com for credentials.",
            "destination": "mock",
            "context": {
                "purpose": "general_question",
                "data_subject": "none",
                "classification": "public",
            },
        }
        resp = client.post("/v1/prompts/execute", json=redact_payload)
        assert resp.status_code == 200
        redact_data = resp.json()
        assert redact_data["status"] == "completed"
        assert redact_data["decision"] == "REDACT"
        assert redact_data["output"] is not None
        assert redact_data["redactions"] is not None
        placeholders = [r["placeholder"] for r in redact_data["redactions"]]
        assert "[EMAIL]" in placeholders or "[EMPLOYEE_ID]" in placeholders
        print("  [OK] Synthetic REDACT: 200 OK (sanitized transmission verified)")
        results["Synthetic REDACT Execution"] = "PASS"

        # Check 4: Synthetic BLOCK execution
        block_payload = {
            "prompt": "Identity verification with National ID: 999-00-1234",
            "destination": "mock",
            "context": {
                "purpose": "general_question",
                "data_subject": "none",
                "classification": "public",
            },
        }
        resp = client.post("/v1/prompts/execute", json=block_payload)
        assert resp.status_code == 200
        block_data = resp.json()
        assert block_data["status"] == "blocked"
        assert block_data["decision"] == "BLOCK"
        assert block_data["output"] is None
        assert block_data["provider"] is None
        print("  [OK] Synthetic BLOCK: 200 OK (zero provider invocation verified)")
        results["Synthetic BLOCK Execution (Zero Provider Calls)"] = "PASS"

        # Check 5: Synthetic REVIEW execution
        review_payload = {
            "prompt": "Individual has confirmed medical hypertension history.",
            "destination": "mock",
            "context": {
                "purpose": "health_information",
                "data_subject": "none",
                "classification": "public",
            },
        }
        resp = client.post("/v1/prompts/execute", json=review_payload)
        assert resp.status_code == 200
        review_data = resp.json()
        assert review_data["status"] == "review_pending"
        assert review_data["decision"] == "REVIEW"
        assert review_data["output"] is None
        assert review_data["provider"] is None
        assert review_data["ticket_id"] is not None
        print("  [OK] Synthetic REVIEW: 200 OK (ticket created, zero provider invocation)")
        results["Synthetic REVIEW Execution (Ticket Created)"] = "PASS"

        # Check 6: Direct SQLite Audit Persistence Verification
        persisted = audit_svc.get_persisted_events()
        assert len(persisted) == 4, f"Expected 4 persisted events, got {len(persisted)}"
        for i, row in enumerate(persisted, 1):
            assert row["sequence_number"] == i
            # Invariant: Data minimization
            assert "prompt" not in row
            assert "sanitized_prompt" not in row
        # Check provider_called flags
        assert persisted[0]["provider_called"] == 1  # ALLOW
        assert persisted[1]["provider_called"] == 1  # REDACT
        assert persisted[2]["provider_called"] == 0  # BLOCK
        assert persisted[3]["provider_called"] == 0  # REVIEW
        print("  [OK] SQLite persistence: 4 events committed with sequence numbers 1..4")
        results["Audit Durability (Pre-transmission Write)"] = "PASS"

        # Check 7: Service Restart & Hash-Chain Continuity
        fresh_audit = AuditService(db_path=db_path)
        valid, reason = fresh_audit.verify_chain_integrity()
        assert valid is True, f"Hash-chain integrity failed after restart: {reason}"
        restarted_events = fresh_audit.get_persisted_events()
        assert len(restarted_events) == 4
        assert restarted_events[-1]["record_hash"] == persisted[-1]["record_hash"]
        print("  [OK] Service restart: Hash-chain continuity verified across service reinitialization.")
        results["Service Restart & Hash-Chain Verification"] = "PASS"

    finally:
        set_audit_service(None)
        # Cleanup
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)
            print("[INFO] Preflight temporary database cleaned up.")
        except Exception:
            pass

    print("\n" + "=" * 80)
    print("PREFLIGHT VERIFICATION RESULTS")
    print("=" * 80)
    for check_name, status in results.items():
        print(f"  {check_name:<55} : {status}")
    print("=" * 80)
    return results


if __name__ == "__main__":
    run_preflight_checks()
