"""Comprehensive security, authorization, and workflow tests for Employee Privacy Demo."""

import hashlib
import os
from pathlib import Path
import sqlite3
import pytest
from fastapi.testclient import TestClient

from backend.app.agent.models import AgentTaskStatus
from backend.app.agent.repository import AgentRepository
from backend.app.agent.service import AgentService
from backend.app.audit.service import AuditService, set_audit_service
from backend.app.api.v1.agent import set_agent_service
from backend.app.core.exceptions import SecurityInvariantException
from backend.app.core.permits import generate_review_permit
from backend.app.employees.api import set_employee_service
from backend.app.employees.models import (
    DataClassification,
    EmployeeOperationRequest,
    EmployeeOperationType,
    FieldSensitivityTier,
)
from backend.app.employees.repository import (
    CANONICAL_DEMO_EMPLOYEES,
    EmployeeRepository,
)
from backend.app.employees.service import EmployeeService
from backend.app.main import app
from backend.app.models.enums import Destination, PolicyOutcome
from backend.app.models.reviews import ReviewStatus
from backend.app.orchestrator.service import OrchestrationService
from backend.app.reviews.repository import ReviewRepository

EXPECTED_HISTORICAL_SHA256 = "fc33fbde7aa5e0b70bc31623d75cfe908d6f125b62ee7aa605a36dd8c23fede6"


def get_db_fingerprint(db_filename: str) -> str:
    """Calculate SHA256 fingerprint of a database file."""
    with open(db_filename, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


@pytest.fixture
def isolated_demo_env(tmp_path: Path):
    """Enforce strict database isolation for employee demo tests."""
    test_db = str(tmp_path / "test_runtime.db")
    test_agent_db = str(tmp_path / "test_agent.db")
    test_emp_db = str(tmp_path / "test_demo_employees.db")

    audit_svc = AuditService(db_path=test_db)
    review_repo = ReviewRepository(db_path=test_db)
    agent_repo = AgentRepository(db_path=test_agent_db)
    emp_repo = EmployeeRepository(db_path=test_emp_db)

    set_audit_service(audit_svc)
    orchestrator = OrchestrationService(audit_service=audit_svc, review_repo=review_repo)
    agent_svc = AgentService(repository=agent_repo, orchestrator=orchestrator)
    set_agent_service(agent_svc)
    emp_svc = EmployeeService(repository=emp_repo, agent_service=agent_svc)
    set_employee_service(emp_svc)

    client = TestClient(app)

    yield {
        "client": client,
        "emp_service": emp_svc,
        "emp_repo": emp_repo,
        "agent_service": agent_svc,
        "review_repo": review_repo,
        "audit_svc": audit_svc,
    }

    set_audit_service(None)


# ==============================================================================
# 1. Synthetic Directory Seeding, Stability & Search Tests
# ==============================================================================

def test_canonical_employees_seeded(isolated_demo_env):
    """Verify exactly 15 synthetic records are seeded with valid structure."""
    emp_repo = isolated_demo_env["emp_repo"]
    employees = emp_repo.search_employees()
    assert len(employees) == 15
    assert len(CANONICAL_DEMO_EMPLOYEES) == 15

    # Verify all have EMP- prefix and unique IDs
    emp_ids = [e.employee_id for e in employees]
    assert len(set(emp_ids)) == 15
    for eid in emp_ids:
        assert eid.startswith("EMP-")


def test_synthetic_data_stability_across_reopen(isolated_demo_env):
    """Verify dataset remains identical and stable across repository reinitialization."""
    emp_repo = isolated_demo_env["emp_repo"]
    initial_records = emp_repo.search_employees()

    # Reinitialize repository pointing to same database
    reloaded_repo = EmployeeRepository(db_path=emp_repo.db_path)
    reloaded_records = reloaded_repo.search_employees()

    assert len(reloaded_records) == len(initial_records)
    for r1, r2 in zip(initial_records, reloaded_records):
        assert r1.employee_id == r2.employee_id
        assert r1.name == r2.name
        assert r1.department == r2.department
        assert r1.salary == r2.salary


def test_employee_search_and_filtering(isolated_demo_env):
    """Verify keyword search and department/classification filtering."""
    client = isolated_demo_env["client"]

    # Search by name
    res1 = client.get("/v1/employees?q=Rostova")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["total"] == 1
    assert data1["employees"][0]["employee_id"] == "EMP-1001"

    # Search by employee ID
    res2 = client.get("/v1/employees?q=EMP-1002")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["total"] == 1
    assert data2["employees"][0]["name"] == "Marcus Vance"

    # Filter by department
    res3 = client.get("/v1/employees?department=Engineering")
    assert res3.status_code == 200
    data3 = res3.json()
    assert data3["total"] >= 4
    for emp in data3["employees"]:
        assert emp["department"] == "Engineering"

    # Filter by classification
    res4 = client.get("/v1/employees?classification=RESTRICTED")
    assert res4.status_code == 200
    data4 = res4.json()
    assert data4["total"] == 2
    for emp in data4["employees"]:
        assert emp["data_classification"] == "RESTRICTED"


# ==============================================================================
# 2. Backend Authorization & Field Protection Tests
# ==============================================================================

def test_backend_field_authorization_enforcement(isolated_demo_env):
    """Verify backend returns explicit field authorization tiers and refuses raw sensitive access."""
    client = isolated_demo_env["client"]

    resp = client.get("/v1/employees/EMP-1002")
    assert resp.status_code == 200
    data = resp.json()

    auth_map = {f["field_name"]: f for f in data["field_authorizations"]}

    # Public fields: ALLOW
    assert auth_map["name"]["authorized_for_viewer"] is True
    assert auth_map["name"]["governance_action"] == "ALLOW"
    assert auth_map["department"]["authorized_for_viewer"] is True

    # Contact fields: REDACT
    assert auth_map["email"]["sensitivity_tier"] == FieldSensitivityTier.CONTACT_SENSITIVE.value
    assert auth_map["email"]["governance_action"] == "REDACT"
    assert "***" in auth_map["email"]["masked_display_value"]

    # Payroll fields: BLOCK
    assert auth_map["salary"]["sensitivity_tier"] == FieldSensitivityTier.RESTRICTED_PAYROLL.value
    assert auth_map["salary"]["authorized_for_viewer"] is False
    assert auth_map["salary"]["governance_action"] == "BLOCK"
    assert "UNAUTHORIZED PAYROLL ACCESS BLOCKED" in auth_map["salary"]["masked_display_value"]

    # Health fields: REVIEW
    assert auth_map["health_notes"]["sensitivity_tier"] == FieldSensitivityTier.COMPLIANCE_HEALTH.value
    assert auth_map["health_notes"]["authorized_for_viewer"] is False
    assert auth_map["health_notes"]["governance_action"] == "REVIEW"
    assert "COMPLIANCE OFFICER APPROVAL REQUIRED" in auth_map["health_notes"]["masked_display_value"]


def test_tampering_employee_id_fails_safely(isolated_demo_env):
    """Attempting invalid or non-existent employee ID returns 404 without leaking internal state."""
    client = isolated_demo_env["client"]

    resp = client.get("/v1/employees/EMP-9999")
    assert resp.status_code == 404
    data = resp.json()
    msg = data.get("detail") or data.get("error", {}).get("message", "")
    assert "not found" in msg.lower()


# ==============================================================================
# 3. Privacy Firewall & Agent Four Decisions Demonstration Scenarios
# ==============================================================================

def test_scenario_allow_basic_profile(isolated_demo_env):
    """Scenario ALLOW: Summarize permitted public employee profile."""
    client = isolated_demo_env["client"]

    req = {
        "employee_id": "EMP-1001",
        "operation": EmployeeOperationType.SUMMARIZE_PROFILE.value,
        "destination": "mock",
    }
    resp = client.post("/v1/employees/operations/execute", json=req)
    assert resp.status_code == 200
    data = resp.json()

    assert data["policy_decision"] == PolicyOutcome.ALLOW.value
    assert data["status"] == "completed"
    assert data["risk_score"] < 30
    assert len(data["steps"]) > 0
    assert data["final_answer"] is not None
    assert data["pending_ticket_id"] is None
    assert data["audit_reference"] is not None


def test_scenario_redact_contact_report(isolated_demo_env):
    """Scenario REDACT: Generate contact report with verified token sanitization."""
    client = isolated_demo_env["client"]

    req = {
        "employee_id": "EMP-1002",
        "operation": EmployeeOperationType.CONTACT_REPORT.value,
        "destination": "mock",
    }
    resp = client.post("/v1/employees/operations/execute", json=req)
    assert resp.status_code == 200
    data = resp.json()

    assert data["policy_decision"] == PolicyOutcome.REDACT.value
    assert data["status"] == "completed"
    assert "REDACT-EMAIL" in data["policy_reasons"] or "REDACT-PHONE" in data["policy_reasons"] or "REDACT-EMPLOYEE-ID" in data["policy_reasons"]

    # Controlled demonstration view tracks original and sanitized values
    assert "marcus.vance@privai-demo.internal" in data["original_test_values"].values()
    assert "[EMAIL]" in data["sanitized_values"].values()

    # Downstream verification: Raw email and phone NEVER leak into final answer or step output
    assert data["downstream_sanitized_confirmed"] is True
    assert "marcus.vance@privai-demo.internal" not in (data["final_answer"] or "")


def test_scenario_block_unauthorized_payroll(isolated_demo_env):
    """Scenario BLOCK: Attempt unauthorized payroll retrieval; zero provider and tool calls."""
    client = isolated_demo_env["client"]

    req = {
        "employee_id": "EMP-1002",
        "operation": EmployeeOperationType.REQUEST_PAYROLL.value,
        "destination": "mock",
    }
    resp = client.post("/v1/employees/operations/execute", json=req)
    assert resp.status_code == 200
    data = resp.json()

    assert data["policy_decision"] == PolicyOutcome.BLOCK.value
    assert data["status"] == "blocked"
    assert data["risk_score"] >= 80
    assert "BLOCK-UNAUTHORIZED-PAYROLL" in data["policy_reasons"] or "BLOCK-CONFIDENTIAL-HR-EMPID" in data["policy_reasons"]
    assert "blocked by privacy policy" in data["final_answer"].lower()

    # Invariant: Strictly zero provider calls made
    assert data["provider_called"] is False
    assert data["pending_ticket_id"] is None


def test_scenario_review_health_info_and_resume(isolated_demo_env):
    """Scenario REVIEW: Access sensitive medical data, suspend task, and resume with single-use permit."""
    client = isolated_demo_env["client"]
    review_repo = isolated_demo_env["review_repo"]
    agent_svc = isolated_demo_env["agent_service"]

    # Phase 1: Submit request requiring human review
    req = {
        "employee_id": "EMP-1003",
        "operation": EmployeeOperationType.REQUEST_HEALTH.value,
        "destination": "mock",
    }
    resp = client.post("/v1/employees/operations/execute", json=req)
    assert resp.status_code == 200
    data = resp.json()

    assert data["policy_decision"] == PolicyOutcome.REVIEW.value
    assert data["status"] == "waiting_for_approval"
    assert data["pending_ticket_id"] is not None
    assert "suspended pending compliance human review approval" in data["final_answer"].lower()

    ticket_id = data["pending_ticket_id"]
    task_id = data["task_id"]

    # Phase 2: Check review ticket exists in database
    ticket = review_repo.get_ticket(ticket_id)
    assert ticket is not None
    assert ticket.status == ReviewStatus.PENDING

    # Phase 3: Compliance officer approves ticket
    review_repo.approve_ticket(
        ticket_id=ticket.ticket_id,
        rationale="Authorized for occupational health assessment demonstration",
        reviewer_id="officer_dr_patel",
    )

    # Phase 4: Generate cryptographic review permit
    permit = generate_review_permit(
        ticket_id=ticket.ticket_id,
        request_digest=ticket.request_digest,
        approved_by="officer_dr_patel",
        assigned_role="compliance_officer",
    )
    review_repo.record_permit(
        permit_nonce=permit.permit_nonce,
        ticket_id=ticket.ticket_id,
        request_digest=permit.request_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
    )

    # Phase 5: Resume task with permit
    resume_req = {"review_permit": permit.model_dump()}
    resume_resp = client.post(f"/v1/agent/tasks/{task_id}/resume", json=resume_req)
    assert resume_resp.status_code == 200, resume_resp.json()
    resumed_data = resume_resp.json()
    assert resumed_data["status"] == "completed"
    assert resumed_data["completed_steps"] > 0


# ==============================================================================
# 4. Database Isolation and Reset Demo Data Tests
# ==============================================================================

def test_reset_demo_data_is_isolated(isolated_demo_env):
    """Reset Demo Data resets only the synthetic records and never touches historical DB."""
    client = isolated_demo_env["client"]
    emp_repo = isolated_demo_env["emp_repo"]

    # Delete some records to simulate demo changes
    with emp_repo._get_connection() as conn:
        conn.execute("DELETE FROM demo_employees WHERE employee_id = 'EMP-1001'")
        conn.commit()
    assert len(emp_repo.search_employees()) == 14

    # Historical DB SHA256 before reset (if present in environment)
    if os.path.exists("privai_data.db"):
        sha_hist_before = get_db_fingerprint("privai_data.db")
        assert sha_hist_before == EXPECTED_HISTORICAL_SHA256

    # Call Reset Demo Data
    reset_resp = client.post("/v1/employees/reset")
    assert reset_resp.status_code == 200
    reset_data = reset_resp.json()
    assert reset_data["status"] == "ok"
    assert reset_data["records_seeded"] == 15

    # Verify synthetic demo database has all 15 records restored
    assert len(emp_repo.search_employees()) == 15

    # Verify historical DB remains 100% untouched
    if os.path.exists("privai_data.db"):
        sha_hist_after = get_db_fingerprint("privai_data.db")
        assert sha_hist_after == EXPECTED_HISTORICAL_SHA256
    else:
        assert not os.path.exists("privai_data.db"), "Reset demo created privai_data.db!"


def test_employee_repository_refuses_historical_database():
    """EmployeeRepository fails closed if configured with protected historical database."""
    with pytest.raises(SecurityInvariantException):
        EmployeeRepository(db_path="privai_data.db")

    with pytest.raises(SecurityInvariantException):
        EmployeeRepository(db_path="privai_data_incident_forensic.db")
