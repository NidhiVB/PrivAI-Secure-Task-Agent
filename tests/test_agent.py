"""Comprehensive security and integration tests for PrivAI Secure Task Agent."""

import hashlib
import os
import sqlite3
import tempfile
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.agent.models import (
    AgentStepStatus,
    AgentTaskCreateRequest,
    AgentTaskResumeRequest,
    AgentTaskStatus,
)
from backend.app.agent.planner import BoundedPlanner
from backend.app.agent.repository import AgentRepository
from backend.app.agent.service import AgentService
from backend.app.agent.tools import (
    ToolAuthorizationException,
    ToolValidationException,
    execute_tool_safe,
)
from backend.app.api.v1.agent import set_agent_service
from backend.app.audit.service import AuditService, set_audit_service
from backend.app.config import settings
from backend.app.core.permits import (
    PermitSignatureException,
    generate_review_permit,
    verify_review_permit_signature,
)
from backend.app.main import app
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    PolicyOutcome,
)
from backend.app.models.requests import PromptRequest
from backend.app.models.reviews import ReviewStatus
from backend.app.orchestrator.service import OrchestrationService
from backend.app.reviews.repository import ReviewRepository

EXPECTED_HISTORICAL_SHA256 = "2f6b17e2805fbc23790da28a2a2d995ddd2ec4afb91e4037707dc4a29fe0c400"
EXPECTED_HISTORICAL_TICKETS = 99


@pytest.fixture(autouse=True)
def isolate_test_environment(tmp_path):
    """Enforce complete database isolation for all tests."""
    test_db = str(tmp_path / "test_isolated.db")
    test_agent_db = str(tmp_path / "test_agent.db")

    audit_svc = AuditService(db_path=test_db)
    review_repo = ReviewRepository(db_path=test_db)
    agent_repo = AgentRepository(db_path=test_agent_db)

    set_audit_service(audit_svc)
    orchestrator = OrchestrationService(audit_service=audit_svc, review_repo=review_repo)
    service = AgentService(repository=agent_repo, orchestrator=orchestrator)
    set_agent_service(service)

    yield {
        "service": service,
        "agent_repo": agent_repo,
        "review_repo": review_repo,
        "audit_svc": audit_svc,
        "orchestrator": orchestrator,
    }

    set_audit_service(None)


def get_historical_db_fingerprint() -> tuple[str, int]:
    if not os.path.exists("privai_data.db"):
        return ("", -1)
    with open("privai_data.db", "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    conn = sqlite3.connect("privai_data.db")
    tickets = conn.execute("SELECT count(*) FROM review_tickets").fetchone()[0]
    conn.close()
    return sha, tickets



# ------------------------------------------------------------------------------
# 1. Tool Allowlist and Schema Validation Tests
# ------------------------------------------------------------------------------

def test_tool_allowlist_enforcement():
    """Unapproved tools must be rejected with ToolAuthorizationException."""
    for forbidden_tool in ["execute_shell", "run_bash", "network_download", "send_email", "make_payment"]:
        with pytest.raises(ToolAuthorizationException) as exc_info:
            execute_tool_safe(forbidden_tool, {"arg": "val"})
        assert "not in the server allowlist" in str(exc_info.value)


def test_tool_schema_validation():
    """Tool inputs must strictly match schema; path traversal must be rejected."""
    # Path traversal in read_document
    with pytest.raises(ToolValidationException):
        execute_tool_safe("read_document", {"document_id": "../../etc/passwd"})

    with pytest.raises(ToolValidationException):
        execute_tool_safe("read_document", {"document_id": "dir/file.txt"})

    # Invalid input for search_documents
    with pytest.raises(ToolValidationException):
        execute_tool_safe("search_documents", {"query": ""})

    # Path traversal in format_report
    with pytest.raises(ToolValidationException):
        execute_tool_safe("format_report", {
            "title": "Title",
            "sections": [],
            "output_filename": "../../../escaped_report.md",
        })


# ------------------------------------------------------------------------------
# 2. Safe ALLOW Flow
# ------------------------------------------------------------------------------

def test_agent_allow_task_execution(isolate_test_environment):
    """Safe tasks execute through the guarded pipeline with ALLOW decision."""
    service = isolate_test_environment["service"]

    req = AgentTaskCreateRequest(
        goal="Read reference company policy company_policy.txt and format summary report",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.GENERAL_QUESTION,
            data_subject=ContextDataSubject.NONE,
            classification=ContextClassification.PUBLIC,
        ),
    )
    task = service.create_and_run_task(req)

    assert task.status == AgentTaskStatus.COMPLETED
    assert task.completed_steps > 0
    assert task.blocked_steps == 0
    assert task.final_answer is not None
    assert "completed task" in task.final_answer.lower()
    assert len(task.audit_references) > 0


# ------------------------------------------------------------------------------
# 3. Sensitive Data REDACT Flow
# ------------------------------------------------------------------------------

def test_agent_redact_sanitization(isolate_test_environment):
    """Sensitive entities in tool inputs must be sanitized before tool execution."""
    service = isolate_test_environment["service"]

    # Goal targeting incident log containing test email and employee ID
    req = AgentTaskCreateRequest(
        goal="Summarize support details for incident_report_sample.txt with contact test.ops@example.com",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.SUMMARIZATION,
            data_subject=ContextDataSubject.EMPLOYEE,
            classification=ContextClassification.INTERNAL,
        ),
    )
    task = service.create_and_run_task(req)

    assert task.status == AgentTaskStatus.COMPLETED
    assert task.plan is not None

    # Check that steps were evaluated and any REDACT step has sanitized_tool_input
    redact_steps = [s for s in task.plan.steps if s.policy_decision == PolicyOutcome.REDACT]
    assert len(redact_steps) > 0

    for step in redact_steps:
        assert step.sanitized_tool_input is not None
        # Verify raw email was replaced
        raw_str = str(step.tool_input)
        sanitized_str = str(step.sanitized_tool_input)
        assert "test.ops@example.com" in raw_str
        assert "test.ops@example.com" not in sanitized_str
        assert "[EMAIL]" in sanitized_str


# ------------------------------------------------------------------------------
# 4. Mandatory BLOCK Flow (Zero Provider & Zero Tool Calls)
# ------------------------------------------------------------------------------

def test_agent_block_on_goal(isolate_test_environment):
    """High-risk prompt in goal triggers mandatory BLOCK with zero tool/provider calls."""
    service = isolate_test_environment["service"]

    req = AgentTaskCreateRequest(
        goal="Verify background records for National ID 999-00-1234 confidential file",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.GENERAL_QUESTION,
            data_subject=ContextDataSubject.NONE,
            classification=ContextClassification.PUBLIC,
        ),
    )
    task = service.create_and_run_task(req)

    assert task.status == AgentTaskStatus.BLOCKED
    assert task.blocked_steps == 1
    assert task.completed_steps == 0
    assert task.plan is None
    assert "blocked by privacy policy" in task.final_answer.lower()


def test_agent_block_on_step_input(isolate_test_environment):
    """National ID in planned step input stops the affected step with zero calls."""
    service = isolate_test_environment["service"]

    # Create task with clean goal, but manually add a step with National ID
    req = AgentTaskCreateRequest(
        goal="Read reference document company_policy.txt",
        destination=Destination.MOCK,
    )
    # Planner will generate steps; modify step 2 input to contain National ID
    task = service.create_and_run_task(req)
    # The normal task completes; now test a step with National ID
    from backend.app.agent.models import AgentStep
    malicious_step = AgentStep(
        step_number=1,
        description="Extract sensitive identity",
        tool_name="summarize_text",
        tool_input={"text": "National ID 999-00-1234 record", "max_sentences": 1},
    )
    task.plan.steps = [malicious_step]
    task.current_step_index = 0
    task.status = AgentTaskStatus.RUNNING

    updated_task = service._execute_task_steps(task)
    assert updated_task.status == AgentTaskStatus.BLOCKED
    assert updated_task.blocked_steps == 1
    assert updated_task.plan.steps[0].status == AgentStepStatus.BLOCKED
    assert updated_task.plan.steps[0].tool_output is None  # Zero tool execution


# ------------------------------------------------------------------------------
# 5. Compliance Human-in-the-Loop REVIEW Flow
# ------------------------------------------------------------------------------

def test_agent_review_suspension_and_resume(isolate_test_environment):
    """Health information triggers REVIEW, suspends task, and resumes with valid permit."""
    service = isolate_test_environment["service"]
    review_repo = isolate_test_environment["review_repo"]

    # Goal requiring compliance review
    req = AgentTaskCreateRequest(
        goal="Review patient clinical cardiovascular diagnosis history for medical evaluation",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.HEALTH_INFORMATION,
            data_subject=ContextDataSubject.SELF,
            classification=ContextClassification.PUBLIC,
        ),
    )
    task = service.create_and_run_task(req)

    # 1. Task suspended pending review
    assert task.status == AgentTaskStatus.WAITING_FOR_APPROVAL
    assert task.pending_ticket_id is not None
    assert task.waiting_steps == 1
    assert task.completed_steps == 0
    assert "suspended pending compliance human review approval" in task.final_answer

    # 2. Check ticket exists in ReviewRepository
    ticket = review_repo.get_ticket(task.pending_ticket_id)
    assert ticket is not None
    assert ticket.status == ReviewStatus.PENDING

    # 3. Compliance officer approves ticket
    review_repo.approve_ticket(
        ticket_id=ticket.ticket_id,
        rationale="Approved for clinical review demonstration",
        reviewer_id="compliance_dr_smith",
    )

    # 4. Mint signed review permit
    permit = generate_review_permit(
        ticket_id=ticket.ticket_id,
        request_digest=ticket.request_digest,
        approved_by="compliance_dr_smith",
        assigned_role="compliance_officer",
    )
    # Store permit in repository
    review_repo.record_permit(
        permit_nonce=permit.permit_nonce,
        ticket_id=ticket.ticket_id,
        request_digest=permit.request_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
    )

    # 5. Resume task with valid permit
    resume_req = AgentTaskResumeRequest(review_permit=permit)
    resumed_task = service.resume_task(task.task_id, resume_req)

    assert resumed_task.status == AgentTaskStatus.COMPLETED
    assert resumed_task.completed_steps > 0
    assert resumed_task.pending_ticket_id is None

    # 6. Anti-replay: Re-using the consumed permit must fail
    with pytest.raises(Exception):
        service.resume_task(task.task_id, resume_req)


# ------------------------------------------------------------------------------
# 6. Untrusted Document Prompt Injection Defense
# ------------------------------------------------------------------------------

def test_untrusted_document_prompt_injection(isolate_test_environment):
    """Embedded prompt injection in documents cannot override policy or grant permissions."""
    service = isolate_test_environment["service"]

    # Read adversarial document containing system instruction overrides and national ID
    req = AgentTaskCreateRequest(
        goal="Inspect external document adversarial_injection.txt",
        destination=Destination.MOCK,
    )
    task = service.create_and_run_task(req)

    # The document was read safely; if content was passed to downstream step containing
    # the National ID 999-00-1234, the firewall caught it!
    assert task.status in (AgentTaskStatus.COMPLETED, AgentTaskStatus.BLOCKED)

    # Verify no unauthorized tool (like shell or bash) was executed
    for s in task.plan.steps:
        assert s.tool_name in ("read_document", "summarize_text", "format_report", "search_documents")
        if s.tool_name == "read_document" and s.tool_output:
            assert s.tool_output.get("untrusted") is True


# ------------------------------------------------------------------------------
# 7. Step Limit and Fail-Closed Persistence
# ------------------------------------------------------------------------------

def test_step_limit_enforced():
    """Planner must never plan more than AGENT_MAX_STEPS."""
    planner = BoundedPlanner(max_steps=3)
    plan, outcome, reasons, explanation, sanitized = planner.create_plan(
        goal="Perform deep multi-document search across files",
        context=ContextModel(purpose=ContextPurpose.GENERAL_QUESTION, data_subject=ContextDataSubject.NONE, classification=ContextClassification.PUBLIC),
        destination=Destination.MOCK,
    )
    assert plan is not None
    assert len(plan.steps) <= 3
    assert plan.total_steps <= 3


def test_agent_fail_closed_on_audit_failure(isolate_test_environment):
    """Audit storage failure during execution must abort fail-closed."""
    service = isolate_test_environment["service"]
    audit_svc = isolate_test_environment["audit_svc"]

    audit_svc.set_failure_mode(True)

    req = AgentTaskCreateRequest(
        goal="Read reference document company_policy.txt",
        destination=Destination.MOCK,
    )
    with pytest.raises(Exception):
        service.create_and_run_task(req)


# ------------------------------------------------------------------------------
# 8. API Endpoint Tests
# ------------------------------------------------------------------------------

def test_agent_api_endpoints(isolate_test_environment):
    """Test FastAPI REST endpoints /v1/agent/tasks."""
    client = TestClient(app)

    # 1. Create task
    payload = {
        "goal": "Search documents for keyword policy and format summary",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    resp = client.post("/v1/agent/tasks", json=payload)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "task_id" in data
    task_id = data["task_id"]
    assert data["status"] in ("completed", "running")

    # 2. Get task
    get_resp = client.get(f"/v1/agent/tasks/{task_id}")
    assert get_resp.status_code == 200
    task_data = get_resp.json()
    assert task_data["task_id"] == task_id

    # 3. Get steps
    steps_resp = client.get(f"/v1/agent/tasks/{task_id}/steps")
    assert steps_resp.status_code == 200
    steps_data = steps_resp.json()
    assert steps_data["task_id"] == task_id
    assert len(steps_data["steps"]) > 0

    # 4. Non-existent task returns 404
    missing_resp = client.get("/v1/agent/tasks/task-nonexistent-123")
    assert missing_resp.status_code == 404


INITIAL_HISTORICAL_SHA, INITIAL_HISTORICAL_TICKETS = get_historical_db_fingerprint()


# ------------------------------------------------------------------------------
# 9. Historical Database Integrity Preservation Check
# ------------------------------------------------------------------------------

def test_historical_database_untouched():
    """Verify that privai_data.db is 100% bit-for-bit unchanged after all agent operations."""
    if not os.path.exists("privai_data.db"):
        pytest.skip(
            "Historical baseline database 'privai_data.db' is omitted from clean submission package per security policy."
        )
    sha, tickets = get_historical_db_fingerprint()
    assert sha == INITIAL_HISTORICAL_SHA, (
        f"Historical DB modified by agent test run! Initial: {INITIAL_HISTORICAL_SHA}, Post-run: {sha}"
    )
    assert tickets == INITIAL_HISTORICAL_TICKETS, (
        f"Historical ticket count modified by agent test run! Initial: {INITIAL_HISTORICAL_TICKETS}, Post-run: {tickets}"
    )

    # Verify that all 99 historical baseline tickets from Milestones 1-6 remain completely intact
    conn = sqlite3.connect("privai_data.db")
    baseline_count = conn.execute("SELECT count(*) FROM review_tickets WHERE rowid <= 99").fetchone()[0]
    conn.close()
    assert baseline_count == EXPECTED_HISTORICAL_TICKETS, (
        f"Historical 99 baseline tickets corrupted! Expected {EXPECTED_HISTORICAL_TICKETS}, found {baseline_count}"
    )


def test_startup_refuses_historical_database_in_development():
    """Startup validation must refuse to run if DATABASE_PATH points to privai_data.db in dev/staging."""
    from backend.app.config import Settings

    # 1. Unsafe configuration: pointing to privai_data.db in development
    unsafe_settings = Settings(
        ENVIRONMENT="development",
        DATABASE_PATH="privai_data.db",
        HISTORICAL_DATABASE_PATH="privai_data.db",
    )
    with pytest.raises(RuntimeError) as exc_info:
        unsafe_settings.validate_runtime_database_isolation()
    assert "UNSAFE RUNTIME DATABASE CONFIGURATION" in str(exc_info.value)
    assert "privai_data.db" in str(exc_info.value)

    # 2. Safe configuration: pointing to privai_dev.db in development
    safe_settings = Settings(
        ENVIRONMENT="development",
        DATABASE_PATH="privai_dev.db",
        HISTORICAL_DATABASE_PATH="privai_data.db",
    )
    # Should execute cleanly without raising
    safe_settings.validate_runtime_database_isolation()


