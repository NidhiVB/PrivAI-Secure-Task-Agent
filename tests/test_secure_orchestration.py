"""Security and integration tests for Milestone 4: Secure Orchestration and Mock Provider Integration."""

import pytest
from fastapi.testclient import TestClient

from backend.app.audit.service import AuditService
from backend.app.core.exceptions import (
    AuditWriteException,
    DetectionException,
    PolicyUnavailableException,
    ProviderException,
    RedactionVerificationException,
    SecurityInvariantException,
)
from backend.app.detectors.detector import SensitiveDetector
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    ExecutionStatus,
    FindingCategory,
    PolicyOutcome,
)
from backend.app.models.findings import Finding
from backend.app.models.permit import ProviderPermit
from backend.app.models.requests import PromptRequest
from backend.app.orchestrator.service import OrchestrationService
from backend.app.policy.engine import DeterministicPolicyEngine
from backend.app.providers.mock import MockProvider
from backend.app.redaction.redactor import Redactor
from backend.app.redaction.verifier import RedactionVerifier
from backend.app.risk.scorer import RiskScorer


@pytest.fixture
def mock_provider() -> MockProvider:
    provider = MockProvider()
    provider.reset()
    return provider


@pytest.fixture
def audit_service() -> AuditService:
    service = AuditService()
    service.clear()
    return service


@pytest.fixture
def orchestrator(mock_provider: MockProvider, audit_service: AuditService) -> OrchestrationService:
    return OrchestrationService(
        mock_provider=mock_provider,
        audit_service=audit_service,
    )


@pytest.fixture
def public_context() -> ContextModel:
    return ContextModel(
        purpose=ContextPurpose.GENERAL_QUESTION,
        data_subject=ContextDataSubject.NONE,
        classification=ContextClassification.PUBLIC,
    )


# 1. Safe ALLOW prompt results in exactly one provider call (T-01)
def test_safe_allow_prompt_results_in_one_provider_call(
    orchestrator: OrchestrationService,
    mock_provider: MockProvider,
    public_context: ContextModel,
) -> None:
    """Verify clean ALLOW prompt invokes mock provider exactly once with original text."""
    prompt = "Explain Dijkstra's shortest path algorithm."
    req = PromptRequest(
        prompt=prompt,
        destination=Destination.MOCK,
        context=public_context,
    )

    response = orchestrator.execute(req)

    assert response.status == ExecutionStatus.COMPLETED
    assert response.decision == PolicyOutcome.ALLOW
    assert response.output == "Mock response generated locally."
    assert response.provider is not None
    assert response.provider.name == "mock"
    assert response.redactions is None

    # Invariant: Exactly one provider call, received exact original prompt
    assert mock_provider.call_count == 1
    assert mock_provider.received_prompts == [prompt]


# 2. REDACT results in one provider call containing only verified sanitized prompt (T-06)
def test_redact_results_in_one_provider_call_with_sanitized_prompt_only(
    orchestrator: OrchestrationService,
    mock_provider: MockProvider,
    public_context: ContextModel,
) -> None:
    """Verify sanitizable prompt invokes provider exactly once with verified sanitized text only."""
    synthetic_email = "alex.researcher@example.org"
    prompt = f"Please contact {synthetic_email} for datasets."
    req = PromptRequest(
        prompt=prompt,
        destination=Destination.MOCK,
        context=public_context,
    )

    response = orchestrator.execute(req)

    assert response.status == ExecutionStatus.COMPLETED
    assert response.decision == PolicyOutcome.REDACT
    assert response.redactions is not None
    assert len(response.redactions) == 1
    assert response.redactions[0].placeholder == "[EMAIL]"

    # Invariant: Exactly one provider call, received sanitized prompt, NEVER original sensitive value
    assert mock_provider.call_count == 1
    received = mock_provider.received_prompts[0]
    assert received == "Please contact [EMAIL] for datasets."
    assert synthetic_email not in received


# 3. BLOCK results in zero provider calls (T-07)
def test_block_results_in_zero_provider_calls(
    orchestrator: OrchestrationService,
    mock_provider: MockProvider,
    public_context: ContextModel,
) -> None:
    """Verify mandatory block produces zero provider calls."""
    prompt = "Applicant national ID is 999-00-1234 for processing."
    req = PromptRequest(
        prompt=prompt,
        destination=Destination.MOCK,
        context=public_context,
    )

    response = orchestrator.execute(req)

    assert response.status == ExecutionStatus.BLOCKED
    assert response.decision == PolicyOutcome.BLOCK
    assert response.output is None
    assert response.provider is None

    # Invariant: Zero provider calls
    assert mock_provider.call_count == 0
    assert len(mock_provider.received_prompts) == 0


# 4. Pending REVIEW results in zero provider calls (T-08)
def test_pending_review_results_in_zero_provider_calls(
    orchestrator: OrchestrationService,
    mock_provider: MockProvider,
    public_context: ContextModel,
) -> None:
    """Verify review outcome produces zero provider calls and pending status."""
    prompt = "Patient was diagnosed with clinical hypertension."
    health_ctx = ContextModel(
        purpose=ContextPurpose.HEALTH_INFORMATION,
        data_subject=ContextDataSubject.SELF,
        classification=ContextClassification.PUBLIC,
    )
    req = PromptRequest(
        prompt=prompt,
        destination=Destination.MOCK,
        context=health_ctx,
    )

    response = orchestrator.execute(req)

    assert response.status == ExecutionStatus.REVIEW_PENDING
    assert response.decision == PolicyOutcome.REVIEW
    assert response.output is None
    assert response.provider is None

    # Invariant: Zero provider calls
    assert mock_provider.call_count == 0
    assert len(mock_provider.received_prompts) == 0


# 5. Client cannot forge an ALLOW decision (T-14)
def test_client_cannot_forge_allow_decision(client: TestClient, mock_provider: MockProvider) -> None:
    """Verify client attempt to inject decision="ALLOW" is rejected by schema."""
    initial_count = mock_provider.call_count
    payload = {
        "prompt": "Sensitive text with National ID: 999-00-1234",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
        "decision": "ALLOW",
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 422
    assert "Extra inputs are not permitted" in response.text
    assert mock_provider.call_count == initial_count


# 6. Client cannot submit a forged sanitized prompt (T-14)
def test_client_cannot_submit_forged_sanitized_prompt(
    client: TestClient, mock_provider: MockProvider
) -> None:
    """Verify client cannot inject pre-sanitized text to bypass server redactor."""
    initial_count = mock_provider.call_count
    payload = {
        "prompt": "Secret prompt with email alex@example.com",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
        "sanitized_prompt": "Harmless text",
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 422
    assert "Extra inputs are not permitted" in response.text
    assert mock_provider.call_count == initial_count


# 7. Replacing the prompt after analysis triggers fresh checks (T-15)
def test_prompt_swap_after_analysis_triggers_fresh_checks(
    client: TestClient, mock_provider: MockProvider
) -> None:
    """Verify prompt changed between analyze and execute triggers fresh policy evaluation."""
    mock_provider.reset()

    # Step 1: Analyze benign prompt
    analyze_payload = {
        "prompt": "Explain quicksort algorithm.",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    analyze_resp = client.post("/v1/prompts/analyze", json=analyze_payload)
    assert analyze_resp.status_code == 200
    assert analyze_resp.json()["decision"] == "ALLOW"
    assert mock_provider.call_count == 0  # Analyze never calls provider

    # Step 2: Client changes prompt to restricted data at execute time
    execute_payload = {
        "prompt": "National ID token: 999-00-1234",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    execute_resp = client.post("/v1/prompts/execute", json=execute_payload)
    assert execute_resp.status_code == 200
    data = execute_resp.json()
    assert data["status"] == "blocked"
    assert data["decision"] == "BLOCK"
    assert mock_provider.call_count == 0


# 8. High-risk mandatory block cannot be bypassed (T-21)
def test_high_risk_mandatory_block_cannot_be_bypassed(
    orchestrator: OrchestrationService,
    mock_provider: MockProvider,
) -> None:
    """Verify restricted classification sent to external destination is blocked regardless of claims."""
    ctx = ContextModel(
        purpose=ContextPurpose.GENERAL_QUESTION,
        data_subject=ContextDataSubject.NONE,
        classification=ContextClassification.RESTRICTED,
    )
    req = PromptRequest(
        prompt="Top secret architectural blueprints.",
        destination=Destination.GROQ,
        context=ctx,
    )
    response = orchestrator.execute(req)
    assert response.decision == PolicyOutcome.BLOCK
    assert response.status == ExecutionStatus.BLOCKED
    assert mock_provider.call_count == 0


# 9. Redaction verification failure results in zero provider calls (T-11)
def test_redaction_verification_failure_results_in_zero_calls(
    mock_provider: MockProvider,
    audit_service: AuditService,
    public_context: ContextModel,
) -> None:
    """Verify that if post-redaction verifier detects residual data, engine fails closed."""
    # Create verifier that always detects a residual finding
    failing_verifier = RedactionVerifier()
    failing_verifier.verify = lambda text: (_ for _ in ()).throw(  # type: ignore
        RedactionVerificationException("Residual sensitive pattern detected in sanitized text.")
    )

    orchestrator_failing = OrchestrationService(
        verifier=failing_verifier,
        mock_provider=mock_provider,
        audit_service=audit_service,
    )

    req = PromptRequest(
        prompt="Email alex@example.com for help.",
        destination=Destination.MOCK,
        context=public_context,
    )

    with pytest.raises(RedactionVerificationException):
        orchestrator_failing.execute(req)

    # Invariant: Zero provider calls
    assert mock_provider.call_count == 0
    assert len(mock_provider.received_prompts) == 0


# 10. Detector, policy, and risk-scoring exceptions fail closed (T-10, T-11)
def test_detector_exception_fails_closed(
    mock_provider: MockProvider,
    audit_service: AuditService,
    public_context: ContextModel,
) -> None:
    """Verify detector exception aborts execution fail-closed with zero provider calls."""
    failing_detector = SensitiveDetector()
    failing_detector.detect = lambda text: (_ for _ in ()).throw(  # type: ignore
        DetectionException("Detector crashed unexpectedly.")
    )

    service = OrchestrationService(
        detector=failing_detector,
        mock_provider=mock_provider,
        audit_service=audit_service,
    )

    req = PromptRequest(prompt="Hello", destination=Destination.MOCK, context=public_context)
    with pytest.raises(DetectionException):
        service.execute(req)

    assert mock_provider.call_count == 0


def test_policy_engine_exception_fails_closed(
    mock_provider: MockProvider,
    audit_service: AuditService,
    public_context: ContextModel,
) -> None:
    """Verify policy engine exception aborts execution fail-closed with zero provider calls."""
    failing_engine = DeterministicPolicyEngine()
    failing_engine.evaluate = lambda **kwargs: (_ for _ in ()).throw(  # type: ignore
        PolicyUnavailableException("Policy engine internal error.")
    )

    service = OrchestrationService(
        policy_engine=failing_engine,
        mock_provider=mock_provider,
        audit_service=audit_service,
    )

    req = PromptRequest(prompt="Hello", destination=Destination.MOCK, context=public_context)
    with pytest.raises(PolicyUnavailableException):
        service.execute(req)

    assert mock_provider.call_count == 0


# 11. Malformed metadata cannot bypass policy (T-16)
def test_malformed_metadata_rejected(client: TestClient, mock_provider: MockProvider) -> None:
    """Verify malformed context enums are rejected with 422 and zero provider calls."""
    initial_count = mock_provider.call_count
    payload = {
        "prompt": "Test query",
        "destination": "mock",
        "context": {
            "purpose": "unsupported_purpose",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 422
    assert mock_provider.call_count == initial_count


# 12. Provider exceptions produce safe errors (T-18)
def test_provider_exceptions_produce_safe_errors(
    client: TestClient,
    mock_provider: MockProvider,
) -> None:
    """Verify simulated provider outage returns safe normalized 502 with zero leaked prompts."""
    # Configure mock provider in main app to simulate failure
    from backend.app.api.v1.prompts import orchestrator

    orchestrator.mock_provider.set_failure_mode(True)

    try:
        payload = {
            "prompt": "Draft a general greeting note.",
            "destination": "mock",
            "context": {
                "purpose": "general_question",
                "data_subject": "none",
                "classification": "public",
            },
        }
        response = client.post("/v1/prompts/execute", json=payload)
        assert response.status_code == 502
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] in ("PROVIDER_ERROR", "PROVIDER_UNAVAILABLE")
        # Invariant: Prompt text is not in error message
        assert "Draft a general greeting" not in str(data)
    finally:
        orchestrator.mock_provider.reset()


# 13. Logs and audit records contain no raw prompt or sensitive values (T-13)
def test_logs_and_audit_records_contain_no_raw_prompt_or_sensitive_values(
    orchestrator: OrchestrationService,
    audit_service: AuditService,
    public_context: ContextModel,
) -> None:
    """Verify audit events never store raw prompt, sanitized prompt text, or matched sensitive values."""
    audit_service.clear()
    synthetic_email = "confidential.user@example.com"
    prompt = f"Please notify {synthetic_email} about the results."
    req = PromptRequest(
        prompt=prompt,
        destination=Destination.MOCK,
        context=public_context,
    )

    response = orchestrator.execute(req)
    assert response.status == ExecutionStatus.COMPLETED

    events = audit_service.events
    assert len(events) == 1
    event = events[0]

    # Verify event structure
    assert event.decision == PolicyOutcome.REDACT
    assert event.provider_called is True
    assert event.redaction_count == 1
    assert event.request_digest.startswith("sha256:")

    # Security Invariant: Zero raw prompts or sensitive text in audit event
    event_str = event.model_dump_json()
    assert synthetic_email not in event_str
    assert "Please notify" not in event_str
    assert "[EMAIL]" not in event_str  # Prompt text not stored in audit
    assert "prompt" not in event.model_dump()
    assert "sanitized_prompt" not in event.model_dump()


# 14. The exact outgoing prompt is checked at the provider boundary
def test_outgoing_prompt_boundary_check_enforced(
    orchestrator: OrchestrationService,
    mock_provider: MockProvider,
) -> None:
    """Verify provider gateway rejects permit if outgoing prompt does not match authorized permit prompt."""
    permit = ProviderPermit(
        permit_id="PERMIT-001",
        request_digest="sha256:dummy",
        outcome=PolicyOutcome.ALLOW,
        policy_version="policy-v1",
        destination=Destination.MOCK,
        redaction_verified=False,
        authorized_prompt="Authorized prompt text",
        created_at="2026-10-16T12:00:00Z",
    )

    # Attempt to transmit a swapped prompt
    with pytest.raises(SecurityInvariantException, match="does not match authorized permit prompt"):
        orchestrator._call_provider_gateway(permit, "Forged or swapped prompt")

    assert mock_provider.call_count == 0


def test_provider_gateway_refuses_block_or_review_permit(
    orchestrator: OrchestrationService,
    mock_provider: MockProvider,
) -> None:
    """Verify provider gateway strictly refuses to execute a permit with outcome BLOCK or REVIEW."""
    permit_block = ProviderPermit(
        permit_id="PERMIT-BLOCK",
        request_digest="sha256:dummy",
        outcome=PolicyOutcome.BLOCK,
        policy_version="policy-v1",
        destination=Destination.MOCK,
        redaction_verified=False,
        authorized_prompt="Blocked prompt",
        created_at="2026-10-16T12:00:00Z",
    )

    with pytest.raises(SecurityInvariantException, match="non-transmissible outcome"):
        orchestrator._call_provider_gateway(permit_block, "Blocked prompt")

    assert mock_provider.call_count == 0


# 15. Required audit write failure fails closed with zero provider calls (T-12)
def test_required_audit_write_failure_fails_closed(
    orchestrator: OrchestrationService,
    mock_provider: MockProvider,
    audit_service: AuditService,
    public_context: ContextModel,
) -> None:
    """Verify that if mandatory audit write fails, execution aborts with zero provider calls."""
    audit_service.set_failure_mode(True)

    req = PromptRequest(
        prompt="Explain heap sort.",
        destination=Destination.MOCK,
        context=public_context,
    )

    with pytest.raises(AuditWriteException):
        orchestrator.execute(req)

    # Invariant: Zero provider calls
    assert mock_provider.call_count == 0
    assert len(mock_provider.received_prompts) == 0


# 16. End-to-end API verification for /v1/prompts/execute outcomes
def test_api_execute_allow_outcome(client: TestClient) -> None:
    """Verify /v1/prompts/execute returns 200 with completed status for ALLOW."""
    payload = {
        "prompt": "How does public-key cryptography work?",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["decision"] == "ALLOW"
    assert data["output"] == "Mock response generated locally."
    assert data["redactions"] is None


def test_api_execute_redact_outcome(client: TestClient) -> None:
    """Verify /v1/prompts/execute returns 200 with completed status and redaction summaries for REDACT."""
    payload = {
        "prompt": "Contact user at test.dev@example.com for credentials.",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["decision"] == "REDACT"
    assert data["output"] == "Mock response generated locally."
    assert data["redactions"] is not None
    assert len(data["redactions"]) == 1
    assert data["redactions"][0]["placeholder"] == "[EMAIL]"


def test_api_execute_block_outcome(client: TestClient) -> None:
    """Verify /v1/prompts/execute returns 200 with status=blocked and null output for BLOCK."""
    payload = {
        "prompt": "Identity verification with National ID: 999-00-1234",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "blocked"
    assert data["decision"] == "BLOCK"
    assert data["output"] is None
    assert data["provider"] is None


def test_api_execute_review_outcome(client: TestClient) -> None:
    """Verify /v1/prompts/execute returns 200 with status=review_pending and null output for REVIEW."""
    payload = {
        "prompt": "Individual has confirmed medical hypertension history.",
        "destination": "mock",
        "context": {
            "purpose": "health_information",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "review_pending"
    assert data["decision"] == "REVIEW"
    assert data["output"] is None
    assert data["provider"] is None


def test_audit_service_durable_sqlite_persistence(tmp_path) -> None:
    """Verify AuditService optionally persists events to SQLite with data minimization."""
    from backend.app.models.audit import AuditEvent

    db_file = str(tmp_path / "audit.db")
    service = AuditService(db_path=db_file)

    event = AuditEvent(
        event_id="evt-12345",
        timestamp="2026-10-17T12:00:00Z",
        request_digest="sha256:abcdef",
        destination="groq",
        decision=PolicyOutcome.REVIEW,
        rule_ids=["REVIEW-HEALTH-DATA"],
        risk_score=55,
        policy_version="policy-v1",
        detector_version="detector-v1",
        status="review_pending",
        provider_called=False,
        redaction_count=0,
        latency_ms=12,
    )

    service.record(event)

    # 1. In-memory check
    assert len(service.events) == 1

    # 2. Durable SQLite query check
    persisted = service.get_persisted_events()
    assert len(persisted) == 1
    row = persisted[0]
    assert row["event_id"] == "evt-12345"
    assert row["decision"] == "REVIEW"
    assert row["status"] == "review_pending"
    assert row["destination"] == "groq"
    assert row["provider_called"] == 0

    # 3. Invariant: raw prompt or PII columns do not exist in schema
    assert "prompt" not in row
    assert "sanitized_prompt" not in row

    # 4. Clear clears both
    service.clear()
    assert len(service.events) == 0
    assert len(service.get_persisted_events()) == 0

