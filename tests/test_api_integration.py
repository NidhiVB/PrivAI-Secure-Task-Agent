"""End-to-end API integration and security tests for Milestone 5."""

import pytest
from fastapi.testclient import TestClient

from backend.app.api.v1.prompts import orchestrator


@pytest.fixture(autouse=True)
def reset_orchestrator() -> None:
    """Ensure clean state for mock provider and audit events before each test."""
    orchestrator.mock_provider.reset()
    orchestrator.audit_service.clear()
    yield
    orchestrator.mock_provider.reset()
    orchestrator.audit_service.clear()


# ---------------------------------------------------------------------------
# 1. Analyze Endpoint Invariants (POST /v1/prompts/analyze)
# ---------------------------------------------------------------------------


def test_analyze_endpoint_never_calls_provider_all_outcomes(client: TestClient) -> None:
    """Verify POST /v1/prompts/analyze evaluates all policy outcomes with strictly zero provider calls."""
    test_cases = [
        # ALLOW case
        (
            {
                "prompt": "Explain the concept of public key cryptography.",
                "destination": "mock",
                "context": {
                    "purpose": "general_question",
                    "data_subject": "none",
                    "classification": "public",
                },
            },
            "ALLOW",
        ),
        # REDACT case
        (
            {
                "prompt": "Contact researcher at user.test@example.org for questions.",
                "destination": "mock",
                "context": {
                    "purpose": "general_question",
                    "data_subject": "none",
                    "classification": "public",
                },
            },
            "REDACT",
        ),
        # BLOCK case
        (
            {
                "prompt": "Applicant SSN is 999-00-1234 for verification.",
                "destination": "mock",
                "context": {
                    "purpose": "general_question",
                    "data_subject": "none",
                    "classification": "public",
                },
            },
            "BLOCK",
        ),
        # REVIEW case
        (
            {
                "prompt": "Patient clinical hypertension records.",
                "destination": "mock",
                "context": {
                    "purpose": "health_information",
                    "data_subject": "none",
                    "classification": "public",
                },
            },
            "REVIEW",
        ),
    ]

    for payload, expected_decision in test_cases:
        resp = client.post("/v1/prompts/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == expected_decision
        assert "analysis_id" in data
        assert data["request_digest"].startswith("sha256:")
        assert "risk" in data
        assert "score" in data["risk"]
        assert "band" in data["risk"]
        assert "explanation" in data
        assert "rule_ids" in data["explanation"]

        # Critical Invariant: Analyze MUST NEVER invoke any provider
        assert orchestrator.mock_provider.call_count == 0
        assert len(orchestrator.mock_provider.received_prompts) == 0


# ---------------------------------------------------------------------------
# 2. Execute Endpoint Invariants (POST /v1/prompts/execute)
# ---------------------------------------------------------------------------


def test_execute_allow_flow_transmits_exact_prompt_once(client: TestClient) -> None:
    """Verify authorized ALLOW execution invokes provider exactly once with exact submitted prompt."""
    prompt = "How does binary search work on sorted arrays?"
    payload = {
        "prompt": prompt,
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
    assert data["provider"] == {"name": "mock", "model": "mock-v1"}
    assert data["redactions"] is None

    # Invariant: Provider invoked once with exact prompt
    assert orchestrator.mock_provider.call_count == 1
    assert orchestrator.mock_provider.received_prompts == [prompt]


def test_execute_redact_flow_transmits_sanitized_prompt_only(client: TestClient) -> None:
    """Verify REDACT execution sends only verified sanitized prompt and preserves placeholders."""
    synthetic_email = "dev.lead@example.net"
    synthetic_phone = "555-123-4567"
    prompt = f"Reach {synthetic_email} or call {synthetic_phone}."
    payload = {
        "prompt": prompt,
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
    assert len(data["redactions"]) == 2
    placeholders = {r["placeholder"] for r in data["redactions"]}
    assert placeholders == {"[EMAIL]", "[PHONE]"}

    # Invariant: Provider called once with sanitized prompt, zero sensitive data
    assert orchestrator.mock_provider.call_count == 1
    received = orchestrator.mock_provider.received_prompts[0]
    assert received == "Reach [EMAIL] or call [PHONE]."
    assert synthetic_email not in received
    assert synthetic_phone not in received


def test_execute_block_flow_zero_provider_calls(client: TestClient) -> None:
    """Verify BLOCK outcome returns status=blocked, null output, and zero provider calls."""
    payload = {
        "prompt": "Restricted corporate security keys and credentials.",
        "destination": "groq",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "restricted",
        },
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "blocked"
    assert data["decision"] == "BLOCK"
    assert data["output"] is None
    assert data["provider"] is None
    assert "BLOCK-RESTRICTED-DATA" in data["explanation"]["rule_ids"]

    # Invariant: Zero provider calls
    assert orchestrator.mock_provider.call_count == 0


def test_execute_review_flow_zero_provider_calls(client: TestClient) -> None:
    """Verify REVIEW outcome returns status=review_pending, null output, and zero provider calls."""
    payload = {
        "prompt": "Patient diagnosis notes and therapy history.",
        "destination": "mock",
        "context": {
            "purpose": "health_information",
            "data_subject": "self",
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

    # Invariant: Zero provider calls
    assert orchestrator.mock_provider.call_count == 0


# ---------------------------------------------------------------------------
# 3. Security Boundary & Anti-Bypass Invariants
# ---------------------------------------------------------------------------


def test_prompt_substitution_between_analyze_and_execute(client: TestClient) -> None:
    """Verify prompt substitution between analyze and execute triggers authoritative re-evaluation (T-15)."""
    # 1. Analyze harmless prompt -> ALLOW
    analyze_payload = {
        "prompt": "What is the speed of light?",
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
    assert orchestrator.mock_provider.call_count == 0

    # 2. Execute altered prompt with National ID -> must BLOCK, zero provider calls
    execute_payload = {
        "prompt": "Applicant ID is 999-00-1234",
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
    assert orchestrator.mock_provider.call_count == 0


def test_client_injected_bypass_fields_rejected(client: TestClient) -> None:
    """Verify client attempts to forge decision, sanitized prompt, risk score, or permits are rejected (T-14)."""
    forged_fields = [
        {"decision": "ALLOW"},
        {"sanitized_prompt": "Safe text"},
        {"risk_score": 0},
        {"approved": True},
        {"provider_allowed": True},
    ]

    base_payload = {
        "prompt": "Sensitive prompt with 999-00-1234",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }

    for extra in forged_fields:
        payload = {**base_payload, **extra}
        response = client.post("/v1/prompts/execute", json=payload)
        assert response.status_code == 422
        assert "Extra inputs are not permitted" in response.text

    assert orchestrator.mock_provider.call_count == 0


def test_missing_or_malformed_metadata_rejected(client: TestClient) -> None:
    """Verify malformed context or missing required fields return safe 422 errors (T-16)."""
    # Missing prompt
    resp_missing_prompt = client.post(
        "/v1/prompts/execute",
        json={"destination": "mock", "context": {"purpose": "coding", "data_subject": "none", "classification": "public"}},
    )
    assert resp_missing_prompt.status_code == 422
    assert "error" in resp_missing_prompt.json()

    # Empty prompt
    resp_empty_prompt = client.post(
        "/v1/prompts/execute",
        json={"prompt": "   ", "destination": "mock", "context": {"purpose": "coding", "data_subject": "none", "classification": "public"}},
    )
    assert resp_empty_prompt.status_code == 422
    assert "error" in resp_empty_prompt.json()

    # Unknown destination
    resp_bad_dest = client.post(
        "/v1/prompts/execute",
        json={"prompt": "Hello", "destination": "unsupported_provider", "context": {"purpose": "coding", "data_subject": "none", "classification": "public"}},
    )
    assert resp_bad_dest.status_code == 422
    assert "error" in resp_bad_dest.json()

    assert orchestrator.mock_provider.call_count == 0


def test_oversized_payload_returns_413(client: TestClient) -> None:
    """Verify oversized prompts (> 10 KiB) return 413 without invoking provider (T-17)."""
    oversized = "A" * 10241
    payload = {
        "prompt": oversized,
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert orchestrator.mock_provider.call_count == 0


def test_provider_failure_returns_normalized_safe_502(client: TestClient) -> None:
    """Verify provider communication failure returns normalized 502 with safe error envelope (T-18)."""
    orchestrator.mock_provider.set_failure_mode(True)
    try:
        payload = {
            "prompt": "Please summarize this paragraph.",
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
        assert "request_id" in data["error"]
        # Invariant: No prompt text in error response
        assert "summarize this paragraph" not in str(data)
    finally:
        orchestrator.mock_provider.reset()


def test_audit_records_data_minimization_invariant(client: TestClient) -> None:
    """Verify audit service preserves data minimization: zero prompts or PII in audit records (T-13)."""
    synthetic_email = "audit.check@example.org"
    prompt = f"Send audit report to {synthetic_email} immediately."
    payload = {
        "prompt": prompt,
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/execute", json=payload)
    assert response.status_code == 200

    events = orchestrator.audit_service.events
    assert len(events) == 1
    event = events[0]

    assert event.decision == "REDACT"
    assert event.provider_called is True
    assert event.redaction_count == 1
    assert event.request_digest.startswith("sha256:")

    # Invariant: No raw prompt, sanitized text, or PII in audit record
    dumped = event.model_dump()
    dumped_str = event.model_dump_json()
    assert synthetic_email not in dumped_str
    assert "Send audit report" not in dumped_str
    assert "[EMAIL]" not in dumped_str
    assert "prompt" not in dumped
    assert "sanitized_prompt" not in dumped
