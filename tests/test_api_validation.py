"""API validation tests for /v1/prompts endpoints and error formatting."""

from fastapi.testclient import TestClient


def test_analyze_valid_request(client: TestClient) -> None:
    """Verify POST /v1/prompts/analyze accepts valid requests and returns 200."""
    payload = {
        "prompt": "Explain how encryption works.",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "analysis_id" in data
    assert data["request_digest"].startswith("sha256:")
    assert data["decision"] == "ALLOW"
    assert data["policy_version"] == "policy-v1"
    assert "risk" in data
    assert data["risk"]["score"] == 0


def test_execute_valid_request(client: TestClient) -> None:
    """Verify POST /v1/prompts/execute accepts valid requests and returns 200."""
    payload = {
        "prompt": "Draft a general thank-you note.",
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
    assert "request_id" in data
    assert data["status"] == "completed"
    assert data["decision"] == "ALLOW"
    assert "output" in data


def test_analyze_rejects_missing_prompt(client: TestClient) -> None:
    """Verify missing required prompt field returns 422 with safe error response."""
    payload = {
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/analyze", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "request_id" in data["error"]


def test_analyze_rejects_empty_prompt(client: TestClient) -> None:
    """Verify empty prompt returns 422 with safe error response."""
    payload = {
        "prompt": "   ",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/analyze", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_analyze_rejects_client_injected_decision(client: TestClient) -> None:
    """Verify client-supplied decision or sanitized_prompt are rejected (extra='forbid')."""
    payload = {
        "prompt": "Normal prompt",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
        "decision": "ALLOW",
        "risk": {"score": 0, "band": "low", "version": "risk-v1"},
        "sanitized_prompt": "Bypassed prompt",
    }
    response = client.post("/v1/prompts/analyze", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "Extra inputs are not permitted" in data["error"]["message"]


def test_analyze_rejects_arbitrary_destination(client: TestClient) -> None:
    """Verify SSRF prevention: arbitrary URL destinations are rejected."""
    payload = {
        "prompt": "Normal prompt",
        "destination": "https://attacker.com/leak",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/analyze", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_oversized_prompt_returns_413(client: TestClient) -> None:
    """Verify prompt exceeding 10 KiB UTF-8 bytes returns 413 Payload Too Large."""
    oversized_prompt = "x" * 10241
    payload = {
        "prompt": oversized_prompt,
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/analyze", json=payload)
    assert response.status_code == 413
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"
    # Invariant: Prompt text must NOT be echoed in error message
    assert "x" * 100 not in data["error"]["message"]


def test_oversized_body_returns_413(client: TestClient) -> None:
    """Verify request body exceeding 32 KiB returns 413 Payload Too Large."""
    # Body limit is 32768 bytes
    huge_padding = " " * 33000
    huge_json = f'{{"prompt": "hello", "destination": "mock", "context": {{"purpose": "general_question", "data_subject": "none", "classification": "public"}}, "pad": "{huge_padding}"}}'
    
    response = client.post(
        "/v1/prompts/analyze",
        content=huge_json,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_malformed_json_returns_safe_error(client: TestClient) -> None:
    """Verify malformed JSON body returns 422 or 400 with structured safe error."""
    response = client.post(
        "/v1/prompts/analyze",
        content="{invalid_json:",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code in (400, 422)
    data = response.json()
    assert "error" in data
    assert "request_id" in data["error"]


def test_analyze_detects_sensitive_findings(client: TestClient) -> None:
    """Verify POST /v1/prompts/analyze returns detected findings with data minimization."""
    payload = {
        "prompt": "Contact EMP-123456 at alex@example.com for support.",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert len(data["findings"]) == 2
    categories = [f["category"] for f in data["findings"]]
    assert "EMPLOYEE_ID" in categories
    assert "EMAIL" in categories
    # Invariant: Matched raw sensitive values must NOT appear in finding dicts
    for f in data["findings"]:
        assert "alex@example.com" not in str(f)
        assert "EMP-123456" not in str(f)
        assert "text" not in f
        assert "matched_value" not in f


def test_analyze_redact_decision_api(client: TestClient) -> None:
    """Verify POST /v1/prompts/analyze returns REDACT decision for sanitizable email."""
    payload = {
        "prompt": "Please contact test.user@example.com for inquiries.",
        "destination": "mock",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "public",
        },
    }
    response = client.post("/v1/prompts/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "REDACT"
    assert "REDACT-EMAIL" in data["explanation"]["rule_ids"]
    assert "test.user@example.com" not in data["explanation"]["summary"]
    assert data["risk"]["score"] > 0


def test_analyze_block_decision_api(client: TestClient) -> None:
    """Verify POST /v1/prompts/analyze returns BLOCK decision for restricted classification to GROQ."""
    payload = {
        "prompt": "Restricted internal system blueprints.",
        "destination": "groq",
        "context": {
            "purpose": "general_question",
            "data_subject": "none",
            "classification": "restricted",
        },
    }
    response = client.post("/v1/prompts/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "BLOCK"
    assert "BLOCK-RESTRICTED-DATA" in data["explanation"]["rule_ids"]
