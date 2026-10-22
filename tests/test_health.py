"""Tests for /health endpoint and readiness behavior."""

from fastapi.testclient import TestClient
from backend.app.config import settings


def test_health_root_endpoint_success(client: TestClient) -> None:
    """Verify GET /health returns 200 with expected schema."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["provider_mode"] == "mock"
    assert data["policy_loaded"] is True
    # Invariant: No sensitive environment/secret exposure
    assert "api_key" not in data
    assert "groq_api_key" not in data
    assert "path" not in data
    assert "secret" not in data


def test_health_v1_endpoint_success(client: TestClient) -> None:
    """Verify GET /v1/health returns 200 and matches root health."""
    response = client.get("/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["provider_mode"] == "mock"
    assert data["policy_loaded"] is True


def test_health_readiness_failure(client: TestClient, monkeypatch) -> None:
    """Verify GET /health returns 503 fail-closed if policy is not loaded."""
    monkeypatch.setattr(settings, "POLICY_LOADED", False)
    response = client.get("/health")
    assert response.status_code == 503
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "POLICY_UNAVAILABLE"
    assert "request_id" in data["error"]
