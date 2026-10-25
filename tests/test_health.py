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


def test_health_cors_exact_frontend_origin_get(client: TestClient) -> None:
    """Verify GET /health includes Access-Control-Allow-Origin for production frontend."""
    frontend_origin = "https://privai-secure-task-agent-1.onrender.com"
    response = client.get("/health", headers={"Origin": frontend_origin})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == frontend_origin
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_health_cors_exact_frontend_origin_options_preflight(client: TestClient) -> None:
    """Verify OPTIONS /health preflight succeeds with 200 and allowed origin."""
    frontend_origin = "https://privai-secure-task-agent-1.onrender.com"
    response = client.options(
        "/health",
        headers={
            "Origin": frontend_origin,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == frontend_origin
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_health_cors_disallowed_origin_rejected(client: TestClient) -> None:
    """Verify disallowed origins do not receive CORS allow headers."""
    disallowed_origin = "https://unauthorized-malicious-site.com"
    # Preflight must fail with 400
    opt_resp = client.options(
        "/health",
        headers={
            "Origin": disallowed_origin,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert opt_resp.status_code == 400
    assert "access-control-allow-origin" not in opt_resp.headers

    # Simple GET must omit access-control-allow-origin
    get_resp = client.get("/health", headers={"Origin": disallowed_origin})
    assert get_resp.status_code == 200
    assert "access-control-allow-origin" not in get_resp.headers


def test_cors_config_parsing_edge_cases() -> None:
    """Verify assemble_cors_origins cleanses trailing slashes, quotes, and array formats."""
    from backend.app.config import Settings

    cases = [
        ("https://privai-secure-task-agent-1.onrender.com/", ["https://privai-secure-task-agent-1.onrender.com"]),
        ("'https://privai-secure-task-agent-1.onrender.com'", ["https://privai-secure-task-agent-1.onrender.com"]),
        ("['https://privai-secure-task-agent-1.onrender.com/']", ["https://privai-secure-task-agent-1.onrender.com"]),
        ('["https://privai-secure-task-agent-1.onrender.com/"]', ["https://privai-secure-task-agent-1.onrender.com"]),
        ("privai-secure-task-agent-1.onrender.com", ["https://privai-secure-task-agent-1.onrender.com"]),
        (["http://localhost:5173/", "https://privai-secure-task-agent-1.onrender.com/"], ["http://localhost:5173", "https://privai-secure-task-agent-1.onrender.com"]),
    ]

    for raw, expected in cases:
        parsed = Settings.assemble_cors_origins(raw)
        assert parsed == expected, f"Failed for raw input: {raw!r}, got: {parsed!r}"

