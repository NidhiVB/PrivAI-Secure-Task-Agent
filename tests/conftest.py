"""Pytest fixtures and configuration."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app


@pytest.fixture(autouse=True)
def force_mock_mode_for_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure automated tests always run in mock mode regardless of local .env setting."""
    from backend.app.config import settings

    monkeypatch.setattr(settings, "PROVIDER_MODE", "mock")


@pytest.fixture(autouse=True)
def isolate_database_for_tests(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Ensure automated tests use an isolated temporary database and never write to privai_data.db."""
    from backend.app.config import settings
    from backend.app.audit.service import AuditService, set_audit_service
    from backend.app.reviews.repository import ReviewRepository
    from backend.app.api.v1.prompts import orchestrator
    from backend.app.api.v1 import reviews as reviews_module
    from backend.app.api.v1 import audit as audit_module

    test_db = str(tmp_path_factory.mktemp("test_db") / "privai_test.db")
    test_agent_db = str(tmp_path_factory.mktemp("test_agent_db") / "privai_agent_test.db")
    monkeypatch.setattr(settings, "DATABASE_PATH", test_db)
    monkeypatch.setattr(settings, "AGENT_DATABASE_PATH", test_agent_db)

    test_audit = AuditService(db_path=test_db)
    test_repo = ReviewRepository(db_path=test_db)

    set_audit_service(test_audit)
    orchestrator.audit_service = test_audit
    orchestrator.review_repo = test_repo
    reviews_module.review_repo = test_repo
    reviews_module.audit_service = test_audit
    audit_module.audit_service = test_audit

    from backend.app.agent.repository import AgentRepository
    from backend.app.agent.service import AgentService
    from backend.app.api.v1 import agent as agent_module

    test_agent_repo = AgentRepository(db_path=test_agent_db)
    agent_svc = AgentService(repository=test_agent_repo, orchestrator=orchestrator)
    agent_module.set_agent_service(agent_svc)

    yield

    set_audit_service(None)



@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)
