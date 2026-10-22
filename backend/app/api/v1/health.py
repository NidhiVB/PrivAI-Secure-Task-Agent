"""Health and readiness endpoint."""

from fastapi import APIRouter
from backend.app.config import settings
from backend.app.core.exceptions import PolicyUnavailableException
from backend.app.models.responses import HealthResponse, SafeErrorResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    responses={
        200: {"model": HealthResponse, "description": "System is healthy and policy is loaded"},
        503: {"model": SafeErrorResponse, "description": "Policy is not loaded or engine unavailable"},
    },
    summary="Health and readiness probe",
)
def get_health() -> HealthResponse:
    """Check service health and policy status.

    Security Invariant: Never exposes environment dumps, secret keys,
    file paths, or stack traces.
    """
    if not settings.POLICY_LOADED:
        raise PolicyUnavailableException("Policy engine is not ready or configuration failed to load.")

    return HealthResponse(
        status="ok",
        provider_mode=settings.PROVIDER_MODE,
        policy_loaded=settings.POLICY_LOADED,
    )
