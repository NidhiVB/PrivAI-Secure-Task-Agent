"""Prompt endpoints for PrivAI."""

from fastapi import APIRouter
from backend.app.models.requests import PromptRequest
from backend.app.models.responses import (
    PromptAnalyzeResponse,
    PromptExecuteResponse,
    SafeErrorResponse,
)
from backend.app.orchestrator.service import OrchestrationService

orchestrator = OrchestrationService()
router = APIRouter(prefix="/prompts", tags=["Prompts"])


def set_orchestrator(service: OrchestrationService) -> None:
    """Inject orchestrator service (useful for test isolation)."""
    global orchestrator
    orchestrator = service



@router.post(
    "/analyze",
    response_model=PromptAnalyzeResponse,
    responses={
        200: {"model": PromptAnalyzeResponse, "description": "Analysis completed"},
        400: {"model": SafeErrorResponse, "description": "Bad Request"},
        413: {"model": SafeErrorResponse, "description": "Payload Too Large"},
        422: {"model": SafeErrorResponse, "description": "Unprocessable Entity"},
        503: {"model": SafeErrorResponse, "description": "Service Unavailable"},
    },
    summary="Analyze prompt locally (never calls provider)",
)
def analyze_prompt(request: PromptRequest) -> PromptAnalyzeResponse:
    """Analyze prompt locally.

    Security Invariants:
    1. Never calls an external AI provider.
    2. Input is strictly validated; extra client-supplied fields are rejected.
    3. Digested against canonical JSON and policy version.
    4. Deterministic detection returns sanitized finding metadata without raw values.
    5. Pure deterministic risk scoring and policy engine evaluation.
    """
    return orchestrator.analyze(request)


@router.post(
    "/execute",
    response_model=PromptExecuteResponse,
    responses={
        200: {"model": PromptExecuteResponse, "description": "Execution completed"},
        400: {"model": SafeErrorResponse, "description": "Bad Request"},
        413: {"model": SafeErrorResponse, "description": "Payload Too Large"},
        422: {"model": SafeErrorResponse, "description": "Unprocessable Entity"},
        502: {"model": SafeErrorResponse, "description": "Bad Gateway / Provider Error"},
        503: {"model": SafeErrorResponse, "description": "Service Unavailable"},
    },
    summary="Execute prompt through policy firewall and permit gate",
)
def execute_prompt(request: PromptRequest) -> PromptExecuteResponse:
    """Execute prompt through policy firewall and internal permit gate.

    Security Invariants:
    1. Authoritative backend validation, detection, risk scoring, and policy evaluation.
    2. Revalidates exact submitted request; rejects and ignores client analysis claims.
    3. Only ALLOW or verified REDACT permits reach the provider.
    4. BLOCK and pending REVIEW always yield zero provider calls.
    5. Fail-closed on component error, verifier failure, or audit storage outage.
    """
    return orchestrator.execute(request)
