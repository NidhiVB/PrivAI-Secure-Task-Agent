"""Agent API endpoints for PrivAI Secure Task Agent."""

from fastapi import APIRouter, HTTPException, status

from backend.app.agent.models import (
    AgentStepsResponse,
    AgentTaskCreateRequest,
    AgentTaskResponse,
    AgentTaskResumeRequest,
)
from backend.app.agent.service import AgentService
from backend.app.models.responses import SafeErrorResponse

agent_service = AgentService()
router = APIRouter(prefix="/agent", tags=["Agent"])


def set_agent_service(service: AgentService) -> None:
    """Inject agent service (useful for test isolation)."""
    global agent_service
    agent_service = service


def get_agent_service() -> AgentService:
    """Get active agent service instance."""
    return agent_service


@router.post(
    "/tasks",
    response_model=AgentTaskResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"model": AgentTaskResponse, "description": "Task created and execution initiated"},
        400: {"model": SafeErrorResponse, "description": "Bad Request"},
        403: {"model": SafeErrorResponse, "description": "Forbidden / Blocked by Policy"},
        422: {"model": SafeErrorResponse, "description": "Unprocessable Entity"},
        503: {"model": SafeErrorResponse, "description": "Service Unavailable"},
    },
    summary="Create and execute a bounded agent task",
)
def create_agent_task(request: AgentTaskCreateRequest) -> AgentTaskResponse:
    """Create and execute a bounded, policy-governed agent task.

    Security Invariants:
    1. Pre-execution firewall evaluates the user goal before planning.
    2. Server-side allowlist strictly constrains tool selection.
    3. BLOCK stops execution with zero provider and tool calls.
    4. REVIEW creates an encrypted review ticket and suspends execution.
    5. Audit events committed fail-closed before sensitive actions.
    """
    task = agent_service.create_and_run_task(request)
    return AgentTaskResponse(
        task_id=task.task_id,
        goal=task.goal,
        status=task.status,
        current_step_index=task.current_step_index,
        plan=task.plan,
        final_answer=task.final_answer,
        completed_steps=task.completed_steps,
        blocked_steps=task.blocked_steps,
        waiting_steps=task.waiting_steps,
        pending_ticket_id=task.pending_ticket_id,
        audit_references=task.audit_references,
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


@router.get(
    "/tasks/{task_id}",
    response_model=AgentTaskResponse,
    responses={
        200: {"model": AgentTaskResponse, "description": "Task retrieved successfully"},
        404: {"model": SafeErrorResponse, "description": "Task not found"},
    },
    summary="Retrieve agent task status and results",
)
def get_agent_task(task_id: str) -> AgentTaskResponse:
    """Retrieve current task status, step indices, and safe results."""
    task = agent_service.repository.get_task(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task '{task_id}' not found.",
        )
    return AgentTaskResponse(
        task_id=task.task_id,
        goal=task.goal,
        status=task.status,
        current_step_index=task.current_step_index,
        plan=task.plan,
        final_answer=task.final_answer,
        completed_steps=task.completed_steps,
        blocked_steps=task.blocked_steps,
        waiting_steps=task.waiting_steps,
        pending_ticket_id=task.pending_ticket_id,
        audit_references=task.audit_references,
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


@router.get(
    "/tasks/{task_id}/steps",
    response_model=AgentStepsResponse,
    responses={
        200: {"model": AgentStepsResponse, "description": "Steps retrieved successfully"},
        404: {"model": SafeErrorResponse, "description": "Task not found"},
    },
    summary="Retrieve authorized, sanitized step history for a task",
)
def get_agent_task_steps(task_id: str) -> AgentStepsResponse:
    """Retrieve ordered execution steps for a task."""
    task = agent_service.repository.get_task(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task '{task_id}' not found.",
        )
    steps = agent_service.repository.get_steps(task_id)
    return AgentStepsResponse(task_id=task_id, steps=steps)


@router.post(
    "/tasks/{task_id}/resume",
    response_model=AgentTaskResponse,
    responses={
        200: {"model": AgentTaskResponse, "description": "Task resumed and completed"},
        400: {"model": SafeErrorResponse, "description": "Invalid task state"},
        403: {"model": SafeErrorResponse, "description": "Permit rejected or invalid"},
        404: {"model": SafeErrorResponse, "description": "Task not found"},
    },
    summary="Resume a task suspended in review approval state",
)
def resume_agent_task(task_id: str, request: AgentTaskResumeRequest) -> AgentTaskResponse:
    """Resume task execution using an authorized, cryptographic review permit."""
    task = agent_service.resume_task(task_id, request)
    return AgentTaskResponse(
        task_id=task.task_id,
        goal=task.goal,
        status=task.status,
        current_step_index=task.current_step_index,
        plan=task.plan,
        final_answer=task.final_answer,
        completed_steps=task.completed_steps,
        blocked_steps=task.blocked_steps,
        waiting_steps=task.waiting_steps,
        pending_ticket_id=task.pending_ticket_id,
        audit_references=task.audit_references,
        created_at=task.created_at,
        updated_at=task.updated_at,
    )
