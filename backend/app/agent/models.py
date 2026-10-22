"""Data models for PrivAI Secure Task Agent."""

from enum import Enum
import re
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.models.context import ContextModel
from backend.app.models.enums import Destination, PolicyOutcome
from backend.app.models.reviews import ReviewPermit

UNSAFE_CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_AGENT_GOAL_CHARS = 4096


class AgentTaskStatus(str, Enum):
    """Lifecycle statuses for an Agent Task."""

    CREATED = "created"
    PLANNING = "planning"
    RUNNING = "running"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentStepStatus(str, Enum):
    """Execution statuses for an Agent Step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    FAILED = "failed"


class AgentStep(BaseModel):
    """A single planned or executed step in an Agent Task."""

    model_config = ConfigDict(extra="forbid")

    step_number: int = Field(..., ge=1, le=10, description="1-indexed sequence number")
    description: str = Field(..., description="Human-readable step objective")
    tool_name: str = Field(..., description="Server-allowlisted tool identifier")
    tool_input: dict[str, Any] = Field(default_factory=dict, description="Raw input arguments for tool")
    sanitized_tool_input: dict[str, Any] | None = Field(
        default=None, description="Sanitized input arguments if REDACT was applied"
    )
    policy_decision: PolicyOutcome | None = Field(
        default=None, description="Authoritative firewall decision on step inputs"
    )
    policy_reason_codes: list[str] = Field(
        default_factory=list, description="Reason codes from policy evaluation"
    )
    status: AgentStepStatus = Field(
        default=AgentStepStatus.PENDING, description="Execution status of this step"
    )
    ticket_id: str | None = Field(
        default=None, description="Human review ticket identifier if step is pending approval"
    )
    tool_output: dict[str, Any] | None = Field(
        default=None, description="Sanitized execution output from tool"
    )
    explanation: str | None = Field(
        default=None, description="Safe explanation of step decision or result"
    )


class AgentPlan(BaseModel):
    """Bounded multi-step execution plan generated for a task."""

    model_config = ConfigDict(extra="forbid")

    goal: str = Field(..., description="The user goal this plan addresses")
    steps: list[AgentStep] = Field(default_factory=list, description="Ordered execution steps")
    total_steps: int = Field(..., ge=0, le=10, description="Total count of steps in plan")


class AgentTask(BaseModel):
    """Complete domain model for an Agent Task."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., description="Unique task identifier, e.g. 'task-...'")
    goal: str = Field(..., description="Sanitized user goal")
    status: AgentTaskStatus = Field(..., description="Current task status")
    plan: AgentPlan | None = Field(default=None, description="Structured task plan")
    current_step_index: int = Field(default=0, ge=0, description="Index of currently active step")
    final_answer: str | None = Field(default=None, description="Synthesized final answer")
    completed_steps: int = Field(default=0, ge=0, description="Number of successfully completed steps")
    blocked_steps: int = Field(default=0, ge=0, description="Number of blocked steps")
    waiting_steps: int = Field(default=0, ge=0, description="Number of steps waiting for approval")
    pending_ticket_id: str | None = Field(
        default=None, description="Active ticket ID if task is waiting for human review"
    )
    audit_references: list[str] = Field(
        default_factory=list, description="List of audit event hashes or request digests"
    )
    context: ContextModel = Field(..., description="Context metadata for firewall rules")
    destination: Destination = Field(..., description="Target AI provider (mock or groq)")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")
    updated_at: str = Field(..., description="ISO 8601 update timestamp")


class AgentTaskCreateRequest(BaseModel):
    """Input payload to create and execute a bounded Agent Task."""

    model_config = ConfigDict(extra="forbid")

    goal: str = Field(..., description="User-specified objective for the agent")
    context: ContextModel | None = Field(
        default=None, description="Optional context classification metadata"
    )
    destination: Destination | None = Field(
        default=None, description="Target AI provider destination (defaults to mock)"
    )
    review_permit: ReviewPermit | None = Field(
        default=None, description="Optional review permit if resuming or pre-approved"
    )

    @field_validator("goal")
    @classmethod
    def validate_goal(cls, v: str) -> str:
        """Validate goal string bounds and safety."""
        if not v or not v.strip():
            raise ValueError("Task goal must not be empty or whitespace only.")
        if len(v) > MAX_AGENT_GOAL_CHARS:
            raise ValueError(
                f"Task goal exceeds maximum allowed length of {MAX_AGENT_GOAL_CHARS} characters."
            )
        if UNSAFE_CONTROL_CHARS_PATTERN.search(v):
            raise ValueError("Task goal contains unsafe control characters.")
        return v.strip()


class AgentTaskResumeRequest(BaseModel):
    """Input payload to resume a task waiting for human approval."""

    model_config = ConfigDict(extra="forbid")

    review_permit: ReviewPermit = Field(
        ..., description="Signed cryptographic review permit authorizing execution"
    )


class AgentTaskResponse(BaseModel):
    """Safe external representation of an Agent Task."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., description="Task identifier")
    goal: str = Field(..., description="Task goal")
    status: AgentTaskStatus = Field(..., description="Task lifecycle status")
    current_step_index: int = Field(..., description="Current step index")
    plan: AgentPlan | None = Field(default=None, description="Execution plan")
    final_answer: str | None = Field(default=None, description="Synthesized final answer")
    completed_steps: int = Field(..., description="Count of completed steps")
    blocked_steps: int = Field(..., description="Count of blocked steps")
    waiting_steps: int = Field(..., description="Count of steps waiting for approval")
    pending_ticket_id: str | None = Field(
        default=None, description="Active review ticket ID if waiting for approval"
    )
    audit_references: list[str] = Field(
        default_factory=list, description="Cryptographic audit references"
    )
    created_at: str = Field(..., description="Creation timestamp")
    updated_at: str = Field(..., description="Update timestamp")


class AgentStepsResponse(BaseModel):
    """Response containing step history for a task."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., description="Task identifier")
    steps: list[AgentStep] = Field(default_factory=list, description="Ordered steps")
