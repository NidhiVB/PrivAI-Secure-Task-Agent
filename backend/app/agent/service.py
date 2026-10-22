"""Agent orchestration service coordinating planning, policy enforcement, and tool execution."""

import datetime
import time
import uuid
from typing import Any

from backend.app.agent.models import (
    AgentPlan,
    AgentStep,
    AgentStepStatus,
    AgentTask,
    AgentTaskCreateRequest,
    AgentTaskResumeRequest,
    AgentTaskStatus,
)
from backend.app.agent.planner import BoundedPlanner
from backend.app.agent.repository import AgentRepository
from backend.app.agent.tools import SERVER_TOOL_ALLOWLIST, execute_tool_safe
from backend.app.config import settings
from backend.app.core.exceptions import (
    AuditWriteException,
    PrivAIException,
    SecurityInvariantException,
)
from backend.app.core.permits import verify_review_permit_signature
from backend.app.core.security import compute_request_digest
from backend.app.detectors.detector import SensitiveDetector
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    PolicyOutcome,
)
from backend.app.models.requests import PromptRequest
from backend.app.models.reviews import ReviewPermit, ReviewStatus
from backend.app.orchestrator.service import OrchestrationService
from backend.app.policy.engine import DeterministicPolicyEngine
from backend.app.redaction.redactor import Redactor
from backend.app.risk.scorer import RiskScorer


class AgentService:
    """Coordinates bounded task lifecycle and enforces PrivAI firewall invariants.

    Security Invariants:
    1. Mandatory Pre-Execution Firewall: Goal and step inputs are inspected before any execution.
    2. Strict Allowlist: Only server-approved tools can be planned or executed.
    3. Zero Provider/Tool Egress: BLOCK stops affected actions with 0 provider and tool calls.
    4. Compliance Approval Gate: REVIEW suspends the task until a cryptographically signed,
       single-use permit is presented and atomically consumed.
    5. Untrusted Data Quarantine: Document content is treated as untrusted data; embedded
       instructions cannot bypass policy engine checks or alter allowlisted capabilities.
    6. Bounded Limits: Enforces max steps, execution timeout, and retry limits.
    """

    def __init__(
        self,
        repository: AgentRepository | None = None,
        orchestrator: OrchestrationService | None = None,
        planner: BoundedPlanner | None = None,
    ) -> None:
        self.orchestrator = orchestrator or OrchestrationService()
        self.repository = repository or AgentRepository()
        self.detector = self.orchestrator.detector or SensitiveDetector()
        self.redactor = self.orchestrator.redactor or Redactor()
        self.risk_scorer = self.orchestrator.risk_scorer or RiskScorer()
        self.policy_engine = self.orchestrator.policy_engine or DeterministicPolicyEngine()
        self.planner = planner or BoundedPlanner(
            policy_engine=self.policy_engine,
            detector=self.detector,
            risk_scorer=self.risk_scorer,
            max_steps=settings.AGENT_MAX_STEPS,
        )

    def create_and_run_task(self, request: AgentTaskCreateRequest) -> AgentTask:
        """Create a new bounded agent task and begin execution."""
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        context = request.context or ContextModel(
            purpose=ContextPurpose.GENERAL_QUESTION,
            data_subject=ContextDataSubject.NONE,
            classification=ContextClassification.PUBLIC,
        )
        destination = request.destination or Destination.MOCK

        # 1. Planning Phase with Pre-Execution Firewall Evaluation
        plan, outcome, reasons, explanation, sanitized_goal = self.planner.create_plan(
            goal=request.goal,
            context=context,
            destination=destination,
        )

        task = AgentTask(
            task_id=task_id,
            goal=sanitized_goal,
            status=AgentTaskStatus.CREATED,
            plan=plan,
            current_step_index=0,
            final_answer=None,
            completed_steps=0,
            blocked_steps=0,
            waiting_steps=0,
            pending_ticket_id=None,
            audit_references=[],
            context=context,
            destination=destination,
            created_at=now,
            updated_at=now,
        )

        # 2. Check for Immediate Goal-Level Policy Decision
        if outcome == PolicyOutcome.BLOCK:
            task.status = AgentTaskStatus.BLOCKED
            task.blocked_steps = 1
            task.final_answer = (
                f"Task execution blocked by privacy policy: {explanation}. "
                f"Triggered rules: {', '.join(reasons)}."
            )
            # Record audit event (zero provider and zero tool calls)
            audit_digest = self._audit_event(
                task=task,
                decision=PolicyOutcome.BLOCK,
                rule_ids=reasons,
                status="blocked",
                provider_called=False,
            )
            task.audit_references.append(audit_digest)
            self.repository.create_task(task)
            return task

        if outcome == PolicyOutcome.REVIEW:
            # Check if review permit was provided
            if request.review_permit is None:
                ticket_id = f"ticket-{uuid.uuid4().hex[:12]}"
                # Create review ticket in review repository
                digest = compute_request_digest(
                    PromptRequest(prompt=request.goal, destination=destination, context=context),
                    self.orchestrator.policy_version,
                )
                self.orchestrator.review_repo.create_ticket(
                    ticket_id=ticket_id,
                    request_digest=digest,
                    assigned_role="compliance_officer",
                    risk_score=75,
                    triggered_rule_ids=reasons,
                    prompt_content=request.goal,
                )
                task.status = AgentTaskStatus.WAITING_FOR_APPROVAL
                task.waiting_steps = 1
                task.pending_ticket_id = ticket_id
                task.final_answer = (
                    f"Task suspended pending compliance human review approval. "
                    f"Review ticket '{ticket_id}' has been created. Zero provider or tool calls made."
                )
                audit_digest = self._audit_event(
                    task=task,
                    decision=PolicyOutcome.REVIEW,
                    rule_ids=reasons,
                    status="review_pending",
                    provider_called=False,
                )
                task.audit_references.append(audit_digest)
                self.repository.create_task(task)
                return task
            else:
                # Validate and consume review permit
                self._validate_and_consume_permit(request.review_permit, request.goal, context, destination)
                # Now synthesize plan with approved goal
                plan = self.planner._synthesize_bounded_plan(sanitized_goal)
                task.plan = plan

        # Pre-execution audit logging (fails closed if audit persistence fails)
        audit_digest = self._audit_event(
            task=task,
            decision=outcome,
            rule_ids=reasons,
            status="task_started",
            provider_called=False,
        )
        task.audit_references.append(audit_digest)

        # Persist task before execution
        task.status = AgentTaskStatus.RUNNING
        self.repository.create_task(task)

        # 3. Execute planned steps sequentially under bounded invariants
        return self._execute_task_steps(task, active_permit=request.review_permit)

    def resume_task(self, task_id: str, request: AgentTaskResumeRequest) -> AgentTask:
        """Resume a task suspended in WAITING_FOR_APPROVAL status."""
        task = self.repository.get_task(task_id)
        if not task:
            raise PrivAIException(f"Task '{task_id}' not found.", code="TASK_NOT_FOUND", status_code=404)

        if task.status != AgentTaskStatus.WAITING_FOR_APPROVAL:
            raise PrivAIException(
                f"Task '{task_id}' is in status '{task.status.value}', cannot resume.",
                code="INVALID_TASK_STATE",
                status_code=400,
            )

        # Validate cryptographic permit signature
        verify_review_permit_signature(request.review_permit)

        # Verify permit belongs to this task's pending ticket
        if task.pending_ticket_id and request.review_permit.ticket_id != task.pending_ticket_id:
            raise SecurityInvariantException(
                f"Review permit ticket '{request.review_permit.ticket_id}' does not match "
                f"task pending ticket '{task.pending_ticket_id}'."
            )

        # Atomically consume permit
        self.orchestrator.review_repo.consume_permit_atomic(
            permit_nonce=request.review_permit.permit_nonce,
            expected_digest=request.review_permit.request_digest,
        )

        task.status = AgentTaskStatus.RUNNING
        task.pending_ticket_id = None
        task.waiting_steps = max(0, task.waiting_steps - 1)

        # If task was waiting at the plan level (no plan yet), generate plan now
        if not task.plan:
            task.plan = self.planner._synthesize_bounded_plan(task.goal)

        # Update step if waiting
        if task.plan and task.current_step_index < len(task.plan.steps):
            waiting_step = task.plan.steps[task.current_step_index]
            if waiting_step.status == AgentStepStatus.WAITING_FOR_APPROVAL:
                waiting_step.status = AgentStepStatus.PENDING
                waiting_step.policy_decision = PolicyOutcome.ALLOW
                waiting_step.ticket_id = None
                self.repository.save_step(task.task_id, waiting_step)

        self.repository.update_task(task)
        return self._execute_task_steps(task, active_permit=request.review_permit)

    def _execute_task_steps(self, task: AgentTask, active_permit: ReviewPermit | None = None) -> AgentTask:
        """Sequential bounded execution loop with runtime policy re-validation."""
        if not task.plan or not task.plan.steps:
            task.status = AgentTaskStatus.COMPLETED
            task.final_answer = f"Task completed: {task.goal} (Zero steps required)."
            return self.repository.update_task(task)

        start_time = time.time()
        timeout_seconds = settings.AGENT_TIMEOUT_SECONDS

        # Pipeline scratchpad for intermediate context passing
        pipeline_context: dict[str, Any] = {}
        task_authorized_by_permit = active_permit is not None

        while task.current_step_index < len(task.plan.steps):
            # Check execution timeout
            if time.time() - start_time > timeout_seconds:
                task.status = AgentTaskStatus.FAILED
                task.final_answer = f"Execution aborted: task timed out after {timeout_seconds} seconds."
                return self.repository.update_task(task)

            step = task.plan.steps[task.current_step_index]
            step.status = AgentStepStatus.RUNNING

            # Inject output from earlier steps if required
            self._inject_pipeline_context(step, pipeline_context)

            # 1. Server-side Tool Allowlist Check
            if step.tool_name not in SERVER_TOOL_ALLOWLIST:
                step.status = AgentStepStatus.FAILED
                step.explanation = f"Tool '{step.tool_name}' is not in server allowlist."
                task.status = AgentTaskStatus.FAILED
                task.final_answer = f"Execution halted: unapproved tool '{step.tool_name}' requested."
                self.repository.save_step(task.task_id, step)
                return self.repository.update_task(task)

            # 2. Runtime Firewall Evaluation on Tool Input
            input_text = self._extract_text_for_evaluation(step.tool_input)
            findings = self.detector.detect(input_text)
            risk = self.risk_scorer.evaluate(findings, task.context, task.destination)
            decision = self.policy_engine.evaluate(
                prompt=input_text,
                findings=findings,
                context=task.context,
                destination=task.destination,
                risk_score=risk,
            )

            step.policy_decision = decision.action
            step.policy_reason_codes = decision.reason_codes
            step.explanation = decision.explanation.summary

            # 3. Handle Step Policy Decisions
            if decision.action == PolicyOutcome.BLOCK:
                step.status = AgentStepStatus.BLOCKED
                task.blocked_steps += 1
                task.status = AgentTaskStatus.BLOCKED
                task.final_answer = (
                    f"Step {step.step_number} ('{step.description}') blocked by privacy policy: "
                    f"{decision.explanation.summary}. Zero tool or provider calls made."
                )
                audit_digest = self._audit_event(
                    task=task,
                    decision=PolicyOutcome.BLOCK,
                    rule_ids=decision.reason_codes,
                    status="step_blocked",
                    provider_called=False,
                )
                task.audit_references.append(audit_digest)
                self.repository.save_step(task.task_id, step)
                return self.repository.update_task(task)

            if decision.action == PolicyOutcome.REVIEW:
                if not task_authorized_by_permit:
                    # Suspend step and create review ticket
                    ticket_id = f"ticket-{uuid.uuid4().hex[:12]}"
                    digest = compute_request_digest(
                        PromptRequest(prompt=input_text, destination=task.destination, context=task.context),
                        self.orchestrator.policy_version,
                    )
                    self.orchestrator.review_repo.create_ticket(
                        ticket_id=ticket_id,
                        request_digest=digest,
                        assigned_role="compliance_officer",
                        risk_score=risk.score,
                        triggered_rule_ids=decision.reason_codes,
                        prompt_content=input_text,
                    )
                    step.status = AgentStepStatus.WAITING_FOR_APPROVAL
                    step.ticket_id = ticket_id
                    task.status = AgentTaskStatus.WAITING_FOR_APPROVAL
                    task.waiting_steps += 1
                    task.pending_ticket_id = ticket_id
                    task.final_answer = (
                        f"Step {step.step_number} suspended pending compliance review approval. "
                        f"Review ticket '{ticket_id}' generated. Zero tool calls executed."
                    )
                    audit_digest = self._audit_event(
                        task=task,
                        decision=PolicyOutcome.REVIEW,
                        rule_ids=decision.reason_codes,
                        status="step_review_pending",
                        provider_called=False,
                    )
                    task.audit_references.append(audit_digest)
                    self.repository.save_step(task.task_id, step)
                    return self.repository.update_task(task)
                else:
                    # Active permit was validated and consumed at the task boundary
                    step.policy_decision = PolicyOutcome.ALLOW

            # Effective tool input (sanitized if REDACT)
            effective_input = dict(step.tool_input)
            if decision.action == PolicyOutcome.REDACT and decision.redactions:
                sanitized_input = self._sanitize_tool_input(step.tool_input, decision.redactions)
                step.sanitized_tool_input = sanitized_input
                effective_input = sanitized_input

            # 4. Execute Allowed/Redacted Tool
            try:
                tool_output = execute_tool_safe(step.tool_name, effective_input)
            except Exception as exc:
                step.status = AgentStepStatus.FAILED
                step.explanation = f"Tool execution failed: {str(exc)}"
                task.status = AgentTaskStatus.FAILED
                task.final_answer = f"Execution halted at step {step.step_number}: {str(exc)}"
                self.repository.save_step(task.task_id, step)
                return self.repository.update_task(task)

            step.tool_output = tool_output
            step.status = AgentStepStatus.COMPLETED
            task.completed_steps += 1

            # Update pipeline context with tool result
            pipeline_context[f"step_{step.step_number}"] = tool_output
            if "content" in tool_output:
                pipeline_context["last_content"] = tool_output["content"]
            if "summary" in tool_output:
                pipeline_context["last_summary"] = tool_output["summary"]
            if "employee" in tool_output:
                emp = tool_output["employee"]
                pipeline_context["last_employee"] = emp
                pipeline_context["last_content"] = (
                    f"Employee details for {emp.get('employee_id')} {emp.get('name')}: "
                    f"Department: {emp.get('department')}, Role: {emp.get('job_title')}, "
                    f"Contact Email: {emp.get('email')}, Phone: {emp.get('phone')}."
                )

            # Record audit event for completed step (fails closed if audit persistence fails)
            audit_digest = self._audit_event(
                task=task,
                decision=decision.action,
                rule_ids=decision.reason_codes,
                status="step_completed",
                provider_called=False,
            )
            task.audit_references.append(audit_digest)

            self.repository.save_step(task.task_id, step)
            task.current_step_index += 1

        # 5. Task Completion and Final Answer Synthesis
        task.status = AgentTaskStatus.COMPLETED
        task.final_answer = self._synthesize_final_answer(task, pipeline_context)
        return self.repository.update_task(task)

    def _extract_text_for_evaluation(self, tool_input: dict[str, Any]) -> str:
        """Extract all textual fields from tool input for policy inspection."""
        parts: list[str] = []
        for k, v in tool_input.items():
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        for sub_k, sub_v in item.items():
                            if isinstance(sub_v, str):
                                parts.append(sub_v)
                    elif isinstance(item, str):
                        parts.append(item)
        return " ".join(parts) if parts else "safe_tool_execution"

    def _sanitize_tool_input(self, tool_input: dict[str, Any], redactions: list[Any]) -> dict[str, Any]:
        """Apply redactions to textual values in tool input dictionary."""
        sanitized = dict(tool_input)
        for k, v in sanitized.items():
            if isinstance(v, str):
                findings = self.detector.detect(v)
                sanitized_val, _ = self.redactor.redact(v, findings)
                sanitized[k] = sanitized_val
            elif isinstance(v, list):
                new_list = []
                for item in v:
                    if isinstance(item, dict):
                        new_dict = {}
                        for sub_k, sub_v in item.items():
                            if isinstance(sub_v, str):
                                findings = self.detector.detect(sub_v)
                                sub_sanitized, _ = self.redactor.redact(sub_v, findings)
                                new_dict[sub_k] = sub_sanitized
                            else:
                                new_dict[sub_k] = sub_v
                        new_list.append(new_dict)
                    else:
                        new_list.append(item)
                sanitized[k] = new_list
        return sanitized

    def _inject_pipeline_context(self, step: AgentStep, pipeline_context: dict[str, Any]) -> None:
        """Feed results from earlier steps into downstream tools (e.g. read -> summarize)."""
        if step.tool_name == "summarize_text":
            if "last_content" in pipeline_context and not step.tool_input.get("text", "").strip():
                step.tool_input["text"] = pipeline_context["last_content"]
            elif "last_content" in pipeline_context and any(k in step.tool_input.get("text", "") for k in ("Content from", "Employee record", "details for")):
                step.tool_input["text"] = pipeline_context["last_content"]

        elif step.tool_name == "format_report":
            summary = pipeline_context.get("last_summary") or pipeline_context.get("last_content")
            if summary and step.tool_input.get("sections"):
                step.tool_input["sections"][0]["content"] = summary[:2000]

    def _synthesize_final_answer(self, task: AgentTask, pipeline_context: dict[str, Any]) -> str:
        """Generate final user-facing answer summarizing completed task."""
        lines = [
            f"PrivAI Secure Task Agent completed task: '{task.goal}'",
            "",
            f"- Completed Steps: {task.completed_steps}",
            f"- Blocked Steps: {task.blocked_steps}",
            f"- Execution Status: {task.status.value.upper()}",
            "",
            "Key Results:",
        ]
        if "last_summary" in pipeline_context:
            lines.append(f"Summary: {pipeline_context['last_summary']}")
        elif "last_content" in pipeline_context:
            lines.append(f"Content Sample: {pipeline_context['last_content'][:300]}...")

        if task.plan:
            for s in task.plan.steps:
                lines.append(f"  Step {s.step_number}: [{s.status.value.upper()}] {s.description}")

        return "\n".join(lines)

    def _validate_and_consume_permit(
        self, permit: ReviewPermit, prompt_text: str, context: ContextModel, destination: Destination
    ) -> None:
        """Validate review permit and consume atomically in review repository."""
        verify_review_permit_signature(permit)
        digest = compute_request_digest(
            PromptRequest(prompt=prompt_text, destination=destination, context=context),
            self.orchestrator.policy_version,
        )
        self.orchestrator.review_repo.consume_permit_atomic(
            permit_nonce=permit.permit_nonce,
            expected_digest=digest,
        )

    def _audit_event(
        self,
        task: AgentTask,
        decision: PolicyOutcome,
        rule_ids: list[str],
        status: str,
        provider_called: bool,
    ) -> str:
        """Record audit event in shared audit service with fail-closed semantics."""
        digest = compute_request_digest(
            PromptRequest(prompt=task.goal, destination=task.destination, context=task.context),
            self.orchestrator.policy_version,
        )
        try:
            self.orchestrator._record_audit_event(
                request_digest=digest,
                destination=task.destination.value,
                decision=decision,
                rule_ids=rule_ids,
                risk_score=0 if decision == PolicyOutcome.ALLOW else 75,
                status=status,
                provider_called=provider_called,
                redaction_count=0,
                latency_ms=10,
                event_type=f"agent_task_{status}",
                actor_id="privai_agent",
            )
        except Exception as exc:
            # Fail closed!
            raise AuditWriteException(f"Fail-closed: audit write failed during agent execution: {exc}")
        return digest
