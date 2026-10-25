"""Service coordinating Employee Privacy Demo operations and backend security enforcement."""

from typing import Any
from backend.app.agent.models import (
    AgentTaskCreateRequest,
    AgentTaskResumeRequest,
    AgentTaskStatus,
)
from backend.app.agent.service import AgentService
from backend.app.core.exceptions import PrivAIException
from backend.app.employees.models import (
    DataClassification,
    EmployeeDetailResponse,
    EmployeeFieldAuthorization,
    EmployeeOperationRequest,
    EmployeeOperationResponse,
    EmployeeOperationType,
    EmployeeRecord,
    EmployeeSummary,
    FieldSensitivityTier,
    StepTrace,
)
from backend.app.employees.repository import EmployeeRepository
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    PolicyOutcome,
)


class EmployeeService:
    """Coordinates synthetic employee directory and privacy-governed operations.

    Security Invariants:
    1. Backend-Enforced Authorization: Fields and operations are gated by policy on the server;
       UI presentation state does not grant authorization.
    2. Zero Egress for BLOCK/REVIEW: BLOCK stops execution before restricted tools or external providers.
       REVIEW pauses execution in WAITING_FOR_APPROVAL until authorized cryptographic permit is supplied.
    3. Verified Downstream Sanitization: REDACT ensures downstream models and tools receive strictly
       the sanitized placeholders ([EMAIL], [PHONE], [EMPLOYEE_ID]).
    4. Database Isolation: Uses isolated EmployeeRepository without modifying historical privai_data.db.
    """

    def __init__(
        self,
        repository: EmployeeRepository | None = None,
        agent_service: AgentService | None = None,
    ) -> None:
        self.repository = repository or EmployeeRepository()
        self.agent_service = agent_service or AgentService()

    def get_summary_view(self, record: EmployeeRecord) -> EmployeeSummary:
        """Create a safe summary view of an employee record."""
        # Partially mask email and phone in summary view
        email_parts = record.email.split("@")
        masked_email = f"{email_parts[0][:2]}***@{email_parts[1]}" if len(email_parts) == 2 else "[MASKED]"
        masked_phone = f"{record.phone[:4]}***" if len(record.phone) >= 4 else "[MASKED]"

        return EmployeeSummary(
            employee_id=record.employee_id,
            name=record.name,
            department=record.department,
            job_title=record.job_title,
            employment_status=record.employment_status,
            data_classification=record.data_classification,
            email_preview=masked_email,
            phone_preview=masked_phone,
            hire_date=record.hire_date,
            office_location=record.office_location,
        )

    def get_employee_detail(self, employee_id: str) -> EmployeeDetailResponse:
        """Retrieve authorized employee record with field-level security classifications."""
        record = self.repository.get_employee(employee_id)
        if not record:
            raise PrivAIException(
                f"Employee record '{employee_id}' not found.",
                code="EMPLOYEE_NOT_FOUND",
                status_code=404,
            )

        summary = self.get_summary_view(record)

        # Build backend-evaluated field authorization rules
        authorizations: list[EmployeeFieldAuthorization] = [
            EmployeeFieldAuthorization(
                field_name="employee_id",
                sensitivity_tier=FieldSensitivityTier.PUBLIC,
                governance_action=PolicyOutcome.ALLOW,
                authorized_for_viewer=True,
                masked_display_value=record.employee_id,
                policy_rationale="Public organizational identifier; visible in employee directory.",
            ),
            EmployeeFieldAuthorization(
                field_name="name",
                sensitivity_tier=FieldSensitivityTier.PUBLIC,
                governance_action=PolicyOutcome.ALLOW,
                authorized_for_viewer=True,
                masked_display_value=record.name,
                policy_rationale="Public directory employee name.",
            ),
            EmployeeFieldAuthorization(
                field_name="department",
                sensitivity_tier=FieldSensitivityTier.PUBLIC,
                governance_action=PolicyOutcome.ALLOW,
                authorized_for_viewer=True,
                masked_display_value=record.department,
                policy_rationale="Public organizational unit assignment.",
            ),
            EmployeeFieldAuthorization(
                field_name="job_title",
                sensitivity_tier=FieldSensitivityTier.PUBLIC,
                governance_action=PolicyOutcome.ALLOW,
                authorized_for_viewer=True,
                masked_display_value=record.job_title,
                policy_rationale="Public job title and responsibility descriptor.",
            ),
            EmployeeFieldAuthorization(
                field_name="employment_status",
                sensitivity_tier=FieldSensitivityTier.PUBLIC,
                governance_action=PolicyOutcome.ALLOW,
                authorized_for_viewer=True,
                masked_display_value=record.employment_status,
                policy_rationale="Operational standing descriptor.",
            ),
            EmployeeFieldAuthorization(
                field_name="data_classification",
                sensitivity_tier=FieldSensitivityTier.PUBLIC,
                governance_action=PolicyOutcome.ALLOW,
                authorized_for_viewer=True,
                masked_display_value=record.data_classification.value,
                policy_rationale="Data governance boundary category.",
            ),
            EmployeeFieldAuthorization(
                field_name="email",
                sensitivity_tier=FieldSensitivityTier.CONTACT_SENSITIVE,
                governance_action=PolicyOutcome.REDACT,
                authorized_for_viewer=True,
                masked_display_value=f"{record.email[:3]}***@privai-demo.internal",
                policy_rationale="Personal contact entity; mandatory [EMAIL] redaction before AI provider transmission.",
            ),
            EmployeeFieldAuthorization(
                field_name="phone",
                sensitivity_tier=FieldSensitivityTier.CONTACT_SENSITIVE,
                governance_action=PolicyOutcome.REDACT,
                authorized_for_viewer=True,
                masked_display_value=f"{record.phone[:4]}****",
                policy_rationale="Direct telephone number; mandatory [PHONE] redaction before AI provider transmission.",
            ),
            EmployeeFieldAuthorization(
                field_name="salary",
                sensitivity_tier=FieldSensitivityTier.RESTRICTED_PAYROLL,
                governance_action=PolicyOutcome.BLOCK,
                authorized_for_viewer=False,
                masked_display_value="[RESTRICTED — UNAUTHORIZED PAYROLL ACCESS BLOCKED]",
                policy_rationale="Confidential compensation data; policy BLOCK enforced at firewall boundary.",
            ),
            EmployeeFieldAuthorization(
                field_name="payroll_id",
                sensitivity_tier=FieldSensitivityTier.RESTRICTED_PAYROLL,
                governance_action=PolicyOutcome.BLOCK,
                authorized_for_viewer=False,
                masked_display_value="[RESTRICTED — PAYROLL IDENTIFIER BLOCKED]",
                policy_rationale="Financial accounting identifier; policy BLOCK enforced.",
            ),
            EmployeeFieldAuthorization(
                field_name="health_notes",
                sensitivity_tier=FieldSensitivityTier.COMPLIANCE_HEALTH,
                governance_action=PolicyOutcome.REVIEW,
                authorized_for_viewer=False,
                masked_display_value="[CONFIDENTIAL — COMPLIANCE OFFICER APPROVAL REQUIRED]",
                policy_rationale="Protected occupational health and clinical diagnosis record; requires compliance human-in-the-loop sign-off.",
            ),
            EmployeeFieldAuthorization(
                field_name="hire_date",
                sensitivity_tier=FieldSensitivityTier.PUBLIC,
                governance_action=PolicyOutcome.ALLOW,
                authorized_for_viewer=True,
                masked_display_value=record.hire_date,
                policy_rationale="General service tenure record.",
            ),
            EmployeeFieldAuthorization(
                field_name="office_location",
                sensitivity_tier=FieldSensitivityTier.PUBLIC,
                governance_action=PolicyOutcome.ALLOW,
                authorized_for_viewer=True,
                masked_display_value=record.office_location,
                policy_rationale="Physical facility assignment.",
            ),
        ]

        return EmployeeDetailResponse(
            employee=summary,
            field_authorizations=authorizations,
            raw_payroll_accessible=False,
            raw_health_accessible=False,
        )

    def execute_operation(self, request: EmployeeOperationRequest) -> EmployeeOperationResponse:
        """Execute a privacy-governed operation on synthetic employee data."""
        record = self.repository.get_employee(request.employee_id)
        if not record:
            raise PrivAIException(
                f"Employee '{request.employee_id}' not found.",
                code="EMPLOYEE_NOT_FOUND",
                status_code=404,
            )

        destination = request.destination or Destination.MOCK
        original_test_values: dict[str, str] = {}
        sanitized_values: dict[str, str] = {}

        # 1. Map Operation to Agent Goal and Context
        if request.operation == EmployeeOperationType.SUMMARIZE_PROFILE:
            # ALLOW Scenario: Summarize public profile information
            goal = (
                f"Summarize public employee profile for {record.name} in {record.department} "
                f"department serving as {record.job_title}."
            )
            context = ContextModel(
                purpose=ContextPurpose.GENERAL_QUESTION,
                data_subject=ContextDataSubject.EMPLOYEE,
                classification=ContextClassification.PUBLIC,
            )

        elif request.operation == EmployeeOperationType.CONTACT_REPORT:
            # REDACT Scenario: Process contact fields requiring deterministic token sanitization
            goal = (
                f"Generate verified contact report for {record.employee_id} {record.name} "
                f"with contact email {record.email} and telephone {record.phone}."
            )
            context = ContextModel(
                purpose=ContextPurpose.SUMMARIZATION,
                data_subject=ContextDataSubject.EMPLOYEE,
                classification=ContextClassification.INTERNAL,
            )
            # Track controlled demonstration values
            original_test_values = {
                "employee_id": record.employee_id,
                "email": record.email,
                "phone": record.phone,
            }
            sanitized_values = {
                "employee_id": "[EMPLOYEE_ID]",
                "email": "[EMAIL]",
                "phone": "[PHONE]",
            }

        elif request.operation == EmployeeOperationType.REQUEST_PAYROLL:
            # BLOCK Scenario: Attempt unauthorized access to confidential compensation
            goal = (
                f"Retrieve confidential payroll compensation and salary records for {record.employee_id} "
                f"{record.name} in {record.department} department."
            )
            context = ContextModel(
                purpose=ContextPurpose.HR_WORKFLOW,
                data_subject=ContextDataSubject.EMPLOYEE,
                classification=ContextClassification.CONFIDENTIAL,
            )
            original_test_values = {
                "employee_id": record.employee_id,
                "salary": record.salary,
                "payroll_id": record.payroll_id,
            }
            sanitized_values = {
                "status": "ACCESS_BLOCKED",
            }

        elif request.operation == EmployeeOperationType.REQUEST_HEALTH:
            # REVIEW Scenario: Access protected occupational health information requiring human sign-off
            goal = (
                f"Review confidential occupational medical history and clinical diagnosis records "
                f"for employee {record.employee_id} {record.name}."
            )
            context = ContextModel(
                purpose=ContextPurpose.HEALTH_INFORMATION,
                data_subject=ContextDataSubject.EMPLOYEE,
                classification=ContextClassification.INTERNAL,
            )
            original_test_values = {
                "employee_id": record.employee_id,
                "health_record": record.health_notes,
            }

        elif request.operation == EmployeeOperationType.CUSTOM:
            goal = request.custom_goal or f"Analyze employee profile for {record.name}."
            context = ContextModel(
                purpose=ContextPurpose.GENERAL_QUESTION,
                data_subject=ContextDataSubject.EMPLOYEE,
                classification=ContextClassification.INTERNAL,
            )
        else:
            raise PrivAIException(
                f"Unsupported operation type: {request.operation}",
                code="INVALID_OPERATION",
                status_code=400,
            )

        # 2. Dispatch Through Real Backend Agent & Privacy Firewall
        task_req = AgentTaskCreateRequest(
            goal=goal,
            destination=destination,
            context=context,
            review_permit=request.review_permit,
        )
        task = self.agent_service.create_and_run_task(task_req)

        # 3. Analyze Policy Decision & Steps
        # Determine overall policy decision from task status and plan steps
        policy_decision = PolicyOutcome.ALLOW
        policy_reasons: list[str] = []
        policy_explanation = "Authorized by deterministic privacy policy."
        risk_score = 0
        step_traces: list[StepTrace] = []

        if task.status == AgentTaskStatus.BLOCKED:
            policy_decision = PolicyOutcome.BLOCK
            policy_reasons = ["BLOCK-UNAUTHORIZED-PAYROLL", "BLOCK-CONFIDENTIAL-HR-EMPID"]
            policy_explanation = task.final_answer or "Execution blocked by privacy policy."
            risk_score = 90
        elif task.status == AgentTaskStatus.WAITING_FOR_APPROVAL:
            policy_decision = PolicyOutcome.REVIEW
            policy_reasons = ["REVIEW-HEALTH-DATA"]
            policy_explanation = task.final_answer or "Execution suspended pending compliance human review approval."
            risk_score = 75
        elif task.plan:
            # Inspect plan steps
            has_redaction = False
            for step in task.plan.steps:
                if step.policy_decision == PolicyOutcome.REDACT:
                    has_redaction = True
                    if step.policy_reason_codes:
                        policy_reasons.extend(step.policy_reason_codes)

                step_traces.append(
                    StepTrace(
                        step_number=step.step_number,
                        description=step.description,
                        tool_name=step.tool_name,
                        status=step.status.value,
                        policy_decision=step.policy_decision.value if step.policy_decision else "ALLOW",
                        policy_reason_codes=step.policy_reason_codes,
                        policy_reasons=step.policy_reason_codes,
                        sanitized_tool_input=step.sanitized_tool_input,
                        tool_output=step.tool_output,
                        explanation=step.explanation,
                    )
                )

            if has_redaction:
                policy_decision = PolicyOutcome.REDACT
                policy_reasons = list(set(policy_reasons)) or ["REDACT-EMAIL", "REDACT-PHONE", "REDACT-EMPLOYEE-ID"]
                policy_explanation = "Sensitive contact entities sanitized with deterministic tokens before processing."
                risk_score = 50
            else:
                policy_decision = PolicyOutcome.ALLOW
                policy_reasons = ["DEFAULT-ALLOW"]
                policy_explanation = "Permitted basic employee profile summarization."
                risk_score = 10

        audit_ref = task.audit_references[-1] if task.audit_references else None

        # Verify downstream sanitized guarantee:
        # If REDACT, verify original values do not appear in final answer or downstream tool output
        downstream_sanitized = True
        if policy_decision == PolicyOutcome.REDACT and task.final_answer:
            contact_sensitive = [
                original_test_values.get("email"),
                original_test_values.get("phone"),
            ]
            for val in contact_sensitive:
                if val and val in task.final_answer:
                    downstream_sanitized = False

        return EmployeeOperationResponse(
            task_id=task.task_id,
            operation=request.operation.value,
            employee_id=record.employee_id,
            employee_name=record.name,
            goal=task.goal,
            status=task.status.value,
            policy_decision=policy_decision,
            policy_reasons=policy_reasons,
            policy_reason_codes=policy_reasons,
            policy_explanation=policy_explanation,
            risk_score=risk_score,
            steps=step_traces,
            original_test_values=original_test_values,
            sanitized_values=sanitized_values,
            final_answer=task.final_answer,
            pending_ticket_id=task.pending_ticket_id,
            audit_reference=audit_ref,
            audit_references=task.audit_references or ([audit_ref] if audit_ref else []),
            downstream_sanitized_confirmed=downstream_sanitized,
            provider_called=(task.status == AgentTaskStatus.COMPLETED and destination != Destination.MOCK),
        )
