"""Data models and schemas for the Synthetic Employee Privacy Demo."""

from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.app.models.enums import Destination, PolicyOutcome
from backend.app.models.reviews import ReviewPermit


class DataClassification(str, Enum):
    """Data classification tiers for employee records."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class FieldSensitivityTier(str, Enum):
    """Sensitivity classification for individual fields."""
    PUBLIC = "PUBLIC"
    CONTACT_SENSITIVE = "CONTACT_SENSITIVE"
    RESTRICTED_PAYROLL = "RESTRICTED_PAYROLL"
    COMPLIANCE_HEALTH = "COMPLIANCE_HEALTH"


class EmployeeOperationType(str, Enum):
    """Standard demo operations for employee records."""
    SUMMARIZE_PROFILE = "summarize_profile"
    CONTACT_REPORT = "contact_report"
    REQUEST_PAYROLL = "request_payroll"
    REQUEST_HEALTH = "request_health"
    CUSTOM = "custom"


class EmployeeRecord(BaseModel):
    """Complete synthetic employee record stored in isolated database."""
    model_config = ConfigDict(extra="forbid")

    employee_id: str = Field(..., description="Unique synthetic employee identifier (e.g. EMP-1001)")
    name: str = Field(..., description="Synthetic employee name")
    department: str = Field(..., description="Assigned organizational department")
    job_title: str = Field(..., description="Job title / role")
    employment_status: str = Field(default="Active", description="Employment status (Active, On Leave, etc.)")
    data_classification: DataClassification = Field(..., description="Data governance classification")
    email: str = Field(..., description="Synthetic business email address")
    phone: str = Field(..., description="Synthetic phone number")
    salary: str = Field(..., description="Synthetic compensation amount")
    payroll_id: str = Field(..., description="Synthetic payroll identifier")
    health_notes: str = Field(..., description="Synthetic health/occupational notes")
    hire_date: str = Field(..., description="ISO hire date")
    office_location: str = Field(..., description="Office facility location")
    created_at: str = Field(default="", description="Record creation timestamp")
    updated_at: str = Field(default="", description="Record update timestamp")


class EmployeeFieldAuthorization(BaseModel):
    """Field-level authorization metadata evaluated on the backend."""
    model_config = ConfigDict(extra="forbid")

    field_name: str
    sensitivity_tier: FieldSensitivityTier
    governance_action: PolicyOutcome
    authorized_for_viewer: bool
    masked_display_value: str
    policy_rationale: str


class EmployeeSummary(BaseModel):
    """Authorized summary view of an employee record."""
    model_config = ConfigDict(extra="forbid")

    employee_id: str
    name: str
    department: str
    job_title: str
    employment_status: str
    data_classification: DataClassification
    email_preview: str
    phone_preview: str
    hire_date: str
    office_location: str


class EmployeeDetailResponse(BaseModel):
    """Employee record response with explicit field-level authorization view."""
    model_config = ConfigDict(extra="forbid")

    employee: EmployeeSummary
    field_authorizations: list[EmployeeFieldAuthorization]
    raw_payroll_accessible: bool = False
    raw_health_accessible: bool = False


class EmployeeSearchResponse(BaseModel):
    """Search and filter response for employee directory."""
    model_config = ConfigDict(extra="forbid")

    total: int
    employees: list[EmployeeSummary]
    departments: list[str]
    classifications: list[str]


class EmployeeOperationRequest(BaseModel):
    """Request to execute a privacy-governed operation on an employee record."""
    model_config = ConfigDict(extra="forbid")

    employee_id: str = Field(..., min_length=4, max_length=16, description="Target employee ID (e.g. EMP-1002)")
    operation: EmployeeOperationType = Field(..., description="Selected operation type")
    destination: Destination = Field(default=Destination.MOCK, description="Target AI provider")
    custom_goal: str | None = Field(default=None, max_length=1024, description="Optional custom goal for operation=custom")
    review_permit: ReviewPermit | None = Field(default=None, description="Cryptographic permit to resume suspended review task")


class StepTrace(BaseModel):
    """Step execution trace for the demonstration UI."""
    model_config = ConfigDict(extra="forbid")

    step_number: int
    description: str
    tool_name: str
    status: str
    policy_decision: str
    policy_reason_codes: list[str] = Field(default_factory=list)
    policy_reasons: list[str] = Field(default_factory=list)
    sanitized_tool_input: dict[str, Any] | None = None
    tool_output: dict[str, Any] | None = None
    explanation: str | None = None

    @model_validator(mode="before")
    @classmethod
    def sync_step_reasons(cls, data: Any) -> Any:
        if isinstance(data, dict):
            reasons = data.get("policy_reasons") or data.get("policy_reason_codes") or []
            if not data.get("policy_reasons"):
                data["policy_reasons"] = list(reasons)
            if not data.get("policy_reason_codes"):
                data["policy_reason_codes"] = list(reasons)
        return data


class EmployeeOperationResponse(BaseModel):
    """Comprehensive response for employee privacy demo operation."""
    model_config = ConfigDict(extra="forbid")

    task_id: str
    operation: str
    employee_id: str
    employee_name: str
    goal: str
    status: str
    policy_decision: PolicyOutcome
    policy_reasons: list[str] = Field(default_factory=list)
    policy_reason_codes: list[str] = Field(default_factory=list)
    policy_explanation: str
    risk_score: int
    steps: list[StepTrace] = Field(default_factory=list)
    original_test_values: dict[str, str] = Field(default_factory=dict)
    sanitized_values: dict[str, str] = Field(default_factory=dict)
    final_answer: str | None = None
    pending_ticket_id: str | None = None
    audit_reference: str | None = None
    audit_references: list[str] = Field(default_factory=list)
    downstream_sanitized_confirmed: bool = True
    provider_called: bool = False

    @model_validator(mode="before")
    @classmethod
    def sync_reasons_and_audits(cls, data: Any) -> Any:
        if isinstance(data, dict):
            reasons = data.get("policy_reasons") or data.get("policy_reason_codes") or []
            if not data.get("policy_reasons"):
                data["policy_reasons"] = list(reasons)
            if not data.get("policy_reason_codes"):
                data["policy_reason_codes"] = list(reasons)

            audit_ref = data.get("audit_reference")
            audit_refs = data.get("audit_references") or []
            if audit_ref and not audit_refs:
                data["audit_references"] = [audit_ref]
            elif audit_refs and not audit_ref:
                data["audit_reference"] = audit_refs[0]
        return data


class EmployeeResetResponse(BaseModel):
    """Response returned when synthetic demo data is reset."""
    model_config = ConfigDict(extra="forbid")

    status: str
    message: str
    records_seeded: int
    database_path: str
