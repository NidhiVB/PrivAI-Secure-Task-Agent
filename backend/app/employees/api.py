"""FastAPI routing endpoints for Employee Privacy Demo."""

from fastapi import APIRouter, HTTPException, Query, status

from backend.app.core.exceptions import PrivAIException
from backend.app.employees.models import (
    EmployeeDetailResponse,
    EmployeeOperationRequest,
    EmployeeOperationResponse,
    EmployeeResetResponse,
    EmployeeSearchResponse,
)
from backend.app.employees.service import EmployeeService
from backend.app.models.responses import SafeErrorResponse

router = APIRouter(prefix="/employees", tags=["Employee Privacy Demo"])
employee_service = EmployeeService()


def set_employee_service(service: EmployeeService) -> None:
    """Inject custom employee service for testing isolation."""
    global employee_service
    employee_service = service


def get_employee_service() -> EmployeeService:
    """Get active employee service instance."""
    return employee_service


@router.get(
    "",
    response_model=EmployeeSearchResponse,
    summary="Search and filter synthetic employee directory",
    responses={
        200: {"model": EmployeeSearchResponse, "description": "Filtered synthetic employee records"},
        500: {"model": SafeErrorResponse, "description": "Internal server error"},
    },
)
def list_employees(
    q: str | None = Query(default=None, description="Search query by name, ID, department, or title"),
    query: str | None = Query(default=None, description="Alias for search query"),
    department: str | None = Query(default=None, description="Department filter"),
    classification: str | None = Query(default=None, description="Data classification filter"),
) -> EmployeeSearchResponse:
    """Search and filter the synthetic employee dataset."""
    search_q = q or query
    records = employee_service.repository.search_employees(
        query=search_q,
        department=department,
        classification=classification,
    )
    summaries = [employee_service.get_summary_view(r) for r in records]
    departments = employee_service.repository.list_departments()
    classifications = employee_service.repository.list_classifications()

    return EmployeeSearchResponse(
        total=len(summaries),
        employees=summaries,
        departments=departments,
        classifications=classifications,
    )


@router.get(
    "/departments",
    response_model=list[str],
    summary="List all distinct employee departments",
)
def get_departments() -> list[str]:
    """Return all unique departments present in synthetic directory."""
    return employee_service.repository.list_departments()


@router.get(
    "/classifications",
    response_model=list[str],
    summary="List all distinct employee data classifications",
)
def get_classifications() -> list[str]:
    """Return all unique data classifications present in synthetic directory."""
    return employee_service.repository.list_classifications()


@router.get(
    "/{employee_id}",
    response_model=EmployeeDetailResponse,
    summary="Retrieve employee profile with backend-enforced field authorizations",
    responses={
        200: {"model": EmployeeDetailResponse, "description": "Authorized employee view"},
        404: {"model": SafeErrorResponse, "description": "Employee not found"},
    },
)
def get_employee_profile(employee_id: str) -> EmployeeDetailResponse:
    """Retrieve full employee details and backend-governed field authorization metadata."""
    try:
        return employee_service.get_employee_detail(employee_id)
    except PrivAIException as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
        )


@router.post(
    "/reset",
    response_model=EmployeeResetResponse,
    summary="Reset synthetic demo data to default baseline",
    responses={
        200: {"model": EmployeeResetResponse, "description": "Demo dataset reset successfully"},
        500: {"model": SafeErrorResponse, "description": "Reset failed"},
    },
)
def reset_demo_data() -> EmployeeResetResponse:
    """Reset only the synthetic demo employee dataset to default seed records.

    Safety: Strictly never modifies historical privai_data.db or forensic tables.
    """
    seeded_count = employee_service.repository.reset_demo_data()
    return EmployeeResetResponse(
        status="ok",
        message="Synthetic employee demo dataset successfully reset to baseline.",
        records_seeded=seeded_count,
        database_path=employee_service.repository.db_path,
    )


@router.post(
    "/operations/execute",
    response_model=EmployeeOperationResponse,
    summary="Execute a privacy-governed operation on an employee record",
    responses={
        200: {"model": EmployeeOperationResponse, "description": "Operation executed through privacy firewall"},
        400: {"model": SafeErrorResponse, "description": "Invalid operation request"},
        404: {"model": SafeErrorResponse, "description": "Employee record not found"},
    },
)
def execute_employee_operation(request: EmployeeOperationRequest) -> EmployeeOperationResponse:
    """Execute a realistic privacy-governed operation against synthetic employee data.

    Demonstrates ALLOW, REDACT, BLOCK, and REVIEW decisions through the real backend firewall and agent.
    """
    try:
        return employee_service.execute_operation(request)
    except PrivAIException as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
        )
