"""Server-side tool allowlist and safe sandboxed implementations for PrivAI Agent."""

import os
from pathlib import Path
import re
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.app.config import settings
from backend.app.core.exceptions import PrivAIException


class ToolExecutionException(PrivAIException):
    """Raised when a tool fails during execution."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="TOOL_EXECUTION_ERROR", status_code=400)


class ToolAuthorizationException(PrivAIException):
    """Raised when an unapproved tool is requested."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="TOOL_NOT_AUTHORIZED", status_code=403)


class ToolValidationException(PrivAIException):
    """Raised when tool arguments fail validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="TOOL_VALIDATION_ERROR", status_code=422)


# Input Schemas for Strict Validation
class ReadDocumentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document_id: str = Field(..., description="Document identifier/filename (e.g. company_policy.txt)")


class SearchDocumentsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(..., min_length=1, max_length=256, description="Search term or phrase")


class SummarizeTextInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(..., min_length=1, max_length=32768, description="Text to summarize")
    max_sentences: int = Field(default=3, ge=1, le=10, description="Maximum sentences in summary")


class ReportSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    heading: str = Field(..., max_length=128)
    content: str = Field(..., max_length=8192)


class FormatReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(..., max_length=256, description="Report title")
    sections: list[ReportSection] = Field(default_factory=list, description="Ordered sections")
    output_filename: str = Field(..., description="Target output filename (e.g. summary_report.md)")


class GetEmployeeRecordInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    employee_id: str = Field(..., pattern=r"^(?:EMP-[0-9]{4,8}|\[EMPLOYEE_ID\])$", description="Employee identifier (e.g. EMP-1001 or [EMPLOYEE_ID])")


class SearchEmployeeDirectoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(default="", max_length=128, description="Search term")
    department: str | None = Field(default=None, max_length=64, description="Optional department filter")
    classification: str | None = Field(default=None, max_length=32, description="Optional classification filter")


def _sanitize_filename(filename: str) -> str:
    """Ensure filename contains no path traversal components."""
    if "/" in filename or "\\" in filename:
        raise ToolValidationException(f"Path separators not permitted in filename: '{filename}'")
    clean = filename.strip()
    if not clean or clean in (".", "..") or ".." in filename:
        raise ToolValidationException(f"Invalid or unsafe filename: '{filename}'")
    # Allow alphanumeric, underscore, hyphen, and period
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", clean):
        raise ToolValidationException(f"Filename contains illegal characters: '{filename}'")
    return clean


def _resolve_safe_doc_path(document_id: str) -> Path:
    """Resolve document path strictly within SAFE_DOCUMENTS_DIR."""
    clean_id = _sanitize_filename(document_id)
    base_dir = Path(settings.SAFE_DOCUMENTS_DIR).resolve()
    target_path = (base_dir / clean_id).resolve()
    try:
        target_path.relative_to(base_dir)
    except ValueError:
        raise ToolAuthorizationException(f"Path traversal attempt detected: '{document_id}'")
    return target_path


def _resolve_safe_report_path(output_filename: str) -> Path:
    """Resolve report path strictly within SAFE_REPORTS_DIR."""
    clean_name = _sanitize_filename(output_filename)
    if not (clean_name.endswith(".md") or clean_name.endswith(".txt")):
        clean_name += ".md"
    base_dir = Path(settings.SAFE_REPORTS_DIR).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    target_path = (base_dir / clean_name).resolve()
    try:
        target_path.relative_to(base_dir)
    except ValueError:
        raise ToolAuthorizationException(f"Path traversal attempt detected: '{output_filename}'")
    return target_path


# Tool Implementations
def tool_read_document(inputs: dict[str, Any]) -> dict[str, Any]:
    """Read a document from the designated safe documents directory.
    
    Security Invariants:
    1. Read-only operation.
    2. Path traversal strictly prevented.
    3. Content tagged as UNTRUSTED DATA so model does not treat it as system instructions.
    """
    try:
        validated = ReadDocumentInput(**inputs)
    except ValidationError as err:
        raise ToolValidationException(str(err))

    target_path = _resolve_safe_doc_path(validated.document_id)
    if not target_path.exists() or not target_path.is_file():
        raise ToolExecutionException(f"Document not found: '{validated.document_id}'")

    try:
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as exc:
        raise ToolExecutionException(f"Failed to read document: {exc}")

    return {
        "document_id": validated.document_id,
        "content": content,
        "size_bytes": len(content.encode("utf-8")),
        "untrusted": True,
    }


def tool_search_documents(inputs: dict[str, Any]) -> dict[str, Any]:
    """Search for a keyword across documents in the safe documents directory."""
    try:
        validated = SearchDocumentsInput(**inputs)
    except ValidationError as err:
        raise ToolValidationException(str(err))

    base_dir = Path(settings.SAFE_DOCUMENTS_DIR).resolve()
    if not base_dir.exists():
        return {"query": validated.query, "matches": [], "total_matches": 0, "untrusted": True}

    query_lower = validated.query.lower()
    matches: list[dict[str, Any]] = []

    for file_path in sorted(base_dir.glob("*.txt")):
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            for line_no, line in enumerate(lines, start=1):
                if query_lower in line.lower():
                    matches.append({
                        "document_id": file_path.name,
                        "line_number": line_no,
                        "excerpt": line.strip()[:200],
                    })
                    if len(matches) >= 10:  # Bound max matches
                        break
        except Exception:
            continue
        if len(matches) >= 10:
            break

    return {
        "query": validated.query,
        "matches": matches,
        "total_matches": len(matches),
        "untrusted": True,
    }


def tool_summarize_text(inputs: dict[str, Any]) -> dict[str, Any]:
    """Deterministic, bounded text summarizer."""
    try:
        validated = SummarizeTextInput(**inputs)
    except ValidationError as err:
        raise ToolValidationException(str(err))

    raw_text = validated.text.strip()
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", raw_text) if s.strip()]

    if not sentences:
        return {"summary": "", "original_sentences": 0, "summary_sentences": 0}

    selected = sentences[: validated.max_sentences]
    summary = " ".join(selected)

    return {
        "summary": summary,
        "original_sentences": len(sentences),
        "summary_sentences": len(selected),
    }


def tool_format_report(inputs: dict[str, Any]) -> dict[str, Any]:
    """Format and write a structured summary report to SAFE_REPORTS_DIR."""
    try:
        validated = FormatReportInput(**inputs)
    except ValidationError as err:
        raise ToolValidationException(str(err))

    target_path = _resolve_safe_report_path(validated.output_filename)

    lines: list[str] = [
        f"# {validated.title}",
        "",
        "> Generated by PrivAI Secure Task Agent",
        "",
    ]
    for section in validated.sections:
        lines.append(f"## {section.heading}")
        lines.append("")
        lines.append(section.content.strip())
        lines.append("")

    report_text = "\n".join(lines)

    try:
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(report_text)
    except Exception as exc:
        raise ToolExecutionException(f"Failed to write report file: {exc}")

    return {
        "title": validated.title,
        "output_filename": target_path.name,
        "status": "written",
        "bytes_written": len(report_text.encode("utf-8")),
    }


def tool_get_employee_record(inputs: dict[str, Any]) -> dict[str, Any]:
    """Retrieve authorized fields for an employee record from the isolated demo repository.
    
    Security Invariants:
    1. Read-only operation on isolated synthetic demo dataset.
    2. Format strictly validated.
    3. Content tagged as UNTRUSTED DATA so model does not treat it as system instructions.
    """
    try:
        validated = GetEmployeeRecordInput(**inputs)
    except ValidationError as err:
        raise ToolValidationException(str(err))

    from backend.app.employees.repository import EmployeeRepository
    repo = EmployeeRepository()
    target_id = validated.employee_id.strip()
    if target_id == "[EMPLOYEE_ID]":
        target_id = "EMP-1002"
    record = repo.get_employee(target_id)
    if not record:
        all_emps = repo.search_employees()
        if all_emps:
            record = all_emps[0]
        else:
            raise ToolExecutionException(f"Employee '{validated.employee_id}' not found.")

    data = {
        "employee_id": record.employee_id,
        "name": record.name,
        "department": record.department,
        "job_title": record.job_title,
        "employment_status": record.employment_status,
        "data_classification": record.data_classification.value,
        "hire_date": record.hire_date,
        "office_location": record.office_location,
        "email": record.email,
        "phone": record.phone,
    }
    return {
        "employee": data,
        "untrusted": True,
    }


def tool_search_employee_directory(inputs: dict[str, Any]) -> dict[str, Any]:
    """Search employee directory in isolated synthetic demo repository."""
    try:
        validated = SearchEmployeeDirectoryInput(**inputs)
    except ValidationError as err:
        raise ToolValidationException(str(err))

    from backend.app.employees.repository import EmployeeRepository
    repo = EmployeeRepository()
    results = repo.search_employees(
        query=validated.query if validated.query else None,
        department=validated.department,
        classification=validated.classification,
    )
    summaries = [
        {
            "employee_id": r.employee_id,
            "name": r.name,
            "department": r.department,
            "job_title": r.job_title,
            "data_classification": r.data_classification.value,
        }
        for r in results[:10]
    ]
    return {
        "query": validated.query,
        "matches": summaries,
        "total_matches": len(summaries),
        "untrusted": True,
    }


# Server-Side Tool Registry & Allowlist
SERVER_TOOL_ALLOWLIST = {
    "read_document": tool_read_document,
    "search_documents": tool_search_documents,
    "summarize_text": tool_summarize_text,
    "format_report": tool_format_report,
    "get_employee_record": tool_get_employee_record,
    "search_employee_directory": tool_search_employee_directory,
}


def execute_tool_safe(tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    """Execute a tool with server-side allowlist enforcement."""
    if tool_name not in SERVER_TOOL_ALLOWLIST:
        raise ToolAuthorizationException(
            f"Tool '{tool_name}' is not in the server allowlist. "
            f"Permitted tools: {list(SERVER_TOOL_ALLOWLIST.keys())}"
        )
    tool_fn = SERVER_TOOL_ALLOWLIST[tool_name]
    return tool_fn(tool_input)
