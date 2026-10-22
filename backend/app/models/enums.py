"""Enumeration types for PrivAI models."""

from enum import Enum


class Destination(str, Enum):
    """Allowed AI destination providers (server-side allowlist only)."""

    MOCK = "mock"
    GROQ = "groq"


class ContextPurpose(str, Enum):
    """Purpose of the prompt execution."""

    GENERAL_QUESTION = "general_question"
    SUMMARIZATION = "summarization"
    CODING = "coding"
    HR_WORKFLOW = "hr_workflow"
    HEALTH_INFORMATION = "health_information"
    OTHER = "other"


class ContextDataSubject(str, Enum):
    """Subject of the data contained within the prompt."""

    NONE = "none"
    SELF = "self"
    THIRD_PARTY = "third_party"
    EMPLOYEE = "employee"
    UNKNOWN = "unknown"


class ContextClassification(str, Enum):
    """Data classification level."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class PolicyOutcome(str, Enum):
    """Authoritative policy decision outcomes."""

    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class ExecutionStatus(str, Enum):
    """Execution status returned to client."""

    COMPLETED = "completed"
    BLOCKED = "blocked"
    REVIEW_PENDING = "review_pending"


class RiskBand(str, Enum):
    """Risk scoring bands."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    """Supported sensitive information categories."""

    EMAIL = "EMAIL"
    PHONE = "PHONE"
    EMPLOYEE_ID = "EMPLOYEE_ID"
    NATIONAL_ID = "NATIONAL_ID"
    SALARY = "SALARY"
    HEALTH = "HEALTH"
    OTHER = "OTHER"
