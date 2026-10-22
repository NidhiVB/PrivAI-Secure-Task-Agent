"""PrivAI custom application exceptions."""


class PrivAIException(Exception):
    """Base exception for PrivAI errors."""

    def __init__(
        self,
        message: str = "A security or validation error occurred.",
        code: str = "INTERNAL_ERROR",
        status_code: int = 500,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


class PayloadTooLargeException(PrivAIException):
    """Raised when request payload or prompt exceeds byte limits."""

    def __init__(
        self,
        message: str = "Request payload exceeds maximum allowed size.",
        code: str = "PAYLOAD_TOO_LARGE",
    ) -> None:
        super().__init__(message=message, code=code, status_code=413)


class PromptValidationException(PrivAIException):
    """Raised when prompt text fails semantic or character checks."""

    def __init__(
        self,
        message: str = "The submitted prompt failed validation.",
        code: str = "INVALID_PROMPT",
    ) -> None:
        super().__init__(message=message, code=code, status_code=422)


class PolicyUnavailableException(PrivAIException):
    """Raised when deterministic policy engine fails to load or evaluate."""

    def __init__(
        self,
        message: str = "The request could not be safely processed because policy evaluation is unavailable.",
        code: str = "POLICY_UNAVAILABLE",
    ) -> None:
        super().__init__(message=message, code=code, status_code=503)


class DetectionException(PrivAIException):
    """Raised when sensitive information detection fails closed."""

    def __init__(
        self,
        message: str = "Sensitive content detection failed to complete safely.",
        code: str = "DETECTION_FAILED",
    ) -> None:
        super().__init__(message=message, code=code, status_code=503)


class RedactionException(PrivAIException):
    """Raised when prompt redaction encounters an unexpected error."""

    def __init__(
        self,
        message: str = "Redaction could not be safely applied to the prompt.",
        code: str = "REDACTION_FAILED",
    ) -> None:
        super().__init__(message=message, code=code, status_code=503)


class RedactionVerificationException(PrivAIException):
    """Raised when post-redaction verification detects residual sensitive data."""

    def __init__(
        self,
        message: str = "Sanitized prompt failed post-redaction privacy verification.",
        code: str = "REDACTION_VERIFICATION_FAILED",
    ) -> None:
        super().__init__(message=message, code=code, status_code=503)


class ProviderException(PrivAIException):
    """Raised when an AI provider communication error or timeout occurs."""

    def __init__(
        self,
        message: str = "The AI provider failed to complete the request safely.",
        code: str = "PROVIDER_ERROR",
        status_code: int = 502,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class AuditWriteException(PrivAIException):
    """Raised when a mandatory privacy audit log write fails."""

    def __init__(
        self,
        message: str = "Required audit log write failed. Aborting execution fail-closed.",
        code: str = "AUDIT_WRITE_FAILED",
    ) -> None:
        super().__init__(message=message, code=code, status_code=503)


class SecurityInvariantException(PrivAIException):
    """Raised when an internal security invariant or boundary gate is violated."""

    def __init__(
        self,
        message: str = "Security invariant violation detected.",
        code: str = "INVARIANT_VIOLATION",
    ) -> None:
        super().__init__(message=message, code=code, status_code=503)
