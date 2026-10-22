"""Prompt redactor implementation using right-to-left span substitution."""

from typing import Mapping, Sequence
from backend.app.core.exceptions import RedactionException
from backend.app.models.enums import FindingCategory
from backend.app.models.findings import Finding, RedactionSummary

DEFAULT_PLACEHOLDERS: dict[FindingCategory, str] = {
    FindingCategory.EMAIL: "[EMAIL]",
    FindingCategory.PHONE: "[PHONE]",
    FindingCategory.EMPLOYEE_ID: "[EMPLOYEE_ID]",
    FindingCategory.NATIONAL_ID: "[NATIONAL_ID]",
    FindingCategory.SALARY: "[SALARY]",
    FindingCategory.HEALTH: "[HEALTH]",
    FindingCategory.OTHER: "[REDACTED]",
}


class Redactor:
    """Span-based redactor applying right-to-left placeholder substitutions.

    Security Invariants:
    1. Replaces spans strictly right-to-left (descending start offset) so preceding
       offsets remain valid.
    2. Surrounding text, whitespace, and punctuation are preserved intact.
    3. Fails closed with RedactionException on offset out-of-bounds or unexpected error.
    4. Never logs or echoes raw prompt or matched values.
    """

    def __init__(
        self, placeholders: Mapping[FindingCategory, str] | None = None
    ) -> None:
        self.placeholders: dict[FindingCategory, str] = (
            dict(placeholders) if placeholders is not None else DEFAULT_PLACEHOLDERS.copy()
        )

    def redact(
        self, prompt: str, findings: Sequence[Finding]
    ) -> tuple[str, list[RedactionSummary]]:
        """Apply redactions to prompt and return (sanitized_prompt, redaction_summaries)."""
        if not findings:
            return prompt, []

        try:
            prompt_len = len(prompt)
            # Sort findings strictly right-to-left (start descending)
            sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)

            sanitized = prompt
            applied_summaries: list[RedactionSummary] = []
            seen_categories: set[FindingCategory] = set()

            for finding in sorted_findings:
                # Offset boundary validation
                if finding.start < 0 or finding.end > prompt_len or finding.start > finding.end:
                    raise RedactionException(
                        message="Invalid finding offsets detected during redaction."
                    )

                placeholder = self.placeholders.get(finding.category, "[REDACTED]")
                # Replace exact span right-to-left
                sanitized = sanitized[:finding.start] + placeholder + sanitized[finding.end:]

                if finding.category not in seen_categories:
                    applied_summaries.append(
                        RedactionSummary(
                            category=finding.category,
                            placeholder=placeholder,
                        )
                    )
                    seen_categories.add(finding.category)

            # Keep summaries in stable category order
            applied_summaries.sort(key=lambda s: s.category.value)
            return sanitized, applied_summaries

        except RedactionException:
            raise
        except Exception as exc:
            # Invariant: Fail closed, never leak text in exception messages
            raise RedactionException(
                message=f"Redaction failed due to an unexpected error: {type(exc).__name__}"
            ) from exc
