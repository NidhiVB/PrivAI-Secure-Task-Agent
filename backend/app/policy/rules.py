"""Deterministic policy rule definitions and configuration validation."""

from dataclasses import dataclass
from typing import Callable, Sequence

from backend.app.core.exceptions import PolicyUnavailableException
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextPurpose,
    Destination,
    FindingCategory,
    PolicyOutcome,
)
from backend.app.models.findings import Finding
from backend.app.models.risk import RiskScore


@dataclass(frozen=True)
class PolicyEvaluationContext:
    """Read-only context container passed to policy rule conditions."""

    prompt: str
    findings: Sequence[Finding]
    context: ContextModel
    destination: Destination
    risk_score: RiskScore

    @property
    def categories(self) -> set[FindingCategory]:
        return {f.category for f in self.findings}

    def has_category(self, category: FindingCategory) -> bool:
        return category in self.categories


@dataclass(frozen=True)
class PolicyRule:
    """Specification of a versioned deterministic policy rule.

    Per blueprint docs/policies.md:
    Each rule has a stable ID, version, category, severity, action,
    destination scope, and safe non-leaking explanation.
    """

    rule_id: str
    version: str
    action: PolicyOutcome
    severity: float
    safe_explanation: str
    category: FindingCategory | None = None
    destination_scope: set[Destination] | None = None  # None means all destinations
    condition: Callable[[PolicyEvaluationContext], bool] | None = None

    def matches(self, ctx: PolicyEvaluationContext) -> bool:
        """Evaluate if the rule applies to the given evaluation context."""
        # 1. Destination scope check
        if self.destination_scope is not None and ctx.destination not in self.destination_scope:
            return False

        # 2. Category match check (if category is specified)
        if self.category is not None and not ctx.has_category(self.category):
            return False

        # 3. Dynamic condition check (if specified)
        if self.condition is not None:
            return self.condition(ctx)

        # If category matches and no custom condition, rule matches
        return self.category is not None


def validate_rules(rules: Sequence[PolicyRule]) -> None:
    """Validate policy rules at initialization.

    Fails closed if duplicate rule IDs, invalid actions, or out-of-range severities exist.
    """
    seen_ids: set[str] = set()
    for rule in rules:
        if not rule.rule_id or not rule.rule_id.strip():
            raise PolicyUnavailableException(message="Policy rule contains empty rule_id.")
        if rule.rule_id in seen_ids:
            raise PolicyUnavailableException(
                message=f"Duplicate policy rule ID detected: {rule.rule_id}"
            )
        seen_ids.add(rule.rule_id)

        if not isinstance(rule.action, PolicyOutcome):
            raise PolicyUnavailableException(
                message=f"Rule {rule.rule_id} contains invalid action: {rule.action}"
            )

        if not (0.0 <= rule.severity <= 1.0):
            raise PolicyUnavailableException(
                message=f"Rule {rule.rule_id} severity {rule.severity} is out of bounds [0.0, 1.0]."
            )

        if not rule.safe_explanation or not rule.safe_explanation.strip():
            raise PolicyUnavailableException(
                message=f"Rule {rule.rule_id} missing safe explanation."
            )


def get_default_policy_rules() -> list[PolicyRule]:
    """Return versioned default deterministic rules based on docs/policies.md."""
    rules: list[PolicyRule] = [
        # =========================================================================
        # 1. MANDATORY HARD-BLOCK RULES (Highest Precedence)
        # =========================================================================
        PolicyRule(
            rule_id="BLOCK-RESTRICTED-DATA",
            version="policy-v1",
            action=PolicyOutcome.BLOCK,
            severity=1.0,
            safe_explanation="Restricted data classification cannot be transmitted to external AI providers.",
            destination_scope={Destination.GROQ},
            condition=lambda ctx: ctx.context.classification == ContextClassification.RESTRICTED,
        ),
        PolicyRule(
            rule_id="BLOCK-NATIONAL-ID",
            version="policy-v1",
            action=PolicyOutcome.BLOCK,
            severity=1.0,
            category=FindingCategory.NATIONAL_ID,
            safe_explanation="Government and national personal identifiers are prohibited from transmission.",
        ),
        PolicyRule(
            rule_id="BLOCK-CONFIDENTIAL-HR-EMPID",
            version="policy-v1",
            action=PolicyOutcome.BLOCK,
            severity=0.9,
            category=FindingCategory.EMPLOYEE_ID,
            safe_explanation="Employee identifiers tied to confidential HR workflows cannot be transmitted.",
            condition=lambda ctx: (
                ctx.context.classification in (ContextClassification.CONFIDENTIAL, ContextClassification.RESTRICTED)
                and ctx.context.purpose == ContextPurpose.HR_WORKFLOW
            ),
        ),
        PolicyRule(
            rule_id="BLOCK-UNAUTHORIZED-PAYROLL",
            version="policy-v1",
            action=PolicyOutcome.BLOCK,
            severity=0.9,
            category=FindingCategory.SALARY,
            safe_explanation="Unauthorized salary and payroll disclosure is strictly prohibited.",
            condition=lambda ctx: (
                ctx.context.classification in (ContextClassification.CONFIDENTIAL, ContextClassification.RESTRICTED)
            ),
        ),
        PolicyRule(
            rule_id="BLOCK-PROHIBITED-HEALTH",
            version="policy-v1",
            action=PolicyOutcome.BLOCK,
            severity=0.95,
            category=FindingCategory.HEALTH,
            safe_explanation="Confidential or restricted health information disclosure is prohibited.",
            condition=lambda ctx: (
                ctx.context.classification in (ContextClassification.CONFIDENTIAL, ContextClassification.RESTRICTED)
            ),
        ),
        PolicyRule(
            rule_id="BLOCK-BULK-IDENTIFIERS",
            version="policy-v1",
            action=PolicyOutcome.BLOCK,
            severity=0.9,
            safe_explanation="Bulk disclosure of multiple sensitive identifiers is prohibited.",
            condition=lambda ctx: len(ctx.findings) > 10,
        ),

        # =========================================================================
        # 2. REVIEW RULES (Requires authorized human intervention)
        # =========================================================================
        PolicyRule(
            rule_id="REVIEW-HEALTH-DATA",
            version="policy-v1",
            action=PolicyOutcome.REVIEW,
            severity=0.8,
            category=FindingCategory.HEALTH,
            safe_explanation="Identifiable health details require authorized human review before transmission.",
        ),
        PolicyRule(
            rule_id="REVIEW-SALARY-DATA",
            version="policy-v1",
            action=PolicyOutcome.REVIEW,
            severity=0.7,
            category=FindingCategory.SALARY,
            safe_explanation="Named compensation or payroll records require authorized human review.",
        ),
        PolicyRule(
            rule_id="REVIEW-CONFIDENTIAL-CONTEXT",
            version="policy-v1",
            action=PolicyOutcome.REVIEW,
            severity=0.75,
            safe_explanation="Confidential classification with sensitive findings requires human authorization.",
            condition=lambda ctx: (
                ctx.context.classification == ContextClassification.CONFIDENTIAL
                and len(ctx.findings) > 0
            ),
        ),
        PolicyRule(
            rule_id="REVIEW-HIGH-RISK-SCORE",
            version="policy-v1",
            action=PolicyOutcome.REVIEW,
            severity=0.75,
            safe_explanation="Aggregate privacy risk score exceeds safe review threshold (score >= 75).",
            condition=lambda ctx: ctx.risk_score.score >= 75,
        ),

        # =========================================================================
        # 3. REDACT RULES (Sanitizable content permitted only after verified redaction)
        # =========================================================================
        PolicyRule(
            rule_id="REDACT-EMAIL",
            version="policy-v1",
            action=PolicyOutcome.REDACT,
            severity=0.5,
            category=FindingCategory.EMAIL,
            safe_explanation="Email addresses must be sanitized before transmission.",
        ),
        PolicyRule(
            rule_id="REDACT-PHONE",
            version="policy-v1",
            action=PolicyOutcome.REDACT,
            severity=0.5,
            category=FindingCategory.PHONE,
            safe_explanation="Phone numbers must be sanitized before transmission.",
        ),
        PolicyRule(
            rule_id="REDACT-EMPLOYEE-ID",
            version="policy-v1",
            action=PolicyOutcome.REDACT,
            severity=0.6,
            category=FindingCategory.EMPLOYEE_ID,
            safe_explanation="Employee identification numbers must be sanitized before transmission.",
        ),
        PolicyRule(
            rule_id="REDACT-OTHER",
            version="policy-v1",
            action=PolicyOutcome.REDACT,
            severity=0.4,
            category=FindingCategory.OTHER,
            safe_explanation="Sensitive patterns must be sanitized before transmission.",
        ),
    ]

    validate_rules(rules)
    return rules
