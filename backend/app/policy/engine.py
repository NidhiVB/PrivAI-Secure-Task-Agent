"""Deterministic policy engine enforcing security rules and precedence."""

from typing import Sequence

from backend.app.core.exceptions import (
    PolicyUnavailableException,
    RedactionException,
    RedactionVerificationException,
)
from backend.app.models.context import ContextModel
from backend.app.models.enums import Destination, FindingCategory, PolicyOutcome
from backend.app.models.findings import Finding
from backend.app.models.policy import PolicyDecision
from backend.app.models.responses import Explanation
from backend.app.models.risk import RiskScore
from backend.app.policy.rules import (
    PolicyEvaluationContext,
    PolicyRule,
    get_default_policy_rules,
    validate_rules,
)
from backend.app.redaction.redactor import Redactor
from backend.app.redaction.verifier import RedactionVerifier


class DeterministicPolicyEngine:
    """Deterministic, provider-independent policy engine.

    Security Invariants:
    1. Mandatory Precedence:
       Pre-check / Availability -> BLOCK -> REVIEW -> verified REDACT -> ALLOW -> Fail-closed.
    2. Mandatory BLOCK rules strictly override low risk scores or redaction.
    3. Unresolved REVIEW requests never authorize transmission.
    4. REDACT is permitted ONLY when redaction has succeeded and post-redaction verification passed.
    5. Fails closed with 503 / PolicyUnavailableException on component failures or malformed data.
    6. Strict Data Minimization: Matched values and raw prompts never appear in explanations or logs.
    """

    def __init__(
        self,
        rules: Sequence[PolicyRule] | None = None,
        redactor: Redactor | None = None,
        verifier: RedactionVerifier | None = None,
        policy_version: str = "policy-v1",
    ) -> None:
        self.rules: list[PolicyRule] = (
            list(rules) if rules is not None else get_default_policy_rules()
        )
        validate_rules(self.rules)
        self.redactor = redactor if redactor is not None else Redactor()
        self.verifier = verifier if verifier is not None else RedactionVerifier()
        self.policy_version = policy_version

    def evaluate(
        self,
        prompt: str,
        findings: Sequence[Finding],
        context: ContextModel,
        destination: Destination,
        risk_score: RiskScore,
        redaction_verified: bool | None = None,
    ) -> PolicyDecision:
        """Evaluate deterministic policy against findings, context, destination, and risk.

        Args:
            prompt: Original prompt text.
            findings: Detected sensitive findings.
            context: Context metadata claims.
            destination: Target provider destination.
            risk_score: Explainable risk score calculated for this request.
            redaction_verified: Optional pre-computed verification flag. If explicitly False,
                                fails closed when redaction is required.

        Returns:
            Authoritative PolicyDecision with outcome, reason codes, and safe explanations.

        Raises:
            PolicyUnavailableException: If inputs are invalid or policy evaluation fails closed.
            RedactionVerificationException: If redaction verification fails.
            RedactionException: If redaction operation fails.
        """
        # Invariant 1: Input validity pre-check (fail closed on malformed / missing inputs)
        if prompt is None or not isinstance(prompt, str) or not prompt.strip():
            raise PolicyUnavailableException(message="Prompt cannot be empty or invalid.")
        if context is None or not isinstance(context, ContextModel):
            raise PolicyUnavailableException(message="Context metadata is missing or malformed.")
        if destination is None:
            raise PolicyUnavailableException(message="Destination cannot be None.")
        if risk_score is None:
            raise PolicyUnavailableException(message="Risk score is required for policy evaluation.")

        try:
            eval_ctx = PolicyEvaluationContext(
                prompt=prompt,
                findings=findings,
                context=context,
                destination=destination,
                risk_score=risk_score,
            )

            # Categorize matching rules by action
            matching_block: list[PolicyRule] = []
            matching_review: list[PolicyRule] = []
            matching_redact: list[PolicyRule] = []

            for rule in self.rules:
                if rule.matches(eval_ctx):
                    if rule.action == PolicyOutcome.BLOCK:
                        matching_block.append(rule)
                    elif rule.action == PolicyOutcome.REVIEW:
                        matching_review.append(rule)
                    elif rule.action == PolicyOutcome.REDACT:
                        matching_redact.append(rule)

            # Unique categories detected (for safe reporting without exposing sensitive values)
            finding_categories: list[FindingCategory] = sorted(
                list({f.category for f in findings}), key=lambda c: c.value
            )

            # Invariant 2: Mandatory Hard BLOCK rules have highest precedence
            if matching_block:
                rule_ids = [r.rule_id for r in matching_block]
                summary = "; ".join(r.safe_explanation for r in matching_block)
                return PolicyDecision(
                    action=PolicyOutcome.BLOCK,
                    risk_score=risk_score,
                    reason_codes=rule_ids,
                    explanation=Explanation(
                        rule_ids=rule_ids,
                        summary=f"Request blocked by policy: {summary}",
                        actions=["Remove restricted or prohibited content and resubmit."],
                    ),
                    finding_categories=finding_categories,
                    requires_redaction=False,
                    requires_review=False,
                    policy_version=self.policy_version,
                )

            # Invariant 3: REVIEW rules have second highest precedence
            # Pending review never authorizes transmission
            if matching_review:
                rule_ids = [r.rule_id for r in matching_review]
                summary = "; ".join(r.safe_explanation for r in matching_review)
                return PolicyDecision(
                    action=PolicyOutcome.REVIEW,
                    risk_score=risk_score,
                    reason_codes=rule_ids,
                    explanation=Explanation(
                        rule_ids=rule_ids,
                        summary=f"Request held for human review: {summary}",
                        actions=["Hold for authorized human review before transmission."],
                    ),
                    finding_categories=finding_categories,
                    requires_redaction=False,
                    requires_review=True,
                    policy_version=self.policy_version,
                )

            # Invariant 4: REDACT rules require verified sanitization before transmission
            if matching_redact:
                # If caller explicitly provided an unverified flag, fail closed immediately
                if redaction_verified is False:
                    raise RedactionVerificationException(
                        message="Redaction was required but verification status was unverified/false."
                    )

                # Perform span replacement and post-redaction verification
                sanitized_text, redaction_summaries = self.redactor.redact(prompt, findings)

                # Post-redaction verification check
                # Raises RedactionVerificationException if any sensitive patterns remain
                self.verifier.verify(sanitized_text)

                rule_ids = [r.rule_id for r in matching_redact]
                summary = "; ".join(r.safe_explanation for r in matching_redact)
                return PolicyDecision(
                    action=PolicyOutcome.REDACT,
                    risk_score=risk_score,
                    reason_codes=rule_ids,
                    explanation=Explanation(
                        rule_ids=rule_ids,
                        summary=f"Sanitization required: {summary}",
                        actions=["Review the sanitized prompt."],
                    ),
                    finding_categories=finding_categories,
                    requires_redaction=True,
                    requires_review=False,
                    policy_version=self.policy_version,
                    sanitized_prompt=sanitized_text,
                    redactions=redaction_summaries,
                )

            # Invariant 5: No rule match and risk below review threshold -> ALLOW
            if risk_score.score >= 75:
                # Secondary safety check: High risk without specific rule match triggers review
                return PolicyDecision(
                    action=PolicyOutcome.REVIEW,
                    risk_score=risk_score,
                    reason_codes=["REVIEW-HIGH-RISK-SCORE"],
                    explanation=Explanation(
                        rule_ids=["REVIEW-HIGH-RISK-SCORE"],
                        summary="Request held for human review: Aggregate privacy risk score exceeds safe threshold.",
                        actions=["Hold for authorized human review before transmission."],
                    ),
                    finding_categories=finding_categories,
                    requires_redaction=False,
                    requires_review=True,
                    policy_version=self.policy_version,
                )

            return PolicyDecision(
                action=PolicyOutcome.ALLOW,
                risk_score=risk_score,
                reason_codes=["DEFAULT-ALLOW"],
                explanation=Explanation(
                    rule_ids=["DEFAULT-ALLOW"],
                    summary="No configured sensitive patterns were detected and risk is within safe limits.",
                    actions=[],
                ),
                finding_categories=finding_categories,
                requires_redaction=False,
                requires_review=False,
                policy_version=self.policy_version,
            )

        except (RedactionVerificationException, RedactionException, PolicyUnavailableException):
            # Invariant: Re-raise known security exceptions to fail closed with appropriate error code
            raise
        except Exception as exc:
            # Invariant: Catch-all fail-closed behavior, never default to ALLOW on internal error
            raise PolicyUnavailableException(
                message=f"Policy evaluation failed closed due to an internal error: {type(exc).__name__}"
            ) from exc
