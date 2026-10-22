"""Comprehensive unit tests for deterministic policy engine."""

import pytest
from unittest.mock import MagicMock

from backend.app.core.exceptions import (
    PolicyUnavailableException,
    RedactionException,
    RedactionVerificationException,
)
from backend.app.detectors.detector import SensitiveDetector
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    FindingCategory,
    PolicyOutcome,
    RiskBand,
)
from backend.app.models.findings import Finding
from backend.app.models.risk import RiskScore
from backend.app.policy.engine import DeterministicPolicyEngine
from backend.app.policy.rules import PolicyRule, validate_rules
from backend.app.redaction.redactor import Redactor
from backend.app.redaction.verifier import RedactionVerifier
from backend.app.risk.scorer import RiskScorer


@pytest.fixture
def detector() -> SensitiveDetector:
    return SensitiveDetector()


@pytest.fixture
def scorer() -> RiskScorer:
    return RiskScorer()


@pytest.fixture
def policy_engine() -> DeterministicPolicyEngine:
    return DeterministicPolicyEngine()


@pytest.fixture
def public_context() -> ContextModel:
    return ContextModel(
        purpose=ContextPurpose.GENERAL_QUESTION,
        data_subject=ContextDataSubject.NONE,
        classification=ContextClassification.PUBLIC,
    )


# 1. Empty and ordinary prompts
def test_ordinary_prompt_allowed(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify ordinary non-sensitive prompt yields ALLOW with default rule."""
    prompt = "Explain the difference between TCP and UDP protocols."
    findings: list[Finding] = []
    risk = scorer.evaluate(findings, public_context, Destination.MOCK)

    decision = policy_engine.evaluate(
        prompt=prompt,
        findings=findings,
        context=public_context,
        destination=Destination.MOCK,
        risk_score=risk,
    )

    assert decision.action == PolicyOutcome.ALLOW
    assert decision.outcome == PolicyOutcome.ALLOW
    assert "DEFAULT-ALLOW" in decision.reason_codes
    assert decision.requires_redaction is False
    assert decision.requires_review is False
    assert len(decision.finding_categories) == 0


def test_empty_prompt_fails_closed(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify empty or whitespace prompt fails closed with PolicyUnavailableException."""
    risk = scorer.calculate_score(0, 0, 0, 0, 0)

    with pytest.raises(PolicyUnavailableException, match="cannot be empty or invalid"):
        policy_engine.evaluate(
            prompt="",
            findings=[],
            context=public_context,
            destination=Destination.MOCK,
            risk_score=risk,
        )

    with pytest.raises(PolicyUnavailableException, match="cannot be empty or invalid"):
        policy_engine.evaluate(
            prompt="   \t\n  ",
            findings=[],
            context=public_context,
            destination=Destination.MOCK,
            risk_score=risk,
        )


# 2. Prompts containing low- and high-severity findings
def test_low_severity_finding_yields_redact(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify low-severity finding (email, severity 0.5) yields REDACT."""
    prompt = "Contact alex@example.com for further updates."
    findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=8,
            end=24,
            confidence=0.95,
            severity=0.5,
        )
    ]
    risk = scorer.evaluate(findings, public_context, Destination.GROQ)

    decision = policy_engine.evaluate(
        prompt=prompt,
        findings=findings,
        context=public_context,
        destination=Destination.GROQ,
        risk_score=risk,
    )

    assert decision.action == PolicyOutcome.REDACT
    assert decision.requires_redaction is True
    assert decision.requires_review is False
    assert FindingCategory.EMAIL in decision.finding_categories
    assert "REDACT-EMAIL" in decision.reason_codes
    assert decision.sanitized_prompt == "Contact [EMAIL] for further updates."


def test_high_severity_national_id_yields_block(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify high-severity finding (national ID, severity 1.0) yields BLOCK."""
    prompt = "Applicant identity token: 999-00-1234."
    findings = [
        Finding(
            rule_id="DETECT-NATID-001",
            category=FindingCategory.NATIONAL_ID,
            start=26,
            end=37,
            confidence=0.99,
            severity=1.0,
        )
    ]
    risk = scorer.evaluate(findings, public_context, Destination.MOCK)

    decision = policy_engine.evaluate(
        prompt=prompt,
        findings=findings,
        context=public_context,
        destination=Destination.MOCK,
        risk_score=risk,
    )

    assert decision.action == PolicyOutcome.BLOCK
    assert "BLOCK-NATIONAL-ID" in decision.reason_codes
    assert decision.requires_redaction is False
    assert decision.requires_review is False


# 3. Risk-factor boundary values and invalid inputs
def test_risk_boundary_inputs_in_policy_engine(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify policy evaluation with risk score at boundaries (0 and 100)."""
    # Score 0 with no findings -> ALLOW
    risk_0 = scorer.calculate_score(0.0, 0.0, 0.0, 0.0, 0.0)
    decision_0 = policy_engine.evaluate(
        prompt="Safe question.",
        findings=[],
        context=public_context,
        destination=Destination.MOCK,
        risk_score=risk_0,
    )
    assert decision_0.action == PolicyOutcome.ALLOW

    # Score 100 with no specific rule matches -> triggers REVIEW due to risk >= 75
    risk_100 = scorer.calculate_score(1.0, 1.0, 1.0, 1.0, 1.0)
    decision_100 = policy_engine.evaluate(
        prompt="Safe text with extreme context risk score.",
        findings=[],
        context=public_context,
        destination=Destination.MOCK,
        risk_score=risk_100,
    )
    assert decision_100.action == PolicyOutcome.REVIEW
    assert "REVIEW-HIGH-RISK-SCORE" in decision_100.reason_codes


def test_invalid_policy_inputs_rejected(
    policy_engine: DeterministicPolicyEngine,
    public_context: ContextModel,
) -> None:
    """Verify None destination or None risk score raises PolicyUnavailableException."""
    with pytest.raises(PolicyUnavailableException, match="Destination cannot be None"):
        policy_engine.evaluate(
            prompt="Test",
            findings=[],
            context=public_context,
            destination=None,  # type: ignore
            risk_score=RiskScore(score=0, band=RiskBand.LOW),
        )

    with pytest.raises(PolicyUnavailableException, match="Risk score is required"):
        policy_engine.evaluate(
            prompt="Test",
            findings=[],
            context=public_context,
            destination=Destination.MOCK,
            risk_score=None,  # type: ignore
        )


# 4. Mandatory block rules overriding low risk scores
def test_mandatory_block_overrides_low_risk_score(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
) -> None:
    """Verify that a mandatory block rule strictly overrides an artificially low risk score."""
    # Restricted data sent externally to GROQ must be BLOCKED even with score=0
    restricted_ctx = ContextModel(
        purpose=ContextPurpose.GENERAL_QUESTION,
        data_subject=ContextDataSubject.NONE,
        classification=ContextClassification.RESTRICTED,
    )
    artificially_low_risk = scorer.calculate_score(0.0, 0.0, 0.0, 0.0, 0.0)

    decision = policy_engine.evaluate(
        prompt="Internal restricted architecture documentation.",
        findings=[],
        context=restricted_ctx,
        destination=Destination.GROQ,
        risk_score=artificially_low_risk,
    )

    assert decision.action == PolicyOutcome.BLOCK
    assert "BLOCK-RESTRICTED-DATA" in decision.reason_codes
    assert decision.risk_score.score == 0  # Score was low, but BLOCK won


def test_mandatory_block_confidential_hr_employee_id(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
) -> None:
    """Verify confidential HR employee ID is BLOCKED even if email was also present."""
    hr_ctx = ContextModel(
        purpose=ContextPurpose.HR_WORKFLOW,
        data_subject=ContextDataSubject.EMPLOYEE,
        classification=ContextClassification.CONFIDENTIAL,
    )
    prompt = "Review confidential performance report for EMP-123456 and email alex@example.com"
    findings = [
        Finding(
            rule_id="DETECT-EMPID-001",
            category=FindingCategory.EMPLOYEE_ID,
            start=47,
            end=57,
            confidence=0.95,
            severity=0.6,
        ),
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=72,
            end=88,
            confidence=0.95,
            severity=0.5,
        ),
    ]
    risk = scorer.evaluate(findings, hr_ctx, Destination.MOCK)

    decision = policy_engine.evaluate(
        prompt=prompt,
        findings=findings,
        context=hr_ctx,
        destination=Destination.MOCK,
        risk_score=risk,
    )

    # BLOCK has precedence over REDACT
    assert decision.action == PolicyOutcome.BLOCK
    assert "BLOCK-CONFIDENTIAL-HR-EMPID" in decision.reason_codes
    assert decision.requires_redaction is False


# 5. Redaction-required cases
def test_redaction_required_email_phone_employee_id(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify multiple sanitizable findings trigger verified REDACT with right-to-left substitution."""
    prompt = "Contact EMP-123456 at 555-123-4567 or email alex@example.com."
    findings = [
        Finding(
            rule_id="DETECT-EMPID-001",
            category=FindingCategory.EMPLOYEE_ID,
            start=8,
            end=18,
            confidence=0.95,
            severity=0.6,
        ),
        Finding(
            rule_id="DETECT-PHONE-001",
            category=FindingCategory.PHONE,
            start=22,
            end=34,
            confidence=0.90,
            severity=0.5,
        ),
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=44,
            end=60,
            confidence=0.95,
            severity=0.5,
        ),
    ]
    risk = scorer.evaluate(findings, public_context, Destination.MOCK)

    decision = policy_engine.evaluate(
        prompt=prompt,
        findings=findings,
        context=public_context,
        destination=Destination.MOCK,
        risk_score=risk,
    )

    assert decision.action == PolicyOutcome.REDACT
    assert decision.requires_redaction is True
    assert decision.requires_review is False
    assert decision.sanitized_prompt == "Contact [EMPLOYEE_ID] at [PHONE] or email [EMAIL]."
    assert decision.redactions is not None
    assert len(decision.redactions) == 3


# 6. Failed redaction verification
def test_failed_redaction_verification_fails_closed(
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify that if post-redaction verifier detects residual sensitive data, engine fails closed."""
    mock_verifier = MagicMock(spec=RedactionVerifier)
    mock_verifier.verify.side_effect = RedactionVerificationException(
        "Residual sensitive data detected."
    )

    engine = DeterministicPolicyEngine(verifier=mock_verifier)
    prompt = "Send email to alex@example.com."
    findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=14,
            end=30,
            confidence=0.95,
            severity=0.5,
        )
    ]
    risk = scorer.evaluate(findings, public_context, Destination.MOCK)

    with pytest.raises(RedactionVerificationException):
        engine.evaluate(
            prompt=prompt,
            findings=findings,
            context=public_context,
            destination=Destination.MOCK,
            risk_score=risk,
        )


def test_explicit_unverified_redaction_flag_fails_closed(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify caller passing redaction_verified=False fails closed immediately."""
    prompt = "Send email to alex@example.com."
    findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=14,
            end=30,
            confidence=0.95,
            severity=0.5,
        )
    ]
    risk = scorer.evaluate(findings, public_context, Destination.MOCK)

    with pytest.raises(RedactionVerificationException, match="unverified/false"):
        policy_engine.evaluate(
            prompt=prompt,
            findings=findings,
            context=public_context,
            destination=Destination.MOCK,
            risk_score=risk,
            redaction_verified=False,
        )


def test_redactor_error_fails_closed(
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify redactor runtime error fails closed with RedactionException."""
    mock_redactor = MagicMock(spec=Redactor)
    mock_redactor.redact.side_effect = RedactionException("Span replacement failed.")

    engine = DeterministicPolicyEngine(redactor=mock_redactor)
    findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=0,
            end=16,
            confidence=0.95,
            severity=0.5,
        )
    ]
    risk = scorer.calculate_score(0.5, 0.2, 0.0, 0.0, 0.7)

    with pytest.raises(RedactionException):
        engine.evaluate(
            prompt="alex@example.com",
            findings=findings,
            context=public_context,
            destination=Destination.MOCK,
            risk_score=risk,
        )


# 7. REVIEW decisions that remain pending
def test_review_decision_for_health_data(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify identifiable health data requires REVIEW and pending review never authorizes transmission."""
    prompt = "Patient was diagnosed with condition X."
    findings = [
        Finding(
            rule_id="DETECT-HEALTH-001",
            category=FindingCategory.HEALTH,
            start=26,
            end=37,
            confidence=0.90,
            severity=0.8,
        )
    ]
    risk = scorer.evaluate(findings, public_context, Destination.MOCK)

    decision = policy_engine.evaluate(
        prompt=prompt,
        findings=findings,
        context=public_context,
        destination=Destination.MOCK,
        risk_score=risk,
    )

    assert decision.action == PolicyOutcome.REVIEW
    assert decision.requires_review is True
    assert decision.requires_redaction is False
    assert "REVIEW-HEALTH-DATA" in decision.reason_codes


def test_review_decision_for_salary_data(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify named salary/payroll data requires REVIEW."""
    prompt = "Annual compensation is $150,000."
    findings = [
        Finding(
            rule_id="DETECT-SALARY-001",
            category=FindingCategory.SALARY,
            start=23,
            end=31,
            confidence=0.85,
            severity=0.7,
        )
    ]
    risk = scorer.evaluate(findings, public_context, Destination.MOCK)

    decision = policy_engine.evaluate(
        prompt=prompt,
        findings=findings,
        context=public_context,
        destination=Destination.MOCK,
        risk_score=risk,
    )

    assert decision.action == PolicyOutcome.REVIEW
    assert decision.requires_review is True
    assert "REVIEW-SALARY-DATA" in decision.reason_codes


# 8. Deterministic results for identical inputs
def test_deterministic_results_for_identical_inputs(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify evaluating identical inputs 50 times yields exact same decisions and attributes."""
    prompt = "Contact support at alex@example.com for help."
    findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=19,
            end=35,
            confidence=0.95,
            severity=0.5,
        )
    ]
    risk = scorer.evaluate(findings, public_context, Destination.GROQ)

    decisions = [
        policy_engine.evaluate(
            prompt=prompt,
            findings=findings,
            context=public_context,
            destination=Destination.GROQ,
            risk_score=risk,
        )
        for _ in range(50)
    ]

    first = decisions[0]
    for d in decisions[1:]:
        assert d.action == first.action
        assert d.reason_codes == first.reason_codes
        assert d.sanitized_prompt == first.sanitized_prompt
        assert d.explanation == first.explanation
        assert d.finding_categories == first.finding_categories


# 9. Missing or malformed context
def test_missing_or_malformed_context_fails_closed(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
) -> None:
    """Verify missing context fails closed with PolicyUnavailableException."""
    risk = scorer.calculate_score(0, 0, 0, 0, 0)
    with pytest.raises(PolicyUnavailableException, match="Context metadata is missing or malformed"):
        policy_engine.evaluate(
            prompt="Hello world",
            findings=[],
            context=None,  # type: ignore
            destination=Destination.MOCK,
            risk_score=risk,
        )

    with pytest.raises(PolicyUnavailableException, match="Context metadata is missing or malformed"):
        policy_engine.evaluate(
            prompt="Hello world",
            findings=[],
            context={"invalid": "dict"},  # type: ignore
            destination=Destination.MOCK,
            risk_score=risk,
        )


# 10. Exceptions and fail-closed behavior
def test_rule_exception_fails_closed(
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify internal exception during policy rule matching fails closed."""
    failing_rule = PolicyRule(
        rule_id="BUGGY-RULE",
        version="v1",
        action=PolicyOutcome.BLOCK,
        severity=1.0,
        safe_explanation="Buggy rule",
        condition=lambda ctx: (_ for _ in ()).throw(RuntimeError("Unexpected condition error")),
    )
    engine = DeterministicPolicyEngine(rules=[failing_rule])
    risk = scorer.calculate_score(0, 0, 0, 0, 0)

    with pytest.raises(PolicyUnavailableException, match="failed closed due to an internal error"):
        engine.evaluate(
            prompt="Test prompt",
            findings=[],
            context=public_context,
            destination=Destination.MOCK,
            risk_score=risk,
        )


def test_invalid_policy_configuration_fails_closed() -> None:
    """Verify duplicate rule IDs or out-of-range severities fail validation."""
    with pytest.raises(PolicyUnavailableException, match="Duplicate policy rule ID"):
        validate_rules([
            PolicyRule("DUP-01", "v1", PolicyOutcome.BLOCK, 1.0, "Desc 1"),
            PolicyRule("DUP-01", "v1", PolicyOutcome.ALLOW, 0.0, "Desc 2"),
        ])

    with pytest.raises(PolicyUnavailableException, match="out of bounds"):
        validate_rules([
            PolicyRule("BAD-SEV", "v1", PolicyOutcome.BLOCK, 1.5, "Invalid severity"),
        ])


# 11. No sensitive values in decision explanations or logs
def test_no_sensitive_values_in_decision_explanations(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
    public_context: ContextModel,
) -> None:
    """Verify raw prompt text and sensitive values never appear in explanations or finding categories."""
    synthetic_email = "alex.secret@example.org"
    synthetic_phone = "+1-555-0199"
    synthetic_empid = "EMP-987654"

    prompt = f"Reach {synthetic_empid} by calling {synthetic_phone} or email {synthetic_email}."
    findings = [
        Finding(
            rule_id="DETECT-EMPID-001",
            category=FindingCategory.EMPLOYEE_ID,
            start=6,
            end=16,
            confidence=0.95,
            severity=0.6,
        ),
        Finding(
            rule_id="DETECT-PHONE-001",
            category=FindingCategory.PHONE,
            start=28,
            end=40,
            confidence=0.90,
            severity=0.5,
        ),
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=50,
            end=73,
            confidence=0.95,
            severity=0.5,
        ),
    ]
    risk = scorer.evaluate(findings, public_context, Destination.GROQ)

    decision = policy_engine.evaluate(
        prompt=prompt,
        findings=findings,
        context=public_context,
        destination=Destination.GROQ,
        risk_score=risk,
    )

    explanation_str = str(decision.explanation)
    reason_codes_str = str(decision.reason_codes)
    categories_str = str(decision.finding_categories)

    # Invariant: Strictly zero sensitive values in explanations, reason codes, or categories
    for sensitive_val in [synthetic_email, synthetic_phone, synthetic_empid]:
        assert sensitive_val not in explanation_str
        assert sensitive_val not in reason_codes_str
        assert sensitive_val not in categories_str


# 12. Precedence test: BLOCK > REVIEW > REDACT > ALLOW
def test_precedence_block_over_review_and_redact(
    policy_engine: DeterministicPolicyEngine,
    scorer: RiskScorer,
) -> None:
    """Verify precedence hierarchy: BLOCK beats REVIEW, REVIEW beats REDACT."""
    # Context with National ID (BLOCK), Health (REVIEW), and Email (REDACT)
    ctx = ContextModel(
        purpose=ContextPurpose.HEALTH_INFORMATION,
        data_subject=ContextDataSubject.SELF,
        classification=ContextClassification.INTERNAL,
    )
    prompt = "National ID 123-45-6789, condition X, email alex@example.com"
    findings = [
        Finding(
            rule_id="R1",
            category=FindingCategory.NATIONAL_ID,
            start=12,
            end=23,
            confidence=0.99,
            severity=1.0,
        ),
        Finding(
            rule_id="R2",
            category=FindingCategory.HEALTH,
            start=25,
            end=36,
            confidence=0.90,
            severity=0.8,
        ),
        Finding(
            rule_id="R3",
            category=FindingCategory.EMAIL,
            start=44,
            end=60,
            confidence=0.95,
            severity=0.5,
        ),
    ]
    risk = scorer.evaluate(findings, ctx, Destination.MOCK)

    # BLOCK wins over REVIEW and REDACT
    decision = policy_engine.evaluate(prompt, findings, ctx, Destination.MOCK, risk)
    assert decision.action == PolicyOutcome.BLOCK

    # Now remove National ID: Health (REVIEW) and Email (REDACT) remain
    findings_no_block = findings[1:]
    decision_review = policy_engine.evaluate(prompt, findings_no_block, ctx, Destination.MOCK, risk)
    # REVIEW wins over REDACT
    assert decision_review.action == PolicyOutcome.REVIEW
    assert decision_review.requires_review is True

    # Now remove Health: only Email (REDACT) remains
    prompt_email_only = "Contact email alex@example.com"
    findings_redact_only = [
        Finding(
            rule_id="R3",
            category=FindingCategory.EMAIL,
            start=14,
            end=30,
            confidence=0.95,
            severity=0.5,
        )
    ]
    risk_email_only = scorer.evaluate(findings_redact_only, ctx, Destination.MOCK)
    decision_redact = policy_engine.evaluate(
        prompt_email_only, findings_redact_only, ctx, Destination.MOCK, risk_email_only
    )
    # REDACT wins
    assert decision_redact.action == PolicyOutcome.REDACT
    assert decision_redact.requires_redaction is True
