"""Unit tests for deterministic risk scoring module."""

import pytest
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    FindingCategory,
    RiskBand,
)
from backend.app.models.findings import Finding
from backend.app.risk.scorer import RiskScorer


@pytest.fixture
def scorer() -> RiskScorer:
    return RiskScorer(version="risk-v1")


def test_blueprint_worked_example(scorer: RiskScorer) -> None:
    """Verify exact formula result from docs/risk_scoring.md.

    Blueprint worked example:
    S=0.5, N=0.2, C=0.6, D=1.0, I=0.7
    risk = round(100 * (0.15 + 0.02 + 0.15 + 0.20 + 0.105)) = 63.
    """
    result = scorer.calculate_score(s=0.5, n=0.2, c=0.6, d=1.0, i=0.7)
    assert result.score == 63
    assert result.band == RiskBand.HIGH
    assert result.factors is not None
    assert result.factors.severity == 0.5
    assert result.factors.normalized_count == 0.2
    assert result.factors.context == 0.6
    assert result.factors.destination == 1.0
    assert result.factors.identifiability == 0.7
    assert result.factor_contributions["severity"] == 0.15
    assert result.factor_contributions["count"] == 0.02
    assert result.factor_contributions["context"] == 0.15
    assert result.factor_contributions["destination"] == 0.20
    assert result.factor_contributions["identifiability"] == 0.105
    assert "SCORE-BAND-HIGH" in result.reason_codes


def test_boundary_all_zeros(scorer: RiskScorer) -> None:
    """Verify lowest boundary score is 0 and categorized as LOW band."""
    result = scorer.calculate_score(s=0.0, n=0.0, c=0.0, d=0.0, i=0.0)
    assert result.score == 0
    assert result.band == RiskBand.LOW
    assert "SCORE-ZERO-RISK" in result.reason_codes
    assert "SCORE-BAND-LOW" in result.reason_codes


def test_boundary_all_ones(scorer: RiskScorer) -> None:
    """Verify maximum boundary score is 100 and categorized as VERY_HIGH band."""
    result = scorer.calculate_score(s=1.0, n=1.0, c=1.0, d=1.0, i=1.0)
    assert result.score == 100
    assert result.band == RiskBand.VERY_HIGH
    assert "SCORE-BAND-VERY_HIGH" in result.reason_codes


def test_risk_bands_thresholds(scorer: RiskScorer) -> None:
    """Verify risk bands per blueprint: 0-19 low, 20-49 moderate, 50-74 high, 75-100 very high."""
    # Score 19 -> LOW
    # 0.30*0.2 + 0.10*0.2 + 0.25*0.2 + 0.20*0.2 + 0.15*0.2 = 0.20 -> 20 (moderate)
    # Let's test specific factor combinations:
    # 19:
    r19 = scorer.calculate_score(s=0.19, n=0.19, c=0.19, d=0.19, i=0.19)
    assert r19.score == 19
    assert r19.band == RiskBand.LOW

    # 20:
    r20 = scorer.calculate_score(s=0.20, n=0.20, c=0.20, d=0.20, i=0.20)
    assert r20.score == 20
    assert r20.band == RiskBand.MODERATE

    # 49:
    r49 = scorer.calculate_score(s=0.49, n=0.49, c=0.49, d=0.49, i=0.49)
    assert r49.score == 49
    assert r49.band == RiskBand.MODERATE

    # 50:
    r50 = scorer.calculate_score(s=0.50, n=0.50, c=0.50, d=0.50, i=0.50)
    assert r50.score == 50
    assert r50.band == RiskBand.HIGH

    # 74:
    r74 = scorer.calculate_score(s=0.74, n=0.74, c=0.74, d=0.74, i=0.74)
    assert r74.score == 74
    assert r74.band == RiskBand.HIGH

    # 75:
    r75 = scorer.calculate_score(s=0.75, n=0.75, c=0.75, d=0.75, i=0.75)
    assert r75.score == 75
    assert r75.band == RiskBand.VERY_HIGH


def test_invalid_factor_values_raise_error(scorer: RiskScorer) -> None:
    """Verify that factors outside [0.0, 1.0] raise ValueError."""
    with pytest.raises(ValueError, match="is out of valid range"):
        scorer.calculate_score(s=-0.1, n=0.5, c=0.5, d=0.5, i=0.5)

    with pytest.raises(ValueError, match="is out of valid range"):
        scorer.calculate_score(s=1.1, n=0.5, c=0.5, d=0.5, i=0.5)

    with pytest.raises(ValueError, match="is out of valid range"):
        scorer.calculate_score(s=0.5, n=-0.01, c=0.5, d=0.5, i=0.5)

    with pytest.raises(ValueError, match="is out of valid range"):
        scorer.calculate_score(s=0.5, n=0.5, c=1.05, d=0.5, i=0.5)

    with pytest.raises(ValueError, match="is out of valid range"):
        scorer.calculate_score(s=0.5, n=0.5, c=0.5, d=-0.5, i=0.5)

    with pytest.raises(ValueError, match="is out of valid range"):
        scorer.calculate_score(s=0.5, n=0.5, c=0.5, d=0.5, i=2.0)


def test_empty_findings_evaluation(scorer: RiskScorer) -> None:
    """Verify empty findings produces S=0, N=0, I=0 and low score."""
    ctx = ContextModel(
        purpose=ContextPurpose.GENERAL_QUESTION,
        data_subject=ContextDataSubject.NONE,
        classification=ContextClassification.PUBLIC,
    )
    result = scorer.evaluate(findings=[], context=ctx, destination=Destination.MOCK)
    assert result.score == 0
    assert result.band == RiskBand.LOW
    assert result.factors is not None
    assert result.factors.severity == 0.0
    assert result.factors.normalized_count == 0.0
    assert result.factors.context == 0.0
    assert result.factors.destination == 0.0
    assert result.factors.identifiability == 0.0


def test_single_email_finding_evaluation(scorer: RiskScorer) -> None:
    """Verify evaluation for single email finding."""
    ctx = ContextModel(
        purpose=ContextPurpose.HR_WORKFLOW,  # 0.6
        data_subject=ContextDataSubject.NONE,
        classification=ContextClassification.PUBLIC,
    )
    findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=10,
            end=25,
            confidence=0.95,
            severity=0.5,
        )
    ]
    # S = 0.5, N = 1/5 = 0.2, C = 0.6, D = 1.0 (GROQ), I = 0.7
    result = scorer.evaluate(findings=findings, context=ctx, destination=Destination.GROQ)
    assert result.score == 63
    assert result.band == RiskBand.HIGH


def test_linkage_risk_increases_with_distinct_categories(scorer: RiskScorer) -> None:
    """Verify identifiability/linkage factor I increases when distinct categories are combined."""
    ctx = ContextModel(
        purpose=ContextPurpose.GENERAL_QUESTION,
        data_subject=ContextDataSubject.NONE,
        classification=ContextClassification.PUBLIC,
    )
    single_cat_findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=0,
            end=10,
            confidence=0.9,
            severity=0.5,
        ),
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=20,
            end=30,
            confidence=0.9,
            severity=0.5,
        ),
    ]
    multi_cat_findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=0,
            end=10,
            confidence=0.9,
            severity=0.5,
        ),
        Finding(
            rule_id="DETECT-EMPID-001",
            category=FindingCategory.EMPLOYEE_ID,
            start=20,
            end=30,
            confidence=0.9,
            severity=0.6,
        ),
    ]

    r_single = scorer.evaluate(single_cat_findings, ctx, Destination.MOCK)
    r_multi = scorer.evaluate(multi_cat_findings, ctx, Destination.MOCK)

    assert r_single.factors is not None
    assert r_multi.factors is not None
    # Multi category findings should have higher identifiability factor
    assert r_multi.factors.identifiability > r_single.factors.identifiability


def test_count_normalization_capped_at_five(scorer: RiskScorer) -> None:
    """Verify N factor caps at 1.0 when count >= 5."""
    findings_5 = [
        Finding(
            rule_id=f"R-{i}",
            category=FindingCategory.EMAIL,
            start=i * 10,
            end=i * 10 + 5,
            confidence=0.9,
            severity=0.5,
        )
        for i in range(5)
    ]
    findings_10 = [
        Finding(
            rule_id=f"R-{i}",
            category=FindingCategory.EMAIL,
            start=i * 10,
            end=i * 10 + 5,
            confidence=0.9,
            severity=0.5,
        )
        for i in range(10)
    ]

    n5 = scorer.compute_n(findings_5)
    n10 = scorer.compute_n(findings_10)

    assert n5 == 1.0
    assert n10 == 1.0


def test_missing_or_invalid_context_fails_closed(scorer: RiskScorer) -> None:
    """Verify that missing context raises an error rather than silently defaulting to 0."""
    with pytest.raises(ValueError, match="Context cannot be None"):
        scorer.compute_c(None)


def test_unknown_destination_raises_error(scorer: RiskScorer) -> None:
    """Verify unknown destination is rejected."""
    with pytest.raises(ValueError, match="not recognized"):
        scorer.compute_d("unknown_provider")


def test_deterministic_consistency(scorer: RiskScorer) -> None:
    """Verify identical inputs always produce identical score and breakdown."""
    ctx = ContextModel(
        purpose=ContextPurpose.CODING,
        data_subject=ContextDataSubject.SELF,
        classification=ContextClassification.INTERNAL,
    )
    findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=5,
            end=20,
            confidence=0.95,
            severity=0.5,
        )
    ]

    scores = [scorer.evaluate(findings, ctx, Destination.MOCK) for _ in range(50)]
    first = scores[0]
    for other in scores[1:]:
        assert other.score == first.score
        assert other.band == first.band
        assert other.factor_contributions == first.factor_contributions
        assert other.reason_codes == first.reason_codes
