"""Deterministic, explainable privacy risk scorer.

Implements the blueprint specification from docs/risk_scoring.md:
risk = round(100 * (0.30*S + 0.10*N + 0.25*C + 0.20*D + 0.15*I))

Where:
- S = normalized maximum detected severity in [0, 1]
- N = normalized count factor: min(len(findings) / 5, 1) in [0, 1]
- C = context sensitivity in [0, 1] from structured metadata
- D = destination exposure factor in [0, 1] from destination registry
- I = identifiability/linkage factor in [0, 1] from categories and linkage indicators
"""

from decimal import Decimal, ROUND_HALF_UP
from typing import Mapping, Sequence

from backend.app.core.exceptions import PrivAIException
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
from backend.app.models.risk import RiskFactors, RiskScore

# Factor weight constants (must sum to 1.0)
WEIGHT_SEVERITY: float = 0.30
WEIGHT_COUNT: float = 0.10
WEIGHT_CONTEXT: float = 0.25
WEIGHT_DESTINATION: float = 0.20
WEIGHT_IDENTIFIABILITY: float = 0.15

# Server-controlled destination exposure registry
DEFAULT_DESTINATION_EXPOSURE: dict[Destination, float] = {
    Destination.MOCK: 0.0,   # Local mock adapter, zero external egress
    Destination.GROQ: 1.0,   # Third-party cloud LLM provider
}

# Deterministic context sensitivity baselines
CLASSIFICATION_SENSITIVITY: dict[ContextClassification, float] = {
    ContextClassification.PUBLIC: 0.0,
    ContextClassification.INTERNAL: 0.4,
    ContextClassification.CONFIDENTIAL: 0.8,
    ContextClassification.RESTRICTED: 1.0,
}

PURPOSE_SENSITIVITY: dict[ContextPurpose, float] = {
    ContextPurpose.GENERAL_QUESTION: 0.0,
    ContextPurpose.CODING: 0.1,
    ContextPurpose.SUMMARIZATION: 0.2,
    ContextPurpose.OTHER: 0.3,
    ContextPurpose.HR_WORKFLOW: 0.6,
    ContextPurpose.HEALTH_INFORMATION: 0.8,
}

DATA_SUBJECT_SENSITIVITY: dict[ContextDataSubject, float] = {
    ContextDataSubject.NONE: 0.0,
    ContextDataSubject.SELF: 0.2,
    ContextDataSubject.UNKNOWN: 0.5,
    ContextDataSubject.EMPLOYEE: 0.5,
    ContextDataSubject.THIRD_PARTY: 0.7,
}

# Category base identifiability scores
CATEGORY_IDENTIFIABILITY: dict[FindingCategory, float] = {
    FindingCategory.NATIONAL_ID: 1.0,
    FindingCategory.EMAIL: 0.7,
    FindingCategory.PHONE: 0.7,
    FindingCategory.EMPLOYEE_ID: 0.6,
    FindingCategory.SALARY: 0.5,
    FindingCategory.HEALTH: 0.5,
    FindingCategory.OTHER: 0.3,
}


def round_half_up(value: float) -> int:
    """Perform standard mathematical half-up rounding (matching blueprint example)."""
    d = Decimal(str(round(value, 6)))
    return int(d.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


class RiskScorer:
    """Deterministic, explainable privacy risk scorer.

    Security Invariants:
    1. Purely deterministic and provider-independent.
    2. Strictly validates factor boundaries [0.0, 1.0].
    3. Missing factors fail closed or take documented conservative defaults.
    4. Explanations never include raw prompt text or matched values.
    5. Heuristic score can never downgrade or override mandatory security rules.
    """

    def __init__(
        self,
        destination_registry: Mapping[Destination, float] | None = None,
        version: str = "risk-v1",
    ) -> None:
        self.destination_registry: dict[Destination, float] = (
            dict(destination_registry)
            if destination_registry is not None
            else DEFAULT_DESTINATION_EXPOSURE.copy()
        )
        self.version = version

    def compute_s(self, findings: Sequence[Finding]) -> float:
        """Compute S (normalized maximum detected category severity in [0, 1])."""
        if not findings:
            return 0.0
        max_severity = max(f.severity for f in findings)
        if not (0.0 <= max_severity <= 1.0):
            raise ValueError(f"Finding severity {max_severity} is out of bounds [0.0, 1.0].")
        return round(float(max_severity), 4)

    def compute_n(self, findings: Sequence[Finding]) -> float:
        """Compute N (normalized count factor: min(count / 5, 1) in [0, 1])."""
        count = len(findings)
        if count < 0:
            raise ValueError(f"Findings count cannot be negative: {count}")
        normalized = min(count / 5.0, 1.0)
        return round(float(normalized), 4)

    def compute_c(self, context: ContextModel | None) -> float:
        """Compute C (context sensitivity in [0, 1] from structured metadata).

        Security Invariant: Missing or malformed context does not silently default
        to 0.0; it fails closed or defaults conservatively to restricted sensitivity.
        """
        if context is None:
            raise ValueError("Context cannot be None. Fails closed under missing context.")

        class_sens = CLASSIFICATION_SENSITIVITY.get(context.classification)
        purpose_sens = PURPOSE_SENSITIVITY.get(context.purpose)
        subject_sens = DATA_SUBJECT_SENSITIVITY.get(context.data_subject)

        if class_sens is None or purpose_sens is None or subject_sens is None:
            raise ValueError("Context contains unknown or unmapped enum values.")

        # Highest indicated sensitivity wins (user claims of 'public' cannot mask sensitive purpose)
        c = max(class_sens, purpose_sens, subject_sens)
        return round(float(c), 4)

    def compute_d(self, destination: Destination | str) -> float:
        """Compute D (destination exposure factor in [0, 1] from registry)."""
        if isinstance(destination, str):
            try:
                dest_enum = Destination(destination)
            except ValueError as exc:
                raise ValueError(f"Destination '{destination}' is not recognized.") from exc
        else:
            dest_enum = destination

        if dest_enum not in self.destination_registry:
            raise ValueError(f"Destination '{dest_enum}' not found in destination registry.")

        exposure = self.destination_registry[dest_enum]
        if not (0.0 <= exposure <= 1.0):
            raise ValueError(f"Destination exposure {exposure} is out of bounds [0.0, 1.0].")
        return round(float(exposure), 4)

    def compute_i(self, findings: Sequence[Finding]) -> float:
        """Compute I (identifiability/linkage factor in [0, 1])."""
        if not findings:
            return 0.0

        base_identifiability = max(
            CATEGORY_IDENTIFIABILITY.get(f.category, 0.3) for f in findings
        )

        # Linkage indicator: Combining distinct categories amplifies linkage risk
        distinct_categories = {f.category for f in findings}
        linkage_boost = 0.1 * (len(distinct_categories) - 1) if len(distinct_categories) > 1 else 0.0

        i_factor = min(1.0, base_identifiability + linkage_boost)
        return round(float(i_factor), 4)

    def calculate_score(
        self,
        s: float,
        n: float,
        c: float,
        d: float,
        i: float,
        raw_count: int | None = None,
    ) -> RiskScore:
        """Calculate deterministic risk score from validated factor inputs."""
        # Validate factor ranges [0.0, 1.0]
        for name, val in [("S", s), ("N", n), ("C", c), ("D", d), ("I", i)]:
            if not isinstance(val, (int, float)) or not (0.0 <= val <= 1.0):
                raise ValueError(f"Factor {name}={val} is out of valid range [0.0, 1.0].")

        # Weighted factor contributions
        s_contrib = round(WEIGHT_SEVERITY * s, 4)
        n_contrib = round(WEIGHT_COUNT * n, 4)
        c_contrib = round(WEIGHT_CONTEXT * c, 4)
        d_contrib = round(WEIGHT_DESTINATION * d, 4)
        i_contrib = round(WEIGHT_IDENTIFIABILITY * i, 4)

        raw_sum = s_contrib + n_contrib + c_contrib + d_contrib + i_contrib
        raw_score = 100.0 * raw_sum
        clamped_score = max(0, min(100, round_half_up(raw_score)))

        # Determine risk band per blueprint: 0-19 low, 20-49 moderate, 50-74 high, 75-100 very high
        if clamped_score < 20:
            band = RiskBand.LOW
        elif clamped_score < 50:
            band = RiskBand.MODERATE
        elif clamped_score < 75:
            band = RiskBand.HIGH
        else:
            band = RiskBand.VERY_HIGH

        # Generate explainable reason codes
        reason_codes: list[str] = []
        if clamped_score == 0:
            reason_codes.append("SCORE-ZERO-RISK")
        else:
            if s > 0:
                reason_codes.append("SCORE-FACTOR-SEVERITY")
            if n > 0:
                reason_codes.append("SCORE-FACTOR-COUNT")
            if c > 0:
                reason_codes.append("SCORE-FACTOR-CONTEXT")
            if d > 0:
                reason_codes.append("SCORE-FACTOR-DESTINATION")
            if i > 0:
                reason_codes.append("SCORE-FACTOR-IDENTIFIABILITY")

        reason_codes.append(f"SCORE-BAND-{band.value.upper()}")

        factors = RiskFactors(
            severity=round(s, 4),
            count=raw_count if raw_count is not None else int(round(n * 5.0)),
            normalized_count=round(n, 4),
            context=round(c, 4),
            destination=round(d, 4),
            identifiability=round(i, 4),
        )

        contributions = {
            "severity": s_contrib,
            "count": n_contrib,
            "context": c_contrib,
            "destination": d_contrib,
            "identifiability": i_contrib,
        }

        return RiskScore(
            score=clamped_score,
            band=band,
            factors=factors,
            factor_contributions=contributions,
            reason_codes=reason_codes,
            version=self.version,
        )

    def evaluate(
        self,
        findings: Sequence[Finding],
        context: ContextModel,
        destination: Destination,
    ) -> RiskScore:
        """Compute full explainable risk score from findings, context, and destination."""
        s = self.compute_s(findings)
        n = self.compute_n(findings)
        c = self.compute_c(context)
        d = self.compute_d(destination)
        i = self.compute_i(findings)

        return self.calculate_score(
            s=s,
            n=n,
            c=c,
            d=d,
            i=i,
            raw_count=len(findings),
        )
