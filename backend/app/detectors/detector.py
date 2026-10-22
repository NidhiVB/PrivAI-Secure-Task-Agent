"""Sensitive information detector implementation."""

from typing import Sequence
from backend.app.core.exceptions import DetectionException
from backend.app.detectors.rules import DetectorRule, get_default_rules
from backend.app.models.findings import Finding


class SensitiveDetector:
    """Deterministic, rule-based sensitive data detector.

    Security Invariants:
    1. Purely deterministic execution; zero external provider or network calls.
    2. Python Unicode code-point offsets are used consistently.
    3. Never logs raw prompt content or matched sensitive text.
    4. Fails closed on any unexpected error.
    """

    def __init__(self, rules: Sequence[DetectorRule] | None = None) -> None:
        self.rules: list[DetectorRule] = list(rules) if rules is not None else get_default_rules()

    def detect(self, text: str) -> list[Finding]:
        """Scan text and return deduplicated, non-overlapping findings sorted by start offset.

        Raises DetectionException on any unexpected error to ensure fail-closed behavior.
        """
        try:
            raw_findings: list[Finding] = []
            for rule in self.rules:
                raw_findings.extend(rule.find_matches(text))

            return self.resolve_overlaps(raw_findings)
        except DetectionException:
            raise
        except Exception as exc:
            # Invariant: Fail closed, never leak text in exception messages
            raise DetectionException(
                message=f"Detection failed due to an unexpected error: {type(exc).__name__}"
            ) from exc

    @staticmethod
    def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
        """Resolve overlapping or nested findings.

        Sorting strategy:
        1. Start offset ascending
        2. Span length (end - start) descending (longer matches preferred)
        3. Severity descending
        4. Confidence descending

        When spans overlap:
        - Completely subsumed spans are discarded.
        - Partially overlapping spans keep the higher severity/longer match.
        """
        if not findings:
            return []

        # Sort findings deterministically
        sorted_findings = sorted(
            findings,
            key=lambda f: (f.start, -(f.end - f.start), -f.severity, -f.confidence),
        )

        resolved: list[Finding] = []
        for candidate in sorted_findings:
            if not resolved:
                resolved.append(candidate)
                continue

            last = resolved[-1]
            if candidate.start < last.end:
                # Overlap detected
                if candidate.end <= last.end:
                    # Candidate is completely subsumed by last
                    continue
                # Partial overlap: compare severity and span length
                last_score = (last.severity, last.end - last.start, last.confidence)
                candidate_score = (
                    candidate.severity,
                    candidate.end - candidate.start,
                    candidate.confidence,
                )
                if candidate_score > last_score:
                    resolved[-1] = candidate
            else:
                resolved.append(candidate)

        return resolved
