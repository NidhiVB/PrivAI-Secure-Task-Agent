"""Post-redaction verification implementation."""

from backend.app.core.exceptions import RedactionVerificationException
from backend.app.detectors.detector import SensitiveDetector


class RedactionVerifier:
    """Verifies that sanitized prompts contain zero remaining configured sensitive patterns.

    Security Invariants:
    1. Re-runs detection over the sanitized prompt.
    2. Any remaining sensitive matches immediately fail closed with RedactionVerificationException.
    3. Placeholders themselves ([EMAIL], [PHONE], [EMPLOYEE_ID]) do not trigger false detections.
    4. Never logs or echoes raw prompt or matched values in verification results or errors.
    """

    def __init__(self, detector: SensitiveDetector | None = None) -> None:
        self.detector = detector if detector is not None else SensitiveDetector()

    def verify(self, sanitized_prompt: str) -> bool:
        """Verify that sanitized prompt has no residual sensitive findings.

        Returns True if verification succeeds.
        Raises RedactionVerificationException if any sensitive findings are detected.
        """
        residual_findings = self.detector.detect(sanitized_prompt)
        if residual_findings:
            # Invariant: Fail closed; never transmit a prompt that failed verification
            # Do not echo text or values in the exception message
            raise RedactionVerificationException(
                message=(
                    f"Redaction verification failed closed: {len(residual_findings)} "
                    f"sensitive pattern(s) remain in the sanitized prompt."
                )
            )
        return True
