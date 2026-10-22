"""Deterministic rule definitions for sensitive data detection."""

import re
from dataclasses import dataclass
from backend.app.config import settings
from backend.app.models.enums import FindingCategory
from backend.app.models.findings import Finding


@dataclass(frozen=True)
class DetectorRule:
    """Specification of a deterministic regex detection rule."""

    rule_id: str
    category: FindingCategory
    pattern: re.Pattern[str]
    confidence: float
    severity: float
    description: str = ""

    def find_matches(self, text: str) -> list[Finding]:
        """Scan text and return findings with Python Unicode code-point offsets."""
        findings: list[Finding] = []
        for match in self.pattern.finditer(text):
            start = match.start()
            end = match.end()
            # Ensure valid non-empty span
            if end > start:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        category=self.category,
                        start=start,
                        end=end,
                        confidence=self.confidence,
                        severity=self.severity,
                    )
                )
        return findings


def get_default_rules() -> list[DetectorRule]:
    """Compile and return the standard deterministic detection rules."""
    # 1. Email pattern: standard RFC-compliant address with word boundary
    email_pattern = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    # 2. Phone pattern:
    # Supports:
    # - North American: (555) 123-4567, 555-123-4567, 555.123.4567, 555 123 4567
    # - International: +1-555-123-4567, +44 20 7946 0958, +1 (555) 123-4567
    # Word boundary prevents false matches on dates (2026-10-15) or IP addresses (192.168.1.1)
    phone_pattern = re.compile(
        r"(?:(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\+\d{1,3}(?:[-.\s]?\d{2,4}){2,4}\b)"
    )

    # 3. Employee ID pattern: configurable organization format, defaults to EMP-123456
    employee_id_pattern = re.compile(settings.EMPLOYEE_ID_PATTERN)

    # 4. National ID pattern: standard 3-2-4 digit format (e.g. 999-00-1234)
    national_id_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    # 5. Health terms pattern: medical diagnostic and clinical context indicators
    health_pattern = re.compile(
        r"\b(?:diagnos(?:is|ed)|hypertension|diabetes|prescription|medical\s+history|patient)\b",
        re.IGNORECASE,
    )

    # 6. Salary & compensation pattern (matches salary/payroll terms and currency amounts without matching [SALARY])
    salary_pattern = re.compile(
        r"(?<!\[)(?:(?:\b(?:salary|payroll|compensation|remuneration|hourly\s+rate|annual\s+base)\b)|(?:\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?))(?!\])",
        re.IGNORECASE,
    )

    return [
        DetectorRule(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            pattern=email_pattern,
            confidence=0.95,
            severity=0.5,
            description="Detects standard RFC-compliant email addresses",
        ),
        DetectorRule(
            rule_id="DETECT-PHONE-001",
            category=FindingCategory.PHONE,
            pattern=phone_pattern,
            confidence=0.90,
            severity=0.5,
            description="Detects North American and international phone numbers",
        ),
        DetectorRule(
            rule_id="DETECT-EMPID-001",
            category=FindingCategory.EMPLOYEE_ID,
            pattern=employee_id_pattern,
            confidence=0.95,
            severity=0.6,
            description="Detects organization-specific employee identification numbers",
        ),
        DetectorRule(
            rule_id="DETECT-NATID-001",
            category=FindingCategory.NATIONAL_ID,
            pattern=national_id_pattern,
            confidence=0.95,
            severity=1.0,
            description="Detects standard national and government personal identification numbers",
        ),
        DetectorRule(
            rule_id="DETECT-HEALTH-001",
            category=FindingCategory.HEALTH,
            pattern=health_pattern,
            confidence=0.85,
            severity=0.8,
            description="Detects health terms and medical diagnostic indicators",
        ),
        DetectorRule(
            rule_id="DETECT-SALARY-001",
            category=FindingCategory.SALARY,
            pattern=salary_pattern,
            confidence=0.90,
            severity=0.7,
            description="Detects salary, compensation, and payroll terms or currency amounts",
        ),
    ]
