"""Unit and integration tests for SensitiveDetector, Redactor, and RedactionVerifier."""

import pytest
from backend.app.core.exceptions import (
    DetectionException,
    RedactionException,
    RedactionVerificationException,
)
from backend.app.detectors.detector import SensitiveDetector
from backend.app.detectors.rules import DetectorRule, get_default_rules
from backend.app.models.enums import FindingCategory
from backend.app.models.findings import Finding
from backend.app.redaction.redactor import Redactor
from backend.app.redaction.verifier import RedactionVerifier


# ---------------------------------------------------------------------------
# 1. Email Detection Tests
# ---------------------------------------------------------------------------


def test_detect_email_positive() -> None:
    """Verify email detector identifies various valid email patterns."""
    detector = SensitiveDetector()
    prompt = "Contact alex.smith+work@sub.example.co.uk for inquiries."
    findings = detector.detect(prompt)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.EMAIL
    assert f.rule_id == "DETECT-EMAIL-001"
    assert f.confidence == 0.95
    assert f.severity == 0.5
    # Invariant: Offsets map exactly to the target value
    assert prompt[f.start : f.end] == "alex.smith+work@sub.example.co.uk"


def test_detect_email_punctuation_preserved() -> None:
    """Verify trailing punctuation like commas, periods, and parentheses are not captured."""
    detector = SensitiveDetector()
    prompt = "Email us at (contact@example.com), or info@test.org."
    findings = detector.detect(prompt)

    assert len(findings) == 2
    assert prompt[findings[0].start : findings[0].end] == "contact@example.com"
    assert prompt[findings[1].start : findings[1].end] == "info@test.org"


def test_detect_email_negative() -> None:
    """Verify non-emails and broken formats are not falsely flagged."""
    detector = SensitiveDetector()
    prompt = "Reach out via user@ or @domain.com or just plain text and alex@.com."
    findings = detector.detect(prompt)
    email_findings = [f for f in findings if f.category == FindingCategory.EMAIL]
    assert len(email_findings) == 0


# ---------------------------------------------------------------------------
# 2. Phone Detection Tests
# ---------------------------------------------------------------------------


def test_detect_phone_north_american_formats() -> None:
    """Verify phone detector catches common North American phone formats."""
    detector = SensitiveDetector()
    test_cases = [
        ("Call 555-123-4567 immediately.", "555-123-4567"),
        ("Call (555) 123-4567 today.", "(555) 123-4567"),
        ("Call 555.123.4567 now.", "555.123.4567"),
        ("Call 555 123 4567 please.", "555 123 4567"),
        ("Direct line: +1-555-123-4567.", "+1-555-123-4567"),
    ]
    for prompt, expected in test_cases:
        findings = detector.detect(prompt)
        assert len(findings) == 1, f"Failed on prompt: {prompt}"
        f = findings[0]
        assert f.category == FindingCategory.PHONE
        assert prompt[f.start : f.end] == expected


def test_detect_phone_international_formats() -> None:
    """Verify phone detector catches international phone numbers."""
    detector = SensitiveDetector()
    prompt = "London office: +44 20 7946 0958."
    findings = detector.detect(prompt)

    assert len(findings) == 1
    assert findings[0].category == FindingCategory.PHONE
    assert prompt[findings[0].start : findings[0].end] == "+44 20 7946 0958"


def test_detect_phone_negative_dates_and_ip() -> None:
    """Verify phone detector does NOT match dates, semver, or IP addresses."""
    detector = SensitiveDetector()
    prompt = "Server 192.168.1.1 was deployed on 2026-10-15 running release 1.0.0 with 12345 requests."
    findings = detector.detect(prompt)
    phone_findings = [f for f in findings if f.category == FindingCategory.PHONE]
    assert len(phone_findings) == 0


# ---------------------------------------------------------------------------
# 3. Employee ID Detection Tests
# ---------------------------------------------------------------------------


def test_detect_employee_id_positive() -> None:
    """Verify employee ID detector catches configured EMP-XXXXXX format."""
    detector = SensitiveDetector()
    prompt = "Review performance for EMP-123456 and contractor EMP-98765432."
    findings = detector.detect(prompt)

    emp_findings = [f for f in findings if f.category == FindingCategory.EMPLOYEE_ID]
    assert len(emp_findings) == 2
    assert prompt[emp_findings[0].start : emp_findings[0].end] == "EMP-123456"
    assert prompt[emp_findings[1].start : emp_findings[1].end] == "EMP-98765432"
    assert emp_findings[0].rule_id == "DETECT-EMPID-001"
    assert emp_findings[0].severity == 0.6


def test_detect_employee_id_negative() -> None:
    """Verify invalid or partial employee ID prefixes are ignored."""
    detector = SensitiveDetector()
    prompt = "EMPLOYEE record EMP-12 or EMP-ABCDEF is invalid."
    findings = detector.detect(prompt)
    emp_findings = [f for f in findings if f.category == FindingCategory.EMPLOYEE_ID]
    assert len(emp_findings) == 0


# ---------------------------------------------------------------------------
# 4. Unicode Code-Point Offsets & Boundary Tests
# ---------------------------------------------------------------------------


def test_unicode_code_point_offsets_emojis_and_accents() -> None:
    """Verify Python Unicode code-point offsets handle emojis and multi-byte UTF-8 without drift."""
    detector = SensitiveDetector()
    # Emojis (🚀, 🔒, 👤) take 1 Python code-point each, but 4 bytes in UTF-8
    prompt = "Alert 🚀 🔒 👤: Employee EMP-104928 emailed test@company.com with résumé details."
    findings = detector.detect(prompt)

    assert len(findings) == 2
    # Verify exact code-point slicing matches target sensitive text
    emp_finding = next(f for f in findings if f.category == FindingCategory.EMPLOYEE_ID)
    email_finding = next(f for f in findings if f.category == FindingCategory.EMAIL)

    assert prompt[emp_finding.start : emp_finding.end] == "EMP-104928"
    assert prompt[email_finding.start : email_finding.end] == "test@company.com"


def test_boundary_start_end_and_whole_prompt() -> None:
    """Verify detection at the prompt start, end, and solitary input."""
    detector = SensitiveDetector()

    # Solitary prompt
    f_solo = detector.detect("alex@example.com")
    assert len(f_solo) == 1
    assert (f_solo[0].start, f_solo[0].end) == (0, 16)

    # Start boundary
    f_start = detector.detect("555-123-4567 is the support number.")
    assert len(f_start) == 1
    assert f_start[0].start == 0

    # End boundary
    f_end = detector.detect("The internal ID is EMP-123456")
    assert len(f_end) == 1
    assert f_end[0].end == len("The internal ID is EMP-123456")


# ---------------------------------------------------------------------------
# 5. Overlapping Spans & Conflict Resolution
# ---------------------------------------------------------------------------


def test_overlapping_nested_findings_resolution() -> None:
    """Verify overlapping matches resolve to the higher-severity, encompassing span."""
    detector = SensitiveDetector()
    # A constructed scenario where span A completely subsumes span B
    findings = [
        Finding(
            rule_id="DETECT-EMPID-001",
            category=FindingCategory.EMPLOYEE_ID,
            start=10,
            end=20,
            confidence=0.95,
            severity=0.6,
        ),
        Finding(
            rule_id="DETECT-PHONE-001",
            category=FindingCategory.PHONE,
            start=14,
            end=20,
            confidence=0.90,
            severity=0.5,
        ),
    ]
    resolved = detector.resolve_overlaps(findings)
    assert len(resolved) == 1
    assert resolved[0].rule_id == "DETECT-EMPID-001"
    assert resolved[0].start == 10
    assert resolved[0].end == 20


# ---------------------------------------------------------------------------
# 6. Redaction Correctness & Right-to-Left Substitution
# ---------------------------------------------------------------------------


def test_redaction_single_item() -> None:
    """Verify single span is correctly replaced with exact placeholder."""
    detector = SensitiveDetector()
    redactor = Redactor()

    prompt = "Please send invoice to billing@example.com."
    findings = detector.detect(prompt)
    sanitized, summaries = redactor.redact(prompt, findings)

    assert sanitized == "Please send invoice to [EMAIL]."
    assert len(summaries) == 1
    assert summaries[0].category == FindingCategory.EMAIL
    assert summaries[0].placeholder == "[EMAIL]"


def test_redaction_multiple_categories_and_punctuation() -> None:
    """Verify multiple categories are redacted right-to-left preserving punctuation."""
    detector = SensitiveDetector()
    redactor = Redactor()

    prompt = "Staff EMP-123456 (phone: 555-123-4567, email: staff@company.org) submitted report."
    findings = detector.detect(prompt)
    sanitized, summaries = redactor.redact(prompt, findings)

    assert (
        sanitized
        == "Staff [EMPLOYEE_ID] (phone: [PHONE], email: [EMAIL]) submitted report."
    )
    categories = [s.category for s in summaries]
    assert FindingCategory.EMAIL in categories
    assert FindingCategory.PHONE in categories
    assert FindingCategory.EMPLOYEE_ID in categories


def test_redaction_empty_findings_returns_original() -> None:
    """Verify redacting with no findings returns prompt unaltered."""
    redactor = Redactor()
    prompt = "This is a completely safe prompt with no sensitive info."
    sanitized, summaries = redactor.redact(prompt, [])
    assert sanitized == prompt
    assert summaries == []


# ---------------------------------------------------------------------------
# 7. Post-Redaction Verification
# ---------------------------------------------------------------------------


def test_redaction_verifier_success() -> None:
    """Verify RedactionVerifier passes on properly sanitized prompts."""
    detector = SensitiveDetector()
    redactor = Redactor()
    verifier = RedactionVerifier(detector)

    prompt = "Call 555-123-4567 or email support@example.com regarding EMP-999999."
    findings = detector.detect(prompt)
    sanitized, _ = redactor.redact(prompt, findings)

    # Verification must succeed
    assert verifier.verify(sanitized) is True


def test_placeholders_do_not_trigger_false_detection() -> None:
    """Verify placeholder text itself does not trigger detector rules."""
    detector = SensitiveDetector()
    placeholders_text = (
        "Here are placeholders: [EMAIL], [PHONE], [EMPLOYEE_ID], [NATIONAL_ID], [SALARY], [HEALTH]."
    )
    findings = detector.detect(placeholders_text)
    assert len(findings) == 0


def test_redaction_verifier_fails_closed_on_residual_data() -> None:
    """Verify RedactionVerifier raises RedactionVerificationException if sensitive data survives."""
    detector = SensitiveDetector()
    verifier = RedactionVerifier(detector)

    # Corrupted text where sensitive email was not removed
    leaked_sanitized_prompt = "Contact [EMAIL] or fallback-leak@example.com."
    with pytest.raises(RedactionVerificationException) as exc:
        verifier.verify(leaked_sanitized_prompt)

    assert "Redaction verification failed closed" in str(exc.value)
    # Invariant: Does not leak the sensitive email in the error message
    assert "fallback-leak@example.com" not in str(exc.value)


# ---------------------------------------------------------------------------
# 8. Fail-Closed Error Handling Tests
# ---------------------------------------------------------------------------


def test_redactor_invalid_offsets_fails_closed() -> None:
    """Verify redactor raises RedactionException if given out-of-bounds offsets."""
    redactor = Redactor()
    prompt = "Short prompt"
    invalid_findings = [
        Finding(
            rule_id="DETECT-EMAIL-001",
            category=FindingCategory.EMAIL,
            start=5,
            end=100,  # Out of bounds (> len(prompt))
            confidence=0.9,
            severity=0.5,
        )
    ]
    with pytest.raises(RedactionException) as exc:
        redactor.redact(prompt, invalid_findings)
    assert "Invalid finding offsets" in str(exc.value)


def test_detector_exception_fails_closed() -> None:
    """Verify detector wraps unexpected exceptions into DetectionException without data leak."""
    broken_rule = DetectorRule(
        rule_id="BROKEN-001",
        category=FindingCategory.OTHER,
        pattern=None,  # type: ignore (will raise AttributeError on pattern.finditer)
        confidence=1.0,
        severity=1.0,
    )
    detector = SensitiveDetector(rules=[broken_rule])
    with pytest.raises(DetectionException) as exc:
        detector.detect("Any text")
    assert "Detection failed due to an unexpected error" in str(exc.value)
