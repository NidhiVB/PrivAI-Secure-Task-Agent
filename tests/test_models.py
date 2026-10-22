"""Unit tests for Pydantic models, validation, and invariants."""

import pytest
from pydantic import ValidationError

from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    PolicyOutcome,
    RiskBand,
)
from backend.app.models.findings import Finding
from backend.app.models.requests import PromptRequest
from backend.app.models.risk import RiskScore


def test_valid_prompt_request() -> None:
    """Verify valid PromptRequest builds successfully."""
    req = PromptRequest(
        prompt="Explain binary search algorithm.",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.GENERAL_QUESTION,
            data_subject=ContextDataSubject.NONE,
            classification=ContextClassification.PUBLIC,
        ),
    )
    assert req.prompt == "Explain binary search algorithm."
    assert req.destination == Destination.MOCK
    assert req.context.purpose == ContextPurpose.GENERAL_QUESTION


def test_empty_prompt_rejected() -> None:
    """Verify empty prompt raises ValidationError."""
    with pytest.raises(ValidationError) as exc:
        PromptRequest(
            prompt="",
            destination=Destination.MOCK,
            context=ContextModel(
                purpose=ContextPurpose.GENERAL_QUESTION,
                data_subject=ContextDataSubject.NONE,
                classification=ContextClassification.PUBLIC,
            ),
        )
    assert "Prompt must not be empty or whitespace only" in str(exc.value)


def test_whitespace_only_prompt_rejected() -> None:
    """Verify prompt with only whitespace characters raises ValidationError."""
    with pytest.raises(ValidationError) as exc:
        PromptRequest(
            prompt="   \t  \n  ",
            destination=Destination.MOCK,
            context=ContextModel(
                purpose=ContextPurpose.GENERAL_QUESTION,
                data_subject=ContextDataSubject.NONE,
                classification=ContextClassification.PUBLIC,
            ),
        )
    assert "Prompt must not be empty or whitespace only" in str(exc.value)


def test_prompt_exceeding_byte_limit_rejected() -> None:
    """Verify prompt exceeding 10240 UTF-8 bytes raises ValidationError."""
    oversized_prompt = "a" * 10241
    with pytest.raises(ValidationError) as exc:
        PromptRequest(
            prompt=oversized_prompt,
            destination=Destination.MOCK,
            context=ContextModel(
                purpose=ContextPurpose.GENERAL_QUESTION,
                data_subject=ContextDataSubject.NONE,
                classification=ContextClassification.PUBLIC,
            ),
        )
    assert "exceeds maximum allowed limit" in str(exc.value)


def test_multibyte_utf8_prompt_limit_enforced() -> None:
    """Verify multi-byte UTF-8 character length is checked by byte count, not code points."""
    # Each '€' character is 3 bytes in UTF-8
    # 3414 * 3 = 10242 bytes > 10240 limit
    oversized_multibyte = "€" * 3414
    with pytest.raises(ValidationError) as exc:
        PromptRequest(
            prompt=oversized_multibyte,
            destination=Destination.MOCK,
            context=ContextModel(
                purpose=ContextPurpose.GENERAL_QUESTION,
                data_subject=ContextDataSubject.NONE,
                classification=ContextClassification.PUBLIC,
            ),
        )
    assert "exceeds maximum allowed limit" in str(exc.value)


def test_prompt_unsafe_control_chars_rejected() -> None:
    """Verify prompt containing unsafe control characters (e.g. NULL byte) is rejected."""
    with pytest.raises(ValidationError) as exc:
        PromptRequest(
            prompt="Hello \x00 world",
            destination=Destination.MOCK,
            context=ContextModel(
                purpose=ContextPurpose.GENERAL_QUESTION,
                data_subject=ContextDataSubject.NONE,
                classification=ContextClassification.PUBLIC,
            ),
        )
    assert "unsafe control characters" in str(exc.value)


def test_prompt_legitimate_newlines_and_tabs_allowed() -> None:
    """Verify legitimate formatting characters (newlines, carriage returns, tabs) are preserved."""
    req = PromptRequest(
        prompt="Line 1\r\n\tLine 2\nLine 3",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.CODING,
            data_subject=ContextDataSubject.NONE,
            classification=ContextClassification.INTERNAL,
        ),
    )
    assert "\r\n\t" in req.prompt


def test_forbid_extra_fields_in_context() -> None:
    """Verify unknown fields in ContextModel are strictly forbidden."""
    with pytest.raises(ValidationError) as exc:
        ContextModel(
            purpose=ContextPurpose.GENERAL_QUESTION,
            data_subject=ContextDataSubject.NONE,
            classification=ContextClassification.PUBLIC,
            extra_field="malicious_or_unknown",  # type: ignore
        )
    assert "Extra inputs are not permitted" in str(exc.value)


def test_forbid_extra_fields_in_prompt_request() -> None:
    """Verify client cannot inject decisions, risk scores, or bypass fields."""
    with pytest.raises(ValidationError) as exc:
        PromptRequest(
            prompt="Test prompt",
            destination=Destination.MOCK,
            context=ContextModel(
                purpose=ContextPurpose.GENERAL_QUESTION,
                data_subject=ContextDataSubject.NONE,
                classification=ContextClassification.PUBLIC,
            ),
            decision="ALLOW",  # type: ignore
            risk_score=0,  # type: ignore
            sanitized_prompt="Bypass",  # type: ignore
        )
    assert "Extra inputs are not permitted" in str(exc.value)


def test_destination_enum_validation() -> None:
    """Verify arbitrary URLs or unsupported destinations are rejected."""
    with pytest.raises(ValidationError):
        PromptRequest(
            prompt="Test prompt",
            destination="https://evil.example.com/api",  # type: ignore
            context=ContextModel(
                purpose=ContextPurpose.GENERAL_QUESTION,
                data_subject=ContextDataSubject.NONE,
                classification=ContextClassification.PUBLIC,
            ),
        )


def test_finding_omits_raw_value() -> None:
    """Verify Finding model does not store matched raw text (data minimization)."""
    finding = Finding(
        rule_id="DETECT-EMAIL-001",
        category="EMAIL",
        start=10,
        end=25,
        confidence=0.95,
        severity=0.5,
    )
    dumped = finding.model_dump()
    assert "text" not in dumped
    assert "matched_value" not in dumped
    assert "raw" not in dumped
