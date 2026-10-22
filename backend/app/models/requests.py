"""Request models with strict validation."""

import re
from pydantic import BaseModel, ConfigDict, Field, field_validator
from backend.app.models.context import ContextModel
from backend.app.models.enums import Destination
from backend.app.models.reviews import ReviewPermit

# Unsafe control characters: ASCII 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F
# (Preserves \t (0x09), \n (0x0A), \r (0x0D))
UNSAFE_CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_PROMPT_UTF8_BYTES = 10240


class PromptRequest(BaseModel):
    """Authoritative input schema for analyze and execute endpoints.

    Strict configuration: extra fields (e.g. client-supplied decisions,
    risk scores, or permits) are forbidden and rejected.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt: str = Field(..., description="Prompt text to be inspected")
    destination: Destination = Field(..., description="Target AI provider")
    context: ContextModel = Field(..., description="Context metadata")
    review_permit: ReviewPermit | None = Field(
        default=None, description="Cryptographic single-use review permit authorizing execution"
    )

    @field_validator("prompt")
    @classmethod
    def validate_prompt(cls, v: str) -> str:
        """Validate prompt length, whitespace content, and unsafe control characters."""
        if not v or not v.strip():
            raise ValueError("Prompt must not be empty or whitespace only.")

        byte_length = len(v.encode("utf-8"))
        if byte_length > MAX_PROMPT_UTF8_BYTES:
            raise ValueError(
                f"Prompt size of {byte_length} bytes exceeds maximum allowed limit of {MAX_PROMPT_UTF8_BYTES} UTF-8 bytes."
            )

        if UNSAFE_CONTROL_CHARS_PATTERN.search(v):
            raise ValueError("Prompt contains unsafe control characters.")

        return v
