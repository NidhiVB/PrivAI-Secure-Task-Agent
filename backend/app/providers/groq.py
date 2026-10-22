"""Groq Cloud AI provider adapter implementing OpenAI-compatible chat completions."""

import time
import httpx

from backend.app.config import settings
from backend.app.core.exceptions import ProviderException
from backend.app.models.responses import ProviderInfo
from backend.app.providers.base import BaseProvider, ProviderResponse


class GroqProvider(BaseProvider):
    """Groq Cloud API provider adapter.

    Security Invariants:
    1. Zero Groq calls for BLOCK and pending REVIEW decisions.
    2. REDACT transmits strictly verified sanitized text.
    3. GROQ_API_KEY is read only on the backend; never exposed via responses, logs, or errors.
    4. PROVIDER_MODE=mock remains the default. Explicit opt-in (PROVIDER_MODE=groq) required.
    5. Provider failures, timeouts, and network issues fail closed and return normalized 502 errors.
    6. Third-party provider output is treated as untrusted plain text.
    7. No raw prompts, sanitized prompts, or API keys are stored in audit logs or exceptions.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
        provider_mode: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else settings.GROQ_API_KEY
        self.base_url = (base_url or settings.GROQ_BASE_URL).rstrip("/")
        self.model = model or settings.GROQ_MODEL
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.PROVIDER_TIMEOUT_SECONDS
        )
        self.max_retries = (
            max_retries
            if max_retries is not None
            else settings.PROVIDER_MAX_RETRIES
        )
        self.provider_mode = (
            provider_mode
            if provider_mode is not None
            else settings.PROVIDER_MODE
        )
        self._client = client

    @property
    def is_configured(self) -> bool:
        """Check if an API key is provided and non-empty."""
        return bool(self._api_key and self._api_key.strip())

    def get_info(self) -> ProviderInfo:
        """Return provider identification metadata."""
        return ProviderInfo(name="groq", model=self.model)

    def generate(self, prompt: str) -> ProviderResponse:
        """Execute text generation against Groq Cloud API with authorized prompt.

        Security Invariant:
        Must only be invoked by OrchestrationService permit gate with pre-validated,
        sanitized prompt (or clean ALLOW prompt).
        """
        # Invariant 4: Require explicit opt-in to use Groq
        if self.provider_mode != "groq":
            raise ProviderException(
                message="Groq provider is disabled. Configure PROVIDER_MODE=groq in environment to enable.",
                code="PROVIDER_DISABLED",
                status_code=502,
            )

        # Invariant 3 & 5: Require API key when Groq mode is active; missing key fails closed
        if not self.is_configured:
            raise ProviderException(
                message="Groq API key is not configured.",
                code="PROVIDER_NOT_CONFIGURED",
                status_code=502,
            )

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "PrivAI-Firewall/1.0",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
        }

        # Bounded retries: only retry on connection drops, timeouts, or transient 503 errors
        attempts = 0
        max_attempts = 1 + max(0, self.max_retries)

        while attempts < max_attempts:
            attempts += 1
            try:
                if self._client is not None:
                    response = self._client.post(
                        endpoint,
                        headers=headers,
                        json=payload,
                        timeout=self.timeout_seconds,
                    )
                else:
                    with httpx.Client(timeout=self.timeout_seconds) as client:
                        response = client.post(
                            endpoint,
                            headers=headers,
                            json=payload,
                        )

                # Check for HTTP error responses
                if response.status_code >= 400:
                    # Retry on 503 Service Unavailable if attempts remaining
                    if response.status_code == 503 and attempts < max_attempts:
                        time.sleep(0.05 * attempts)
                        continue

                    # Rate limit handling (429)
                    if response.status_code == 429:
                        raise ProviderException(
                            message="Groq provider rate limit exceeded.",
                            code="PROVIDER_RATE_LIMITED",
                            status_code=502,
                        )

                    # Authentication failure (401)
                    if response.status_code == 401:
                        raise ProviderException(
                            message="Groq provider authentication failed. Check API key configuration.",
                            code="PROVIDER_AUTH_ERROR",
                            status_code=502,
                        )

                    # General HTTP error - never echo upstream headers or error payload
                    raise ProviderException(
                        message=f"Groq provider returned error status {response.status_code}.",
                        code="PROVIDER_ERROR",
                        status_code=502,
                    )

                # Successful HTTP status: parse JSON
                try:
                    data = response.json()
                except Exception as exc:
                    raise ProviderException(
                        message="Groq provider returned invalid JSON response.",
                        code="PROVIDER_MALFORMED_RESPONSE",
                        status_code=502,
                    ) from exc

                if not isinstance(data, dict):
                    raise ProviderException(
                        message="Groq provider returned non-dictionary JSON response.",
                        code="PROVIDER_MALFORMED_RESPONSE",
                        status_code=502,
                    )

                choices = data.get("choices")
                if not choices or not isinstance(choices, list):
                    raise ProviderException(
                        message="Groq provider response missing choices array.",
                        code="PROVIDER_MALFORMED_RESPONSE",
                        status_code=502,
                    )

                first_choice = choices[0]
                if not isinstance(first_choice, dict):
                    raise ProviderException(
                        message="Groq provider response choice format is invalid.",
                        code="PROVIDER_MALFORMED_RESPONSE",
                        status_code=502,
                    )

                msg = first_choice.get("message")
                if not msg or not isinstance(msg, dict):
                    raise ProviderException(
                        message="Groq provider response missing message structure.",
                        code="PROVIDER_MALFORMED_RESPONSE",
                        status_code=502,
                    )

                content = msg.get("content")
                if content is None or not isinstance(content, str):
                    raise ProviderException(
                        message="Groq provider response missing text content.",
                        code="PROVIDER_MALFORMED_RESPONSE",
                        status_code=502,
                    )

                returned_model = str(data.get("model", self.model))

                # Security Invariant: treat provider output as untrusted plain text
                return ProviderResponse(
                    text=content,
                    model=returned_model,
                    provider_name="groq",
                )

            except httpx.TimeoutException as exc:
                if attempts < max_attempts:
                    time.sleep(0.05 * attempts)
                    continue
                raise ProviderException(
                    message="Groq provider request timed out.",
                    code="PROVIDER_TIMEOUT",
                    status_code=502,
                ) from exc

            except httpx.ConnectError as exc:
                if attempts < max_attempts:
                    time.sleep(0.05 * attempts)
                    continue
                raise ProviderException(
                    message="Failed to connect to Groq provider.",
                    code="PROVIDER_UNAVAILABLE",
                    status_code=502,
                ) from exc

            except httpx.RequestError as exc:
                # Other transport/network errors
                raise ProviderException(
                    message="Network error communicating with Groq provider.",
                    code="PROVIDER_UNAVAILABLE",
                    status_code=502,
                ) from exc

            except ProviderException:
                raise

            except Exception as exc:
                raise ProviderException(
                    message="Unexpected error executing Groq provider request.",
                    code="PROVIDER_EXECUTION_ERROR",
                    status_code=502,
                ) from exc

        # If loop ends without response
        raise ProviderException(
            message="Groq provider failed after maximum retry attempts.",
            code="PROVIDER_ERROR",
            status_code=502,
        )
