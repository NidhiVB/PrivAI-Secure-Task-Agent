"""Deterministic in-memory mock AI provider adapter."""

from backend.app.core.exceptions import ProviderException
from backend.app.models.responses import ProviderInfo
from backend.app.providers.base import BaseProvider, ProviderResponse


class MockProvider(BaseProvider):
    """Deterministic in-memory mock AI provider.

    Security Invariants:
    1. Zero network egress; operates strictly offline and in-memory.
    2. Exposes call counter and in-memory prompt inspection strictly for unit testing.
    3. Normal application logging never logs prompts or sensitive values.
    4. Can simulate provider failures and timeouts for fail-closed security testing.
    """

    def __init__(self, name: str = "mock", model: str = "mock-v1") -> None:
        self.name = name
        self.model = model
        self._call_count: int = 0
        self._received_prompts: list[str] = []
        self._simulate_failure: bool = False
        self._failure_exception: Exception | None = None

    @property
    def call_count(self) -> int:
        """Total number of successful calls to generate()."""
        return self._call_count

    @property
    def received_prompts(self) -> list[str]:
        """In-memory copy of prompts received by this provider (test inspection only)."""
        return list(self._received_prompts)

    def set_failure_mode(
        self, enabled: bool = True, exception: Exception | None = None
    ) -> None:
        """Configure the mock provider to simulate an outage, timeout, or error."""
        self._simulate_failure = enabled
        self._failure_exception = exception

    def reset(self) -> None:
        """Reset call counter, received prompt buffer, and simulated failure mode."""
        self._call_count = 0
        self._received_prompts.clear()
        self._simulate_failure = False
        self._failure_exception = None

    def generate(self, prompt: str) -> ProviderResponse:
        """Generate a predictable deterministic mock response."""
        if self._simulate_failure:
            if self._failure_exception is not None:
                raise self._failure_exception
            raise ProviderException(
                message="Mock AI provider simulated execution failure.",
                code="PROVIDER_UNAVAILABLE",
                status_code=502,
            )

        self._call_count += 1
        self._received_prompts.append(prompt)

        return ProviderResponse(
            text="Mock response generated locally.",
            model=self.model,
            provider_name=self.name,
        )

    def get_info(self) -> ProviderInfo:
        """Return provider identification metadata."""
        return ProviderInfo(name=self.name, model=self.model)
