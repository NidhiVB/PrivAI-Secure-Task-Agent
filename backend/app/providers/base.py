"""Base AI provider interface and response structures."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from backend.app.models.responses import ProviderInfo


@dataclass(frozen=True)
class ProviderResponse:
    """Standardized provider execution output."""

    text: str
    model: str
    provider_name: str


class BaseProvider(ABC):
    """Abstract base class for all AI provider adapters.

    Security Invariants:
    1. Providers must never be invoked directly from API endpoints or frontend clients.
    2. Calls must pass through the central orchestrator's internal permit gate.
    3. Implementations must never log raw prompt content or sensitive values.
    """

    @abstractmethod
    def generate(self, prompt: str) -> ProviderResponse:
        """Execute text generation against the authorized prompt."""
        ...

    @abstractmethod
    def get_info(self) -> ProviderInfo:
        """Return provider identification metadata."""
        ...
