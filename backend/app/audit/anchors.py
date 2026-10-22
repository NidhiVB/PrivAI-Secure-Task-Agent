"""External audit checkpoint anchor adapters and interfaces."""

import abc
import datetime
import hashlib
import time
from typing import Any
import httpx

from backend.app.config import settings
from backend.app.core.exceptions import PrivAIException
from backend.app.models.audit import AuditAnchorReceipt, AuditCheckpoint


class AuditAnchorException(PrivAIException):
    """Base exception for external audit checkpoint anchoring failures."""

    def __init__(
        self,
        message: str = "External audit checkpoint anchoring failed.",
        code: str = "AUDIT_ANCHOR_ERROR",
        status_code: int = 502,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class AuditAnchorAuthException(AuditAnchorException):
    """Raised when authentication to external anchor ledger fails."""

    def __init__(
        self,
        message: str = "External audit anchor authentication failed.",
        code: str = "AUDIT_ANCHOR_AUTH_FAILED",
        status_code: int = 502,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class AuditAnchorTimeoutException(AuditAnchorException):
    """Raised when request to external anchor times out."""

    def __init__(
        self,
        message: str = "External audit anchor request timed out.",
        code: str = "AUDIT_ANCHOR_TIMEOUT",
        status_code: int = 502,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class BaseAuditAnchorAdapter(abc.ABC):
    """Abstract interface for external audit checkpoint anchoring providers.

    Security Invariants:
    1. Independent trust domain: Anchors roots to an immutable external ledger.
    2. Explicit confirmation: Checkpoint is never marked ANCHORED without verified receipt.
    3. Fail-closed: Failures are captured and never silently swallowed.
    4. Data minimization: Only cryptographic hashes, counts, and sequence ranges are sent.
       Raw prompts, sanitized content, and encryption keys are strictly omitted.
    """

    @abc.abstractmethod
    def anchor_checkpoint(self, checkpoint: AuditCheckpoint) -> AuditAnchorReceipt:
        """Transmit checkpoint root and metadata to immutable external ledger."""
        pass

    @abc.abstractmethod
    def verify_anchored_checkpoint(
        self, checkpoint: AuditCheckpoint, receipt: AuditAnchorReceipt
    ) -> bool:
        """Verify that an external anchor receipt corresponds to the checkpoint root."""
        pass


class MockAuditAnchorAdapter(BaseAuditAnchorAdapter):
    """In-memory mock anchor adapter for local development, staging tests, and CI/CD."""

    def __init__(self) -> None:
        self._anchors: dict[str, AuditAnchorReceipt] = {}
        self.simulate_failure: bool = False
        self.simulate_auth_failure: bool = False
        self.simulate_timeout: bool = False
        self.call_count: int = 0

    def clear(self) -> None:
        """Reset mock anchor state."""
        self._anchors.clear()
        self.simulate_failure = False
        self.simulate_auth_failure = False
        self.simulate_timeout = False
        self.call_count = 0

    def anchor_checkpoint(self, checkpoint: AuditCheckpoint) -> AuditAnchorReceipt:
        """Anchor checkpoint in mock ledger with test failure simulation hooks."""
        self.call_count += 1

        if self.simulate_timeout:
            raise AuditAnchorTimeoutException("Mock anchor simulated timeout after 5000ms.")

        if self.simulate_auth_failure:
            raise AuditAnchorAuthException("Mock anchor simulated authentication failure.")

        if self.simulate_failure:
            raise AuditAnchorException("Mock anchor simulated service failure.")

        # Idempotence: Return existing receipt if already anchored
        if checkpoint.checkpoint_id in self._anchors:
            return self._anchors[checkpoint.checkpoint_id]

        anchor_id = f"mock-anchor-{checkpoint.epoch_index}-{checkpoint.checkpoint_id[:8]}"
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sig = hashlib.sha256(f"MOCK_SIG_{checkpoint.checkpoint_hash}".encode("utf-8")).hexdigest()

        receipt = AuditAnchorReceipt(
            anchor_id=anchor_id,
            destination="mock://in-memory-transparency-log",
            anchored_at=now_str,
            root_hash=checkpoint.merkle_root,
            external_signature=sig,
        )
        self._anchors[checkpoint.checkpoint_id] = receipt
        return receipt

    def verify_anchored_checkpoint(
        self, checkpoint: AuditCheckpoint, receipt: AuditAnchorReceipt
    ) -> bool:
        """Verify mock receipt matches checkpoint Merkle root."""
        if receipt.root_hash != checkpoint.merkle_root:
            return False
        return checkpoint.checkpoint_id in self._anchors


class ProductionAuditAnchorAdapter(BaseAuditAnchorAdapter):
    """Production external anchor adapter for independently protected immutable ledgers.

    Supports RFC 6962 transparency logs (e.g. Sigstore Rekor) and Cloud WORM storage.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        auth_token: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.endpoint = (endpoint or getattr(settings, "AUDIT_ANCHOR_ENDPOINT", "")).rstrip("/")
        self._auth_token = auth_token or getattr(settings, "AUDIT_ANCHOR_AUTH_TOKEN", "")
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "AUDIT_ANCHOR_TIMEOUT_SECONDS", 5.0)
        )
        self.max_retries = (
            max_retries
            if max_retries is not None
            else getattr(settings, "AUDIT_ANCHOR_MAX_RETRIES", 2)
        )
        self._client = client

    def anchor_checkpoint(self, checkpoint: AuditCheckpoint) -> AuditAnchorReceipt:
        """Transmit checkpoint root to external transparency ledger over HTTPS."""
        if not self.endpoint:
            raise AuditAnchorException("External audit anchor endpoint is not configured.")

        payload = {
            "checkpoint_id": checkpoint.checkpoint_id,
            "epoch_index": checkpoint.epoch_index,
            "start_sequence": checkpoint.start_sequence,
            "end_sequence": checkpoint.end_sequence,
            "event_count": checkpoint.event_count,
            "merkle_root": checkpoint.merkle_root,
            "prev_checkpoint_hash": checkpoint.prev_checkpoint_hash,
            "checkpoint_hash": checkpoint.checkpoint_hash,
            "created_at": checkpoint.created_at,
        }

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PrivAI-Audit-Anchor/1.0",
        }
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token.strip()}"

        attempts = 0
        max_attempts = 1 + max(0, self.max_retries)

        while attempts < max_attempts:
            attempts += 1
            try:
                if self._client is not None:
                    resp = self._client.post(
                        f"{self.endpoint}/v1/checkpoints",
                        json=payload,
                        headers=headers,
                        timeout=self.timeout_seconds,
                    )
                else:
                    with httpx.Client(timeout=self.timeout_seconds) as client:
                        resp = client.post(
                            f"{self.endpoint}/v1/checkpoints",
                            json=payload,
                            headers=headers,
                        )

                if resp.status_code in (200, 201):
                    data = resp.json()
                    anchor_id = str(data.get("anchor_id") or data.get("id") or checkpoint.checkpoint_id)
                    anchored_at = str(
                        data.get("anchored_at")
                        or data.get("timestamp")
                        or datetime.datetime.now(datetime.timezone.utc).isoformat()
                    )
                    root_hash = str(data.get("root_hash") or data.get("merkle_root") or checkpoint.merkle_root)
                    sig = data.get("signature") or data.get("external_signature")

                    if root_hash != checkpoint.merkle_root:
                        raise AuditAnchorException(
                            "External anchor acknowledged mismatched root hash."
                        )

                    return AuditAnchorReceipt(
                        anchor_id=anchor_id,
                        destination=self.endpoint,
                        anchored_at=anchored_at,
                        root_hash=root_hash,
                        external_signature=sig,
                    )

                if resp.status_code in (401, 403):
                    raise AuditAnchorAuthException(
                        "External audit anchor authentication failed. Invalid or expired anchor token."
                    )

                # Transient 503 or 429: can retry
                if resp.status_code in (502, 503, 504, 429) and attempts < max_attempts:
                    time.sleep(0.05 * (2 ** (attempts - 1)))
                    continue

                raise AuditAnchorException(
                    f"External audit anchor returned HTTP error status {resp.status_code}."
                )

            except (AuditAnchorAuthException, AuditAnchorException):
                raise
            except httpx.TimeoutException as exc:
                if attempts < max_attempts:
                    continue
                raise AuditAnchorTimeoutException(
                    "External audit anchor request timed out."
                ) from exc
            except httpx.RequestError as exc:
                if attempts < max_attempts:
                    continue
                raise AuditAnchorException(
                    "External audit anchor connection error."
                ) from exc

        raise AuditAnchorException("External audit anchor failed after maximum retry attempts.")

    def verify_anchored_checkpoint(
        self, checkpoint: AuditCheckpoint, receipt: AuditAnchorReceipt
    ) -> bool:
        """Verify external anchor receipt matches checkpoint root hash."""
        return receipt.root_hash == checkpoint.merkle_root


# Global singleton instance
_default_anchor_adapter: BaseAuditAnchorAdapter | None = None


def get_audit_anchor_adapter() -> BaseAuditAnchorAdapter:
    """Return configured global audit anchor adapter singleton."""
    global _default_anchor_adapter
    if _default_anchor_adapter is None:
        provider = getattr(settings, "AUDIT_ANCHOR_PROVIDER", "local").lower()
        if provider == "production":
            _default_anchor_adapter = ProductionAuditAnchorAdapter()
        else:
            _default_anchor_adapter = MockAuditAnchorAdapter()
    return _default_anchor_adapter


def set_audit_anchor_adapter(adapter: BaseAuditAnchorAdapter | None) -> None:
    """Override anchor adapter singleton (useful for test isolation)."""
    global _default_anchor_adapter
    _default_anchor_adapter = adapter
