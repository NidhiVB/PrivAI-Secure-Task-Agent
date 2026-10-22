"""Production-grade Key Management Service (KMS) abstraction and enterprise adapters."""

import abc
import base64
import os
import threading
import time
from typing import Any
import httpx

from backend.app.config import settings
from backend.app.core.exceptions import PrivAIException


class KMSException(PrivAIException):
    """Base exception for Key Management Service errors."""

    def __init__(
        self,
        message: str = "Key management service operation failed.",
        code: str = "KMS_ERROR",
        status_code: int = 500,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class KMSKeyNotFoundException(KMSException):
    """Raised when a requested key identifier is not found or revoked."""

    def __init__(self, key_id: str) -> None:
        super().__init__(
            message=f"Key identifier '{key_id}' not found in key management service.",
            code="KMS_KEY_NOT_FOUND",
            status_code=500,
        )


class KMSInvalidKeyException(KMSException):
    """Raised when key material fails length or format constraints."""

    def __init__(self, message: str = "Invalid key material format or length.") -> None:
        super().__init__(
            message=message,
            code="KMS_INVALID_KEY",
            status_code=500,
        )


class KMSRemoteServiceException(KMSException):
    """Raised when external KMS or Secrets Manager is unreachable, times out, or fails."""

    def __init__(
        self,
        message: str = "External KMS service request failed.",
        code: str = "KMS_REMOTE_SERVICE_ERROR",
        status_code: int = 502,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class KMSAuthenticationException(KMSException):
    """Raised when authentication to external KMS or Secrets Manager fails."""

    def __init__(
        self,
        message: str = "External KMS authentication failed.",
        code: str = "KMS_AUTH_FAILED",
        status_code: int = 502,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class BaseKMSClient(abc.ABC):
    """Abstract interface for enterprise KMS and secret managers.

    Security Invariants:
    1. Strict namespace separation between payload encryption keys and HMAC signing secrets.
    2. Explicit key identifiers bind all operations to support zero-downtime key rotation.
    3. Secret key material is never exposed in logs, audit records, or API responses.
    4. Fails closed with KMSException on unknown key IDs or lookup failures.
    """

    @abc.abstractmethod
    def get_active_encryption_key(self) -> tuple[str, bytes]:
        """Return the active (key_id, 32_byte_key) for AES-256-GCM envelope encryption."""
        pass

    @abc.abstractmethod
    def get_encryption_key(self, key_id: str) -> bytes:
        """Retrieve a specific 32-byte encryption key by key_id for decryption."""
        pass

    @abc.abstractmethod
    def get_active_permit_signing_secret(self) -> tuple[str, bytes]:
        """Return the active (key_id, secret_bytes) for HMAC review permit signing."""
        pass

    @abc.abstractmethod
    def get_permit_signing_secret(self, key_id: str) -> bytes:
        """Retrieve a specific permit signing secret by key_id for verification."""
        pass


class LocalKMSClient(BaseKMSClient):
    """Thread-safe, backend-only local KMS client for development, staging, and offline tests.

    Supports key versioning, rotation, and mock testing without requiring cloud credentials.
    """

    def __init__(
        self,
        encryption_keys: dict[str, bytes] | None = None,
        active_encryption_key_id: str | None = None,
        permit_secrets: dict[str, bytes] | None = None,
        active_permit_key_id: str | None = None,
    ) -> None:
        self._encryption_keys: dict[str, bytes] = {}
        self._permit_secrets: dict[str, bytes] = {}
        self._active_enc_key_id = (
            active_encryption_key_id
            or getattr(settings, "ACTIVE_ENCRYPTION_KEY_ID", "enc-key-v1")
        )
        self._active_permit_key_id = (
            active_permit_key_id
            or getattr(settings, "ACTIVE_PERMIT_KEY_ID", "permit-key-v1")
        )

        # Initialize encryption keys
        if encryption_keys:
            for kid, key in encryption_keys.items():
                self.register_encryption_key(kid, key)
        elif settings.REVIEW_ENCRYPTION_KEY:
            raw = settings.REVIEW_ENCRYPTION_KEY.strip()
            key_bytes = bytes.fromhex(raw) if len(raw) == 64 else base64.b64decode(raw)
            self.register_encryption_key(self._active_enc_key_id, key_bytes)
            for kid in ("enc-key-v1", "enc-staging-v1"):
                if kid not in self._encryption_keys:
                    self.register_encryption_key(kid, key_bytes)
        else:
            # Ephemeral deterministic default key for local dev and tests
            dev_key = b"PrivAI_Dev_Default_Key_32_Bytes!"
            self.register_encryption_key(self._active_enc_key_id, dev_key)
            for kid in ("enc-key-v1", "enc-staging-v1"):
                if kid not in self._encryption_keys:
                    self.register_encryption_key(kid, dev_key)

        # Initialize permit signing secrets
        if permit_secrets:
            for kid, secret in permit_secrets.items():
                self.register_permit_secret(kid, secret)
        elif settings.REVIEW_PERMIT_SECRET:
            secret_bytes = settings.REVIEW_PERMIT_SECRET.encode("utf-8")
            self.register_permit_secret(self._active_permit_key_id, secret_bytes)
            for kid in ("permit-key-v1", "permit-staging-v1"):
                if kid not in self._permit_secrets:
                    self.register_permit_secret(kid, secret_bytes)
        else:
            dev_secret = b"privai-dev-permit-signing-secret-key-32bytes-min"
            self.register_permit_secret(self._active_permit_key_id, dev_secret)
            for kid in ("permit-key-v1", "permit-staging-v1"):
                if kid not in self._permit_secrets:
                    self.register_permit_secret(kid, dev_secret)

    def register_encryption_key(self, key_id: str, key_bytes: bytes) -> None:
        """Register or rotate an AES-256 encryption key."""
        if not key_bytes or len(key_bytes) != 32:
            raise KMSInvalidKeyException(
                f"AES-256 encryption key must be exactly 32 bytes (got {len(key_bytes) if key_bytes else 0})."
            )
        self._encryption_keys[key_id] = key_bytes

    def set_active_encryption_key(self, key_id: str) -> None:
        """Rotate active encryption key ID (must already be registered)."""
        if key_id not in self._encryption_keys:
            raise KMSKeyNotFoundException(key_id)
        self._active_enc_key_id = key_id

    def register_permit_secret(self, key_id: str, secret_bytes: bytes) -> None:
        """Register or rotate an HMAC permit signing secret."""
        if not secret_bytes or len(secret_bytes) < 16:
            raise KMSInvalidKeyException(
                f"Permit signing secret must be at least 16 bytes (got {len(secret_bytes) if secret_bytes else 0})."
            )
        self._permit_secrets[key_id] = secret_bytes

    def set_active_permit_key(self, key_id: str) -> None:
        """Rotate active permit signing key ID (must already be registered)."""
        if key_id not in self._permit_secrets:
            raise KMSKeyNotFoundException(key_id)
        self._active_permit_key_id = key_id

    def get_active_encryption_key(self) -> tuple[str, bytes]:
        """Return active encryption key ID and key bytes."""
        if self._active_enc_key_id not in self._encryption_keys:
            raise KMSKeyNotFoundException(self._active_enc_key_id)
        return self._active_enc_key_id, self._encryption_keys[self._active_enc_key_id]

    def get_encryption_key(self, key_id: str) -> bytes:
        """Retrieve encryption key by ID."""
        if key_id not in self._encryption_keys:
            raise KMSKeyNotFoundException(key_id)
        return self._encryption_keys[key_id]

    def get_active_permit_signing_secret(self) -> tuple[str, bytes]:
        """Return active permit signing key ID and secret bytes."""
        if self._active_permit_key_id not in self._permit_secrets:
            raise KMSKeyNotFoundException(self._active_permit_key_id)
        return self._active_permit_key_id, self._permit_secrets[self._active_permit_key_id]

    def get_permit_signing_secret(self, key_id: str) -> bytes:
        """Retrieve permit signing secret by ID."""
        if key_id not in self._permit_secrets:
            raise KMSKeyNotFoundException(key_id)
        return self._permit_secrets[key_id]


class EnterpriseKMSAdapter(BaseKMSClient):
    """Production adapter for external enterprise secret managers (HashiCorp Vault / AWS KMS).

    Acts as an enterprise envelope encryption client that delegates to remote KMS endpoints
    and caches authenticated keys in-memory with automatic TTL eviction.

    Security Invariants:
    1. Strict namespace separation: Encryption keys (/encryption/{id}) vs HMAC permit secrets (/permits/{id}).
    2. Explicit key identifiers bind all operations to support zero-downtime key rotation.
    3. Secret key material is never exposed in logs, audit records, or API responses.
    4. Fails closed with sanitized exceptions on unknown key IDs, lookup failures, or remote errors.
    5. Thread-safe in-memory caching with TTL eviction to minimize latency and network jitter.
    """

    def __init__(
        self,
        provider: str = "vault",
        kms_endpoint: str = "",
        auth_token: str = "",
        active_encryption_key_id: str | None = None,
        active_permit_key_id: str | None = None,
        cache_ttl_seconds: int | None = None,
        timeout_seconds: float | None = None,
        vault_mount: str | None = None,
        key_path_prefix: str | None = None,
        allow_fallback: bool | None = None,
        fallback_client: BaseKMSClient | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.provider = provider.lower()
        self.kms_endpoint = (kms_endpoint or getattr(settings, "KMS_ENDPOINT", "")).rstrip("/")
        self._auth_token = auth_token or getattr(settings, "KMS_AUTH_TOKEN", "")
        self._active_enc_key_id = (
            active_encryption_key_id
            or getattr(settings, "ACTIVE_ENCRYPTION_KEY_ID", "enc-key-v1")
        )
        self._active_permit_key_id = (
            active_permit_key_id
            or getattr(settings, "ACTIVE_PERMIT_KEY_ID", "permit-key-v1")
        )
        self.cache_ttl_seconds = (
            cache_ttl_seconds
            if cache_ttl_seconds is not None
            else getattr(settings, "KMS_CACHE_TTL_SECONDS", 300)
        )
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "KMS_TIMEOUT_SECONDS", 5.0)
        )
        self.vault_mount = vault_mount or getattr(settings, "KMS_VAULT_MOUNT", "secret")
        self.key_path_prefix = key_path_prefix or getattr(settings, "KMS_KEY_PATH_PREFIX", "privai")
        self.allow_fallback = (
            allow_fallback
            if allow_fallback is not None
            else getattr(settings, "KMS_ALLOW_LOCAL_FALLBACK", False)
        )
        self._fallback = fallback_client or LocalKMSClient(
            active_encryption_key_id=self._active_enc_key_id,
            active_permit_key_id=self._active_permit_key_id,
        )
        self._client = client

        # In-memory TTL key cache: "namespace:key_id" -> (bytes, expire_monotonic)
        self._cache: dict[str, tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def _parse_secret_payload(self, raw_data: dict[str, Any], namespace: str, key_id: str) -> bytes:
        """Extract and parse secret material from remote JSON response."""
        val = (
            raw_data.get("key")
            or raw_data.get("secret")
            or raw_data.get("value")
            or raw_data.get("secret_key")
        )
        if not val and isinstance(raw_data.get("data"), dict):
            val = (
                raw_data["data"].get("key")
                or raw_data["data"].get("secret")
                or raw_data["data"].get("value")
            )

        if not val or not isinstance(val, (str, bytes)):
            raise KMSInvalidKeyException(
                f"Missing or malformed key material for key_id '{key_id}' in namespace '{namespace}'."
            )

        if isinstance(val, bytes):
            key_bytes = val
        else:
            v_str = val.strip()
            if len(v_str) == 64:
                try:
                    key_bytes = bytes.fromhex(v_str)
                except ValueError:
                    key_bytes = v_str.encode("utf-8")
            else:
                try:
                    key_bytes = base64.b64decode(v_str)
                except Exception:
                    key_bytes = v_str.encode("utf-8")

        if namespace == "encryption":
            if len(key_bytes) != 32:
                raise KMSInvalidKeyException(
                    f"AES-256 encryption key must be exactly 32 bytes (got {len(key_bytes)} for key '{key_id}')."
                )
        elif namespace == "permits":
            if len(key_bytes) < 16:
                raise KMSInvalidKeyException(
                    f"Permit signing secret must be at least 16 bytes (got {len(key_bytes)} for key '{key_id}')."
                )

        return key_bytes

    def _fetch_remote_secret(self, namespace: str, key_id: str) -> bytes:
        """Retrieve key material from external KMS / Vault endpoint over TLS."""
        if not self.kms_endpoint:
            if self.allow_fallback:
                if namespace == "encryption":
                    return self._fallback.get_encryption_key(key_id)
                return self._fallback.get_permit_signing_secret(key_id)
            raise KMSRemoteServiceException("External KMS endpoint is not configured.")

        # HashiCorp Vault KV v2 REST path: /v1/{mount}/data/{key_path_prefix}/{namespace}/{key_id}
        url = f"{self.kms_endpoint}/v1/{self.vault_mount}/data/{self.key_path_prefix}/{namespace}/{key_id}"
        headers = {
            "User-Agent": "PrivAI-KMS-Client/1.0",
        }
        if self._auth_token:
            headers["X-Vault-Token"] = self._auth_token.strip()

        try:
            if self._client is not None:
                resp = self._client.get(url, headers=headers, timeout=self.timeout_seconds)
            else:
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    resp = client.get(url, headers=headers)
        except httpx.TimeoutException as exc:
            if self.allow_fallback:
                if namespace == "encryption":
                    return self._fallback.get_encryption_key(key_id)
                return self._fallback.get_permit_signing_secret(key_id)
            raise KMSRemoteServiceException(
                f"External KMS request timed out for key '{key_id}'."
            ) from exc
        except httpx.RequestError as exc:
            if self.allow_fallback:
                if namespace == "encryption":
                    return self._fallback.get_encryption_key(key_id)
                return self._fallback.get_permit_signing_secret(key_id)
            raise KMSRemoteServiceException(
                f"External KMS connection error while retrieving key '{key_id}'."
            ) from exc

        if resp.status_code == 404:
            raise KMSKeyNotFoundException(key_id)
        elif resp.status_code in (401, 403):
            raise KMSAuthenticationException(
                "External KMS authentication failed. Invalid or expired KMS auth token."
            )
        elif resp.status_code >= 400:
            if self.allow_fallback:
                if namespace == "encryption":
                    return self._fallback.get_encryption_key(key_id)
                return self._fallback.get_permit_signing_secret(key_id)
            raise KMSRemoteServiceException(
                f"External KMS service returned error status {resp.status_code} for key '{key_id}'."
            )

        try:
            body = resp.json()
            secret_data = body.get("data", {})
            if "data" in secret_data and isinstance(secret_data["data"], dict):
                secret_data = secret_data["data"]
            return self._parse_secret_payload(secret_data, namespace, key_id)
        except (ValueError, KeyError) as exc:
            raise KMSInvalidKeyException(
                f"Malformed JSON payload from external KMS for key '{key_id}'."
            ) from exc

    def _get_key_with_cache(self, namespace: str, key_id: str) -> bytes:
        """Resolve key with thread-safe TTL cache and remote lookup."""
        cache_key = f"{namespace}:{key_id}"
        now = time.monotonic()

        with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None:
                key_bytes, expires_at = cached
                if now < expires_at:
                    return key_bytes
                del self._cache[cache_key]

        key_bytes = self._fetch_remote_secret(namespace, key_id)

        with self._lock:
            self._cache[cache_key] = (key_bytes, time.monotonic() + self.cache_ttl_seconds)

        return key_bytes

    def get_encryption_key(self, key_id: str) -> bytes:
        """Retrieve a specific 32-byte encryption key by key_id for decryption."""
        return self._get_key_with_cache("encryption", key_id)

    def get_active_encryption_key(self) -> tuple[str, bytes]:
        """Return the active (key_id, 32_byte_key) for AES-256-GCM envelope encryption."""
        if not self.kms_endpoint and self.allow_fallback:
            return self._fallback.get_active_encryption_key()
        key_id = self._active_enc_key_id
        return key_id, self.get_encryption_key(key_id)

    def set_active_encryption_key(self, key_id: str) -> None:
        """Rotate active encryption key identifier."""
        self.get_encryption_key(key_id)
        self._active_enc_key_id = key_id

    def get_permit_signing_secret(self, key_id: str) -> bytes:
        """Retrieve a specific permit signing secret by key_id for verification."""
        return self._get_key_with_cache("permits", key_id)

    def get_active_permit_signing_secret(self) -> tuple[str, bytes]:
        """Return the active (key_id, secret_bytes) for HMAC review permit signing."""
        if not self.kms_endpoint and self.allow_fallback:
            return self._fallback.get_active_permit_signing_secret()
        key_id = self._active_permit_key_id
        return key_id, self.get_permit_signing_secret(key_id)

    def set_active_permit_key(self, key_id: str) -> None:
        """Rotate active permit signing key identifier."""
        self.get_permit_signing_secret(key_id)
        self._active_permit_key_id = key_id

    def clear_cache(self) -> None:
        """Clear all in-memory cached keys."""
        with self._lock:
            self._cache.clear()

    def invalidate_key(self, namespace: str, key_id: str) -> None:
        """Evict a specific key from the in-memory cache."""
        cache_key = f"{namespace}:{key_id}"
        with self._lock:
            self._cache.pop(cache_key, None)


# Global singleton instance
_default_kms_client: BaseKMSClient | None = None


def get_kms_client() -> BaseKMSClient:
    """Return the configured global KMS client singleton."""
    global _default_kms_client
    if _default_kms_client is None:
        provider = getattr(settings, "KMS_PROVIDER", "local").lower()
        if provider in ("vault", "aws", "gcp"):
            _default_kms_client = EnterpriseKMSAdapter(
                provider=provider,
                kms_endpoint=getattr(settings, "KMS_ENDPOINT", ""),
                auth_token=getattr(settings, "KMS_AUTH_TOKEN", ""),
                active_encryption_key_id=getattr(settings, "ACTIVE_ENCRYPTION_KEY_ID", "enc-key-v1"),
                active_permit_key_id=getattr(settings, "ACTIVE_PERMIT_KEY_ID", "permit-key-v1"),
                cache_ttl_seconds=getattr(settings, "KMS_CACHE_TTL_SECONDS", 300),
                timeout_seconds=getattr(settings, "KMS_TIMEOUT_SECONDS", 5.0),
                vault_mount=getattr(settings, "KMS_VAULT_MOUNT", "secret"),
                key_path_prefix=getattr(settings, "KMS_KEY_PATH_PREFIX", "privai"),
                allow_fallback=getattr(settings, "KMS_ALLOW_LOCAL_FALLBACK", False),
            )
        else:
            _default_kms_client = LocalKMSClient(
                active_encryption_key_id=getattr(settings, "ACTIVE_ENCRYPTION_KEY_ID", "enc-key-v1"),
                active_permit_key_id=getattr(settings, "ACTIVE_PERMIT_KEY_ID", "permit-key-v1"),
            )
    return _default_kms_client


def set_kms_client(client: BaseKMSClient | None) -> None:
    """Override KMS client (useful for isolated automated tests)."""
    global _default_kms_client
    _default_kms_client = client

