"""Cryptographic single-use review permit generation and verification with KMS key rotation."""

import datetime
import hashlib
import hmac
import secrets

from backend.app.config import settings
from backend.app.core.exceptions import PrivAIException
from backend.app.core.kms import BaseKMSClient, KMSException, get_kms_client
from backend.app.models.reviews import ReviewPermit


class PermitSignatureException(PrivAIException):
    """Raised when permit cryptographic signature verification fails."""

    def __init__(self, message: str = "Invalid review permit signature.") -> None:
        super().__init__(
            message=message,
            code="PERMIT_SIGNATURE_INVALID",
            status_code=403,
        )


def _canonical_permit_string(
    version: str,
    ticket_id: str,
    permit_nonce: str,
    request_digest: str,
    issued_at: str,
    expires_at: str,
    approved_by: str,
    assigned_role: str,
    key_id: str | None = None,
) -> str:
    """Deterministic string representation for HMAC calculation."""
    base = f"{version}|{ticket_id}|{permit_nonce}|{request_digest}|{issued_at}|{expires_at}|{approved_by}|{assigned_role}"
    if key_id:
        return f"{base}|{key_id}"
    return base


def generate_review_permit(
    ticket_id: str,
    request_digest: str,
    approved_by: str,
    assigned_role: str,
    now_utc: datetime.datetime | None = None,
    secret_key: str | None = None,
    key_id: str | None = None,
    kms_client: BaseKMSClient | None = None,
) -> ReviewPermit:
    """Generate and cryptographically sign a single-use review permit.

    Security Invariants:
    1. Cryptographically strong 32-byte URL-safe nonce.
    2. Strict 5-minute (300s) TTL.
    3. Bound to ticket ID, canonical request digest, reviewer identity, and KMS key ID.
    4. Signed using HMAC-SHA256 with backend-only secret key.
    """
    now = now_utc or datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(seconds=settings.REVIEW_PERMIT_TTL_SECONDS)

    issued_at_str = now.isoformat()
    expires_at_str = expires.isoformat()
    nonce = secrets.token_urlsafe(32)

    kms = kms_client or get_kms_client()
    kid = key_id

    if secret_key is not None:
        secret = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    elif key_id is not None:
        try:
            secret = kms.get_permit_signing_secret(key_id)
        except KMSException as exc:
            raise PermitSignatureException(f"Failed to retrieve permit key: {exc.message}") from exc
    else:
        try:
            kid, secret = kms.get_active_permit_signing_secret()
        except KMSException as exc:
            raise PermitSignatureException(f"Failed to retrieve active permit key: {exc.message}") from exc

    canonical_str = _canonical_permit_string(
        version="v1",
        ticket_id=ticket_id,
        permit_nonce=nonce,
        request_digest=request_digest,
        issued_at=issued_at_str,
        expires_at=expires_at_str,
        approved_by=approved_by,
        assigned_role=assigned_role,
        key_id=kid,
    )

    signature = hmac.new(
        secret, canonical_str.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    return ReviewPermit(
        version="v1",
        ticket_id=ticket_id,
        permit_nonce=nonce,
        request_digest=request_digest,
        issued_at=issued_at_str,
        expires_at=expires_at_str,
        approved_by=approved_by,
        assigned_role=assigned_role,
        signature=signature,
        key_id=kid,
    )


def verify_review_permit_signature(
    permit: ReviewPermit,
    secret_key: str | None = None,
    kms_client: BaseKMSClient | None = None,
) -> bool:
    """Verify cryptographic HMAC-SHA256 signature on review permit.

    Uses hmac.compare_digest to prevent timing attacks.
    Resolves signing key via KMS key identifier or legacy active secret.
    """
    kms = kms_client or get_kms_client()

    if secret_key is not None:
        secret = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    elif permit.key_id:
        try:
            secret = kms.get_permit_signing_secret(permit.key_id)
        except KMSException as exc:
            raise PermitSignatureException(f"Signing key '{permit.key_id}' unavailable or revoked.") from exc
    else:
        # Legacy permit without key_id
        try:
            _, secret = kms.get_active_permit_signing_secret()
        except KMSException as exc:
            raise PermitSignatureException("No active signing key configured.") from exc

    canonical_str = _canonical_permit_string(
        version=permit.version,
        ticket_id=permit.ticket_id,
        permit_nonce=permit.permit_nonce,
        request_digest=permit.request_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
        approved_by=permit.approved_by,
        assigned_role=permit.assigned_role,
        key_id=permit.key_id,
    )

    expected_signature = hmac.new(
        secret, canonical_str.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(permit.signature, expected_signature):
        raise PermitSignatureException()

    return True
