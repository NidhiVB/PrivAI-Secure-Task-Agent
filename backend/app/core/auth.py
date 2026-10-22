"""JWT Bearer authentication and Role-Based Access Control (RBAC)."""

import datetime
from typing import Any
import jwt
from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from backend.app.config import settings
from backend.app.core.exceptions import PrivAIException


class AuthException(PrivAIException):
    """Base authentication or authorization exception."""

    def __init__(self, message: str, code: str = "AUTH_FAILED", status_code: int = 401) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class ReviewerUser(BaseModel):
    """Authenticated reviewer identity and claims."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: str = Field(..., description="Subject identifier (sub)")
    roles: list[str] = Field(default_factory=list, description="Assigned roles, e.g. ['compliance_officer']")
    permissions: list[str] = Field(
        default_factory=list, description="Granted permissions, must include 'PrivAI:Reviewer'"
    )


def create_reviewer_token(
    user_id: str,
    roles: list[str],
    permissions: list[str] | None = None,
    expires_delta: datetime.timedelta = datetime.timedelta(hours=1),
    secret_key: str | None = None,
    algorithm: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
) -> str:
    """Create a signed JWT token for a reviewer (for auth & tests)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now + expires_delta

    payload: dict[str, Any] = {
        "sub": user_id,
        "roles": roles,
        "permissions": permissions if permissions is not None else ["PrivAI:Reviewer"],
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": issuer or settings.JWT_ISSUER,
        "aud": audience or settings.JWT_AUDIENCE,
    }

    key = secret_key or settings.JWT_SECRET_KEY
    alg = algorithm or settings.JWT_ALGORITHM
    return jwt.encode(payload, key, algorithm=alg)


def decode_reviewer_token(
    token: str,
    secret_key: str | None = None,
    algorithm: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
) -> ReviewerUser:
    """Verify signature, issuer, audience, expiration, and extract reviewer claims.

    Security Invariant:
    1. Rejects invalid signatures, expired tokens, or issuer/audience mismatches.
    2. Validates that permissions contain 'PrivAI:Reviewer'.
    3. Rejects any attempt to spoof roles without token claim backing.
    """
    key = secret_key or settings.JWT_SECRET_KEY
    alg = algorithm or settings.JWT_ALGORITHM
    iss = issuer or settings.JWT_ISSUER
    aud = audience or settings.JWT_AUDIENCE

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=[alg],
            issuer=iss,
            audience=aud,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthException("Token has expired.", code="TOKEN_EXPIRED", status_code=401) from exc
    except jwt.InvalidIssuerError as exc:
        raise AuthException("Invalid token issuer.", code="INVALID_ISSUER", status_code=401) from exc
    except jwt.InvalidAudienceError as exc:
        raise AuthException("Invalid token audience.", code="INVALID_AUDIENCE", status_code=401) from exc
    except jwt.PyJWTError as exc:
        raise AuthException(f"Token validation failed: {str(exc)}", code="TOKEN_INVALID", status_code=401) from exc

    user_id = str(payload.get("sub", ""))
    if not user_id:
        raise AuthException("Token missing subject identifier.", code="TOKEN_MISSING_SUB", status_code=401)

    roles = payload.get("roles", [])
    if not isinstance(roles, list):
        roles = [str(roles)]

    permissions = payload.get("permissions", [])
    if not isinstance(permissions, list):
        permissions = [str(permissions)]

    # Invariant: Must possess authorized PrivAI permission
    valid_perms = {"PrivAI:Reviewer", "PrivAI:Auditor", "PrivAI:SecurityAdmin"}
    if not any(p in valid_perms for p in permissions):
        raise AuthException(
            "User lacks required 'PrivAI:Reviewer' or 'PrivAI:Auditor' permission.",
            code="FORBIDDEN_INSUFFICIENT_PERMISSIONS",
            status_code=403,
        )

    return ReviewerUser(user_id=user_id, roles=roles, permissions=permissions)


def get_current_reviewer(
    authorization: str | None = Header(None, description="Bearer token"),
) -> ReviewerUser:
    """FastAPI dependency for authenticating reviewers via Bearer JWT."""
    if not authorization:
        raise AuthException(
            "Missing Authorization header.", code="MISSING_AUTH_HEADER", status_code=401
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthException(
            "Invalid Authorization format. Expected 'Bearer <token>'.",
            code="INVALID_AUTH_FORMAT",
            status_code=401,
        )

    token = parts[1]
    return decode_reviewer_token(token)


def get_current_auditor(
    current_user: ReviewerUser = Depends(get_current_reviewer),
) -> ReviewerUser:
    """FastAPI dependency verifying caller possesses auditor or security admin role."""
    authorized_roles = {"auditor", "security_admin", "compliance_officer"}
    if not any(role in authorized_roles for role in current_user.roles):
        raise AuthException(
            message=f"Forbidden: Role '{current_user.roles}' is not authorized to inspect audit checkpoints.",
            code="ROLE_NOT_AUTHORIZED_FOR_AUDIT",
            status_code=403,
        )
    return current_user

