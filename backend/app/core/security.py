"""Security utilities: canonicalization and request digest."""

import hashlib
import json
from typing import Any
from backend.app.models.requests import PromptRequest


def compute_request_digest(request: PromptRequest, policy_version: str) -> str:
    """Compute deterministic SHA-256 digest of canonical request and active policy version.

    Security Invariant: The digest binds exact prompt, destination, context,
    and policy version to prevent prompt-swap and TOCTOU attacks.
    """
    canonical_dict = {
        "prompt": request.prompt,
        "destination": request.destination.value,
        "context": {
            "purpose": request.context.purpose.value,
            "data_subject": request.context.data_subject.value,
            "classification": request.context.classification.value,
        },
        "policy_version": policy_version,
    }
    # Deterministic JSON encoding: sorted keys, no whitespace separators
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
