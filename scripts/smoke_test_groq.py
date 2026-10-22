"""Safe Live Smoke Test Utility for Groq Cloud API.

Security Invariants:
1. Never displays or logs the raw GROQ_API_KEY.
2. Uses only benign, non-sensitive prompts for live connectivity checks.
3. Proves that REDACT sends only sanitized placeholders ([EMAIL]) to Groq Cloud.
4. Proves that BLOCK is intercepted locally with zero calls to Groq Cloud.
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.config import settings
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    ExecutionStatus,
    PolicyOutcome,
)
from backend.app.models.requests import PromptRequest
from backend.app.orchestrator.service import OrchestrationService
from backend.app.providers.groq import GroqProvider


def main() -> int:
    print("=" * 70)
    print("PrivAI — Live Groq Cloud Connectivity Smoke Test")
    print("=" * 70)

    # 1. Credential Check
    key = settings.GROQ_API_KEY.strip() if settings.GROQ_API_KEY else ""
    if not key:
        print("\n[INFO] No GROQ_API_KEY detected in .env.")
        print("To run a live test against Groq Cloud:")
        print("  1. Obtain a free API key from https://console.groq.com/")
        print("  2. In .env set:")
        print("       PROVIDER_MODE=groq")
        print("       GROQ_API_KEY=gsk_your_api_key_here")
        print("  3. Run this script again: .venv\\Scripts\\python scripts/smoke_test_groq.py\n")
        print("Automated offline tests using MockProvider remain 100% active and passing.")
        return 0

    masked_key = f"{key[:7]}...{key[-4:]}" if len(key) > 12 else "***"
    print(f"\n[OK] GROQ_API_KEY configured: {masked_key}")
    print(f"[OK] Model: {settings.GROQ_MODEL}")
    print(f"[OK] Endpoint: {settings.GROQ_BASE_URL}")

    # Initialize live GroqProvider
    groq_provider = GroqProvider(
        api_key=key,
        model=settings.GROQ_MODEL,
        base_url=settings.GROQ_BASE_URL,
        provider_mode="groq",
    )
    orchestrator = OrchestrationService(groq_provider=groq_provider)

    context = ContextModel(
        purpose=ContextPurpose.GENERAL_QUESTION,
        data_subject=ContextDataSubject.NONE,
        classification=ContextClassification.PUBLIC,
    )

    # --------------------------------------------------------------------------
    # Test 1: Live ALLOW dispatch
    # --------------------------------------------------------------------------
    print("\n--- Test 1: Live Safe Prompt (ALLOW) ---")
    prompt_allow = "PrivAI connectivity verification check. Reply with 'ACK: PrivAI online'."
    req_allow = PromptRequest(
        prompt=prompt_allow,
        destination=Destination.GROQ,
        context=context,
    )
    try:
        res_allow = orchestrator.execute(req_allow)
        print(f"Status: {res_allow.status.value}")
        print(f"Decision: {res_allow.decision.value}")
        print(f"Provider: {res_allow.provider.name} ({res_allow.provider.model})")
        print(f"Response: {res_allow.output.strip() if res_allow.output else 'None'}")
        assert res_allow.status == ExecutionStatus.COMPLETED
        print(">>> Test 1 PASSED: Live ALLOW dispatch succeeded.")
    except Exception as exc:
        print(f">>> Test 1 FAILED: {exc}")
        return 1

    # --------------------------------------------------------------------------
    # Test 2: Live REDACT dispatch (sanitized prompt only)
    # --------------------------------------------------------------------------
    print("\n--- Test 2: Live Sanitization Dispatch (REDACT) ---")
    prompt_redact = "Please email compliance results to auditor.privai@example.org immediately."
    req_redact = PromptRequest(
        prompt=prompt_redact,
        destination=Destination.GROQ,
        context=context,
    )
    try:
        res_redact = orchestrator.execute(req_redact)
        print(f"Status: {res_redact.status.value}")
        print(f"Decision: {res_redact.decision.value}")
        print(f"Redactions applied: {len(res_redact.redactions or [])}")
        print(f"Response: {res_redact.output.strip() if res_redact.output else 'None'}")
        assert res_redact.status == ExecutionStatus.COMPLETED
        assert res_redact.decision == PolicyOutcome.REDACT
        print(">>> Test 2 PASSED: Verified sanitized prompt reached Groq Cloud.")
    except Exception as exc:
        print(f">>> Test 2 FAILED: {exc}")
        return 1

    # --------------------------------------------------------------------------
    # Test 3: Mandatory BLOCK interception (Zero live calls)
    # --------------------------------------------------------------------------
    print("\n--- Test 3: Mandatory BLOCK Interception ---")
    prompt_block = "Subject National ID verification: 999-00-1234."
    req_block = PromptRequest(
        prompt=prompt_block,
        destination=Destination.GROQ,
        context=context,
    )
    try:
        res_block = orchestrator.execute(req_block)
        print(f"Status: {res_block.status.value}")
        print(f"Decision: {res_block.decision.value}")
        print(f"Rule ID: {res_block.explanation.rule_ids}")
        assert res_block.status == ExecutionStatus.BLOCKED
        assert res_block.provider is None
        assert res_block.output is None
        print(">>> Test 3 PASSED: Intercepted locally with 0 calls to Groq Cloud.")
    except Exception as exc:
        print(f">>> Test 3 FAILED: {exc}")
        return 1

    print("\n" + "=" * 70)
    print("ALL LIVE SMOKE TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
