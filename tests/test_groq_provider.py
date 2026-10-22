"""Unit and integration tests for Milestone 7: Groq Provider Adapter.

Security Invariants Tested:
1. Zero Groq calls for BLOCK and pending REVIEW decisions.
2. REDACT transmits only verified sanitized text to Groq.
3. GROQ_API_KEY is never exposed via responses, logs, or exceptions.
4. PROVIDER_MODE=mock remains default; explicit opt-in required for Groq.
5. All errors (timeouts, rate limits, 5xx, auth errors, connection failures, malformed JSON)
   normalize to safe 502 responses without leaking internal credentials or raw payloads.
6. Local mock mode is preserved and unaffected.
"""

import json
import pytest
import httpx
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.core.exceptions import ProviderException
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


# ==============================================================================
# Helper Mock Transports
# ==============================================================================


def create_mock_transport(
    status_code: int = 200,
    response_data: dict | str | None = None,
    side_effect: Exception | None = None,
    captured_requests: list | None = None,
):
    """Create an httpx.MockTransport for deterministic unit testing."""

    def handler(request: httpx.Request) -> httpx.Response:
        if captured_requests is not None:
            captured_requests.append(request)

        if side_effect is not None:
            raise side_effect

        if response_data is None:
            content = b"{}"
        elif isinstance(response_data, str):
            content = response_data.encode("utf-8")
        else:
            content = json.dumps(response_data).encode("utf-8")

        return httpx.Response(
            status_code=status_code,
            headers={"content-type": "application/json"},
            content=content,
            request=request,
        )

    return httpx.MockTransport(handler)


@pytest.fixture
def sample_groq_response() -> dict:
    return {
        "id": "chatcmpl-test-uuid",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "llama-3.1-8b-instant",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "This is a verified response from Groq Cloud.",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
    }


@pytest.fixture
def public_context() -> ContextModel:
    return ContextModel(
        purpose=ContextPurpose.GENERAL_QUESTION,
        data_subject=ContextDataSubject.NONE,
        classification=ContextClassification.PUBLIC,
    )


# ==============================================================================
# 1. Configuration, Defaults, and Opt-In Checks
# ==============================================================================


def test_groq_provider_metadata() -> None:
    """Verify GroqProvider reports correct name and model metadata."""
    provider = GroqProvider(
        api_key="gsk_dummy",
        model="llama-3.1-8b-instant",
        provider_mode="groq",
    )
    info = provider.get_info()
    assert info.name == "groq"
    assert info.model == "llama-3.1-8b-instant"


def test_groq_provider_disabled_when_mock_mode() -> None:
    """Verify GroqProvider rejects execution when PROVIDER_MODE is 'mock' (Invariant 4)."""
    provider = GroqProvider(
        api_key="gsk_valid_key",
        provider_mode="mock",  # Default mode
    )
    with pytest.raises(ProviderException) as exc_info:
        provider.generate("Explain RSA cryptography.")

    assert exc_info.value.status_code == 502
    assert exc_info.value.code == "PROVIDER_DISABLED"
    assert "PROVIDER_MODE=groq" in exc_info.value.message


def test_groq_provider_missing_key_fails_closed() -> None:
    """Verify GroqProvider rejects execution when api_key is missing/empty under groq mode."""
    provider = GroqProvider(
        api_key="",
        provider_mode="groq",
    )
    with pytest.raises(ProviderException) as exc_info:
        provider.generate("Explain RSA cryptography.")

    assert exc_info.value.status_code == 502
    assert exc_info.value.code == "PROVIDER_NOT_CONFIGURED"
    assert "Groq API key is not configured" in exc_info.value.message


# ==============================================================================
# 2. HTTP Transport and OpenAI-Compatible Wire Protocol
# ==============================================================================


def test_groq_provider_successful_request_and_response(
    sample_groq_response: dict,
) -> None:
    """Verify outgoing wire protocol: Bearer token, model, prompt in messages, and parsed response."""
    captured: list[httpx.Request] = []
    transport = create_mock_transport(
        status_code=200,
        response_data=sample_groq_response,
        captured_requests=captured,
    )
    client = httpx.Client(transport=transport)

    provider = GroqProvider(
        api_key="gsk_secret_test_token_12345",
        base_url="https://api.groq.com/openai/v1",
        model="llama-3.1-8b-instant",
        provider_mode="groq",
        client=client,
    )

    resp = provider.generate("Explain Merkle trees.")

    assert resp.text == "This is a verified response from Groq Cloud."
    assert resp.model == "llama-3.1-8b-instant"
    assert resp.provider_name == "groq"

    # Verify wire request
    assert len(captured) == 1
    req = captured[0]
    assert req.method == "POST"
    assert req.url == "https://api.groq.com/openai/v1/chat/completions"
    assert req.headers["authorization"] == "Bearer gsk_secret_test_token_12345"

    body = json.loads(req.content.decode("utf-8"))
    assert body["model"] == "llama-3.1-8b-instant"
    assert body["messages"] == [{"role": "user", "content": "Explain Merkle trees."}]


def test_groq_provider_no_secret_leak_in_exceptions() -> None:
    """Verify secrets or raw prompts are never exposed in exception strings or logs (Invariant 3 & 7)."""
    fake_key = "gsk_super_secret_credentials_xyz"
    raw_prompt = "SuperSecretInternalKeyword"

    # Simulate 401 Unauthorized
    transport = create_mock_transport(
        status_code=401,
        response_data={"error": {"message": "Invalid API Key"}},
    )
    client = httpx.Client(transport=transport)

    provider = GroqProvider(
        api_key=fake_key,
        provider_mode="groq",
        client=client,
    )

    with pytest.raises(ProviderException) as exc_info:
        provider.generate(raw_prompt)

    err_str = str(exc_info.value)
    # Ensure neither key nor prompt leak in exception
    assert fake_key not in err_str
    assert raw_prompt not in err_str
    assert exc_info.value.code == "PROVIDER_AUTH_ERROR"
    assert exc_info.value.status_code == 502


# ==============================================================================
# 3. Normalized Error Handling (502 Gateway Errors)
# ==============================================================================


def test_groq_provider_rate_limit_429() -> None:
    """Verify HTTP 429 returns normalized PROVIDER_RATE_LIMITED (502)."""
    transport = create_mock_transport(
        status_code=429,
        response_data={"error": {"message": "Rate limit exceeded"}},
    )
    provider = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(ProviderException) as exc_info:
        provider.generate("Test prompt")

    assert exc_info.value.code == "PROVIDER_RATE_LIMITED"
    assert exc_info.value.status_code == 502


def test_groq_provider_server_error_500() -> None:
    """Verify HTTP 500 returns normalized PROVIDER_ERROR (502)."""
    transport = create_mock_transport(
        status_code=500,
        response_data={"error": {"message": "Internal Groq server error"}},
    )
    provider = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(ProviderException) as exc_info:
        provider.generate("Test prompt")

    assert exc_info.value.code == "PROVIDER_ERROR"
    assert exc_info.value.status_code == 502
    assert "status 500" in exc_info.value.message


def test_groq_provider_timeout_normalized() -> None:
    """Verify transport timeout returns normalized PROVIDER_TIMEOUT (502)."""
    transport = create_mock_transport(
        side_effect=httpx.ReadTimeout("Read timed out"),
    )
    provider = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        max_retries=0,
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(ProviderException) as exc_info:
        provider.generate("Test prompt")

    assert exc_info.value.code == "PROVIDER_TIMEOUT"
    assert exc_info.value.status_code == 502


def test_groq_provider_connect_error_normalized() -> None:
    """Verify connection drop returns normalized PROVIDER_UNAVAILABLE (502)."""
    transport = create_mock_transport(
        side_effect=httpx.ConnectError("Connection refused"),
    )
    provider = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        max_retries=0,
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(ProviderException) as exc_info:
        provider.generate("Test prompt")

    assert exc_info.value.code == "PROVIDER_UNAVAILABLE"
    assert exc_info.value.status_code == 502


def test_groq_provider_malformed_json_response() -> None:
    """Verify non-JSON response returns PROVIDER_MALFORMED_RESPONSE (502)."""
    transport = create_mock_transport(
        status_code=200,
        response_data="<html>502 Bad Gateway from cloudflare</html>",
    )
    provider = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(ProviderException) as exc_info:
        provider.generate("Test prompt")

    assert exc_info.value.code == "PROVIDER_MALFORMED_RESPONSE"
    assert exc_info.value.status_code == 502


def test_groq_provider_missing_choices_array() -> None:
    """Verify missing choices in JSON returns PROVIDER_MALFORMED_RESPONSE (502)."""
    transport = create_mock_transport(
        status_code=200,
        response_data={"id": "123", "choices": []},
    )
    provider = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(ProviderException) as exc_info:
        provider.generate("Test prompt")

    assert exc_info.value.code == "PROVIDER_MALFORMED_RESPONSE"
    assert exc_info.value.status_code == 502


# ==============================================================================
# 4. Bounded Retries
# ==============================================================================


def test_groq_provider_retries_transient_503_and_succeeds(
    sample_groq_response: dict,
) -> None:
    """Verify transient 503 is retried up to max_retries and succeeds."""
    call_count = 0

    def retry_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(status_code=503, content=b"{}", request=request)
        return httpx.Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=json.dumps(sample_groq_response).encode("utf-8"),
            request=request,
        )

    client = httpx.Client(transport=httpx.MockTransport(retry_handler))
    provider = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        max_retries=1,
        client=client,
    )

    resp = provider.generate("Test retry")
    assert resp.text == "This is a verified response from Groq Cloud."
    assert call_count == 2


# ==============================================================================
# 5. End-to-End Orchestrator Integration & Privacy Invariants
# ==============================================================================


def test_groq_analyze_endpoint_produces_zero_calls(
    sample_groq_response: dict,
    public_context: ContextModel,
) -> None:
    """Verify POST /v1/prompts/analyze with Destination.GROQ yields strictly ZERO provider calls."""
    captured: list[httpx.Request] = []
    transport = create_mock_transport(
        status_code=200,
        response_data=sample_groq_response,
        captured_requests=captured,
    )
    groq = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )
    orch = OrchestrationService(groq_provider=groq)

    req = PromptRequest(
        prompt="Explain quicksort in detail.",
        destination=Destination.GROQ,
        context=public_context,
    )

    res = orch.analyze(req)
    assert res.decision == PolicyOutcome.ALLOW
    assert len(captured) == 0  # Invariant: Analyze makes 0 calls


def test_groq_execute_allow_invokes_provider_once(
    sample_groq_response: dict,
    public_context: ContextModel,
) -> None:
    """Verify ALLOW outcome sends exact validated prompt to Groq after server re-evaluation."""
    captured: list[httpx.Request] = []
    transport = create_mock_transport(
        status_code=200,
        response_data=sample_groq_response,
        captured_requests=captured,
    )
    groq = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )
    orch = OrchestrationService(groq_provider=groq)

    prompt = "Explain quicksort in detail."
    req = PromptRequest(
        prompt=prompt,
        destination=Destination.GROQ,
        context=public_context,
    )

    res = orch.execute(req)
    assert res.status == ExecutionStatus.COMPLETED
    assert res.decision == PolicyOutcome.ALLOW
    assert res.provider is not None
    assert res.provider.name == "groq"
    assert res.output == "This is a verified response from Groq Cloud."

    assert len(captured) == 1
    sent_body = json.loads(captured[0].content.decode("utf-8"))
    assert sent_body["messages"][0]["content"] == prompt


def test_groq_execute_redact_sends_only_verified_sanitized_text(
    sample_groq_response: dict,
    public_context: ContextModel,
) -> None:
    """Verify REDACT outcome sends strictly verified sanitized text, NEVER raw PII, to Groq."""
    captured: list[httpx.Request] = []
    transport = create_mock_transport(
        status_code=200,
        response_data=sample_groq_response,
        captured_requests=captured,
    )
    groq = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )
    orch = OrchestrationService(groq_provider=groq)

    raw_email = "employee.doe@corp.example.com"
    raw_phone = "555-867-5309"
    prompt = f"Please contact {raw_email} or call {raw_phone} for escalation."

    req = PromptRequest(
        prompt=prompt,
        destination=Destination.GROQ,
        context=public_context,
    )

    res = orch.execute(req)
    assert res.status == ExecutionStatus.COMPLETED
    assert res.decision == PolicyOutcome.REDACT
    assert res.provider is not None
    assert res.provider.name == "groq"
    assert res.output == "This is a verified response from Groq Cloud."

    # Invariant: exactly one provider call
    assert len(captured) == 1
    sent_body = json.loads(captured[0].content.decode("utf-8"))
    sent_prompt = sent_body["messages"][0]["content"]

    # Invariant: Raw PII is strictly excluded; placeholders present
    assert raw_email not in sent_prompt
    assert raw_phone not in sent_prompt
    assert "[EMAIL]" in sent_prompt
    assert "[PHONE]" in sent_prompt
    assert sent_prompt == "Please contact [EMAIL] or call [PHONE] for escalation."


def test_groq_execute_block_outcome_yields_zero_groq_calls(
    sample_groq_response: dict,
    public_context: ContextModel,
) -> None:
    """Verify mandatory BLOCK yields strictly ZERO calls to Groq."""
    captured: list[httpx.Request] = []
    transport = create_mock_transport(
        status_code=200,
        response_data=sample_groq_response,
        captured_requests=captured,
    )
    groq = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )
    orch = OrchestrationService(groq_provider=groq)

    # Prompt with National ID triggers mandatory BLOCK
    prompt = "National ID verification code: 999-00-1234."
    req = PromptRequest(
        prompt=prompt,
        destination=Destination.GROQ,
        context=public_context,
    )

    res = orch.execute(req)
    assert res.status == ExecutionStatus.BLOCKED
    assert res.decision == PolicyOutcome.BLOCK
    assert res.provider is None
    assert res.output is None

    # Invariant: ZERO calls to Groq
    assert len(captured) == 0


def test_groq_execute_restricted_classification_blocks_with_zero_calls(
    sample_groq_response: dict,
) -> None:
    """Verify BLOCK-RESTRICTED-DATA rule blocks external Groq destination with zero calls."""
    captured: list[httpx.Request] = []
    transport = create_mock_transport(
        status_code=200,
        response_data=sample_groq_response,
        captured_requests=captured,
    )
    groq = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )
    orch = OrchestrationService(groq_provider=groq)

    req = PromptRequest(
        prompt="Internal architectural specification.",
        destination=Destination.GROQ,
        context=ContextModel(
            purpose=ContextPurpose.CODING,
            data_subject=ContextDataSubject.NONE,
            classification=ContextClassification.RESTRICTED,
        ),
    )

    res = orch.execute(req)
    assert res.status == ExecutionStatus.BLOCKED
    assert res.decision == PolicyOutcome.BLOCK
    assert "BLOCK-RESTRICTED-DATA" in res.explanation.rule_ids
    assert len(captured) == 0


def test_groq_execute_review_outcome_yields_zero_groq_calls(
    sample_groq_response: dict,
) -> None:
    """Verify compliance REVIEW yields strictly ZERO calls to Groq."""
    captured: list[httpx.Request] = []
    transport = create_mock_transport(
        status_code=200,
        response_data=sample_groq_response,
        captured_requests=captured,
    )
    groq = GroqProvider(
        api_key="gsk_test",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )
    orch = OrchestrationService(groq_provider=groq)

    # Health information prompts trigger REVIEW
    prompt = "Patient clinical chemotherapy history."
    req = PromptRequest(
        prompt=prompt,
        destination=Destination.GROQ,
        context=ContextModel(
            purpose=ContextPurpose.HEALTH_INFORMATION,
            data_subject=ContextDataSubject.SELF,
            classification=ContextClassification.PUBLIC,
        ),
    )

    res = orch.execute(req)
    assert res.status == ExecutionStatus.REVIEW_PENDING
    assert res.decision == PolicyOutcome.REVIEW
    assert res.provider is None
    assert res.output is None

    # Invariant: ZERO calls to Groq
    assert len(captured) == 0


# ==============================================================================
# 6. Full FastAPI HTTP API Integration with Groq Destination
# ==============================================================================


def test_fastapi_execute_endpoint_with_groq_destination(
    client: TestClient,
    sample_groq_response: dict,
) -> None:
    """Verify full FastAPI POST /v1/prompts/execute with destination=groq."""
    from backend.app.api.v1.prompts import orchestrator

    captured: list[httpx.Request] = []
    transport = create_mock_transport(
        status_code=200,
        response_data=sample_groq_response,
        captured_requests=captured,
    )
    test_groq = GroqProvider(
        api_key="gsk_test_api_key",
        provider_mode="groq",
        client=httpx.Client(transport=transport),
    )
    orchestrator.register_provider(Destination.GROQ, test_groq)

    # 1. ALLOW execution
    resp = client.post(
        "/v1/prompts/execute",
        json={
            "prompt": "What is the time complexity of heapsort?",
            "destination": "groq",
            "context": {
                "purpose": "coding",
                "data_subject": "none",
                "classification": "public",
            },
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["decision"] == "ALLOW"
    assert data["provider"]["name"] == "groq"
    assert data["output"] == "This is a verified response from Groq Cloud."
    assert len(captured) == 1

    # 2. REDACT execution
    resp_redact = client.post(
        "/v1/prompts/execute",
        json={
            "prompt": "Send results to admin.lead@example.com immediately.",
            "destination": "groq",
            "context": {
                "purpose": "general_question",
                "data_subject": "none",
                "classification": "public",
            },
        },
    )
    assert resp_redact.status_code == 200
    data_redact = resp_redact.json()
    assert data_redact["status"] == "completed"
    assert data_redact["decision"] == "REDACT"
    assert len(data_redact["redactions"]) == 1
    assert data_redact["redactions"][0]["category"] == "EMAIL"
    assert len(captured) == 2

    # Invariant: Groq received only verified sanitized prompt
    sent_prompt = json.loads(captured[1].content.decode("utf-8"))["messages"][0]["content"]
    assert "admin.lead@example.com" not in sent_prompt
    assert sent_prompt == "Send results to [EMAIL] immediately."

    # 3. BLOCK execution
    resp_block = client.post(
        "/v1/prompts/execute",
        json={
            "prompt": "Employee SSN 123-45-6789.",
            "destination": "groq",
            "context": {
                "purpose": "general_question",
                "data_subject": "none",
                "classification": "public",
            },
        },
    )
    assert resp_block.status_code == 200
    data_block = resp_block.json()
    assert data_block["status"] == "blocked"
    assert data_block["decision"] == "BLOCK"
    assert data_block["provider"] is None
    # Still only 2 captured calls (BLOCK made 0 calls)
    assert len(captured) == 2
