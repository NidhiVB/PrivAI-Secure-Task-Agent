"""Comprehensive tests for Enterprise KMS & Key Management (Milestone 8 Extension).

Test Invariants:
1. Strict separation between payload encryption keys and HMAC permit signing secrets.
2. Key lookup failures fail closed with sanitized error envelopes.
3. Invalid key lengths / formats rejected immediately.
4. Key rotation for payload encryption: multiple key IDs supported seamlessly.
5. Backward decryption compatibility: legacy unversioned payloads decrypt without data loss.
6. Key rotation for review permit signing: permits carry key IDs; verify cleanly across rotated keys.
7. Zero secret material exposed in exceptions, logs, or audit records.
8. End-to-end orchestration execution with KMS-backed review permits.
"""

import base64
import os
import uuid
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.audit.service import AuditService
from backend.app.core.encryption import EncryptionException, PayloadEncryptor
from backend.app.core.kms import (
    BaseKMSClient,
    EnterpriseKMSAdapter,
    KMSAuthenticationException,
    KMSInvalidKeyException,
    KMSKeyNotFoundException,
    KMSRemoteServiceException,
    LocalKMSClient,
    get_kms_client,
    set_kms_client,
)
from backend.app.core.permits import (
    PermitSignatureException,
    generate_review_permit,
    verify_review_permit_signature,
)
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
from backend.app.models.reviews import ReviewStatus
from backend.app.orchestrator.service import OrchestrationService
from backend.app.providers.mock import MockProvider
from backend.app.reviews.repository import ReviewRepository


@pytest.fixture
def kms_client() -> LocalKMSClient:
    """Fixture providing an isolated LocalKMSClient with known test keys."""
    key_v1 = b"Key_Version_1_Must_Be_32_Bytes!!"
    key_v2 = b"Key_Version_2_Must_Be_32_Bytes!!"
    permit_secret_v1 = b"permit-signing-secret-version-1!"
    permit_secret_v2 = b"permit-signing-secret-version-2!"

    client = LocalKMSClient(
        encryption_keys={"enc-2026-v1": key_v1, "enc-2026-v2": key_v2},
        active_encryption_key_id="enc-2026-v1",
        permit_secrets={"permit-2026-v1": permit_secret_v1, "permit-2026-v2": permit_secret_v2},
        active_permit_key_id="permit-2026-v1",
    )
    set_kms_client(client)
    yield client
    set_kms_client(None)


@pytest.fixture
def test_db_path(tmp_path) -> str:
    return str(tmp_path / "test_kms_privai.db")


# ==============================================================================
# 1. KMS Core: Key Separation, Lookup, and Validation
# ==============================================================================


def test_kms_namespace_separation_and_registration(kms_client: LocalKMSClient) -> None:
    """Verify that encryption keys and permit secrets remain strictly separated."""
    enc_kid, enc_key = kms_client.get_active_encryption_key()
    permit_kid, permit_secret = kms_client.get_active_permit_signing_secret()

    assert enc_kid == "enc-2026-v1"
    assert permit_kid == "permit-2026-v1"
    assert enc_key != permit_secret

    # Attempting to fetch permit secret with encryption key ID fails
    with pytest.raises(KMSKeyNotFoundException):
        kms_client.get_permit_signing_secret("enc-2026-v1")

    # Attempting to fetch encryption key with permit secret ID fails
    with pytest.raises(KMSKeyNotFoundException):
        kms_client.get_encryption_key("permit-2026-v1")


def test_kms_key_lookup_failures_fail_closed(kms_client: LocalKMSClient) -> None:
    """Verify that unknown key IDs raise specific KMS exceptions without leaking info."""
    with pytest.raises(KMSKeyNotFoundException) as exc:
        kms_client.get_encryption_key("non-existent-key-id")
    assert "non-existent-key-id" in str(exc.value)

    with pytest.raises(KMSKeyNotFoundException):
        kms_client.get_permit_signing_secret("non-existent-permit-id")


def test_kms_invalid_key_length_rejected(kms_client: LocalKMSClient) -> None:
    """Verify that keys failing length constraints are immediately rejected."""
    # AES-256 requires exactly 32 bytes
    with pytest.raises(KMSInvalidKeyException):
        kms_client.register_encryption_key("short-key", b"only_16_bytes!!")

    with pytest.raises(KMSInvalidKeyException):
        kms_client.register_encryption_key("long-key", b"a" * 64)

    # Permit secrets require at least 16 bytes
    with pytest.raises(KMSInvalidKeyException):
        kms_client.register_permit_secret("short-secret", b"tiny")


# ==============================================================================
# 2. Payload Envelope Encryption & Key Rotation
# ==============================================================================


def test_payload_encryption_key_rotation(kms_client: LocalKMSClient) -> None:
    """Verify that payloads encrypted under different rotated keys all decrypt cleanly."""
    encryptor = PayloadEncryptor(kms_client=kms_client)
    plaintext_1 = "Sensitive prompt 1: Medical diagnosis record"
    digest_1 = "sha256:digest111"

    # 1. Encrypt under active key (enc-2026-v1)
    ciphertext_1 = encryptor.encrypt(plaintext_1, associated_data=digest_1)
    assert ciphertext_1.startswith("v2:enc-2026-v1:")

    # 2. Rotate active encryption key to enc-2026-v2
    kms_client.set_active_encryption_key("enc-2026-v2")

    plaintext_2 = "Sensitive prompt 2: Salary and compensation data"
    digest_2 = "sha256:digest222"
    ciphertext_2 = encryptor.encrypt(plaintext_2, associated_data=digest_2)
    assert ciphertext_2.startswith("v2:enc-2026-v2:")

    # 3. Decrypt both payloads: each resolves its respective key via key identifier
    decrypted_1 = encryptor.decrypt(ciphertext_1, associated_data=digest_1)
    decrypted_2 = encryptor.decrypt(ciphertext_2, associated_data=digest_2)

    assert decrypted_1 == plaintext_1
    assert decrypted_2 == plaintext_2


def test_backward_compatibility_with_legacy_unversioned_records(kms_client: LocalKMSClient) -> None:
    """Verify that legacy unversioned payloads (from Milestone 8 Phase A) decrypt without error."""
    encryptor = PayloadEncryptor(kms_client=kms_client)
    plaintext = "Legacy stored prompt without version prefix"
    digest = "sha256:legacydigest"

    # Manually create legacy unversioned ciphertext: base64(nonce_12bytes + ciphertext_and_tag)
    _, active_key = kms_client.get_active_encryption_key()
    aesgcm = AESGCM(active_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), digest.encode("utf-8"))
    legacy_payload = base64.b64encode(nonce + ct).decode("utf-8")

    # Ensure this legacy string has NO 'v2:' prefix
    assert not legacy_payload.startswith("v2:")

    # Decrypt via new PayloadEncryptor
    decrypted = encryptor.decrypt(legacy_payload, associated_data=digest)
    assert decrypted == plaintext


def test_decryption_with_revoked_or_missing_key_fails_closed(kms_client: LocalKMSClient) -> None:
    """Verify that attempting to decrypt a payload with an unknown key fails closed."""
    encryptor = PayloadEncryptor(kms_client=kms_client)
    fake_versioned_payload = "v2:revoked-key-id:" + base64.b64encode(os.urandom(32)).decode("utf-8")

    with pytest.raises(EncryptionException) as exc:
        encryptor.decrypt(fake_versioned_payload, associated_data="sha256:dummy")
    assert "KMS_KEY_NOT_FOUND" in exc.value.code


def test_aad_mismatch_fails_closed(kms_client: LocalKMSClient) -> None:
    """Verify that tampering with associated data (request digest) aborts decryption."""
    encryptor = PayloadEncryptor(kms_client=kms_client)
    ct = encryptor.encrypt("Secret data", associated_data="sha256:original")

    with pytest.raises(EncryptionException) as exc:
        encryptor.decrypt(ct, associated_data="sha256:tampered_digest")
    assert exc.value.code == "DECRYPTION_FAILED"


# ==============================================================================
# 3. Review Permit Signing & Key Rotation
# ==============================================================================


def test_permit_signing_key_rotation(kms_client: LocalKMSClient) -> None:
    """Verify that permits minted under different rotated keys verify successfully."""
    # 1. Mint permit under active key (permit-2026-v1)
    permit_1 = generate_review_permit(
        ticket_id="ticket-001",
        request_digest="sha256:digest001",
        approved_by="dr_alice",
        assigned_role="compliance_officer",
        kms_client=kms_client,
    )
    assert permit_1.key_id == "permit-2026-v1"
    assert verify_review_permit_signature(permit_1, kms_client=kms_client) is True

    # 2. Rotate active permit key to permit-2026-v2
    kms_client.set_active_permit_key("permit-2026-v2")

    permit_2 = generate_review_permit(
        ticket_id="ticket-002",
        request_digest="sha256:digest002",
        approved_by="hr_bob",
        assigned_role="hr_admin",
        kms_client=kms_client,
    )
    assert permit_2.key_id == "permit-2026-v2"
    assert verify_review_permit_signature(permit_2, kms_client=kms_client) is True

    # 3. Older permit_1 still verifies cleanly using its own bound key ID
    assert verify_review_permit_signature(permit_1, kms_client=kms_client) is True


def test_permit_with_revoked_key_id_fails_verification(kms_client: LocalKMSClient) -> None:
    """Verify that a permit signed with an unknown or revoked key ID is rejected."""
    permit = generate_review_permit(
        ticket_id="ticket-001",
        request_digest="sha256:digest",
        approved_by="officer",
        assigned_role="compliance_officer",
        kms_client=kms_client,
    )
    tampered_permit = permit.model_copy(update={"key_id": "revoked-or-deleted-key"})

    with pytest.raises(PermitSignatureException):
        verify_review_permit_signature(tampered_permit, kms_client=kms_client)


# ==============================================================================
# 4. Review Repository Integration with KMS Lifecycle
# ==============================================================================


def test_review_repository_encrypted_prompt_lifecycle_and_rotation(
    test_db_path: str,
    kms_client: LocalKMSClient,
) -> None:
    """Verify end-to-end prompt encryption, storage, retrieval, and key rotation."""
    encryptor = PayloadEncryptor(kms_client=kms_client)
    repo = ReviewRepository(db_path=test_db_path, encryptor=encryptor)
    repo.clear()

    # 1. Ticket created under v1 key
    ticket_id_1 = str(uuid.uuid4())
    prompt_1 = "Patient diagnosed with hypertension and prescribed medication."
    digest_1 = "sha256:ticket1digest"

    repo.create_ticket(
        ticket_id=ticket_id_1,
        request_digest=digest_1,
        assigned_role="compliance_officer",
        risk_score=65,
        triggered_rule_ids=["REVIEW-HEALTH"],
        prompt_content=prompt_1,
    )

    # Decrypt prompt
    decrypted_1 = repo.get_decrypted_prompt(ticket_id_1)
    assert decrypted_1 == prompt_1

    # 2. Key rotation in KMS
    kms_client.set_active_encryption_key("enc-2026-v2")

    # 3. Ticket created under v2 key
    ticket_id_2 = str(uuid.uuid4())
    prompt_2 = "Annual compensation review: base salary $145,000."
    digest_2 = "sha256:ticket2digest"

    repo.create_ticket(
        ticket_id=ticket_id_2,
        request_digest=digest_2,
        assigned_role="hr_admin",
        risk_score=70,
        triggered_rule_ids=["REVIEW-HR"],
        prompt_content=prompt_2,
    )

    # 4. Both tickets decrypt accurately across key rotation
    assert repo.get_decrypted_prompt(ticket_id_1) == prompt_1
    assert repo.get_decrypted_prompt(ticket_id_2) == prompt_2


# ==============================================================================
# 5. End-to-End Orchestration with Rotated KMS Permits
# ==============================================================================


def test_orchestration_execute_with_kms_rotated_permit(
    test_db_path: str,
    kms_client: LocalKMSClient,
) -> None:
    """Verify that the orchestration engine executes a prompt approved with a rotated KMS permit."""
    encryptor = PayloadEncryptor(kms_client=kms_client)
    repo = ReviewRepository(db_path=test_db_path, encryptor=encryptor)
    audit = AuditService(db_path=test_db_path)
    repo.clear()
    audit.clear()

    mock_provider = MockProvider()
    orchestrator = OrchestrationService(
        audit_service=audit,
        mock_provider=mock_provider,
        review_repo=repo,
    )

    req = PromptRequest(
        prompt="Patient blood test results enclosed.",
        destination=Destination.MOCK,
        context=ContextModel(
            purpose=ContextPurpose.HEALTH_INFORMATION,
            data_subject=ContextDataSubject.SELF,
            classification=ContextClassification.PUBLIC,
        ),
    )

    # 1. Initial execution yields REVIEW_PENDING
    resp = orchestrator.execute(req)
    assert resp.status == ExecutionStatus.REVIEW_PENDING
    ticket_id = resp.ticket_id

    # 2. Rotate permit key in KMS
    kms_client.set_active_permit_key("permit-2026-v2")

    # 3. Compliance officer approves ticket
    repo.approve_ticket(ticket_id, "Approved under rotated key", "dr_officer")
    ticket = repo.get_ticket(ticket_id)

    # 4. Mint permit with rotated active key
    permit = generate_review_permit(
        ticket_id=ticket_id,
        request_digest=ticket.request_digest,
        approved_by="dr_officer",
        assigned_role=ticket.assigned_role,
        kms_client=kms_client,
    )
    assert permit.key_id == "permit-2026-v2"

    repo.record_permit(
        permit_nonce=permit.permit_nonce,
        ticket_id=permit.ticket_id,
        request_digest=permit.request_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
    )

    # 5. Submit with rotated permit
    approved_req = req.model_copy(update={"review_permit": permit})
    exec_resp = orchestrator.execute(approved_req)

    assert exec_resp.status == ExecutionStatus.COMPLETED
    assert exec_resp.output is not None
    assert mock_provider.call_count == 1


# ==============================================================================
# 6. Enterprise KMS Adapter (Vault REST Protocol, Caching, & Fail-Closed)
# ==============================================================================

import httpx


@pytest.fixture
def mock_vault_server():
    """Mock HashiCorp Vault HTTP handler simulating KV v2 secrets engine."""
    vault_store: dict[str, dict] = {
        "/v1/secret/data/privai/encryption/vault-enc-v1": {
            "data": {"data": {"key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}  # 32 bytes hex
        },
        "/v1/secret/data/privai/encryption/vault-enc-v2": {
            "data": {"data": {"key": base64.b64encode(b"Vault_AES_Key_Version_2_32_Byte!").decode("utf-8")}}
        },
        "/v1/secret/data/privai/permits/vault-permit-v1": {
            "data": {"data": {"secret": "vault-hmac-permit-signing-secret-v1"}}
        },
        "/v1/secret/data/privai/permits/vault-permit-v2": {
            "data": {"data": {"secret": "vault-hmac-permit-signing-secret-v2"}}
        },
        # Same key name across different namespaces
        "/v1/secret/data/privai/encryption/shared-key-id": {
            "data": {"data": {"key": base64.b64encode(b"Shared_Encryption_Key_32_Bytes!!").decode("utf-8")}}
        },
        "/v1/secret/data/privai/permits/shared-key-id": {
            "data": {"data": {"secret": "Shared_Permit_Secret_Signing_Bytes"}}
        },
    }

    call_counts: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        call_counts[path] = call_counts.get(path, 0) + 1

        # Check authentication token
        token = request.headers.get("X-Vault-Token")
        if token == "invalid-token":
            return httpx.Response(403, json={"errors": ["permission denied"]})

        if path in vault_store:
            return httpx.Response(200, json=vault_store[path])
        return httpx.Response(404, json={"errors": ["secret not found"]})

    return handler, call_counts, vault_store


def test_enterprise_kms_vault_success_and_ttl_caching(mock_vault_server) -> None:
    """Verify Vault KV v2 key retrieval, decoding (hex/base64), and in-memory TTL caching."""
    handler, call_counts, _ = mock_vault_server
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="https://vault.privai.internal:8200",
        auth_token="s.privai-root-token-2026",
        active_encryption_key_id="vault-enc-v1",
        active_permit_key_id="vault-permit-v1",
        cache_ttl_seconds=300,
        client=client,
    )

    # 1. First fetch retrieves from remote Vault and caches
    key_id, enc_key_1 = adapter.get_active_encryption_key()
    assert key_id == "vault-enc-v1"
    assert len(enc_key_1) == 32
    assert enc_key_1 == bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    assert call_counts["/v1/secret/data/privai/encryption/vault-enc-v1"] == 1

    # 2. Second fetch hits cache (zero remote network calls)
    enc_key_cached = adapter.get_encryption_key("vault-enc-v1")
    assert enc_key_cached == enc_key_1
    assert call_counts["/v1/secret/data/privai/encryption/vault-enc-v1"] == 1

    # 3. Invalidate key and fetch again -> triggers remote lookup
    adapter.invalidate_key("encryption", "vault-enc-v1")
    enc_key_refreshed = adapter.get_encryption_key("vault-enc-v1")
    assert enc_key_refreshed == enc_key_1
    assert call_counts["/v1/secret/data/privai/encryption/vault-enc-v1"] == 2


def test_enterprise_kms_namespace_separation_enforced(mock_vault_server) -> None:
    """Verify that identical key IDs in encryption and permit namespaces never collide."""
    handler, _, _ = mock_vault_server
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="https://vault.privai.internal:8200",
        auth_token="s.privai-token",
        client=client,
    )

    # Both use "shared-key-id", but routes and returned bytes differ completely
    enc_bytes = adapter.get_encryption_key("shared-key-id")
    permit_bytes = adapter.get_permit_signing_secret("shared-key-id")

    assert enc_bytes == b"Shared_Encryption_Key_32_Bytes!!"
    assert permit_bytes == b"Shared_Permit_Secret_Signing_Bytes"
    assert enc_bytes != permit_bytes


def test_enterprise_kms_lookup_failure_404_fails_closed(mock_vault_server) -> None:
    """Verify that non-existent key in Vault raises KMSKeyNotFoundException."""
    handler, _, _ = mock_vault_server
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="https://vault.privai.internal:8200",
        auth_token="s.privai-token",
        client=client,
    )

    with pytest.raises(KMSKeyNotFoundException) as exc:
        adapter.get_encryption_key("non-existent-vault-key")
    assert "non-existent-vault-key" in exc.value.message
    assert exc.value.code == "KMS_KEY_NOT_FOUND"


def test_enterprise_kms_auth_failure_401_403_fails_closed_without_leaking_token(mock_vault_server) -> None:
    """Verify that invalid Vault token raises KMSAuthenticationException without leaking token."""
    handler, _, _ = mock_vault_server
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    token_secret = "invalid-token-should-never-leak"
    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="https://vault.privai.internal:8200",
        auth_token="invalid-token",
        client=client,
    )

    with pytest.raises(KMSAuthenticationException) as exc:
        adapter.get_encryption_key("vault-enc-v1")
    assert "invalid-token" not in str(exc.value)
    assert exc.value.code == "KMS_AUTH_FAILED"


def test_enterprise_kms_network_timeout_and_errors_fail_closed() -> None:
    """Verify that network timeout and connection drops raise KMSRemoteServiceException."""
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("Connection timed out after 5000ms")

    client = httpx.Client(transport=httpx.MockTransport(timeout_handler))
    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="https://vault.down.internal:8200",
        auth_token="token",
        allow_fallback=False,
        client=client,
    )

    with pytest.raises(KMSRemoteServiceException) as exc:
        adapter.get_encryption_key("vault-enc-v1")
    assert "timed out" in exc.value.message.lower()
    assert exc.value.code == "KMS_REMOTE_SERVICE_ERROR"


def test_enterprise_kms_invalid_key_length_rejected() -> None:
    """Verify that malformed or invalid-length keys returned by remote KMS are rejected."""
    def malformed_handler(request: httpx.Request) -> httpx.Response:
        # Returns only 16 bytes for AES key
        return httpx.Response(200, json={"data": {"data": {"key": "short_16_bytes!"}}})

    client = httpx.Client(transport=httpx.MockTransport(malformed_handler))
    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="https://vault.privai.internal:8200",
        auth_token="token",
        client=client,
    )

    with pytest.raises(KMSInvalidKeyException) as exc:
        adapter.get_encryption_key("short-key")
    assert "must be exactly 32 bytes" in exc.value.message


def test_enterprise_kms_envelope_encryption_rotation_lifecycle(mock_vault_server) -> None:
    """Verify end-to-end payload envelope encryption and rotation through EnterpriseKMSAdapter."""
    handler, _, _ = mock_vault_server
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="https://vault.privai.internal:8200",
        auth_token="token",
        active_encryption_key_id="vault-enc-v1",
        active_permit_key_id="vault-permit-v1",
        client=client,
    )

    encryptor = PayloadEncryptor(kms_client=adapter)

    # 1. Encrypt under vault-enc-v1
    payload_1 = "Patient record under Vault key v1"
    digest_1 = "sha256:d1"
    ct_1 = encryptor.encrypt(payload_1, associated_data=digest_1)
    assert ct_1.startswith("v2:vault-enc-v1:")

    # 2. Rotate active encryption key to vault-enc-v2
    adapter.set_active_encryption_key("vault-enc-v2")
    payload_2 = "Financial report under Vault key v2"
    digest_2 = "sha256:d2"
    ct_2 = encryptor.encrypt(payload_2, associated_data=digest_2)
    assert ct_2.startswith("v2:vault-enc-v2:")

    # 3. Decrypt both payloads cleanly
    assert encryptor.decrypt(ct_1, associated_data=digest_1) == payload_1
    assert encryptor.decrypt(ct_2, associated_data=digest_2) == payload_2


def test_enterprise_kms_permit_rotation_lifecycle(mock_vault_server) -> None:
    """Verify review permits minted and verified across rotated Vault permit signing secrets."""
    handler, _, _ = mock_vault_server
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="https://vault.privai.internal:8200",
        auth_token="token",
        active_permit_key_id="vault-permit-v1",
        client=client,
    )

    # 1. Mint permit under vault-permit-v1
    permit_1 = generate_review_permit(
        ticket_id="ticket-vault-1",
        request_digest="sha256:v1digest",
        approved_by="dr_vault",
        assigned_role="compliance_officer",
        kms_client=adapter,
    )
    assert permit_1.key_id == "vault-permit-v1"
    assert verify_review_permit_signature(permit_1, kms_client=adapter) is True

    # 2. Rotate active permit key to vault-permit-v2
    adapter.set_active_permit_key("vault-permit-v2")
    permit_2 = generate_review_permit(
        ticket_id="ticket-vault-2",
        request_digest="sha256:v2digest",
        approved_by="hr_vault",
        assigned_role="hr_admin",
        kms_client=adapter,
    )
    assert permit_2.key_id == "vault-permit-v2"
    assert verify_review_permit_signature(permit_2, kms_client=adapter) is True

    # 3. Older permit verifies cleanly using its own bound key ID
    assert verify_review_permit_signature(permit_1, kms_client=adapter) is True


def test_enterprise_kms_fail_closed_without_fallback() -> None:
    """Verify that when allow_fallback=False, missing endpoint fails closed with KMSRemoteServiceException."""
    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="",
        auth_token="",
        allow_fallback=False,
    )
    with pytest.raises(KMSRemoteServiceException) as exc:
        adapter.get_encryption_key("any-key")
    assert "not configured" in exc.value.message.lower()


def test_enterprise_kms_graceful_dev_fallback_when_explicitly_configured() -> None:
    """Verify that when allow_fallback=True (dev only), local store safely serves keys."""
    fallback_client = LocalKMSClient(
        encryption_keys={"dev-enc-key": b"Dev_Fallback_Key_32_Bytes_Long!!"},
        active_encryption_key_id="dev-enc-key",
    )
    adapter = EnterpriseKMSAdapter(
        provider="vault",
        kms_endpoint="",
        auth_token="",
        allow_fallback=True,
        fallback_client=fallback_client,
    )

    key_id, enc_key = adapter.get_active_encryption_key()
    assert key_id == "dev-enc-key"
    assert enc_key == b"Dev_Fallback_Key_32_Bytes_Long!!"


# ==============================================================================
# 7. Backward Compatibility with Existing SQLite Database Records
# ==============================================================================


def test_backward_compatibility_with_real_sqlite_tickets() -> None:
    """Verify that all existing records in privai_data.db (both legacy and v2) decrypt without error."""
    import sqlite3
    db_file = "privai_data.db"
    if not os.path.exists(db_file):
        pytest.skip("privai_data.db not found in workspace")

    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT ticket_id, request_digest, encrypted_prompt FROM review_tickets WHERE encrypted_prompt IS NOT NULL"
    ).fetchall()
    conn.close()

    assert len(rows) > 0, "Expected review tickets in privai_data.db"

    repo = ReviewRepository(db_path=db_file)
    decrypted_count = 0

    for r in rows:
        ticket_id = r["ticket_id"]
        decrypted = repo.get_decrypted_prompt(ticket_id)
        assert decrypted is not None
        assert len(decrypted) > 0
        decrypted_count += 1

    assert decrypted_count == len(rows)


# ==============================================================================
# 8. Secret Material Hygiene & Zero-Leakage Checks
# ==============================================================================


def test_secret_hygiene_exceptions_and_models_never_expose_keys() -> None:
    """Verify that string representations of exceptions never leak secret material."""
    secret_bytes = b"SecretKeyNeverExposeInErrors32!!"
    key_id = "test-secret-key-id"

    # 1. KMSInvalidKeyException
    exc1 = KMSInvalidKeyException("Invalid key material format.")
    assert secret_bytes.decode("utf-8") not in str(exc1)

    # 2. KMSKeyNotFoundException
    exc2 = KMSKeyNotFoundException(key_id)
    assert secret_bytes.decode("utf-8") not in str(exc2)

    # 3. KMSRemoteServiceException
    exc3 = KMSRemoteServiceException("External KMS service request failed.")
    assert secret_bytes.decode("utf-8") not in str(exc3)

    # 4. KMSAuthenticationException
    exc4 = KMSAuthenticationException()
    assert "token" not in exc4.message.lower()

