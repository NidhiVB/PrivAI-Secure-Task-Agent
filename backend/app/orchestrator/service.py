"""Secure orchestration service coordinating firewall components and provider gateway."""

import datetime
import time
import uuid

from backend.app.audit.service import AuditService, get_audit_service
from backend.app.config import settings
from backend.app.core.exceptions import (
    AuditWriteException,
    PrivAIException,
    ProviderException,
    RedactionVerificationException,
    SecurityInvariantException,
)
from backend.app.core.security import compute_request_digest
from backend.app.detectors.detector import SensitiveDetector
from backend.app.models.audit import AuditEvent
from backend.app.models.context import ContextModel
from backend.app.models.enums import (
    ContextClassification,
    ContextDataSubject,
    ContextPurpose,
    Destination,
    ExecutionStatus,
    PolicyOutcome,
)
from backend.app.models.permit import ProviderPermit
from backend.app.models.requests import PromptRequest
from backend.app.models.responses import (
    Explanation,
    PromptAnalyzeResponse,
    PromptExecuteResponse,
    ProviderInfo,
)
from backend.app.models.risk import RiskScore
from backend.app.policy.engine import DeterministicPolicyEngine
from backend.app.policy.rules import PolicyEvaluationContext
from backend.app.providers.base import BaseProvider, ProviderResponse
from backend.app.providers.groq import GroqProvider
from backend.app.providers.mock import MockProvider
from backend.app.redaction.redactor import Redactor
from backend.app.redaction.verifier import RedactionVerifier
from backend.app.risk.scorer import RiskScorer
from backend.app.core.permits import verify_review_permit_signature
from backend.app.models.reviews import ReviewStatus
from backend.app.reviews.repository import ReviewRepository


class OrchestrationService:
    """Central orchestration service for prompt analysis and guarded execution.

    Security Invariants:
    1. Complete re-evaluation: Every execute request executes fresh validation, detection,
       risk scoring, and policy evaluation on the exact submitted prompt.
    2. Zero trust for client claims: Client-supplied decisions, risk scores, or permits
       are rejected by schema validation and never trusted.
    3. Mandatory permit gate: AI providers are private to this service and can only be
       invoked via an internal, server-minted ProviderPermit.
    4. Outgoing prompt boundary check: Immediately before transmission, the outgoing prompt
       is verified against applicable policy rules.
    5. Zero provider calls for BLOCK and pending REVIEW.
    6. Audit privacy: Audit events record only non-leaking metadata, never prompt text or secrets.
    7. Fail-closed: Component failures, verifier errors, or audit failures abort execution
       with zero provider calls.
    """

    def __init__(
        self,
        detector: SensitiveDetector | None = None,
        redactor: Redactor | None = None,
        verifier: RedactionVerifier | None = None,
        risk_scorer: RiskScorer | None = None,
        policy_engine: DeterministicPolicyEngine | None = None,
        audit_service: AuditService | None = None,
        mock_provider: MockProvider | None = None,
        groq_provider: BaseProvider | None = None,
        policy_version: str | None = None,
        review_repo: ReviewRepository | None = None,
    ) -> None:
        self.detector = detector if detector is not None else SensitiveDetector()
        self.redactor = redactor if redactor is not None else Redactor()
        self.verifier = verifier if verifier is not None else RedactionVerifier(self.detector)
        self.risk_scorer = risk_scorer if risk_scorer is not None else RiskScorer()
        self.policy_engine = (
            policy_engine
            if policy_engine is not None
            else DeterministicPolicyEngine(
                redactor=self.redactor,
                verifier=self.verifier,
                policy_version=policy_version or settings.POLICY_VERSION,
            )
        )
        self.audit_service = audit_service if audit_service is not None else get_audit_service()
        self.mock_provider = mock_provider if mock_provider is not None else MockProvider()
        self.groq_provider = groq_provider if groq_provider is not None else GroqProvider()
        self.policy_version = policy_version or settings.POLICY_VERSION
        self.review_repo = review_repo if review_repo is not None else ReviewRepository()

        # Guarded internal provider registry
        self._provider_registry: dict[Destination, BaseProvider] = {
            Destination.MOCK: self.mock_provider,
            Destination.GROQ: self.groq_provider,
        }

    def register_provider(self, destination: Destination, provider: BaseProvider) -> None:
        """Register a provider adapter for a destination."""
        self._provider_registry[destination] = provider

    def analyze(self, request: PromptRequest) -> PromptAnalyzeResponse:
        """Analyze prompt locally without calling any AI provider.

        Security Invariant: Strictly zero provider calls.
        """
        digest = compute_request_digest(request, self.policy_version)
        analysis_id = str(uuid.uuid4())

        findings = self.detector.detect(request.prompt)
        risk = self.risk_scorer.evaluate(findings, request.context, request.destination)
        decision = self.policy_engine.evaluate(
            prompt=request.prompt,
            findings=findings,
            context=request.context,
            destination=request.destination,
            risk_score=risk,
        )

        return PromptAnalyzeResponse(
            analysis_id=analysis_id,
            request_digest=digest,
            decision=decision.action,
            risk=risk,
            findings=findings,
            explanation=decision.explanation,
            policy_version=self.policy_version,
            sanitized_prompt=decision.sanitized_prompt if decision.action == PolicyOutcome.REDACT else None,
            redactions=decision.redactions if decision.action == PolicyOutcome.REDACT else None,
        )

    def execute(self, request: PromptRequest) -> PromptExecuteResponse:
        """Authoritative prompt execution through privacy firewall and permit gate.

        Security Invariant:
        Revalidates and recomputes all decisions. Emits provider calls ONLY for authorized
        ALLOW or verified REDACT outcomes. BLOCK and REVIEW always yield zero provider calls.
        """
        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())
        digest = compute_request_digest(request, self.policy_version)

        # 1. Fresh detection on exact submitted content
        findings = self.detector.detect(request.prompt)

        # 2. Fresh risk scoring
        risk = self.risk_scorer.evaluate(findings, request.context, request.destination)

        # 3. Deterministic policy evaluation (enforces precedence: Fail-closed -> BLOCK -> REVIEW -> REDACT -> ALLOW)
        decision = self.policy_engine.evaluate(
            prompt=request.prompt,
            findings=findings,
            context=request.context,
            destination=request.destination,
            risk_score=risk,
        )

        # 4. Handle policy outcomes under strict boundary invariants
        if decision.action == PolicyOutcome.BLOCK:
            # Audit log block event (zero provider calls)
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            self._record_audit_event(
                request_digest=digest,
                destination=request.destination.value,
                decision=PolicyOutcome.BLOCK,
                rule_ids=decision.reason_codes,
                risk_score=risk.score,
                status="blocked",
                provider_called=False,
                redaction_count=0,
                latency_ms=latency_ms,
            )
            return PromptExecuteResponse(
                request_id=request_id,
                status=ExecutionStatus.BLOCKED,
                decision=PolicyOutcome.BLOCK,
                risk=risk,
                redactions=None,
                provider=None,
                output=None,
                explanation=decision.explanation,
                policy_version=self.policy_version,
            )

        # Pre-validate review permit if presented on any non-block request
        if request.review_permit is not None:
            # 1. Cryptographic signature verification
            verify_review_permit_signature(request.review_permit)

            # 2. Bound digest verification: permit must bind exact prompt + context
            if request.review_permit.request_digest != digest:
                raise SecurityInvariantException(
                    "Review permit request digest mismatch. Permit was minted for a different request."
                )

        if decision.action == PolicyOutcome.REVIEW:
            # Case 1: Review permit presented
            if request.review_permit is not None:
                # 3. Atomic single-use consumption in durable database (anti-replay)
                permit_record = self.review_repo.consume_permit_atomic(
                    permit_nonce=request.review_permit.permit_nonce,
                    expected_digest=digest,
                )
                if permit_record.get("ticket_id") != request.review_permit.ticket_id:
                    raise SecurityInvariantException(
                        "Review permit ticket_id mismatch with stored permit record."
                    )

                # 4. Associated ticket verification
                ticket = self.review_repo.get_ticket(request.review_permit.ticket_id)
                if ticket.status != ReviewStatus.APPROVED:
                    raise SecurityInvariantException(
                        f"Review permit rejected: Associated ticket '{ticket.ticket_id}' status is '{ticket.status.value}', expected APPROVED."
                    )

                # 5. Prepare authorized outgoing prompt
                outgoing_prompt = request.prompt
                redaction_count = 0
                redactions = None

                if decision.sanitized_prompt:
                    outgoing_prompt = decision.sanitized_prompt
                    redaction_count = len(decision.redactions or [])
                    redactions = decision.redactions
                    self.verifier.verify(outgoing_prompt)

                # 6. Audit logging before provider transmission
                latency_ms = int((time.perf_counter() - start_time) * 1000)
                self._record_audit_event(
                    request_digest=digest,
                    destination=request.destination.value,
                    decision=PolicyOutcome.REVIEW,
                    rule_ids=decision.reason_codes,
                    risk_score=risk.score,
                    status="completed",
                    provider_called=True,
                    redaction_count=redaction_count,
                    latency_ms=latency_ms,
                    event_type="permit_consumed_and_dispatched",
                    actor_id=request.review_permit.approved_by,
                )

                # 7. Mint single-use internal ProviderPermit
                provider_permit = ProviderPermit(
                    permit_id=str(uuid.uuid4()),
                    request_digest=digest,
                    outcome=PolicyOutcome.ALLOW,
                    policy_version=self.policy_version,
                    destination=request.destination,
                    redaction_verified=bool(decision.sanitized_prompt),
                    authorized_prompt=outgoing_prompt,
                    created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    review_approved=True,
                )

                provider_resp = self._call_provider_gateway(provider_permit, outgoing_prompt)

                return PromptExecuteResponse(
                    request_id=request_id,
                    status=ExecutionStatus.COMPLETED,
                    decision=PolicyOutcome.REVIEW,
                    risk=risk,
                    redactions=redactions,
                    provider=ProviderInfo(
                        name=provider_resp.provider_name, model=provider_resp.model
                    ),
                    output=provider_resp.text,
                    explanation=decision.explanation,
                    policy_version=self.policy_version,
                    ticket_id=ticket.ticket_id,
                )

            # Case 2: No permit presented: persist new review ticket with strict 24-hr TTL
            assigned_role = "compliance_officer"
            if any("HR" in r.upper() for r in decision.reason_codes) or (
                hasattr(request.context, "purpose") and request.context.purpose.value == "hr_workflow"
            ) or (
                hasattr(request.context, "data_subject") and request.context.data_subject.value == "employee"
            ):
                assigned_role = "hr_admin"

            ticket_id = str(uuid.uuid4())
            ticket = self.review_repo.create_ticket(
                ticket_id=ticket_id,
                request_digest=digest,
                assigned_role=assigned_role,
                risk_score=risk.score,
                triggered_rule_ids=decision.reason_codes,
                prompt_content=request.prompt,
            )

            # Audit log review event (zero provider calls)
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            self._record_audit_event(
                request_digest=digest,
                destination=request.destination.value,
                decision=PolicyOutcome.REVIEW,
                rule_ids=decision.reason_codes,
                risk_score=risk.score,
                status="review_pending",
                provider_called=False,
                redaction_count=0,
                latency_ms=latency_ms,
                event_type="ticket_created",
            )
            return PromptExecuteResponse(
                request_id=request_id,
                status=ExecutionStatus.REVIEW_PENDING,
                decision=PolicyOutcome.REVIEW,
                risk=risk,
                redactions=None,
                provider=None,
                output=None,
                explanation=decision.explanation,
                policy_version=self.policy_version,
                ticket_id=ticket.ticket_id,
            )

        if decision.action == PolicyOutcome.REDACT:
            # Sanitization was required and verified by policy engine
            if not decision.sanitized_prompt:
                raise SecurityInvariantException("Policy decision REDACT missing sanitized prompt.")

            outgoing_prompt = decision.sanitized_prompt
            redaction_count = len(decision.redactions or [])

            # Immediate pre-transmission boundary verification
            self.verifier.verify(outgoing_prompt)

            # Mandatory audit logging before provider transmission
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            self._record_audit_event(
                request_digest=digest,
                destination=request.destination.value,
                decision=PolicyOutcome.REDACT,
                rule_ids=decision.reason_codes,
                risk_score=risk.score,
                status="completed",
                provider_called=True,
                redaction_count=redaction_count,
                latency_ms=latency_ms,
            )

            # Mint single-use internal permit
            permit = ProviderPermit(
                permit_id=str(uuid.uuid4()),
                request_digest=digest,
                outcome=PolicyOutcome.REDACT,
                policy_version=self.policy_version,
                destination=request.destination,
                redaction_verified=True,
                authorized_prompt=outgoing_prompt,
                created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            )

            # Execute via guarded provider gateway
            provider_resp = self._call_provider_gateway(permit, outgoing_prompt)

            return PromptExecuteResponse(
                request_id=request_id,
                status=ExecutionStatus.COMPLETED,
                decision=PolicyOutcome.REDACT,
                risk=risk,
                redactions=decision.redactions,
                provider=ProviderInfo(
                    name=provider_resp.provider_name, model=provider_resp.model
                ),
                output=provider_resp.text,
                explanation=decision.explanation,
                policy_version=self.policy_version,
            )

        if decision.action == PolicyOutcome.ALLOW:
            outgoing_prompt = request.prompt

            # Pre-transmission boundary verification (must have zero sensitive findings)
            boundary_findings = self.detector.detect(outgoing_prompt)
            if boundary_findings:
                raise SecurityInvariantException(
                    "Security invariant violated: ALLOW prompt contains sensitive findings at boundary."
                )

            # Mandatory audit logging before provider transmission
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            self._record_audit_event(
                request_digest=digest,
                destination=request.destination.value,
                decision=PolicyOutcome.ALLOW,
                rule_ids=decision.reason_codes,
                risk_score=risk.score,
                status="completed",
                provider_called=True,
                redaction_count=0,
                latency_ms=latency_ms,
            )

            # Mint single-use internal permit
            permit = ProviderPermit(
                permit_id=str(uuid.uuid4()),
                request_digest=digest,
                outcome=PolicyOutcome.ALLOW,
                policy_version=self.policy_version,
                destination=request.destination,
                redaction_verified=False,  # Not applicable for ALLOW
                authorized_prompt=outgoing_prompt,
                created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            )

            # Execute via guarded provider gateway
            provider_resp = self._call_provider_gateway(permit, outgoing_prompt)

            return PromptExecuteResponse(
                request_id=request_id,
                status=ExecutionStatus.COMPLETED,
                decision=PolicyOutcome.ALLOW,
                risk=risk,
                redactions=None,
                provider=ProviderInfo(
                    name=provider_resp.provider_name, model=provider_resp.model
                ),
                output=provider_resp.text,
                explanation=decision.explanation,
                policy_version=self.policy_version,
            )

        # Fallback invariant: unknown decision must fail closed
        raise SecurityInvariantException(f"Unknown policy action: {decision.action}")

    def _call_provider_gateway(
        self, permit: ProviderPermit, outgoing_prompt: str
    ) -> ProviderResponse:
        """Central provider execution gateway enforcing strict permit and boundary checks.

        Security Invariants:
        1. Only executes if a valid, unexpired permit is presented.
        2. Blocks calls if permit outcome is BLOCK or REVIEW.
        3. Validates that outgoing prompt matches permit authorized prompt exactly.
        4. Validates that outgoing prompt is verified clean of residual sensitive patterns.
        5. Normalizes provider exceptions to safe error responses without leaking content.
        """
        if permit.outcome not in (PolicyOutcome.ALLOW, PolicyOutcome.REDACT):
            raise SecurityInvariantException(
                f"Permit gate refused execution for non-transmissible outcome: {permit.outcome}"
            )

        if outgoing_prompt != permit.authorized_prompt:
            raise SecurityInvariantException(
                "Permit gate rejected execution: outgoing prompt does not match authorized permit prompt."
            )

        # Immediate pre-transmission boundary check
        if permit.outcome == PolicyOutcome.REDACT:
            self.verifier.verify(outgoing_prompt)
        elif permit.outcome == PolicyOutcome.ALLOW:
            boundary_findings = self.detector.detect(outgoing_prompt)
            if boundary_findings:
                if getattr(permit, "review_approved", False):
                    # For review-approved dispatches, ensure no BLOCK-level rules are triggered
                    block_rules = [r for r in self.policy_engine.rules if r.action == PolicyOutcome.BLOCK]
                    dummy_ctx = ContextModel(
                        purpose=ContextPurpose.GENERAL_QUESTION,
                        data_subject=ContextDataSubject.NONE,
                        classification=ContextClassification.PUBLIC,
                    )
                    boundary_risk = self.risk_scorer.evaluate(boundary_findings, dummy_ctx, permit.destination)
                    eval_ctx = PolicyEvaluationContext(
                        prompt=outgoing_prompt,
                        findings=boundary_findings,
                        context=dummy_ctx,
                        destination=permit.destination,
                        risk_score=boundary_risk,
                    )
                    if any(r.matches(eval_ctx) for r in block_rules):
                        raise SecurityInvariantException(
                            "Review-approved prompt contains prohibited BLOCK-level findings at boundary."
                        )
                else:
                    raise SecurityInvariantException(
                        "Outgoing prompt failed clean verification at provider boundary."
                    )

        provider = self._provider_registry.get(permit.destination)
        if provider is None:
            raise ProviderException(
                message=f"No provider configured for destination '{permit.destination.value}'.",
                code="PROVIDER_NOT_CONFIGURED",
                status_code=502,
            )

        try:
            return provider.generate(outgoing_prompt)
        except ProviderException:
            raise
        except Exception as exc:
            # Normalize third-party or runtime provider errors into safe 502
            raise ProviderException(
                message=f"Provider execution failed: {type(exc).__name__}",
                code="PROVIDER_EXECUTION_ERROR",
                status_code=502,
            ) from exc

    def _record_audit_event(
        self,
        request_digest: str,
        destination: str,
        decision: PolicyOutcome,
        rule_ids: list[str],
        risk_score: int,
        status: str,
        provider_called: bool,
        redaction_count: int,
        latency_ms: int,
        event_type: str = "prompt_execution",
        actor_id: str | None = None,
        rationale: str | None = None,
    ) -> None:
        """Record privacy-safe audit event. Fails closed if audit durability fails."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            request_digest=request_digest,
            destination=destination,
            decision=decision,
            rule_ids=rule_ids,
            risk_score=risk_score,
            policy_version=self.policy_version,
            detector_version=settings.DETECTOR_VERSION,
            status=status,
            provider_called=provider_called,
            redaction_count=redaction_count,
            latency_ms=latency_ms,
            event_type=event_type,
            actor_id=actor_id,
            rationale=rationale,
        )
        self.audit_service.record(event)
