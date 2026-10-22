"""Privacy-safe operational metadata audit service with tamper-evident hash chaining and Merkle checkpoint anchoring."""

import datetime
import hashlib
import json
import sqlite3
import threading
from typing import Any

from backend.app.config import settings
from backend.app.core.exceptions import AuditWriteException, PrivAIException
from backend.app.audit.merkle import (
    compute_merkle_root,
    generate_inclusion_proof,
    verify_merkle_inclusion_proof,
)
from backend.app.audit.anchors import (
    AuditAnchorException,
    BaseAuditAnchorAdapter,
    get_audit_anchor_adapter,
)
from backend.app.models.audit import (
    AuditCheckpoint,
    AuditEvent,
    CheckpointAnchorStatus,
    MerkleInclusionProofResponse,
)
from backend.app.models.enums import PolicyOutcome

GENESIS_HASH = hashlib.sha256(b"PRIVAI_AUDIT_GENESIS_v1").hexdigest()
GENESIS_CHECKPOINT_HASH = hashlib.sha256(b"PRIVAI_CHECKPOINT_GENESIS_v1").hexdigest()


class CheckpointException(PrivAIException):
    """Base exception for audit checkpointing operations."""

    def __init__(
        self,
        message: str = "Audit checkpoint operation failed.",
        code: str = "CHECKPOINT_ERROR",
        status_code: int = 409,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class CheckpointNotFoundException(CheckpointException):
    """Raised when a requested checkpoint ID is not found."""

    def __init__(self, checkpoint_id: str) -> None:
        super().__init__(
            message=f"Audit checkpoint '{checkpoint_id}' not found.",
            code="CHECKPOINT_NOT_FOUND",
            status_code=404,
        )


class CheckpointSequenceException(CheckpointException):
    """Raised when sequence ranges are non-contiguous, overlapping, or out-of-order."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="CHECKPOINT_SEQUENCE_MISMATCH", status_code=409)


class CheckpointIntegrityException(CheckpointException):
    """Raised when an internal sequence gap or hash chain breakage is detected in a range."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="CHECKPOINT_INTEGRITY_VIOLATION", status_code=409)


class AuditService:
    """Privacy-safe operational metadata audit service.

    Security Invariants:
    1. Data minimization: Never stores raw prompts, sanitized prompts, or matched sensitive values.
    2. Audit write durability: If audit write fails when durability is required, raises
       AuditWriteException to ensure fail-closed abortion before provider transmission.
    3. Tamper-evident hash chaining: Every audit record includes sequence_number, prev_hash,
       and record_hash computed over canonicalized fields.
    4. Deterministic Merkle Checkpointing: Aggregates contiguous sequence ranges into Merkle trees
       and confirms immutable anchoring to external transparency ledgers before marking ANCHORED.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._events: list[AuditEvent] = []
        self._checkpoints: list[AuditCheckpoint] = []
        self._simulate_failure: bool = False
        self._db_path = db_path
        self._lock = threading.Lock()
        if self._db_path:
            self._init_db()

    def _init_db(self) -> None:
        """Initialize durable SQLite audit table if db_path is provided."""
        if not self._db_path:
            return
        with sqlite3.connect(self._db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    rule_ids TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    policy_version TEXT NOT NULL,
                    detector_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    provider_called INTEGER NOT NULL,
                    redaction_count INTEGER NOT NULL,
                    latency_ms INTEGER NOT NULL,
                    event_type TEXT NOT NULL DEFAULT 'prompt_execution',
                    actor_id TEXT,
                    rationale TEXT,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    epoch_index INTEGER UNIQUE NOT NULL,
                    start_sequence INTEGER NOT NULL,
                    end_sequence INTEGER NOT NULL,
                    event_count INTEGER NOT NULL,
                    merkle_root TEXT NOT NULL,
                    prev_checkpoint_hash TEXT NOT NULL,
                    checkpoint_hash TEXT NOT NULL,
                    anchor_status TEXT NOT NULL,
                    anchor_reference TEXT,
                    anchored_at TEXT,
                    created_at TEXT NOT NULL,
                    failure_reason TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_checkpoints_epochs
                    ON audit_checkpoints(epoch_index);
                CREATE INDEX IF NOT EXISTS idx_checkpoints_sequences
                    ON audit_checkpoints(start_sequence, end_sequence);
            """)
            conn.commit()

    @property
    def events(self) -> list[AuditEvent]:
        """Read-only access to recorded audit events (for test inspection)."""
        return list(self._events)

    def set_failure_mode(self, enabled: bool = True) -> None:
        """Simulate an audit storage failure for testing fail-closed behavior."""
        self._simulate_failure = enabled

    def clear(self) -> None:
        """Clear recorded events and checkpoints buffer and optional database table."""
        with self._lock:
            self._events.clear()
            self._checkpoints.clear()
            self._simulate_failure = False
            if self._db_path:
                with sqlite3.connect(self._db_path) as conn:
                    conn.execute("DELETE FROM audit_checkpoints")
                    conn.execute("DELETE FROM audit_events")
                    try:
                        conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('audit_events', 'audit_checkpoints')")
                    except sqlite3.OperationalError:
                        pass
                    conn.commit()

    @staticmethod
    def _compute_record_hash(prev_hash: str, fields: dict[str, Any]) -> str:
        """Compute deterministic SHA-256 hash chaining over canonical record fields."""
        canonical_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        to_hash = f"{prev_hash}|{canonical_json}".encode("utf-8")
        return hashlib.sha256(to_hash).hexdigest()

    def record(self, event: AuditEvent) -> AuditEvent:
        """Record privacy-safe audit event with SHA-256 hash chaining.

        Raises AuditWriteException if audit storage is unavailable.
        """
        if self._simulate_failure:
            raise AuditWriteException(
                message="Audit storage unavailable. Aborting execution fail-closed.",
                code="AUDIT_STORAGE_FAILURE",
            )

        # Invariant verification: Ensure no sensitive keys exist in event data
        event_dict = event.model_dump()
        forbidden_keys = {"prompt", "sanitized_prompt", "raw", "matched_value", "text", "secret"}
        for k in forbidden_keys:
            if k in event_dict:
                raise AuditWriteException(
                    message=f"Privacy violation: Forbidden key '{k}' found in audit event.",
                    code="AUDIT_PRIVACY_VIOLATION",
                )

        prev_hash = GENESIS_HASH
        seq_num = len(self._events) + 1

        if self._db_path:
            with self._lock:
                try:
                    with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                        # Concurrently-safe retrieval of latest hash
                        latest = conn.execute(
                            "SELECT sequence_number, record_hash FROM audit_events ORDER BY sequence_number DESC LIMIT 1"
                        ).fetchone()
                        if latest:
                            seq_num = latest[0] + 1
                            prev_hash = latest[1]
                        else:
                            seq_num = 1
                            prev_hash = GENESIS_HASH

                        canonical_payload = {
                            "sequence_number": seq_num,
                            "event_id": event.event_id,
                            "timestamp": event.timestamp,
                            "request_digest": event.request_digest,
                            "destination": event.destination,
                            "decision": event.decision.value if hasattr(event.decision, "value") else str(event.decision),
                            "rule_ids": sorted(event.rule_ids),
                            "risk_score": event.risk_score,
                            "policy_version": event.policy_version,
                            "detector_version": event.detector_version,
                            "status": event.status,
                            "provider_called": 1 if event.provider_called else 0,
                            "redaction_count": event.redaction_count,
                            "latency_ms": event.latency_ms,
                            "event_type": event.event_type or "prompt_execution",
                            "actor_id": event.actor_id or "",
                            "rationale": event.rationale or "",
                        }
                        record_hash = self._compute_record_hash(prev_hash, canonical_payload)

                        conn.execute("""
                            INSERT INTO audit_events (
                                sequence_number, event_id, timestamp, request_digest, destination,
                                decision, rule_ids, risk_score, policy_version,
                                detector_version, status, provider_called,
                                redaction_count, latency_ms, event_type,
                                actor_id, rationale, prev_hash, record_hash
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            seq_num,
                            event.event_id,
                            event.timestamp,
                            event.request_digest,
                            event.destination,
                            event.decision.value if hasattr(event.decision, "value") else str(event.decision),
                            json.dumps(event.rule_ids),
                            event.risk_score,
                            event.policy_version,
                            event.detector_version,
                            event.status,
                            1 if event.provider_called else 0,
                            event.redaction_count,
                            event.latency_ms,
                            event.event_type or "prompt_execution",
                            event.actor_id,
                            event.rationale,
                            prev_hash,
                            record_hash,
                        ))
                        conn.commit()
                except Exception as exc:
                    raise AuditWriteException(
                        message="Failed to persist audit event to durable storage.",
                        code="AUDIT_STORAGE_FAILURE",
                    ) from exc
        else:
            with self._lock:
                if self._events and self._events[-1].record_hash:
                    prev_hash = self._events[-1].record_hash
                    seq_num = len(self._events) + 1
                else:
                    prev_hash = GENESIS_HASH
                    seq_num = 1

                canonical_payload = {
                    "sequence_number": seq_num,
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "request_digest": event.request_digest,
                    "destination": event.destination,
                    "decision": event.decision.value if hasattr(event.decision, "value") else str(event.decision),
                    "rule_ids": sorted(event.rule_ids),
                    "risk_score": event.risk_score,
                    "policy_version": event.policy_version,
                    "detector_version": event.detector_version,
                    "status": event.status,
                    "provider_called": 1 if event.provider_called else 0,
                    "redaction_count": event.redaction_count,
                    "latency_ms": event.latency_ms,
                    "event_type": event.event_type or "prompt_execution",
                    "actor_id": event.actor_id or "",
                    "rationale": event.rationale or "",
                }
                record_hash = self._compute_record_hash(prev_hash, canonical_payload)

        # Update event with chain fields
        chained_event = event.model_copy(
            update={
                "prev_hash": prev_hash,
                "record_hash": record_hash,
                "sequence_number": seq_num,
            }
        )

        with self._lock:
            self._events.append(chained_event)

        return chained_event

    def get_persisted_events(self) -> list[dict[str, Any]]:
        """Query persisted events from SQLite database (for compliance auditing)."""
        if not self._db_path:
            return []
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM audit_events ORDER BY sequence_number ASC").fetchall()
            return [dict(r) for r in rows]

    def verify_chain_integrity(self) -> tuple[bool, str | None]:
        """Verify the cryptographic integrity of the entire audit hash chain.

        Returns (True, None) if unbroken, or (False, failure_reason).
        """
        if not self._db_path:
            # Verify in-memory chain
            events = self._events
            expected_prev = GENESIS_HASH
            for i, evt in enumerate(events, 1):
                if evt.prev_hash != expected_prev:
                    return False, f"Broken chain at index {i}: prev_hash mismatch."
                canonical_payload = {
                    "sequence_number": evt.sequence_number or i,
                    "event_id": evt.event_id,
                    "timestamp": evt.timestamp,
                    "request_digest": evt.request_digest,
                    "destination": evt.destination,
                    "decision": evt.decision.value if hasattr(evt.decision, "value") else str(evt.decision),
                    "rule_ids": sorted(evt.rule_ids),
                    "risk_score": evt.risk_score,
                    "policy_version": evt.policy_version,
                    "detector_version": evt.detector_version,
                    "status": evt.status,
                    "provider_called": 1 if evt.provider_called else 0,
                    "redaction_count": evt.redaction_count,
                    "latency_ms": evt.latency_ms,
                    "event_type": evt.event_type or "prompt_execution",
                    "actor_id": evt.actor_id or "",
                    "rationale": evt.rationale or "",
                }
                recomputed = self._compute_record_hash(evt.prev_hash, canonical_payload)
                if recomputed != evt.record_hash:
                    return False, f"Tampered record at index {i}: record_hash recomputation failed."
                expected_prev = evt.record_hash
            return True, None

        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM audit_events ORDER BY sequence_number ASC").fetchall()

            expected_prev = GENESIS_HASH
            for r in rows:
                seq = r["sequence_number"]
                if r["prev_hash"] != expected_prev:
                    return False, f"Broken chain at sequence {seq}: prev_hash does not match preceding record."

                rule_ids = json.loads(r["rule_ids"]) if isinstance(r["rule_ids"], str) else r["rule_ids"]
                canonical_payload = {
                    "sequence_number": seq,
                    "event_id": r["event_id"],
                    "timestamp": r["timestamp"],
                    "request_digest": r["request_digest"],
                    "destination": r["destination"],
                    "decision": r["decision"],
                    "rule_ids": sorted(rule_ids),
                    "risk_score": r["risk_score"],
                    "policy_version": r["policy_version"],
                    "detector_version": r["detector_version"],
                    "status": r["status"],
                    "provider_called": r["provider_called"],
                    "redaction_count": r["redaction_count"],
                    "latency_ms": r["latency_ms"],
                    "event_type": r["event_type"],
                    "actor_id": r["actor_id"] or "",
                    "rationale": r["rationale"] or "",
                }
                recomputed = self._compute_record_hash(r["prev_hash"], canonical_payload)
                if recomputed != r["record_hash"]:
                    return False, f"Tampered record detected at sequence {seq}: record_hash recomputation failed."
                expected_prev = r["record_hash"]

        return True, None

    @staticmethod
    def _compute_checkpoint_hash(
        prev_checkpoint_hash: str,
        epoch_index: int,
        start_sequence: int,
        end_sequence: int,
        event_count: int,
        merkle_root: str,
    ) -> str:
        """Compute deterministic SHA-256 hash over canonical checkpoint metadata."""
        payload = f"{prev_checkpoint_hash}|{epoch_index}|{start_sequence}|{end_sequence}|{event_count}|{merkle_root}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _row_to_checkpoint(r: Any) -> AuditCheckpoint:
        """Convert a database row or dict into a validated AuditCheckpoint model."""
        return AuditCheckpoint(
            checkpoint_id=r["checkpoint_id"],
            epoch_index=r["epoch_index"],
            start_sequence=r["start_sequence"],
            end_sequence=r["end_sequence"],
            event_count=r["event_count"],
            merkle_root=r["merkle_root"],
            prev_checkpoint_hash=r["prev_checkpoint_hash"],
            checkpoint_hash=r["checkpoint_hash"],
            anchor_status=CheckpointAnchorStatus(r["anchor_status"]),
            anchor_reference=r["anchor_reference"],
            anchored_at=r["anchored_at"],
            created_at=r["created_at"],
            failure_reason=r["failure_reason"],
        )

    def _save_checkpoint(self, chk: AuditCheckpoint) -> None:
        """Persist or update an AuditCheckpoint atomically."""
        if self._db_path:
            with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                conn.execute(
                    """
                    INSERT INTO audit_checkpoints (
                        checkpoint_id, epoch_index, start_sequence, end_sequence,
                        event_count, merkle_root, prev_checkpoint_hash, checkpoint_hash,
                        anchor_status, anchor_reference, anchored_at, created_at, failure_reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(checkpoint_id) DO UPDATE SET
                        anchor_status = excluded.anchor_status,
                        anchor_reference = excluded.anchor_reference,
                        anchored_at = excluded.anchored_at,
                        failure_reason = excluded.failure_reason
                    """,
                    (
                        chk.checkpoint_id,
                        chk.epoch_index,
                        chk.start_sequence,
                        chk.end_sequence,
                        chk.event_count,
                        chk.merkle_root,
                        chk.prev_checkpoint_hash,
                        chk.checkpoint_hash,
                        chk.anchor_status.value if hasattr(chk.anchor_status, "value") else str(chk.anchor_status),
                        chk.anchor_reference,
                        chk.anchored_at,
                        chk.created_at,
                        chk.failure_reason,
                    ),
                )
                conn.commit()
        else:
            with self._lock:
                for i, existing in enumerate(self._checkpoints):
                    if existing.checkpoint_id == chk.checkpoint_id:
                        self._checkpoints[i] = chk
                        return
                self._checkpoints.append(chk)

    def _get_checkpoint_or_none(self, checkpoint_id: str) -> AuditCheckpoint | None:
        """Retrieve checkpoint or return None if not found."""
        try:
            return self.get_checkpoint(checkpoint_id)
        except CheckpointNotFoundException:
            return None

    def get_latest_checkpoint(self) -> AuditCheckpoint | None:
        """Return the most recent audit checkpoint (by epoch_index)."""
        if self._db_path:
            with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM audit_checkpoints ORDER BY epoch_index DESC LIMIT 1"
                ).fetchone()
                if not row:
                    return None
                return self._row_to_checkpoint(row)
        else:
            with self._lock:
                if not self._checkpoints:
                    return None
                return self._checkpoints[-1]

    def get_checkpoint(self, checkpoint_id: str) -> AuditCheckpoint:
        """Retrieve checkpoint by identifier or raise CheckpointNotFoundException."""
        if self._db_path:
            with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM audit_checkpoints WHERE checkpoint_id = ?",
                    (checkpoint_id,),
                ).fetchone()
                if not row:
                    raise CheckpointNotFoundException(checkpoint_id)
                return self._row_to_checkpoint(row)
        else:
            with self._lock:
                for chk in self._checkpoints:
                    if chk.checkpoint_id == checkpoint_id:
                        return chk
                raise CheckpointNotFoundException(checkpoint_id)

    def list_checkpoints(self, limit: int = 50, offset: int = 0) -> list[AuditCheckpoint]:
        """List audit checkpoints ordered chronologically by epoch_index."""
        if self._db_path:
            with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM audit_checkpoints ORDER BY epoch_index ASC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
                return [self._row_to_checkpoint(r) for r in rows]
        else:
            with self._lock:
                return list(self._checkpoints[offset : offset + limit])

    def _find_checkpoint_by_range(self, start_seq: int, end_seq: int) -> AuditCheckpoint | None:
        """Find an existing checkpoint covering the exact sequence range."""
        if self._db_path:
            with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM audit_checkpoints WHERE start_sequence = ? AND end_sequence = ? LIMIT 1",
                    (start_seq, end_seq),
                ).fetchone()
                if row:
                    return self._row_to_checkpoint(row)
                return None
        else:
            with self._lock:
                for c in self._checkpoints:
                    if c.start_sequence == start_seq and c.end_sequence == end_seq:
                        return c
                return None

    def create_checkpoint(
        self,
        start_sequence: int | None = None,
        end_sequence: int | None = None,
        anchor_adapter: BaseAuditAnchorAdapter | None = None,
    ) -> AuditCheckpoint:
        """Create and anchor a cryptographic Merkle checkpoint over an ordered range of audit events.

        Security Invariants:
        1. Contiguity: start_sequence must exactly equal (latest.end_sequence + 1). No gaps or overlaps.
        2. Hash Chaining: Previous checkpoint reference binds each epoch into an unbroken tree of trees.
        3. Integrity Verification: Validates that all events in range exist and their hash chain is unbroken.
        4. Independent External Anchoring: Checkpoint is marked ANCHORED only upon confirmed receipt
           from external immutable ledger.
        5. Idempotent Recovery: Retrying an identical range returns the existing anchored checkpoint or
           resumes failed anchoring safely without duplication.
        """
        with self._lock:
            # Idempotence & Recovery: Check if checkpoint for this range already exists
            if start_sequence is not None and end_sequence is not None:
                existing = self._find_checkpoint_by_range(start_sequence, end_sequence)
                if existing is not None:
                    if existing.anchor_status == CheckpointAnchorStatus.ANCHORED:
                        return existing
                    # Existing checkpoint was unanchored or failed (e.g., local crash after remote anchor) -> resume anchoring
                    adapter = anchor_adapter or get_audit_anchor_adapter()
                    try:
                        receipt = adapter.anchor_checkpoint(existing)
                        anchored_chk = existing.model_copy(
                            update={
                                "anchor_status": CheckpointAnchorStatus.ANCHORED,
                                "anchor_reference": receipt.anchor_id,
                                "anchored_at": receipt.anchored_at,
                                "failure_reason": None,
                            }
                        )
                        self._save_checkpoint(anchored_chk)
                        return anchored_chk
                    except Exception as exc:
                        sanitized_msg = getattr(exc, "message", str(exc))
                        failed_chk = existing.model_copy(
                            update={
                                "anchor_status": CheckpointAnchorStatus.FAILED,
                                "failure_reason": sanitized_msg,
                            }
                        )
                        self._save_checkpoint(failed_chk)
                        if getattr(settings, "AUDIT_ANCHOR_REQUIRED", True):
                            raise
                        return failed_chk

            latest = self.get_latest_checkpoint()

            if latest is not None:
                if latest.anchor_status == CheckpointAnchorStatus.FAILED and getattr(settings, "AUDIT_ANCHOR_REQUIRED", True):
                    raise CheckpointSequenceException(
                        f"Preceding checkpoint {latest.checkpoint_id} is in FAILED anchor status. "
                        f"Resolve or re-anchor epoch {latest.epoch_index} before creating subsequent checkpoints."
                    )
                expected_start = latest.end_sequence + 1
                epoch_index = latest.epoch_index + 1
                prev_chk_hash = latest.checkpoint_hash
            else:
                expected_start = 1
                epoch_index = 1
                prev_chk_hash = GENESIS_CHECKPOINT_HASH

            if start_sequence is not None and start_sequence != expected_start:
                raise CheckpointSequenceException(
                    f"Invalid start_sequence {start_sequence}; expected {expected_start} to preserve contiguous checkpoint sequence."
                )
            start_seq = expected_start

            # Determine maximum available sequence
            if self._db_path:
                with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                    max_row = conn.execute("SELECT MAX(sequence_number) FROM audit_events").fetchone()
                    max_seq = max_row[0] if max_row and max_row[0] is not None else 0
            else:
                max_seq = (
                    self._events[-1].sequence_number
                    if self._events and self._events[-1].sequence_number
                    else len(self._events)
                )

            if max_seq < start_seq:
                raise CheckpointSequenceException(
                    f"No new uncheckpointed audit events available (current max sequence: {max_seq}, expected start: {start_seq})."
                )

            if end_sequence is None:
                target_end = max_seq
            else:
                if end_sequence < start_seq:
                    raise CheckpointSequenceException(
                        f"end_sequence {end_sequence} cannot be less than start_sequence {start_seq}."
                    )
                if end_sequence > max_seq:
                    raise CheckpointSequenceException(
                        f"end_sequence {end_sequence} exceeds current maximum recorded sequence number {max_seq}."
                    )
                target_end = end_sequence

            expected_count = target_end - start_seq + 1

            # Fetch events in range
            if self._db_path:
                with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        "SELECT sequence_number, event_id, prev_hash, record_hash FROM audit_events WHERE sequence_number >= ? AND sequence_number <= ? ORDER BY sequence_number ASC",
                        (start_seq, target_end),
                    ).fetchall()
                    events = [dict(r) for r in rows]
            else:
                events = [
                    {
                        "sequence_number": e.sequence_number or (i + 1),
                        "event_id": e.event_id,
                        "prev_hash": e.prev_hash,
                        "record_hash": e.record_hash,
                    }
                    for i, e in enumerate(self._events)
                    if start_seq <= (e.sequence_number or (i + 1)) <= target_end
                ]

            if len(events) != expected_count:
                raise CheckpointIntegrityException(
                    f"Missing audit events in sequence range [{start_seq}, {target_end}]: expected {expected_count}, got {len(events)}."
                )

            # Verify unbroken hash chain and sequential ordering
            for i, ev in enumerate(events):
                seq = ev["sequence_number"]
                if seq != start_seq + i:
                    raise CheckpointIntegrityException(
                        f"Sequence gap or reordering at index {i}: expected sequence {start_seq + i}, found {seq}."
                    )
                if i > 0 and ev["prev_hash"] != events[i - 1]["record_hash"]:
                    raise CheckpointIntegrityException(
                        f"Broken audit hash chain detected at sequence {seq}: prev_hash does not match preceding record_hash."
                    )

            # Build Merkle tree over record_hashes
            record_hashes = [ev["record_hash"] for ev in events]
            merkle_root = compute_merkle_root(record_hashes)
            chk_id = f"chk-{start_seq:08d}-{target_end:08d}-{merkle_root[:8]}"
            chk_hash = self._compute_checkpoint_hash(
                prev_chk_hash, epoch_index, start_seq, target_end, expected_count, merkle_root
            )
            created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

            # Idempotence: Check if identical checkpoint already exists
            existing = self._get_checkpoint_or_none(chk_id)
            if existing and existing.anchor_status == CheckpointAnchorStatus.ANCHORED:
                return existing

            # Initialize pending checkpoint record
            chk = AuditCheckpoint(
                checkpoint_id=chk_id,
                epoch_index=epoch_index,
                start_sequence=start_seq,
                end_sequence=target_end,
                event_count=expected_count,
                merkle_root=merkle_root,
                prev_checkpoint_hash=prev_chk_hash,
                checkpoint_hash=chk_hash,
                anchor_status=CheckpointAnchorStatus.PENDING,
                anchor_reference=None,
                anchored_at=None,
                created_at=created_at,
                failure_reason=None,
            )
            self._save_checkpoint(chk)

            # Anchor with external ledger adapter
            adapter = anchor_adapter or get_audit_anchor_adapter()
            try:
                receipt = adapter.anchor_checkpoint(chk)
                chk = chk.model_copy(
                    update={
                        "anchor_status": CheckpointAnchorStatus.ANCHORED,
                        "anchor_reference": receipt.anchor_id,
                        "anchored_at": receipt.anchored_at,
                        "failure_reason": None,
                    }
                )
                self._save_checkpoint(chk)
                return chk
            except Exception as exc:
                sanitized_msg = getattr(exc, "message", str(exc))
                chk = chk.model_copy(
                    update={
                        "anchor_status": CheckpointAnchorStatus.FAILED,
                        "failure_reason": sanitized_msg,
                    }
                )
                self._save_checkpoint(chk)
                if getattr(settings, "AUDIT_ANCHOR_REQUIRED", True):
                    raise
                return chk

    def get_inclusion_proof(
        self, checkpoint_id: str, sequence_number: int
    ) -> MerkleInclusionProofResponse:
        """Generate and self-verify a Merkle inclusion proof for a sequence within a checkpoint."""
        chk = self.get_checkpoint(checkpoint_id)

        if not (chk.start_sequence <= sequence_number <= chk.end_sequence):
            raise CheckpointSequenceException(
                f"Sequence number {sequence_number} outside checkpoint range [{chk.start_sequence}, {chk.end_sequence}]."
            )

        if self._db_path:
            with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT sequence_number, event_id, record_hash FROM audit_events WHERE sequence_number >= ? AND sequence_number <= ? ORDER BY sequence_number ASC",
                    (chk.start_sequence, chk.end_sequence),
                ).fetchall()
                events = [dict(r) for r in rows]
        else:
            events = [
                {
                    "sequence_number": e.sequence_number or (i + 1),
                    "event_id": e.event_id,
                    "record_hash": e.record_hash,
                }
                for i, e in enumerate(self._events)
                if chk.start_sequence <= (e.sequence_number or (i + 1)) <= chk.end_sequence
            ]

        target_idx = sequence_number - chk.start_sequence
        if not (0 <= target_idx < len(events)):
            raise CheckpointIntegrityException(
                f"Audit event for sequence {sequence_number} missing from range."
            )

        target_event = events[target_idx]
        record_hashes = [e["record_hash"] for e in events]
        proof = generate_inclusion_proof(record_hashes, target_idx)
        verified = verify_merkle_inclusion_proof(
            target_event["record_hash"], proof, chk.merkle_root
        )

        return MerkleInclusionProofResponse(
            checkpoint_id=chk.checkpoint_id,
            epoch_index=chk.epoch_index,
            sequence_number=sequence_number,
            event_id=target_event["event_id"],
            record_hash=target_event["record_hash"],
            merkle_root=chk.merkle_root,
            proof=proof,
            verified=verified,
            anchor_status=chk.anchor_status,
            anchor_reference=chk.anchor_reference,
        )

    def verify_checkpoint_integrity(self, checkpoint_id: str) -> tuple[bool, str | None]:
        """Verify the cryptographic integrity of a checkpoint and its constituent events."""
        try:
            chk = self.get_checkpoint(checkpoint_id)
        except CheckpointNotFoundException:
            return False, f"Checkpoint '{checkpoint_id}' not found."

        # 1. Verify previous checkpoint linkage
        if chk.epoch_index > 1:
            if self._db_path:
                with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                    conn.row_factory = sqlite3.Row
                    prev = conn.execute(
                        "SELECT checkpoint_hash FROM audit_checkpoints WHERE epoch_index = ?",
                        (chk.epoch_index - 1,),
                    ).fetchone()
                    if not prev or prev["checkpoint_hash"] != chk.prev_checkpoint_hash:
                        return (
                            False,
                            f"Broken checkpoint chain: prev_checkpoint_hash mismatch at epoch {chk.epoch_index}.",
                        )
            else:
                with self._lock:
                    if len(self._checkpoints) >= chk.epoch_index:
                        prev = self._checkpoints[chk.epoch_index - 2]
                        if prev.checkpoint_hash != chk.prev_checkpoint_hash:
                            return (
                                False,
                                f"Broken checkpoint chain: prev_checkpoint_hash mismatch at epoch {chk.epoch_index}.",
                            )
        else:
            if chk.prev_checkpoint_hash != GENESIS_CHECKPOINT_HASH:
                return False, "Genesis checkpoint prev_checkpoint_hash mismatch."

        # 2. Fetch constituent events
        if self._db_path:
            with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT sequence_number, prev_hash, record_hash FROM audit_events WHERE sequence_number >= ? AND sequence_number <= ? ORDER BY sequence_number ASC",
                    (chk.start_sequence, chk.end_sequence),
                ).fetchall()
                events = [dict(r) for r in rows]
        else:
            events = [
                {
                    "sequence_number": e.sequence_number or (i + 1),
                    "prev_hash": e.prev_hash,
                    "record_hash": e.record_hash,
                }
                for i, e in enumerate(self._events)
                if chk.start_sequence <= (e.sequence_number or (i + 1)) <= chk.end_sequence
            ]

        if len(events) != chk.event_count:
            return False, f"Event count mismatch: expected {chk.event_count}, found {len(events)}."

        # 3. Verify event hash chain
        for i, ev in enumerate(events):
            if i > 0 and ev["prev_hash"] != events[i - 1]["record_hash"]:
                return False, f"Broken event hash chain at sequence {ev['sequence_number']}."

        # 4. Recompute Merkle root
        recomputed_root = compute_merkle_root([e["record_hash"] for e in events])
        if recomputed_root != chk.merkle_root:
            return False, "Merkle root recomputation mismatch."

        # 5. Recompute Checkpoint hash
        recomputed_chk_hash = self._compute_checkpoint_hash(
            chk.prev_checkpoint_hash,
            chk.epoch_index,
            chk.start_sequence,
            chk.end_sequence,
            chk.event_count,
            chk.merkle_root,
        )
        if recomputed_chk_hash != chk.checkpoint_hash:
            return False, "Checkpoint hash recomputation mismatch."

        return True, None


# ==============================================================================
# Centralized AuditService Singleton Management
# ==============================================================================

_default_audit_service: AuditService | None = None
_audit_lock = threading.Lock()


def get_audit_service() -> AuditService:
    """Return the configured global AuditService singleton using settings.DATABASE_PATH."""
    global _default_audit_service
    if _default_audit_service is None:
        with _audit_lock:
            if _default_audit_service is None:
                db_path = getattr(settings, "DATABASE_PATH", "privai_dev.db")
                _default_audit_service = AuditService(db_path=db_path)
    return _default_audit_service


def set_audit_service(service: AuditService | None) -> None:
    """Override the global AuditService instance (useful for test isolation)."""
    global _default_audit_service
    with _audit_lock:
        _default_audit_service = service


