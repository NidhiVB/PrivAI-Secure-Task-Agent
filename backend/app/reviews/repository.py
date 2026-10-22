"""Durable repository for human-review tickets and permits."""

import datetime
import json
import sqlite3
import threading
from typing import Any

from backend.app.config import settings
from backend.app.core.encryption import PayloadEncryptor
from backend.app.core.exceptions import PrivAIException
from backend.app.models.reviews import ReviewStatus, ReviewTicket


class ReviewRepositoryException(PrivAIException):
    """Raised when review repository operations fail."""

    def __init__(self, message: str, code: str = "REVIEW_REPOSITORY_ERROR", status_code: int = 500) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class TicketNotFoundException(ReviewRepositoryException):
    """Raised when a ticket is not found."""

    def __init__(self, ticket_id: str) -> None:
        super().__init__(
            message=f"Review ticket '{ticket_id}' not found.",
            code="TICKET_NOT_FOUND",
            status_code=404,
        )


class TicketExpiredException(ReviewRepositoryException):
    """Raised when an operation is attempted on an expired ticket."""

    def __init__(self, ticket_id: str) -> None:
        super().__init__(
            message=f"Review ticket '{ticket_id}' has expired and cannot be actioned.",
            code="TICKET_EXPIRED",
            status_code=409,
        )


class InvalidTicketTransitionException(ReviewRepositoryException):
    """Raised when an invalid ticket state transition is attempted."""

    def __init__(self, ticket_id: str, current_status: str, attempted_status: str) -> None:
        super().__init__(
            message=f"Cannot transition ticket '{ticket_id}' from {current_status} to {attempted_status}.",
            code="INVALID_TICKET_TRANSITION",
            status_code=409,
        )


class PermitReplayException(ReviewRepositoryException):
    """Raised when a review permit is reused, expired, or invalid."""

    def __init__(self, message: str = "Review permit has expired, been consumed, or is invalid.") -> None:
        super().__init__(
            message=message,
            code="PERMIT_REPLAY_OR_EXPIRED",
            status_code=403,
        )


class ReviewRepository:
    """Thread-safe, durable repository for review tickets and cryptographic permits."""

    _instance = None
    _lock = threading.Lock()

    def __init__(
        self,
        db_path: str | None = None,
        encryptor: PayloadEncryptor | None = None,
    ) -> None:
        self.db_path = db_path if db_path is not None else settings.DATABASE_PATH
        self.encryptor = encryptor if encryptor is not None else PayloadEncryptor()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        """Create schema and indices if they do not exist."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS review_tickets (
                    ticket_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_role TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    triggered_rule_ids TEXT NOT NULL,
                    encrypted_prompt TEXT,
                    decision_rationale TEXT,
                    decided_by TEXT,
                    decided_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_tickets_status_role
                    ON review_tickets(status, assigned_role, expires_at);

                CREATE TABLE IF NOT EXISTS review_permits (
                    permit_nonce TEXT PRIMARY KEY,
                    ticket_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    FOREIGN KEY(ticket_id) REFERENCES review_tickets(ticket_id)
                );

                CREATE INDEX IF NOT EXISTS idx_permits_ticket
                    ON review_permits(ticket_id);
            """)
            conn.commit()

    def clear(self) -> None:
        """Clear all records (for isolated automated testing)."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM review_permits")
            conn.execute("DELETE FROM review_tickets")
            conn.commit()

    def create_ticket(
        self,
        ticket_id: str,
        request_digest: str,
        assigned_role: str,
        risk_score: int,
        triggered_rule_ids: list[str],
        prompt_content: str | None = None,
        now_utc: datetime.datetime | None = None,
    ) -> ReviewTicket:
        """Create and persist a new pending review ticket with strict 24-hour TTL."""
        now = now_utc or datetime.datetime.now(datetime.timezone.utc)
        expires = now + datetime.timedelta(hours=settings.REVIEW_TICKET_TTL_HOURS)

        submitted_at_str = now.isoformat()
        expires_at_str = expires.isoformat()

        encrypted_prompt = None
        if prompt_content:
            encrypted_prompt = self.encryptor.encrypt(prompt_content, associated_data=request_digest)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO review_tickets (
                    ticket_id, request_digest, submitted_at, expires_at,
                    status, assigned_role, risk_score, triggered_rule_ids,
                    encrypted_prompt, decision_rationale, decided_by, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                """,
                (
                    ticket_id,
                    request_digest,
                    submitted_at_str,
                    expires_at_str,
                    ReviewStatus.PENDING.value,
                    assigned_role,
                    risk_score,
                    json.dumps(triggered_rule_ids),
                    encrypted_prompt,
                ),
            )
            conn.commit()

        return ReviewTicket(
            ticket_id=ticket_id,
            request_digest=request_digest,
            submitted_at=submitted_at_str,
            expires_at=expires_at_str,
            status=ReviewStatus.PENDING,
            assigned_role=assigned_role,
            risk_score=risk_score,
            triggered_rule_ids=triggered_rule_ids,
            decision_rationale=None,
            decided_by=None,
            decided_at=None,
        )

    def get_ticket(self, ticket_id: str, now_utc: datetime.datetime | None = None) -> ReviewTicket:
        """Retrieve a ticket by ID, automatically evaluating server-side TTL."""
        now = now_utc or datetime.datetime.now(datetime.timezone.utc)
        now_str = now.isoformat()

        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM review_tickets WHERE ticket_id = ?", (ticket_id,)
            ).fetchone()

            if row is None:
                raise TicketNotFoundException(ticket_id)

            status = row["status"]
            expires_at = row["expires_at"]

            # Dynamic TTL evaluation: if pending and expired, update to EXPIRED
            if status == ReviewStatus.PENDING.value and expires_at <= now_str:
                conn.execute(
                    "UPDATE review_tickets SET status = ? WHERE ticket_id = ? AND status = ?",
                    (ReviewStatus.EXPIRED.value, ticket_id, ReviewStatus.PENDING.value),
                )
                conn.commit()
                status = ReviewStatus.EXPIRED.value

            return ReviewTicket(
                ticket_id=row["ticket_id"],
                request_digest=row["request_digest"],
                submitted_at=row["submitted_at"],
                expires_at=row["expires_at"],
                status=ReviewStatus(status),
                assigned_role=row["assigned_role"],
                risk_score=row["risk_score"],
                triggered_rule_ids=json.loads(row["triggered_rule_ids"]),
                decision_rationale=row["decision_rationale"],
                decided_by=row["decided_by"],
                decided_at=row["decided_at"],
            )

    def get_decrypted_prompt(self, ticket_id: str) -> str | None:
        """Retrieve and decrypt the stored prompt for a ticket using envelope decryption.

        Security Invariant:
        Enforces authenticated AES-256-GCM decryption with request digest AAD binding.
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT encrypted_prompt, request_digest FROM review_tickets WHERE ticket_id = ?",
                (ticket_id,),
            ).fetchone()

            if row is None:
                raise TicketNotFoundException(ticket_id)

            if not row["encrypted_prompt"]:
                return None

            return self.encryptor.decrypt(
                row["encrypted_prompt"], associated_data=row["request_digest"]
            )

    def list_pending_tickets(
        self,
        allowed_roles: list[str] | None = None,
        now_utc: datetime.datetime | None = None,
    ) -> list[ReviewTicket]:
        """List active pending tickets that have not expired, filtered by authorized roles."""
        now = now_utc or datetime.datetime.now(datetime.timezone.utc)
        now_str = now.isoformat()

        with self._get_connection() as conn:
            # First mark any expired pending tickets
            conn.execute(
                "UPDATE review_tickets SET status = ? WHERE status = ? AND expires_at <= ?",
                (ReviewStatus.EXPIRED.value, ReviewStatus.PENDING.value, now_str),
            )
            conn.commit()

            if allowed_roles is None:
                query = "SELECT * FROM review_tickets WHERE status = ? AND expires_at > ? ORDER BY submitted_at ASC"
                params: list[Any] = [ReviewStatus.PENDING.value, now_str]
            else:
                placeholders = ",".join("?" for _ in allowed_roles)
                query = (
                    f"SELECT * FROM review_tickets "
                    f"WHERE status = ? AND expires_at > ? AND assigned_role IN ({placeholders}) "
                    f"ORDER BY submitted_at ASC"
                )
                params = [ReviewStatus.PENDING.value, now_str] + list(allowed_roles)

            rows = conn.execute(query, params).fetchall()

            return [
                ReviewTicket(
                    ticket_id=r["ticket_id"],
                    request_digest=r["request_digest"],
                    submitted_at=r["submitted_at"],
                    expires_at=r["expires_at"],
                    status=ReviewStatus(r["status"]),
                    assigned_role=r["assigned_role"],
                    risk_score=r["risk_score"],
                    triggered_rule_ids=json.loads(r["triggered_rule_ids"]),
                    decision_rationale=r["decision_rationale"],
                    decided_by=r["decided_by"],
                    decided_at=r["decided_at"],
                )
                for r in rows
            ]

    def approve_ticket(
        self,
        ticket_id: str,
        rationale: str,
        reviewer_id: str,
        now_utc: datetime.datetime | None = None,
    ) -> ReviewTicket:
        """Atomically approve a pending ticket.

        Fails closed if ticket is already decided, expired, or non-existent.
        """
        now = now_utc or datetime.datetime.now(datetime.timezone.utc)
        now_str = now.isoformat()

        with self._get_connection() as conn:
            # Atomic conditional update
            cur = conn.execute(
                """
                UPDATE review_tickets
                SET status = ?, decision_rationale = ?, decided_by = ?, decided_at = ?
                WHERE ticket_id = ? AND status = ? AND expires_at > ?
                """,
                (
                    ReviewStatus.APPROVED.value,
                    rationale,
                    reviewer_id,
                    now_str,
                    ticket_id,
                    ReviewStatus.PENDING.value,
                    now_str,
                ),
            )
            conn.commit()

            if cur.rowcount == 0:
                # Check why it failed
                row = conn.execute(
                    "SELECT status, expires_at FROM review_tickets WHERE ticket_id = ?",
                    (ticket_id,),
                ).fetchone()
                if row is None:
                    raise TicketNotFoundException(ticket_id)
                if row["expires_at"] <= now_str:
                    # Update status to expired
                    conn.execute(
                        "UPDATE review_tickets SET status = ? WHERE ticket_id = ?",
                        (ReviewStatus.EXPIRED.value, ticket_id),
                    )
                    conn.commit()
                    raise TicketExpiredException(ticket_id)
                raise InvalidTicketTransitionException(
                    ticket_id=ticket_id,
                    current_status=row["status"],
                    attempted_status=ReviewStatus.APPROVED.value,
                )

        return self.get_ticket(ticket_id, now_utc=now)

    def reject_ticket(
        self,
        ticket_id: str,
        rationale: str,
        reviewer_id: str,
        now_utc: datetime.datetime | None = None,
    ) -> ReviewTicket:
        """Atomically reject a pending ticket.

        Fails closed if ticket is already decided, expired, or non-existent.
        """
        now = now_utc or datetime.datetime.now(datetime.timezone.utc)
        now_str = now.isoformat()

        with self._get_connection() as conn:
            cur = conn.execute(
                """
                UPDATE review_tickets
                SET status = ?, decision_rationale = ?, decided_by = ?, decided_at = ?
                WHERE ticket_id = ? AND status = ? AND expires_at > ?
                """,
                (
                    ReviewStatus.REJECTED.value,
                    rationale,
                    reviewer_id,
                    now_str,
                    ticket_id,
                    ReviewStatus.PENDING.value,
                    now_str,
                ),
            )
            conn.commit()

            if cur.rowcount == 0:
                row = conn.execute(
                    "SELECT status, expires_at FROM review_tickets WHERE ticket_id = ?",
                    (ticket_id,),
                ).fetchone()
                if row is None:
                    raise TicketNotFoundException(ticket_id)
                if row["expires_at"] <= now_str:
                    conn.execute(
                        "UPDATE review_tickets SET status = ? WHERE ticket_id = ?",
                        (ReviewStatus.EXPIRED.value, ticket_id),
                    )
                    conn.commit()
                    raise TicketExpiredException(ticket_id)
                raise InvalidTicketTransitionException(
                    ticket_id=ticket_id,
                    current_status=row["status"],
                    attempted_status=ReviewStatus.REJECTED.value,
                )

        return self.get_ticket(ticket_id, now_utc=now)

    def record_permit(
        self,
        permit_nonce: str,
        ticket_id: str,
        request_digest: str,
        issued_at: str,
        expires_at: str,
    ) -> None:
        """Record issued single-use cryptographic permit."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO review_permits (
                    permit_nonce, ticket_id, request_digest, issued_at, expires_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (permit_nonce, ticket_id, request_digest, issued_at, expires_at),
            )
            conn.commit()

    def consume_permit_atomic(
        self,
        permit_nonce: str,
        expected_digest: str,
        now_utc: datetime.datetime | None = None,
    ) -> dict[str, Any]:
        """Atomically consume a permit in a single transactional conditional update.

        Guarantees:
        1. Single-use: Fails if already consumed (consumed_at IS NOT NULL).
        2. Strict 5-minute TTL: Fails if expires_at <= now.
        3. Request Digest Binding: Fails if request_digest != expected_digest.
        """
        now = now_utc or datetime.datetime.now(datetime.timezone.utc)
        now_str = now.isoformat()

        with self._get_connection() as conn:
            cur = conn.execute(
                """
                UPDATE review_permits
                SET consumed_at = ?
                WHERE permit_nonce = ?
                  AND request_digest = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                """,
                (now_str, permit_nonce, expected_digest, now_str),
            )
            conn.commit()

            if cur.rowcount == 0:
                # Check specific reason for failure
                row = conn.execute(
                    "SELECT * FROM review_permits WHERE permit_nonce = ?",
                    (permit_nonce,),
                ).fetchone()

                if row is None:
                    raise PermitReplayException("Permit nonce not found.")
                if row["consumed_at"] is not None:
                    raise PermitReplayException("Permit has already been consumed (replay attempt blocked).")
                if row["expires_at"] <= now_str:
                    raise PermitReplayException("Permit has expired.")
                if row["request_digest"] != expected_digest:
                    raise PermitReplayException("Permit request digest does not match current request.")
                raise PermitReplayException("Permit is invalid or cannot be consumed.")

            # Return permit record details
            row = conn.execute(
                "SELECT * FROM review_permits WHERE permit_nonce = ?",
                (permit_nonce,),
            ).fetchone()
            return dict(row)
