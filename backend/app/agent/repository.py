"""SQLite persistence repository for Agent Tasks and Steps."""

import datetime
import json
import sqlite3
import threading
from typing import Any

from backend.app.agent.models import (
    AgentPlan,
    AgentStep,
    AgentStepStatus,
    AgentTask,
    AgentTaskStatus,
)
from backend.app.config import settings
from backend.app.models.context import ContextModel
from backend.app.models.enums import Destination, PolicyOutcome


class AgentRepository:
    """Thread-safe SQLite repository for Agent tasks and execution steps.

    Security Invariants:
    1. Isolated storage: By default uses AGENT_DATABASE_PATH (privai_agent.db) to ensure
       historical privai_data.db remains pristine and unmodified.
    2. Atomic operations using SQLite transactions.
    3. Thread safety via per-thread connections or synchronized locks.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or settings.AGENT_DATABASE_PATH
        self._lock = threading.Lock()
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_tasks (
                    task_id TEXT PRIMARY KEY,
                    goal TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_step_index INTEGER NOT NULL DEFAULT 0,
                    final_answer TEXT,
                    completed_steps INTEGER NOT NULL DEFAULT 0,
                    blocked_steps INTEGER NOT NULL DEFAULT 0,
                    waiting_steps INTEGER NOT NULL DEFAULT 0,
                    pending_ticket_id TEXT,
                    audit_references TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_steps (
                    step_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    step_number INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    tool_input_json TEXT NOT NULL,
                    sanitized_tool_input_json TEXT,
                    policy_decision TEXT,
                    policy_reason_codes_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    ticket_id TEXT,
                    tool_output_json TEXT,
                    explanation TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES agent_tasks(task_id)
                )
                """
            )
            conn.commit()

    def create_task(self, task: AgentTask) -> AgentTask:
        """Insert a newly created task into SQLite."""
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO agent_tasks (
                    task_id, goal, status, current_step_index, final_answer,
                    completed_steps, blocked_steps, waiting_steps, pending_ticket_id,
                    audit_references, context_json, destination, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.task_id,
                    task.goal,
                    task.status.value,
                    task.current_step_index,
                    task.final_answer,
                    task.completed_steps,
                    task.blocked_steps,
                    task.waiting_steps,
                    task.pending_ticket_id,
                    json.dumps(task.audit_references),
                    task.context.model_dump_json(),
                    task.destination.value,
                    task.created_at,
                    task.updated_at,
                ),
            )
            if task.plan:
                for step in task.plan.steps:
                    self._insert_step(conn, task.task_id, step)
            conn.commit()
        return task

    def _insert_step(self, conn: sqlite3.Connection, task_id: str, step: AgentStep) -> None:
        step_id = f"{task_id}_{step.step_number}"
        conn.execute(
            """
            INSERT OR REPLACE INTO agent_steps (
                step_id, task_id, step_number, description, tool_name,
                tool_input_json, sanitized_tool_input_json, policy_decision,
                policy_reason_codes_json, status, ticket_id, tool_output_json,
                explanation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                step_id,
                task_id,
                step.step_number,
                step.description,
                step.tool_name,
                json.dumps(step.tool_input),
                json.dumps(step.sanitized_tool_input) if step.sanitized_tool_input else None,
                step.policy_decision.value if step.policy_decision else None,
                json.dumps(step.policy_reason_codes),
                step.status.value,
                step.ticket_id,
                json.dumps(step.tool_output) if step.tool_output else None,
                step.explanation,
                datetime.datetime.now(datetime.timezone.utc).isoformat(),
            ),
        )

    def save_step(self, task_id: str, step: AgentStep) -> None:
        """Persist or update an agent step."""
        with self._lock, self._get_connection() as conn:
            self._insert_step(conn, task_id, step)
            conn.commit()

    def update_task(self, task: AgentTask) -> AgentTask:
        """Update existing task state."""
        task.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                UPDATE agent_tasks SET
                    status = ?,
                    current_step_index = ?,
                    final_answer = ?,
                    completed_steps = ?,
                    blocked_steps = ?,
                    waiting_steps = ?,
                    pending_ticket_id = ?,
                    audit_references = ?,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (
                    task.status.value,
                    task.current_step_index,
                    task.final_answer,
                    task.completed_steps,
                    task.blocked_steps,
                    task.waiting_steps,
                    task.pending_ticket_id,
                    json.dumps(task.audit_references),
                    task.updated_at,
                    task.task_id,
                ),
            )
            if task.plan:
                for step in task.plan.steps:
                    self._insert_step(conn, task.task_id, step)
            conn.commit()
        return task

    def get_steps(self, task_id: str) -> list[AgentStep]:
        """Fetch all steps for a task in step_number order."""
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM agent_steps WHERE task_id = ? ORDER BY step_number ASC
                """,
                (task_id,),
            ).fetchall()

        steps: list[AgentStep] = []
        for r in rows:
            steps.append(
                AgentStep(
                    step_number=r["step_number"],
                    description=r["description"],
                    tool_name=r["tool_name"],
                    tool_input=json.loads(r["tool_input_json"]),
                    sanitized_tool_input=json.loads(r["sanitized_tool_input_json"]) if r["sanitized_tool_input_json"] else None,
                    policy_decision=PolicyOutcome(r["policy_decision"]) if r["policy_decision"] else None,
                    policy_reason_codes=json.loads(r["policy_reason_codes_json"]),
                    status=AgentStepStatus(r["status"]),
                    ticket_id=r["ticket_id"],
                    tool_output=json.loads(r["tool_output_json"]) if r["tool_output_json"] else None,
                    explanation=r["explanation"],
                )
            )
        return steps

    def get_task(self, task_id: str) -> AgentTask | None:
        """Fetch a task and reconstruct its full plan."""
        with self._lock, self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM agent_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()

        if not row:
            return None

        steps = self.get_steps(task_id)
        plan = None
        if steps:
            plan = AgentPlan(
                goal=row["goal"],
                steps=steps,
                total_steps=len(steps),
            )

        return AgentTask(
            task_id=row["task_id"],
            goal=row["goal"],
            status=AgentTaskStatus(row["status"]),
            plan=plan,
            current_step_index=row["current_step_index"],
            final_answer=row["final_answer"],
            completed_steps=row["completed_steps"],
            blocked_steps=row["blocked_steps"],
            waiting_steps=row["waiting_steps"],
            pending_ticket_id=row["pending_ticket_id"],
            audit_references=json.loads(row["audit_references"]),
            context=ContextModel.model_validate_json(row["context_json"]),
            destination=Destination(row["destination"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
