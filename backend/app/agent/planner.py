"""Bounded task planner with mandatory policy firewall evaluation."""

import re
from typing import Any

from backend.app.agent.models import AgentPlan, AgentStep, AgentStepStatus
from backend.app.agent.tools import SERVER_TOOL_ALLOWLIST
from backend.app.config import settings
from backend.app.detectors.detector import SensitiveDetector
from backend.app.models.context import ContextModel
from backend.app.models.enums import Destination, PolicyOutcome
from backend.app.policy.engine import DeterministicPolicyEngine
from backend.app.risk.scorer import RiskScorer


class BoundedPlanner:
    """Bounded, policy-governed task planner.

    Security Invariants:
    1. Pre-planning policy firewall: User goal is evaluated against policy rules before planning.
    2. Zero provider calls for BLOCK or unapproved REVIEW at planning time.
    3. Server-side allowlist: Planned tools must belong to SERVER_TOOL_ALLOWLIST.
    4. Finite step count: Never plans more than settings.AGENT_MAX_STEPS.
    """

    def __init__(
        self,
        policy_engine: DeterministicPolicyEngine | None = None,
        detector: SensitiveDetector | None = None,
        risk_scorer: RiskScorer | None = None,
        max_steps: int | None = None,
    ) -> None:
        self.detector = detector or SensitiveDetector()
        self.risk_scorer = risk_scorer or RiskScorer()
        self.policy_engine = policy_engine or DeterministicPolicyEngine()
        self.max_steps = max_steps or settings.AGENT_MAX_STEPS

    def evaluate_goal(
        self,
        goal: str,
        context: ContextModel,
        destination: Destination,
    ) -> tuple[PolicyOutcome, list[str], str, str]:
        """Evaluate raw user goal against privacy firewall rules.

        Returns: (outcome, reason_codes, explanation_summary, sanitized_goal)
        """
        findings = self.detector.detect(goal)
        risk = self.risk_scorer.evaluate(findings, context, destination)
        decision = self.policy_engine.evaluate(
            prompt=goal,
            findings=findings,
            context=context,
            destination=destination,
            risk_score=risk,
        )
        sanitized_goal = decision.sanitized_prompt if decision.sanitized_prompt else goal
        return decision.action, decision.reason_codes, decision.explanation.summary, sanitized_goal

    def create_plan(
        self,
        goal: str,
        context: ContextModel,
        destination: Destination,
    ) -> tuple[AgentPlan | None, PolicyOutcome, list[str], str, str]:
        """Evaluate goal and generate a bounded plan.

        Returns:
            (plan, outcome, reason_codes, explanation_summary, sanitized_goal)
        """
        outcome, reasons, explanation, sanitized_goal = self.evaluate_goal(goal, context, destination)

        # Precedence Ladder: Mandatory BLOCK aborts planning immediately
        if outcome == PolicyOutcome.BLOCK:
            return None, outcome, reasons, explanation, sanitized_goal

        # Precedence Ladder: Mandatory REVIEW suspends planning until authorized
        if outcome == PolicyOutcome.REVIEW:
            return None, outcome, reasons, explanation, sanitized_goal

        # Outcome is ALLOW or REDACT: Generate bounded plan using sanitized goal
        plan = self._synthesize_bounded_plan(sanitized_goal, original_goal=goal)
        return plan, outcome, reasons, explanation, sanitized_goal

    def _synthesize_bounded_plan(self, goal: str, original_goal: str | None = None) -> AgentPlan:
        """Deterministically map goal to a sequence of allowlisted tool steps."""
        steps: list[AgentStep] = []
        lower_goal = goal.lower()
        analysis_goal = original_goal or goal

        # Heuristic extraction of document targets
        doc_match = re.search(r"([a-zA-Z0-9_\-\.]+\.(?:txt|md))", analysis_goal)
        target_doc = doc_match.group(1) if doc_match else None

        # Heuristic extraction of employee ID targets
        emp_match = re.search(r"\b(EMP-[0-9]{4,8})\b", analysis_goal)
        target_emp_id = emp_match.group(1) if emp_match else None

        if target_doc:
            # Plan variant: Target document specified
            steps.append(
                AgentStep(
                    step_number=1,
                    description=f"Read contents of document '{target_doc}'",
                    tool_name="read_document",
                    tool_input={"document_id": target_doc},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=2,
                    description=f"Summarize key points from '{target_doc}'",
                    tool_name="summarize_text",
                    tool_input={"text": f"Content from {target_doc}", "max_sentences": 3},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=3,
                    description="Format final summary report",
                    tool_name="format_report",
                    tool_input={
                        "title": f"Summary Report: {target_doc}",
                        "sections": [{"heading": "Findings", "content": f"Executive summary for {target_doc}"}],
                        "output_filename": f"summary_{target_doc}.md",
                    },
                    status=AgentStepStatus.PENDING,
                )
            )
        elif target_emp_id:
            # Plan variant: Specific employee record requested
            steps.append(
                AgentStep(
                    step_number=1,
                    description=f"Retrieve profile for employee {target_emp_id}",
                    tool_name="get_employee_record",
                    tool_input={"employee_id": target_emp_id},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=2,
                    description=f"Summarize employee details for {target_emp_id}",
                    tool_name="summarize_text",
                    tool_input={"text": f"Employee record {target_emp_id}: {analysis_goal}", "max_sentences": 3},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=3,
                    description=f"Format employee summary report for {target_emp_id}",
                    tool_name="format_report",
                    tool_input={
                        "title": f"Employee Report: {target_emp_id}",
                        "sections": [{"heading": "Profile", "content": f"Executive summary for employee {target_emp_id}"}],
                        "output_filename": f"employee_{target_emp_id.lower()}_report.md",
                    },
                    status=AgentStepStatus.PENDING,
                )
            )
        elif "employee" in lower_goal or "profile" in lower_goal:
            # Plan variant: Employee directory search and profile summarization
            search_query = "Engineering"
            for dept in ("engineering", "finance", "healthcare", "human resources", "legal", "product"):
                if dept in lower_goal:
                    search_query = dept.title()
                    break
            steps.append(
                AgentStep(
                    step_number=1,
                    description="Search employee directory for matching profile",
                    tool_name="search_employee_directory",
                    tool_input={"query": search_query},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=2,
                    description="Summarize public employee profile",
                    tool_name="summarize_text",
                    tool_input={"text": goal, "max_sentences": 3},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=3,
                    description="Format employee profile report",
                    tool_name="format_report",
                    tool_input={
                        "title": "Employee Profile Report",
                        "sections": [{"heading": "Profile Overview", "content": goal}],
                        "output_filename": "employee_profile_report.md",
                    },
                    status=AgentStepStatus.PENDING,
                )
            )
        elif any(k in lower_goal for k in ("search", "find", "query", "scan")):
            # Plan variant: Search across documents
            query = "policy"
            # Extract simple query keyword
            words = [w for w in re.findall(r"\b[a-zA-Z]{3,}\b", goal) if w.lower() not in ("search", "find", "for", "the", "and")]
            if words:
                query = words[0]
            steps.append(
                AgentStep(
                    step_number=1,
                    description=f"Search documents for keyword '{query}'",
                    tool_name="search_documents",
                    tool_input={"query": query},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=2,
                    description="Read most relevant matching document",
                    tool_name="read_document",
                    tool_input={"document_id": "company_policy.txt"},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=3,
                    description="Format search analysis report",
                    tool_name="format_report",
                    tool_input={
                        "title": f"Search Report: {query}",
                        "sections": [{"heading": "Search Matches", "content": f"Matches for query '{query}'"}],
                        "output_filename": f"search_report_{query}.md",
                    },
                    status=AgentStepStatus.PENDING,
                )
            )
        else:
            # Default bounded plan: Document inspection and reporting
            steps.append(
                AgentStep(
                    step_number=1,
                    description="Read reference company policy document",
                    tool_name="read_document",
                    tool_input={"document_id": "company_policy.txt"},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=2,
                    description="Summarize document text",
                    tool_name="summarize_text",
                    tool_input={"text": "PrivAI company policy reference content", "max_sentences": 3},
                    status=AgentStepStatus.PENDING,
                )
            )
            steps.append(
                AgentStep(
                    step_number=3,
                    description="Generate final task report",
                    tool_name="format_report",
                    tool_input={
                        "title": "Task Execution Report",
                        "sections": [{"heading": "Overview", "content": f"Completed evaluation for goal: {goal}"}],
                        "output_filename": "task_execution_report.md",
                    },
                    status=AgentStepStatus.PENDING,
                )
            )

        # Enforce server-side allowlist on every generated step
        for step in steps:
            if step.tool_name not in SERVER_TOOL_ALLOWLIST:
                raise ValueError(f"Planner generated unapproved tool: {step.tool_name}")

        # Enforce finite step limit
        bounded_steps = steps[: self.max_steps]
        # Re-index
        for idx, s in enumerate(bounded_steps, start=1):
            s.step_number = idx

        return AgentPlan(
            goal=goal,
            steps=bounded_steps,
            total_steps=len(bounded_steps),
        )
