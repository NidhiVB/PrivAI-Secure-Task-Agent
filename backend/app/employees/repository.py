"""Thread-safe SQLite repository for Synthetic Demo Employee Directory."""

import datetime
from pathlib import Path
import sqlite3
import threading
from typing import Any

from backend.app.config import settings
from backend.app.core.exceptions import SecurityInvariantException
from backend.app.employees.models import DataClassification, EmployeeRecord


# Canonical 15 synthetic employee records.
# All names, emails, phones, numbers, and notes are 100% fictional.
CANONICAL_DEMO_EMPLOYEES: list[dict[str, Any]] = [
    {
        "employee_id": "EMP-1001",
        "name": "Elena Rostova",
        "department": "Engineering",
        "job_title": "Lead Software Engineer",
        "employment_status": "Active",
        "data_classification": DataClassification.PUBLIC.value,
        "email": "elena.rostova@privai-demo.internal",
        "phone": "555-019-0142",
        "salary": "$165,000 / year",
        "payroll_id": "PAY-8821",
        "health_notes": "Standard annual ergonomics assessment completed; workstation compliant.",
        "hire_date": "2021-04-12",
        "office_location": "San Francisco - Bldg 2, Floor 4",
    },
    {
        "employee_id": "EMP-1002",
        "name": "Marcus Vance",
        "department": "Finance",
        "job_title": "Senior Financial Analyst",
        "employment_status": "Active",
        "data_classification": DataClassification.CONFIDENTIAL.value,
        "email": "marcus.vance@privai-demo.internal",
        "phone": "555-019-0183",
        "salary": "$148,000 / year",
        "payroll_id": "PAY-9104",
        "health_notes": "Vision screening completed; no corrective optical requirements for display work.",
        "hire_date": "2020-09-01",
        "office_location": "New York - Tower B, Floor 18",
    },
    {
        "employee_id": "EMP-1003",
        "name": "Priya Sharma",
        "department": "Healthcare Operations",
        "job_title": "Lead Clinical Coordinator",
        "employment_status": "Active",
        "data_classification": DataClassification.CONFIDENTIAL.value,
        "email": "priya.sharma@privai-demo.internal",
        "phone": "555-019-0199",
        "salary": "$135,000 / year",
        "payroll_id": "PAY-7320",
        "health_notes": "Confidential clinical diagnosis: recurring migraine management under occupational health accommodation protocol.",
        "hire_date": "2022-01-17",
        "office_location": "Chicago - Medical Wing 3",
    },
    {
        "employee_id": "EMP-1004",
        "name": "Jordan Blake",
        "department": "Human Resources",
        "job_title": "HR Compliance Director",
        "employment_status": "Active",
        "data_classification": DataClassification.RESTRICTED.value,
        "email": "jordan.blake@privai-demo.internal",
        "phone": "555-019-0112",
        "salary": "$175,000 / year",
        "payroll_id": "PAY-6019",
        "health_notes": "Fit for duty certification filed annually; no restrictions.",
        "hire_date": "2019-06-24",
        "office_location": "San Francisco - Bldg 1, Floor 5",
    },
    {
        "employee_id": "EMP-1005",
        "name": "Carlos Mendez",
        "department": "Engineering",
        "job_title": "Senior Cloud Architect",
        "employment_status": "Active",
        "data_classification": DataClassification.INTERNAL.value,
        "email": "carlos.mendez@privai-demo.internal",
        "phone": "555-019-0155",
        "salary": "$172,000 / year",
        "payroll_id": "PAY-5412",
        "health_notes": "Medical leave approved: physical therapy sessions scheduled on Fridays.",
        "hire_date": "2021-11-08",
        "office_location": "Austin - Tech Hub A",
    },
    {
        "employee_id": "EMP-1006",
        "name": "Sarah Jenkins",
        "department": "Product & Design",
        "job_title": "Principal UX Researcher",
        "employment_status": "Active",
        "data_classification": DataClassification.PUBLIC.value,
        "email": "sarah.jenkins@privai-demo.internal",
        "phone": "555-019-0167",
        "salary": "$152,000 / year",
        "payroll_id": "PAY-4211",
        "health_notes": "Standard workplace wellness registration completed.",
        "hire_date": "2022-05-30",
        "office_location": "Seattle - Suite 400",
    },
    {
        "employee_id": "EMP-1007",
        "name": "Liam O'Connor",
        "department": "Legal & Compliance",
        "job_title": "Privacy Counsel",
        "employment_status": "Active",
        "data_classification": DataClassification.RESTRICTED.value,
        "email": "liam.oconnor@privai-demo.internal",
        "phone": "555-019-0174",
        "salary": "$185,000 / year",
        "payroll_id": "PAY-3190",
        "health_notes": "Confidential medical history: hypertension monitoring under occupational wellness care.",
        "hire_date": "2018-10-15",
        "office_location": "New York - Tower B, Floor 22",
    },
    {
        "employee_id": "EMP-1008",
        "name": "Aisha Al-Mansoor",
        "department": "Engineering",
        "job_title": "Security Operations Specialist",
        "employment_status": "Active",
        "data_classification": DataClassification.INTERNAL.value,
        "email": "aisha.almansoor@privai-demo.internal",
        "phone": "555-019-0129",
        "salary": "$140,000 / year",
        "payroll_id": "PAY-2845",
        "health_notes": "No occupational medical limitations.",
        "hire_date": "2023-02-01",
        "office_location": "San Francisco - Bldg 2, Floor 3",
    },
    {
        "employee_id": "EMP-1009",
        "name": "Chen Wei",
        "department": "Finance",
        "job_title": "Senior Payroll Accountant",
        "employment_status": "Active",
        "data_classification": DataClassification.CONFIDENTIAL.value,
        "email": "chen.wei@privai-demo.internal",
        "phone": "555-019-0138",
        "salary": "$128,000 / year",
        "payroll_id": "PAY-1928",
        "health_notes": "Carpal tunnel ergonomic keyboard accommodation approved.",
        "hire_date": "2021-08-16",
        "office_location": "New York - Tower B, Floor 17",
    },
    {
        "employee_id": "EMP-1010",
        "name": "Maya Lin",
        "department": "Healthcare Operations",
        "job_title": "Occupational Health Nurse",
        "employment_status": "Active",
        "data_classification": DataClassification.CONFIDENTIAL.value,
        "email": "maya.lin@privai-demo.internal",
        "phone": "555-019-0186",
        "salary": "$115,000 / year",
        "payroll_id": "PAY-8472",
        "health_notes": "Immunization and biohazard exposure certification fully up to date.",
        "hire_date": "2022-07-11",
        "office_location": "Chicago - Medical Wing 1",
    },
    {
        "employee_id": "EMP-1011",
        "name": "David Kim",
        "department": "Engineering",
        "job_title": "DevOps Engineer",
        "employment_status": "Active",
        "data_classification": DataClassification.INTERNAL.value,
        "email": "david.kim@privai-demo.internal",
        "phone": "555-019-0193",
        "salary": "$138,000 / year",
        "payroll_id": "PAY-7193",
        "health_notes": "Standard occupational evaluation completed.",
        "hire_date": "2023-05-22",
        "office_location": "Austin - Tech Hub B",
    },
    {
        "employee_id": "EMP-1012",
        "name": "Fatima Zahra",
        "department": "Product & Design",
        "job_title": "Product Manager, AI Governance",
        "employment_status": "Active",
        "data_classification": DataClassification.PUBLIC.value,
        "email": "fatima.zahra@privai-demo.internal",
        "phone": "555-019-0149",
        "salary": "$158,000 / year",
        "payroll_id": "PAY-6284",
        "health_notes": "No special medical accommodations required.",
        "hire_date": "2020-11-02",
        "office_location": "San Francisco - Bldg 1, Floor 3",
    },
    {
        "employee_id": "EMP-1013",
        "name": "Gabriel Santos",
        "department": "Human Resources",
        "job_title": "Talent Acquisition Lead",
        "employment_status": "Active",
        "data_classification": DataClassification.INTERNAL.value,
        "email": "gabriel.santos@privai-demo.internal",
        "phone": "555-019-0163",
        "salary": "$122,000 / year",
        "payroll_id": "PAY-5173",
        "health_notes": "Annual physical examination record filed.",
        "hire_date": "2022-09-19",
        "office_location": "Chicago - Central Floor 8",
    },
    {
        "employee_id": "EMP-1014",
        "name": "Hannah Abbott",
        "department": "Legal & Compliance",
        "job_title": "Senior Regulatory Analyst",
        "employment_status": "On Leave",
        "data_classification": DataClassification.CONFIDENTIAL.value,
        "email": "hannah.abbott@privai-demo.internal",
        "phone": "555-019-0118",
        "salary": "$136,000 / year",
        "payroll_id": "PAY-4920",
        "health_notes": "Approved medical leave under confidential physician treatment plan.",
        "hire_date": "2021-03-08",
        "office_location": "New York - Tower B, Floor 22",
    },
    {
        "employee_id": "EMP-1015",
        "name": "Lucas Meyer",
        "department": "Engineering",
        "job_title": "QA Automation Lead",
        "employment_status": "Active",
        "data_classification": DataClassification.PUBLIC.value,
        "email": "lucas.meyer@privai-demo.internal",
        "phone": "555-019-0177",
        "salary": "$132,000 / year",
        "payroll_id": "PAY-3819",
        "health_notes": "Ergonomic review completed; standing desk issued.",
        "hire_date": "2023-01-09",
        "office_location": "Seattle - Suite 400",
    },
]


class EmployeeRepository:
    """Thread-safe isolated SQLite repository for synthetic demo employee directory.

    Security Invariants:
    1. Database Isolation: Operates strictly on EMPLOYEE_DEMO_DATABASE_PATH (privai_demo_employees.db).
       Never touches historical privai_data.db or forensic privai_data_incident_forensic.db.
    2. Reset Isolation: Reset Demo Data only clears and reseeds demo_employees.
    3. Thread-Safe: Uses connection per thread/query with serialized write locks.
    4. Deterministic: Seed records have stable IDs and reproducible attributes.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or settings.EMPLOYEE_DEMO_DATABASE_PATH
        self._lock = threading.Lock()
        self._enforce_isolation_check()
        self._init_schema()

    def _enforce_isolation_check(self) -> None:
        """Prevent misconfiguration that could target historical databases."""
        target = Path(self.db_path).resolve()
        hist = Path(settings.HISTORICAL_DATABASE_PATH).resolve()
        forensic = Path("privai_data_incident_forensic.db").resolve()
        if target == hist or target == forensic:
            raise SecurityInvariantException(
                f"EmployeeRepository cannot operate on protected database: {self.db_path}"
            )

    def _get_connection(self) -> sqlite3.Connection:
        self._enforce_isolation_check()
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS demo_employees (
                    employee_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    department TEXT NOT NULL,
                    job_title TEXT NOT NULL,
                    employment_status TEXT NOT NULL,
                    data_classification TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    salary TEXT NOT NULL,
                    payroll_id TEXT NOT NULL,
                    health_notes TEXT NOT NULL,
                    hire_date TEXT NOT NULL,
                    office_location TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_demo_emp_dept ON demo_employees(department)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_demo_emp_class ON demo_employees(data_classification)"
            )
            conn.commit()

            # Seed initial records if empty
            cursor = conn.execute("SELECT count(*) FROM demo_employees")
            count = cursor.fetchone()[0]
            if count == 0:
                self._seed_records_locked(conn)

    def _seed_records_locked(self, conn: sqlite3.Connection) -> int:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for emp in CANONICAL_DEMO_EMPLOYEES:
            conn.execute(
                """
                INSERT OR REPLACE INTO demo_employees (
                    employee_id, name, department, job_title, employment_status,
                    data_classification, email, phone, salary, payroll_id,
                    health_notes, hire_date, office_location, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    emp["employee_id"],
                    emp["name"],
                    emp["department"],
                    emp["job_title"],
                    emp["employment_status"],
                    emp["data_classification"],
                    emp["email"],
                    emp["phone"],
                    emp["salary"],
                    emp["payroll_id"],
                    emp["health_notes"],
                    emp["hire_date"],
                    emp["office_location"],
                    now,
                    now,
                ),
            )
        conn.commit()
        return len(CANONICAL_DEMO_EMPLOYEES)

    def reset_demo_data(self) -> int:
        """Reset only the synthetic demo employee dataset to default seed records.

        Guaranteed: Does NOT modify any historical, audit, or forensic database.
        """
        self._enforce_isolation_check()
        with self._lock, self._get_connection() as conn:
            conn.execute("DELETE FROM demo_employees")
            count = self._seed_records_locked(conn)
            return count

    def get_employee(self, employee_id: str) -> EmployeeRecord | None:
        """Retrieve full employee record by employee ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM demo_employees WHERE employee_id = ?",
                (employee_id.strip(),),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return EmployeeRecord(**dict(row))

    def search_employees(
        self,
        query: str | None = None,
        department: str | None = None,
        classification: str | None = None,
    ) -> list[EmployeeRecord]:
        """Search and filter synthetic employee directory."""
        sql = "SELECT * FROM demo_employees WHERE 1=1"
        params: list[Any] = []

        if query and query.strip():
            clean_q = f"%{query.strip().lower()}%"
            sql += (
                " AND (LOWER(employee_id) LIKE ? OR LOWER(name) LIKE ? OR LOWER(department) LIKE ? OR LOWER(job_title) LIKE ?)"
            )
            params.extend([clean_q, clean_q, clean_q, clean_q])

        if department and department.strip() and department.lower() != "all":
            sql += " AND LOWER(department) = ?"
            params.append(department.strip().lower())

        if classification and classification.strip() and classification.lower() != "all":
            sql += " AND LOWER(data_classification) = ?"
            params.append(classification.strip().lower())

        sql += " ORDER BY employee_id ASC"

        with self._get_connection() as conn:
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            return [EmployeeRecord(**dict(r)) for r in rows]

    def list_departments(self) -> list[str]:
        """List all distinct employee departments."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT DISTINCT department FROM demo_employees ORDER BY department ASC")
            return [r[0] for r in cursor.fetchall()]

    def list_classifications(self) -> list[str]:
        """List all distinct data classifications."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT DISTINCT data_classification FROM demo_employees ORDER BY data_classification ASC")
            return [r[0] for r in cursor.fetchall()]
