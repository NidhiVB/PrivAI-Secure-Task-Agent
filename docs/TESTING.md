# PrivAI — Automated Testing & Verification Guide

**Document Version**: 1.0.0  
**Test Frameworks**: Pytest 8.3 (Backend) | Vitest 5.0 (Frontend)  
**Status**: All Tests Passing (100% Green Baseline)

---

## 1. Test Suite Summary & Actual Results

| Test Category | Framework | Test Files | Total Tests | Status | Execution Time |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Backend Unit & Integration** | Pytest | 17 files | **204 passed** | **PASS** | ~15.4 s |
| **Frontend Components & SPA** | Vitest | 7 files | **36 passed** | **PASS** | ~35.4 s |
| **Frontend Production Build** | TypeScript + Vite | `dist/` bundle | Compiled cleanly | **PASS** | ~1.1 s |
| **Employee Privacy Demo Test** | Python / TestClient | `verify_employee_demo.py` | 9 verification stages | **PASS** | ~2.5 s |
| **Reproducible Smoke Test** | Python / TestClient | `smoke_test.py` | 10 staged checks | **PASS** | ~3.1 s |

---

## 2. Running Backend Tests (Pytest)

### Environment Prerequisites
Ensure your Python virtual environment is activated and root directory is in `PYTHONPATH`:
```powershell
# Windows PowerShell:
cd PrivAI_GitHub_Submission
.venv\Scripts\activate
```

### Full Backend Suite
Run all 204 unit, integration, cryptographic, policy, agent, and security tests:
```powershell
python -m pytest -v
```

### Targeted Test Runs by Subsystem

#### 1. Core Privacy Firewall & Policy Engine
```powershell
python -m pytest tests/test_detector_redactor.py tests/test_risk_scoring.py tests/test_policy_engine.py -v
```
Verifies entity regex detection, RTL placeholder tokenization, post-redaction residual verifier, multi-factor risk scoring formula, and strict policy precedence.

#### 2. Secure Orchestration & API Security
```powershell
python -m pytest tests/test_secure_orchestration.py tests/test_api_integration.py tests/test_api_validation.py -v
```
Verifies server-side revalidation, internal permit gating, zero-call guarantees on BLOCK/REVIEW, and anti-tamper client rejection.

#### 3. PrivAI Secure Task Agent & Indirect Injection Defenses
```powershell
python -m pytest tests/test_agent.py -v
```
Verifies bounded planner (max 5 steps), server-side tool allowlist enforcement, path traversal rejection, untrusted data quarantine envelopes, and goal pre-screening.

#### 4. Employee Privacy Demo & Database Isolation
```powershell
python -m pytest tests/test_employee_privacy_demo.py -v
```
Verifies synthetic employee directory seeding (15 records), field-level authorization (salary=BLOCK, health=REVIEW, email=REDACT, name=ALLOW), 4 operational workflows, and strict database isolation.

#### 5. Human Review Workflow, KMS & Audit Checkpoint Anchoring
```powershell
python -m pytest tests/test_human_review_workflow.py tests/test_kms_key_management.py tests/test_audit_checkpoint_anchoring.py tests/test_audit_persistence_restart.py -v
```
Verifies AES-256-GCM envelope encryption at rest, HMAC-SHA256 single-use review permits, anti-replay atomic consumption, audit hash-chain continuity across restarts, and Merkle tree epoch checkpoints.

#### 6. Groq Cloud Provider Integration
```powershell
python -m pytest tests/test_groq_provider.py -v
```
Verifies OpenAI-compatible chat completion payload formatting, sanitized-only transmission for REDACT, and strict zero provider calls for BLOCK/REVIEW (using offline mocked HTTP transports).

---

## 3. Running Frontend Tests (Vitest)

### Windows PowerShell Execution
To avoid Windows script execution policy restrictions on `.ps1` wrappers, run via `npm.cmd` or `cmd /c`:
```powershell
cd PrivAI_GitHub_Submission\frontend
cmd /c "npm test"
# Or: npm.cmd test
```

### Frontend Test Suite Breakdown
The 36 frontend tests across 7 test files verify:
1. `App.test.tsx` (5 tests):
   - Renders application header, status indicators, and prompt editor.
   - **Anti-Bypass Invariant**: Modifying prompt text after analysis instantly invalidates prior analysis and locks execution buttons.
2. `ActionControls.test.tsx` (7 tests):
   - Destination selector (`mock` vs. `groq`).
   - Button states, keyboard shortcuts, and execution progress states.
3. `AnalysisPanel.test.tsx` (4 tests):
   - Risk score gauge rendering (0–100) and factor decomposition ($S, N, C, D, I$).
   - Finding cards displaying category, confidence, and severity without exposing raw sensitive text.
4. `PromptEditor.test.tsx` (5 tests):
   - Real-time UTF-8 byte meter (enforcing 10 KiB ceiling).
   - Scenario preset loading and context form selectors.
5. `RedactionAndResponse.test.tsx` (4 tests):
   - Redaction preview with token replacements (`[EMAIL]`, `[PHONE]`, etc.).
   - Model response display, latency meter, and audit reference hashes.
6. `AgentWorkbench.test.tsx` (4 tests):
   - Task goal input, preset tasks, bounded plan visualization, step badges, and final answers.
7. `EmployeePrivacyDemo.test.tsx` (7 tests):
   - Synthetic employee directory table and search filters.
   - Field-level authorization inspector and masking badges.
   - Operational workflow execution (`ALLOW`, `REDACT`, `BLOCK`, `REVIEW`) and Reset Demo Data action.

---

## 4. Frontend Production Build Verification

Verify that the TypeScript types compile and Vite packages the single-page application into production assets:
```powershell
cd PrivAI_GitHub_Submission\frontend
cmd /c "npm run build"
```
**Expected Output**:
```
vite v8.3.4 building client environment for production...
transforming...
✓ 1933 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                   0.98 kB │ gzip:  0.52 kB
dist/assets/index-Co7PAb3P.css    9.27 kB │ gzip:  2.43 kB
dist/assets/index-CWQScmV8.js   324.72 kB │ gzip: 91.47 kB
✓ built in ~1.1s
```

---

## 5. Automated Verification Scripts

The repository includes standalone, reproducible Python verification scripts in `scripts/`:

### 1. Employee Privacy Demo Local Verification
```powershell
python scripts/verify_employee_demo.py
```
Runs 9 verification checks verifying health, synthetic employee directory seeding, department queries, field masking policies, and all 4 operational workflows.

### 2. PrivAI Staging Smoke Test
```powershell
python scripts/smoke_test.py
```
Executes safe non-destructive checks against health probes, ALLOW execution, REDACT sanitization, BLOCK zero-call enforcement, REVIEW ticket creation, audit hash-chain continuity across restarts, and fail-closed persistence.

### 3. Preflight System Checks
```powershell
python scripts/preflight_checks.py
```
Validates runtime dependencies, payload limits, and isolated temporary database configurations.

### 4. Audit Checkpoint Ledger Emulator
```powershell
python scripts/run_staging_ledger.py
```
Starts a lightweight local HTTP ledger sidecar emulator (port 8443) that validates Merkle tree checkpoint anchoring and returns signed receipts.
