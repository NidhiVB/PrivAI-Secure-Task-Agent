# PrivAI — Local Setup, Deployment & Operational Runbook

**Document Version**: 1.0.0  
**Deployment Target**: Local Workstation / Staging Demonstration  
**Operating System**: Windows, Linux, macOS (Windows PowerShell verified)

---

## 1. Deployment Models

PrivAI supports two primary execution topologies:

### Model A: Development Mode (Two Independent Processes)
- **Backend**: FastAPI running on `http://127.0.0.1:8000`.
- **Frontend**: Vite development server running on `http://localhost:5173`.
- **Communication**: Vite's built-in development proxy (`frontend/vite.config.ts`) automatically forwards `/v1` and `/health` requests to `http://localhost:8000`, bypassing CORS.

### Model B: Single-Origin Production Mode (Unified Single Process)
- **Frontend**: Pre-compiled into static HTML/CSS/JS assets (`frontend/dist/`).
- **Backend**: FastAPI automatically detects `frontend/dist/` on startup and mounts it at `/` using Starlette `StaticFiles`.
- **Result**: Entire application (UI + REST API + Health) is served from a single port (`http://127.0.0.1:8000`) with zero cross-origin configuration required.

---

## 2. Windows PowerShell Step-by-Step Setup

### Step 1: Clone or Extract the Repository
```powershell
cd PrivAI_GitHub_Submission
# (Or your cloned/extracted repository directory)
```

### Step 2: Configure Environment Variables
Copy the template configuration file:
```powershell
Copy-Item .env.example .env
```
Default settings in `.env` are pre-configured for safe offline demonstrations:
- `PROVIDER_MODE=mock` (Zero external network egress)
- `DATABASE_PATH=privai_dev.db` (Isolated runtime review tickets)
- `AGENT_DATABASE_PATH=privai_agent.db` (Isolated agent tasks)
- `EMPLOYEE_DEMO_DATABASE_PATH=privai_demo_employees.db` (Isolated synthetic personnel directory)

### Step 3: Setup Python Backend Environment
Ensure Python 3.11+ is installed on your system.
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Setup Node.js Frontend Environment
Ensure Node.js 20+ and npm 10+ are installed.
```powershell
cd frontend

# Install npm dependencies
cmd /c "npm install"
# Or: npm.cmd install

cd ..
```

---

## 3. Starting the Application

### Option 1: Running in Development Mode

#### Terminal 1 (Backend):
```powershell
.venv\Scripts\activate
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

#### Terminal 2 (Frontend):
```powershell
cd frontend
cmd /c "npm run dev"
```
Open **`http://localhost:5173`** in your web browser.

---

### Option 2: Running in Unified Single-Origin Mode

1. Build the frontend production bundle:
   ```powershell
   cd frontend
   cmd /c "npm run build"
   cd ..
   ```
2. Start the FastAPI server:
   ```powershell
   .venv\Scripts\activate
   python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
   ```
3. Open **`http://localhost:8000`** directly. The compiled React single-page application is served directly from the FastAPI root.

---

## 4. Concurrency & Single-Worker Invariant

> [!IMPORTANT]
> **Single-Worker Requirement for SQLite**:
> In SQLite storage configurations, Uvicorn must run with `--workers 1`.
> 
> **Technical Rationale**:
> PrivAI coordinates audit event sequence numbers and review ticket states using process-level thread locks (`threading.Lock()`). In SQLite `DELETE` or `WAL` mode, running multiple OS worker processes without a distributed lock manager can cause database busy timeouts (`sqlite3.OperationalError: database is locked`).
> 
> Production multi-worker clusters require migrating to PostgreSQL or MySQL with row-level locks.

---

## 5. Demonstration Sharing & Tunneling Considerations

When sharing a live demonstration with remote evaluators (e.g. via Cloudflare Tunnels, ngrok, or Tailscale):

1. **Passkey Protection**:
   Configure a secret passkey in `.env`:
   ```dotenv
   TEAM_ACCESS_KEY=your-secure-demonstration-passkey
   ```
   When configured, all requests to `/v1/*` require header `x-privai-team-key: <passkey>` or query parameter `?team_key=<passkey>`.
2. **CORS Regex Matching**:
   The backend allows CORS origins matching `https://.*\.trycloudflare\.com` by default.
3. **Ephemeral URLs**:
   Temporary tunnel URLs expire when the tunnel process stops. Never hardcode tunnel URLs into persistent configuration or test scripts.

---

## 6. Enterprise Qualification Disclaimer

- **Tier 2 (Staging)**: Fully verified in this repository using in-memory local KMS key rotation and local REST ledger sidecar emulator (`scripts/run_staging_ledger.py`).
- **Tier 3 (Production Enterprise)**: Clustering against live HashiCorp Vault clusters and hardware immutable WORM ledgers remains unverified in this repository and should be qualified before production enterprise deployment.
