# PrivAI Frontend — React + TypeScript + Vite

Context-aware AI privacy firewall and redaction preview UI.

## Features
- **Deterministic Privacy Analysis**: Inspects sensitive entities, risk scores ($S, N, C, D, I$), and safe policy reason codes via `POST /v1/prompts/analyze`.
- **Zero Provider Calls Guarantee**: Analysis and non-authorized states (`BLOCK`, `REVIEW`) strictly bypass external AI provider dispatch.
- **Verified Redaction Preview**: Visualizes token substitutions (`[EMAIL]`, `[PHONE]`, etc.) and cryptographic post-redaction verification.
- **Authoritative Execution**: Dispatches through server-side permit gate via `POST /v1/prompts/execute`.
- **Anti-Bypass Invalidation**: Stale analysis invalidation immediately revokes execution permission whenever prompt text or context metadata changes.
- **Privacy Standard**: Zero prompt persistence in `localStorage`/`sessionStorage` and zero sensitive logs in browser console.

## Setup & Running Locally

### 1. Install Dependencies
```bash
npm install
```

### 2. Environment Variables (Optional)
By default, the Vite dev server proxies `/v1` and `/health` directly to `http://localhost:8000`.
To override the backend URL explicitly, create `.env`:
```env
VITE_API_BASE_URL=http://localhost:8000
```

### 3. Run Development Server
```bash
npm run dev
```
The application will be accessible at `http://localhost:5173`.

### 4. Run Test Suite
```bash
npm test
```

### 5. Production Build
```bash
npm run build
```
