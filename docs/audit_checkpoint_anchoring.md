# PrivAI External Audit Checkpoint Anchoring

This document specifies the architecture, cryptographic Merkle tree design, external anchoring adapter contracts, trust model, and operational recovery procedures for PrivAI's external audit checkpoint anchoring subsystem.

---

## 1. Overview & Architectural Motivation

PrivAI records privacy-safe operational metadata for all prompt evaluation, redaction, human-review, and provider dispatch events. In Milestones 1–7, this operational metadata was secured via **local SHA-256 hash chaining** in SQLite (`prev_hash` $\to$ `record_hash`).

### The Distinction Between Local Chaining & External Anchoring

| Dimension | Local SHA-256 Hash Chaining | External Audit Checkpoint Anchoring |
| :--- | :--- | :--- |
| **Trust Domain** | Internal database (`privai_data.db`). | External, independently protected WORM storage / Transparency Log. |
| **Tamper Detection** | Detects unauthorized record mutation **if** the hash chain is recomputed from genesis. | Provides mathematical proof against unauthorized mutation even if the local database is entirely rewritten. |
| **Attacker Resistance** | Vulnerable to privileged attackers (DBA, root server access) who can mutate events and recompute valid intermediate hashes. | Privileged local attackers cannot mutate historical events without invalidating inclusion proofs against externally anchored roots. |
| **Verification Scope** | Requires scanning the entire sequence of events from genesis. | $O(\log N)$ Merkle inclusion proof verification for any individual event against an anchored checkpoint root. |
| **Legal / Compliance** | Soft tamper-evidence (internal logs). | Hard non-repudiation and external transparency (external ledger receipts). |

---

## 2. Deterministic Merkle Tree Specification

PrivAI adopts the **RFC 6962** (Certificate Transparency) standard for Merkle tree construction over audit events to provide cryptographic domain separation and second-preimage attack resistance.

### Leaf and Node Domain Separation

To prevent collision attacks between leaf records and interior tree nodes, single-byte prefixes are prepended prior to SHA-256 hashing:

- **Leaf Hash ($H_{\text{leaf}}$)**:
  $$H_{\text{leaf}}(e) = \text{SHA-256}\Big(\mathtt{0x00} \parallel \text{UTF-8}(e.\text{record\_hash})\Big)$$
- **Interior Node Hash ($H_{\text{node}}$)**:
  $$H_{\text{node}}(L, R) = \text{SHA-256}\Big(\mathtt{0x01} \parallel L \parallel R\Big)$$

### Odd-Node Handling (RFC 6962 Rule)

In unbalanced trees or layers with an odd number of nodes:
- When a layer contains an odd number of nodes $2k + 1$, the first $2k$ nodes are paired: $(N_0, N_1), \dots, (N_{2k-2}, N_{2k-1})$.
- The final unpaired node $N_{2k}$ is **promoted directly to the next layer without re-hashing**:
  $$L_{j+1}[k] = L_j[2k]$$
- This avoids artificial node duplication and preserves strict deterministic symmetry.

### Merkle Inclusion Proof Generation & Verification

For any audit event with `sequence_number` $S$ within checkpoint epoch $[S_{\text{start}}, S_{\text{end}}]$:
1. The leaf index is computed: $\text{leaf\_index} = S - S_{\text{start}}$.
2. For each layer in the Merkle tree, the sibling hash is recorded along with its direction (`left` or `right`).
3. If an odd node is promoted at a layer, no sibling is appended for that layer.
4. **Verification**: Starting from the candidate leaf hash $H_{\text{leaf}}(\text{record\_hash})$, the proof path is folded:
   - If sibling is `left`: $\text{current} \gets \text{SHA-256}(\mathtt{0x01} \parallel \text{sibling} \parallel \text{current})$
   - If sibling is `right`: $\text{current} \gets \text{SHA-256}(\mathtt{0x01} \parallel \text{current} \parallel \text{sibling})$
5. The computed root must match `checkpoint.merkle_root` exactly.

---

## 3. Deterministic Checkpoint Schema

Each checkpoint captures a contiguous, ordered range of audit events:

```json
{
  "checkpoint_id": "chk-00000001-00000100-3f8a2b1c",
  "epoch_index": 1,
  "start_sequence": 1,
  "end_sequence": 100,
  "event_count": 100,
  "merkle_root": "a7b3c4d5e6f7...64-char-hex",
  "prev_checkpoint_hash": "2496a79857d42cf898dfefda6d9e03d4061a9386419d297ff04c1c2aa84333b2",
  "checkpoint_hash": "e1f2a3b4c5d6...64-char-hex",
  "anchor_status": "ANCHORED",
  "anchor_reference": "worm-rec-00000001-3f8a2b1c",
  "anchored_at": "2026-10-18T14:40:00Z",
  "created_at": "2026-10-18T14:39:58Z",
  "failure_reason": null
}
```

### Invariants Enforced
1. **Contiguity**: For epoch $E > 1$, $\text{start\_sequence} = \text{checkpoint}_{E-1}.\text{end\_sequence} + 1$.
2. **No Overlaps or Gaps**: Event sequences must be strictly sequential without missing entries.
3. **Chain of Trees**: `prev_checkpoint_hash` binds checkpoint $E$ to checkpoint $E-1$, chaining all historical epochs back to `GENESIS_CHECKPOINT_HASH`.
4. **Canonical Checkpoint Hash**:
   $$\text{checkpoint\_hash} = \text{SHA-256}\Big(\text{prev\_hash} \mid \text{epoch} \mid \text{start} \mid \text{end} \mid \text{count} \mid \text{merkle\_root}\Big)$$

---

## 4. External Anchoring Adapter Architecture

The anchoring subsystem follows a pluggable adapter model:

```
                  ┌────────────────────────────────────────┐
                  │       BaseAuditAnchorAdapter           │
                  │ (anchor_checkpoint, verify_receipt)   │
                  └───────────────────▲────────────────────┘
                                      │
               ┌──────────────────────┴──────────────────────┐
               │                                             │
┌──────────────────────────────┐              ┌──────────────────────────────┐
│    MockAuditAnchorAdapter    │              │ ProductionAuditAnchorAdapter │
│ (Offline / Automated Tests)  │              │ (REST Ledger / WORM Service) │
│ - In-memory receipt log      │              │ - Transient 503/timeout retry│
│ - Simulated latency/failure  │              │ - Token credential hygiene   │
│ - Idempotent re-anchoring    │              │ - Cryptographic receipts     │
└──────────────────────────────┘              └──────────────────────────────┘
```

### Configuration Environment Variables

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `AUDIT_ANCHOR_PROVIDER` | string | `mock` | `mock` (in-memory test adapter) or `production` (external REST service). |
| `AUDIT_ANCHOR_ENDPOINT` | string | `""` | HTTPS endpoint of the immutable ledger service. |
| `AUDIT_ANCHOR_AUTH_TOKEN` | string | `""` | Bearer authentication token for external ledger dispatch. |
| `AUDIT_ANCHOR_TIMEOUT_SECONDS` | float | `5.0` | Socket and HTTP connection timeout. |
| `AUDIT_ANCHOR_MAX_RETRIES` | int | `3` | Maximum retry attempts on transient network or 503 errors. |
| `AUDIT_ANCHOR_REQUIRED` | bool | `true` | If `true`, failed external anchor fails closed and raises an exception. |
| `AUDIT_CHECKPOINT_EPOCH_SIZE`| int | `100` | Recommended default batch size for periodic anchoring epochs. |

---

## 5. Trust Model & Failure Handling

### The Fail-Closed Invariant
Under **Requirement 5**, PrivAI **never claims an audit checkpoint is externally anchored until the external system confirms success**. 
- A checkpoint starts in `PENDING` status.
- Only upon verified return of an `AuditAnchorReceipt` is its status updated to `ANCHORED`.
- If the external anchor call fails (due to timeout, 401/403 authorization failure, or ledger outage), the checkpoint is marked `FAILED` with a sanitized failure reason.
- If `AUDIT_ANCHOR_REQUIRED=True`, the service immediately aborts and raises `AuditAnchorException`, preventing subsequent epochs from building on an unanchored epoch.

### Local Acknowledgement Crash Recovery (Two-Phase Failure)
If the external ledger successfully anchors the root, but the PrivAI local server crashes before recording the receipt into SQLite:
1. The local checkpoint record remains `FAILED` or unrecorded.
2. The recovery retry calls `create_checkpoint(start_sequence, end_sequence)` with the identical range.
3. The anchoring adapter's `anchor_checkpoint` method is idempotent: it detects the existing remote record and returns the existing receipt.
4. The local service transitions the checkpoint from `FAILED` to `ANCHORED`, restoring local and external synchronization without data loss or duplication.

---

## 6. Auditor REST API Endpoints

PrivAI provides auditor endpoints protected by Role-Based Access Control (RBAC):
- **Authorized Roles**: `PrivAI:Auditor`, `PrivAI:SecurityAdmin`, `PrivAI:ComplianceOfficer`.
- **Privacy Assurance**: Endpoints return only sequence numbers, hashes, timestamps, and Merkle proofs. Raw prompts, sanitized text, API keys, and KMS secrets are strictly omitted.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/v1/audit/checkpoints` | List chronological checkpoints with pagination (`limit`, `offset`). |
| `GET` | `/v1/audit/checkpoints/latest` | Retrieve the latest recorded checkpoint. |
| `GET` | `/v1/audit/checkpoints/{id}` | Retrieve metadata and anchor status for a specific checkpoint. |
| `GET` | `/v1/audit/checkpoints/{id}/proof/{sequence_number}` | Generate RFC 6962 inclusion proof for an individual event. |
| `GET` | `/v1/audit/checkpoints/{id}/verify` | Self-verify checkpoint integrity against raw SQLite event chain. |
| `POST` | `/v1/audit/checkpoints` | (Restricted to SecurityAdmin) Trigger manual checkpoint anchoring. |

---

## 7. Retention & Archival Policy

1. **Epoch Sizing**: Automated checkpointing should run every `AUDIT_CHECKPOINT_EPOCH_SIZE` (default 100) events, or at scheduled time boundaries (e.g., hourly).
2. **Cold Storage Archival**: Checkpoint metadata (`epoch_index`, `merkle_root`, `prev_checkpoint_hash`, `anchor_reference`) must be preserved permanently.
3. **Database Pruning**: If SQLite disk usage requires pruning old operational records, records may be archived to secondary storage **only in complete checkpoint batches**. The Merkle root preserved in the checkpoint guarantees verifiable inclusion even if historical events are moved to cold object storage.
