# PrivAI API Contracts and End-to-End Security Specifications

Base path: `/v1`. JSON content type. Strict request validation (`extra="forbid"`).
Maximum JSON body size: **32 KiB** (`32768` bytes).
Maximum prompt UTF-8 length: **10 KiB** (`10240` bytes).

Security Invariant: Raw prompts, detected sensitive values, credentials, and internal stack traces are never echoed in error messages, audit logs, or response headers.

---

## 1. `POST /v1/prompts/analyze`

Analyzes prompt locally through deterministic detection, factor-based risk scoring, and policy evaluation.
**Critical Invariant:** Strictly **zero AI provider calls** are made under any circumstance.

### Headers
```http
Content-Type: application/json
```

### Request Schema
```json
{
  "prompt": "string, required, 1..10240 UTF-8 bytes",
  "destination": "mock | groq",
  "context": {
    "purpose": "general_question | summarization | coding | hr_workflow | health_information | other",
    "data_subject": "none | self | third_party | employee | unknown",
    "classification": "public | internal | confidential | restricted"
  }
}
```

### Example 1: Benign Prompt (ALLOW)

#### Request
```json
{
  "prompt": "Explain the concept of public key cryptography.",
  "destination": "mock",
  "context": {
    "purpose": "general_question",
    "data_subject": "none",
    "classification": "public"
  }
}
```

#### Response `200 OK`
```json
{
  "analysis_id": "c1f7b03e-5197-4d7a-b9d9-2d1f486d34e9",
  "request_digest": "sha256:d8a2f4e3b1c67890abcdef1234567890abcdef1234567890abcdef1234567890",
  "decision": "ALLOW",
  "risk": {
    "score": 0,
    "band": "low",
    "factors": {
      "severity": 0.0,
      "count": 0,
      "normalized_count": 0.0,
      "context": 0.0,
      "destination": 0.0,
      "identifiability": 0.0
    },
    "factor_contributions": {
      "severity": 0.0,
      "count": 0.0,
      "context": 0.0,
      "destination": 0.0,
      "identifiability": 0.0
    },
    "reason_codes": [
      "SCORE-ZERO-RISK",
      "SCORE-BAND-LOW"
    ],
    "version": "risk-v1"
  },
  "findings": [],
  "explanation": {
    "rule_ids": ["DEFAULT-ALLOW"],
    "summary": "No configured sensitive patterns were detected and risk is within safe limits.",
    "actions": []
  },
  "policy_version": "policy-v1"
}
```

### Example 2: Sensitive Email (REDACT)

#### Request
```json
{
  "prompt": "Please contact test.user@example.org for technical inquiries.",
  "destination": "mock",
  "context": {
    "purpose": "general_question",
    "data_subject": "none",
    "classification": "public"
  }
}
```

#### Response `200 OK`
```json
{
  "analysis_id": "8e3b1d92-7204-4b51-9ca3-1a2f647e8b90",
  "request_digest": "sha256:3a1e7b9c0d4f5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
  "decision": "REDACT",
  "risk": {
    "score": 26,
    "band": "moderate",
    "factors": {
      "severity": 0.5,
      "count": 1,
      "normalized_count": 0.2,
      "context": 0.0,
      "destination": 0.0,
      "identifiability": 0.7
    },
    "factor_contributions": {
      "severity": 0.15,
      "count": 0.02,
      "context": 0.0,
      "destination": 0.0,
      "identifiability": 0.105
    },
    "reason_codes": [
      "SCORE-FACTOR-SEVERITY",
      "SCORE-FACTOR-COUNT",
      "SCORE-FACTOR-IDENTIFIABILITY",
      "SCORE-BAND-MODERATE"
    ],
    "version": "risk-v1"
  },
  "findings": [
    {
      "rule_id": "DETECT-EMAIL-001",
      "category": "EMAIL",
      "start": 15,
      "end": 36,
      "confidence": 0.95,
      "severity": 0.5
    }
  ],
  "explanation": {
    "rule_ids": ["REDACT-EMAIL"],
    "summary": "Sanitization required: Email addresses must be sanitized before transmission.",
    "actions": ["Review the sanitized prompt."]
  },
  "policy_version": "policy-v1"
}
```

### Example 3: National Identifier (BLOCK)

#### Request
```json
{
  "prompt": "Subject verification token: 999-00-1234",
  "destination": "mock",
  "context": {
    "purpose": "general_question",
    "data_subject": "none",
    "classification": "public"
  }
}
```

#### Response `200 OK`
```json
{
  "analysis_id": "2b4c6e80-1a3f-4e5b-9c7d-8f0a2b4c6e80",
  "request_digest": "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
  "decision": "BLOCK",
  "risk": {
    "score": 47,
    "band": "moderate",
    "factors": {
      "severity": 1.0,
      "count": 1,
      "normalized_count": 0.2,
      "context": 0.0,
      "destination": 0.0,
      "identifiability": 1.0
    },
    "factor_contributions": {
      "severity": 0.3,
      "count": 0.02,
      "context": 0.0,
      "destination": 0.0,
      "identifiability": 0.15
    },
    "reason_codes": [
      "SCORE-FACTOR-SEVERITY",
      "SCORE-FACTOR-COUNT",
      "SCORE-FACTOR-IDENTIFIABILITY",
      "SCORE-BAND-MODERATE"
    ],
    "version": "risk-v1"
  },
  "findings": [
    {
      "rule_id": "DETECT-NATID-001",
      "category": "NATIONAL_ID",
      "start": 28,
      "end": 39,
      "confidence": 0.95,
      "severity": 1.0
    }
  ],
  "explanation": {
    "rule_ids": ["BLOCK-NATIONAL-ID"],
    "summary": "Request blocked by policy: Government and national personal identifiers are prohibited from transmission.",
    "actions": ["Remove restricted or prohibited content and resubmit."]
  },
  "policy_version": "policy-v1"
}
```

---

## 2. `POST /v1/prompts/execute`

Executes prompt through the privacy firewall, central orchestrator, and guarded provider gateway.

**Security Invariants:**
1. Revalidates and re-evaluates the exact prompt submitted for execution.
2. Client-supplied analysis IDs, risk scores, decisions, or sanitized prompts are rejected or ignored.
3. Transmits **only** the original prompt for `ALLOW`.
4. Transmits **only** the verified sanitized prompt for `REDACT`.
5. Strictly **zero provider calls** for `BLOCK` or `REVIEW`.
6. Fails closed on any security verification failure, component error, or audit outage.

### Example 1: Authorized ALLOW Execution

#### Request
```json
{
  "prompt": "How does binary search work on sorted arrays?",
  "destination": "mock",
  "context": {
    "purpose": "general_question",
    "data_subject": "none",
    "classification": "public"
  }
}
```

#### Response `200 OK`
```json
{
  "request_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "completed",
  "decision": "ALLOW",
  "risk": {
    "score": 0,
    "band": "low",
    "version": "risk-v1"
  },
  "redactions": null,
  "provider": {
    "name": "mock",
    "model": "mock-v1"
  },
  "output": "Mock response generated locally.",
  "explanation": {
    "rule_ids": ["DEFAULT-ALLOW"],
    "summary": "No configured sensitive patterns were detected and risk is within safe limits.",
    "actions": []
  },
  "policy_version": "policy-v1"
}
```

### Example 2: Verified REDACT Execution

#### Request
```json
{
  "prompt": "Contact dev.lead@example.net or call 555-123-4567.",
  "destination": "mock",
  "context": {
    "purpose": "general_question",
    "data_subject": "none",
    "classification": "public"
  }
}
```

#### Response `200 OK`
```json
{
  "request_id": "7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e",
  "status": "completed",
  "decision": "REDACT",
  "risk": {
    "score": 30,
    "band": "moderate",
    "version": "risk-v1"
  },
  "redactions": [
    {
      "category": "EMAIL",
      "placeholder": "[EMAIL]"
    },
    {
      "category": "PHONE",
      "placeholder": "[PHONE]"
    }
  ],
  "provider": {
    "name": "mock",
    "model": "mock-v1"
  },
  "output": "Mock response generated locally.",
  "explanation": {
    "rule_ids": ["REDACT-EMAIL", "REDACT-PHONE"],
    "summary": "Sanitization required: Email addresses must be sanitized before transmission.; Phone numbers must be sanitized before transmission.",
    "actions": ["Review the sanitized prompt."]
  },
  "policy_version": "policy-v1"
}
```

### Example 3: Mandatory BLOCK Execution (Zero Provider Calls)

#### Request
```json
{
  "prompt": "Confidential employee appraisal for EMP-123456.",
  "destination": "mock",
  "context": {
    "purpose": "hr_workflow",
    "data_subject": "employee",
    "classification": "confidential"
  }
}
```

#### Response `200 OK`
```json
{
  "request_id": "4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a",
  "status": "blocked",
  "decision": "BLOCK",
  "risk": {
    "score": 47,
    "band": "moderate",
    "version": "risk-v1"
  },
  "redactions": null,
  "provider": null,
  "output": null,
  "explanation": {
    "rule_ids": ["BLOCK-CONFIDENTIAL-HR-EMPID"],
    "summary": "Request blocked by policy: Employee identifiers tied to confidential HR workflows cannot be transmitted.",
    "actions": ["Remove restricted or prohibited content and resubmit."]
  },
  "policy_version": "policy-v1"
}
```

### Example 4: Pending REVIEW Execution (Zero Provider Calls)

#### Request
```json
{
  "prompt": "Patient diagnosis notes and therapy history.",
  "destination": "mock",
  "context": {
    "purpose": "health_information",
    "data_subject": "self",
    "classification": "public"
  }
}
```

#### Response `200 OK`
```json
{
  "request_id": "5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9a0b",
  "status": "review_pending",
  "decision": "REVIEW",
  "risk": {
    "score": 53,
    "band": "high",
    "version": "risk-v1"
  },
  "redactions": null,
  "provider": null,
  "output": null,
  "explanation": {
    "rule_ids": ["REVIEW-HEALTH-DATA"],
    "summary": "Request held for human review: Identifiable health details require authorized human review before transmission.",
    "actions": ["Hold for authorized human review before transmission."]
  },
  "policy_version": "policy-v1"
}
```

---

## 3. Standard HTTP Status Codes

| Status | Code | Meaning | Provider Called? |
|---|---|---|---|
| **200** | `OK` | Valid analysis completed or execution returned authoritative policy decision | Only if `ALLOW` or verified `REDACT` |
| **400** | `BAD_REQUEST` | Malformed JSON syntax, invalid headers, or unparseable payload | **No** |
| **413** | `PAYLOAD_TOO_LARGE` | Prompt exceeds 10 KiB or JSON body exceeds 32 KiB | **No** |
| **422** | `UNPROCESSABLE_ENTITY` | Schema validation error, extra forbidden fields, empty prompt, or unsafe control characters | **No** |
| **502** | `BAD_GATEWAY` | AI provider execution error, outage, or timeout | Allowed request was transmitted; provider failed |
| **503** | `SERVICE_UNAVAILABLE` | Policy engine, detector, verifier, or required audit storage failed | **No** (Fails closed prior to transmission) |

---

## 4. Standard Safe Error Response Envelope

All error responses return a standardized, non-leaking JSON envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR | PAYLOAD_TOO_LARGE | PROVIDER_ERROR | POLICY_UNAVAILABLE",
    "message": "Safe human-readable explanation without sensitive details.",
    "request_id": "opaque-uuid"
  }
}
```

**Security Invariants:**
1. Never echoes raw prompt content or detected sensitive values.
2. Never includes internal stack traces, filenames, or server filesystem paths.
3. Never leaks upstream provider API tokens or authorization headers.
