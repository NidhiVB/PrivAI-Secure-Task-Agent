/**
 * PrivAI API Client Service
 *
 * Security Invariants:
 * - Never log raw prompt content or sensitive values to console.
 * - Extracts only safe, server-sanitized error messages.
 * - Authoritative backend validation and policy enforcement.
 */

import type {
  HealthResponse,
  PromptAnalyzeResponse,
  PromptExecuteResponse,
  PromptRequest,
} from '../types/api'

let _rawBaseUrl = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '')
if (_rawBaseUrl && !_rawBaseUrl.startsWith('http://') && !_rawBaseUrl.startsWith('https://')) {
  _rawBaseUrl = `https://${_rawBaseUrl}`
}
const API_BASE_URL = _rawBaseUrl

export class ApiError extends Error {
  code: string
  requestId?: string
  status: number

  constructor(message: string, code: string = 'API_ERROR', status: number = 500, requestId?: string) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
    this.requestId = requestId
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let errorCode = `HTTP_${response.status}`
    let errorMessage = `Request failed with status ${response.status}`
    let requestId: string | undefined

    try {
      const data = (await response.json()) as Record<string, unknown>
      if ('error' in data && data.error && typeof data.error === 'object') {
        const err = data.error as { code?: string; message?: string; request_id?: string }
        if (err.code) errorCode = err.code
        if (err.message) errorMessage = err.message
        if (err.request_id) requestId = err.request_id
      } else if ('detail' in data && typeof data.detail === 'string') {
        errorMessage = data.detail
      }
    } catch {
      // JSON parse error or empty body; keep safe generic status message
    }

    throw new ApiError(errorMessage, errorCode, response.status, requestId)
  }

  return response.json() as Promise<T>
}

export function getTeamAccessKey(): string {
  try {
    return sessionStorage.getItem('privai_team_key') || (import.meta.env.VITE_TEAM_ACCESS_KEY as string) || ''
  } catch {
    return ''
  }
}

export function setTeamAccessKey(key: string): void {
  try {
    if (key) {
      sessionStorage.setItem('privai_team_key', key.trim())
    } else {
      sessionStorage.removeItem('privai_team_key')
    }
  } catch {
    // Ignore storage issues in test/private browsing environments
  }
}

function buildHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = { ...extra }
  const teamKey = getTeamAccessKey()
  if (teamKey) {
    headers['x-privai-team-key'] = teamKey
  }
  return headers
}

/**
 * Fetch backend health status.
 */
export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const url = `${API_BASE_URL}/health`
  const response = await fetch(url, {
    method: 'GET',
    headers: buildHeaders({
      Accept: 'application/json',
    }),
    signal,
  })
  return handleResponse<HealthResponse>(response)
}

/**
 * Perform pre-flight privacy analysis on a prompt.
 * Guarantee: Zero AI provider calls.
 */
export async function analyzePrompt(
  request: PromptRequest,
  signal?: AbortSignal
): Promise<PromptAnalyzeResponse> {
  const url = `${API_BASE_URL}/v1/prompts/analyze`
  const response = await fetch(url, {
    method: 'POST',
    headers: buildHeaders({
      'Content-Type': 'application/json',
      Accept: 'application/json',
    }),
    body: JSON.stringify(request),
    signal,
  })
  return handleResponse<PromptAnalyzeResponse>(response)
}

/**
 * Submit prompt for authoritative server-side execution.
 * Guarantee: Server revalidates all rules; dispatches to provider ONLY on authorized ALLOW / REDACT.
 */
export async function executePrompt(
  request: PromptRequest,
  signal?: AbortSignal
): Promise<PromptExecuteResponse> {
  const url = `${API_BASE_URL}/v1/prompts/execute`
  const response = await fetch(url, {
    method: 'POST',
    headers: buildHeaders({
      'Content-Type': 'application/json',
      Accept: 'application/json',
    }),
    body: JSON.stringify(request),
    signal,
  })
  return handleResponse<PromptExecuteResponse>(response)
}

/**
 * Fetch pending review tickets using authenticated reviewer JWT.
 */
export async function listPendingReviews(
  token: string,
  signal?: AbortSignal
): Promise<import('../types/api').ReviewPendingListResponse> {
  const url = `${API_BASE_URL}/v1/reviews/pending`
  const response = await fetch(url, {
    method: 'GET',
    headers: buildHeaders({
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    }),
    signal,
  })
  return handleResponse<import('../types/api').ReviewPendingListResponse>(response)
}

/**
 * Approve a pending review ticket and mint a single-use review permit.
 */
export async function approveReview(
  ticketId: string,
  rationale: string,
  token: string,
  signal?: AbortSignal
): Promise<import('../types/api').ReviewActionResponse> {
  const url = `${API_BASE_URL}/v1/reviews/${encodeURIComponent(ticketId)}/approve`
  const response = await fetch(url, {
    method: 'POST',
    headers: buildHeaders({
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    }),
    body: JSON.stringify({ rationale }),
    signal,
  })
  return handleResponse<import('../types/api').ReviewActionResponse>(response)
}

/**
 * Reject a pending review ticket. Never issues a permit.
 */
export async function rejectReview(
  ticketId: string,
  rationale: string,
  token: string,
  signal?: AbortSignal
): Promise<import('../types/api').ReviewActionResponse> {
  const url = `${API_BASE_URL}/v1/reviews/${encodeURIComponent(ticketId)}/reject`
  const response = await fetch(url, {
    method: 'POST',
    headers: buildHeaders({
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    }),
    body: JSON.stringify({ rationale }),
    signal,
  })
  return handleResponse<import('../types/api').ReviewActionResponse>(response)
}

/**
 * PrivAI Secure Task Agent API Calls
 */

export async function createAgentTask(
  request: import('../types/api').AgentTaskCreateRequest,
  signal?: AbortSignal
): Promise<import('../types/api').AgentTaskResponse> {
  const url = `${API_BASE_URL}/v1/agent/tasks`
  const response = await fetch(url, {
    method: 'POST',
    headers: buildHeaders({
      'Content-Type': 'application/json',
      Accept: 'application/json',
    }),
    body: JSON.stringify(request),
    signal,
  })
  return handleResponse<import('../types/api').AgentTaskResponse>(response)
}

export async function getAgentTask(
  taskId: string,
  signal?: AbortSignal
): Promise<import('../types/api').AgentTaskResponse> {
  const url = `${API_BASE_URL}/v1/agent/tasks/${encodeURIComponent(taskId)}`
  const response = await fetch(url, {
    method: 'GET',
    headers: buildHeaders({
      Accept: 'application/json',
    }),
    signal,
  })
  return handleResponse<import('../types/api').AgentTaskResponse>(response)
}

export async function getAgentTaskSteps(
  taskId: string,
  signal?: AbortSignal
): Promise<import('../types/api').AgentStepsResponse> {
  const url = `${API_BASE_URL}/v1/agent/tasks/${encodeURIComponent(taskId)}/steps`
  const response = await fetch(url, {
    method: 'GET',
    headers: buildHeaders({
      Accept: 'application/json',
    }),
    signal,
  })
  return handleResponse<import('../types/api').AgentStepsResponse>(response)
}

export async function resumeAgentTask(
  taskId: string,
  request: import('../types/api').AgentTaskResumeRequest,
  signal?: AbortSignal
): Promise<import('../types/api').AgentTaskResponse> {
  const url = `${API_BASE_URL}/v1/agent/tasks/${encodeURIComponent(taskId)}/resume`
  const response = await fetch(url, {
    method: 'POST',
    headers: buildHeaders({
      'Content-Type': 'application/json',
      Accept: 'application/json',
    }),
    body: JSON.stringify(request),
    signal,
  })
  return handleResponse<import('../types/api').AgentTaskResponse>(response)
}

/**
 * PrivAI Employee Privacy Demo API Calls
 */

export async function getEmployees(
  params?: {
    query?: string
    department?: string
    classification?: string
    limit?: number
    offset?: number
  },
  signal?: AbortSignal
): Promise<import('../types/api').EmployeeSearchResponse> {
  const queryParams = new URLSearchParams()
  if (params?.query) {
    queryParams.set('q', params.query)
    queryParams.set('query', params.query)
  }
  if (params?.department) queryParams.set('department', params.department)
  if (params?.classification) queryParams.set('classification', params.classification)
  if (params?.limit !== undefined) queryParams.set('limit', String(params.limit))
  if (params?.offset !== undefined) queryParams.set('offset', String(params.offset))

  const qs = queryParams.toString()
  const url = `${API_BASE_URL}/v1/employees${qs ? `?${qs}` : ''}`
  const response = await fetch(url, {
    method: 'GET',
    headers: buildHeaders({
      Accept: 'application/json',
    }),
    signal,
  })
  const raw = await handleResponse<Record<string, unknown>>(response)
  const employees = Array.isArray(raw.employees) ? (raw.employees as import('../types/api').EmployeeSummary[]) : []
  const count = typeof raw.total === 'number'
    ? raw.total
    : typeof raw.total_count === 'number'
    ? raw.total_count
    : employees.length
  return {
    employees,
    total_count: count,
    total: count,
    departments: Array.isArray(raw.departments) ? (raw.departments as string[]) : [],
    classifications: Array.isArray(raw.classifications) ? (raw.classifications as string[]) : [],
  }
}

export async function getEmployeeDetail(
  employeeId: string,
  signal?: AbortSignal
): Promise<import('../types/api').EmployeeDetailResponse> {
  const url = `${API_BASE_URL}/v1/employees/${encodeURIComponent(employeeId)}`
  const response = await fetch(url, {
    method: 'GET',
    headers: buildHeaders({
      Accept: 'application/json',
    }),
    signal,
  })
  return handleResponse<import('../types/api').EmployeeDetailResponse>(response)
}

export async function getEmployeeDepartments(signal?: AbortSignal): Promise<string[]> {
  const url = `${API_BASE_URL}/v1/employees/departments`
  const response = await fetch(url, {
    method: 'GET',
    headers: buildHeaders({
      Accept: 'application/json',
    }),
    signal,
  })
  return handleResponse<string[]>(response)
}

export async function getEmployeeClassifications(signal?: AbortSignal): Promise<string[]> {
  const url = `${API_BASE_URL}/v1/employees/classifications`
  const response = await fetch(url, {
    method: 'GET',
    headers: buildHeaders({
      Accept: 'application/json',
    }),
    signal,
  })
  return handleResponse<string[]>(response)
}

export async function resetEmployeeDemoData(signal?: AbortSignal): Promise<import('../types/api').EmployeeResetResponse> {
  const url = `${API_BASE_URL}/v1/employees/reset`
  const response = await fetch(url, {
    method: 'POST',
    headers: buildHeaders({
      Accept: 'application/json',
    }),
    signal,
  })
  return handleResponse<import('../types/api').EmployeeResetResponse>(response)
}

export async function executeEmployeeOperation(
  request: import('../types/api').EmployeeOperationRequest,
  signal?: AbortSignal
): Promise<import('../types/api').EmployeeOperationResponse> {
  const url = `${API_BASE_URL}/v1/employees/operations/execute`
  const response = await fetch(url, {
    method: 'POST',
    headers: buildHeaders({
      'Content-Type': 'application/json',
      Accept: 'application/json',
    }),
    body: JSON.stringify(request),
    signal,
  })
  const raw = await handleResponse<Record<string, unknown>>(response)

  // Normalize policy reasons (backend returns policy_reasons; frontend expects policy_reason_codes)
  const rawReasons = raw.policy_reason_codes || raw.policy_reasons
  const policyReasonCodes: string[] = Array.isArray(rawReasons)
    ? rawReasons.filter((r): r is string => typeof r === 'string')
    : []

  // Normalize audit references (backend returns audit_reference string; frontend expects audit_references array)
  let auditReferences: string[] = []
  if (Array.isArray(raw.audit_references)) {
    auditReferences = raw.audit_references.filter((r): r is string => typeof r === 'string')
  } else if (typeof raw.audit_reference === 'string' && raw.audit_reference.trim().length > 0) {
    auditReferences = [raw.audit_reference.trim()]
  }

  // Normalize steps defensively
  const rawSteps = Array.isArray(raw.steps) ? raw.steps : []
  const steps: import('../types/api').StepTrace[] = rawSteps.map((s: any, idx: number) => {
    const sReasons = s?.policy_reason_codes || s?.policy_reasons
    const stepReasonCodes: string[] = Array.isArray(sReasons)
      ? sReasons.filter((r: unknown): r is string => typeof r === 'string')
      : []
    return {
      step_number: typeof s?.step_number === 'number' ? s.step_number : idx + 1,
      description: typeof s?.description === 'string' ? s.description : '',
      tool_name: typeof s?.tool_name === 'string' ? s.tool_name : '',
      status: typeof s?.status === 'string' ? s.status : 'completed',
      policy_decision: typeof s?.policy_decision === 'string' ? s.policy_decision : 'ALLOW',
      policy_reason_codes: stepReasonCodes,
      policy_reasons: stepReasonCodes,
      sanitized_tool_input: s?.sanitized_tool_input && typeof s.sanitized_tool_input === 'object' ? s.sanitized_tool_input : null,
      tool_output: s?.tool_output && typeof s.tool_output === 'object' ? s.tool_output : null,
      explanation: typeof s?.explanation === 'string' ? s.explanation : null,
    }
  })

  return {
    operation: (raw.operation as any) || request.operation,
    employee_id: typeof raw.employee_id === 'string' ? raw.employee_id : request.employee_id,
    task_id: typeof raw.task_id === 'string' ? raw.task_id : '',
    status: typeof raw.status === 'string' ? raw.status : 'completed',
    policy_decision: (raw.policy_decision as any) || 'ALLOW',
    policy_reason_codes: policyReasonCodes,
    policy_reasons: policyReasonCodes,
    policy_explanation: typeof raw.policy_explanation === 'string' ? raw.policy_explanation : '',
    risk_score: typeof raw.risk_score === 'number' ? raw.risk_score : 0,
    downstream_sanitized_confirmed: typeof raw.downstream_sanitized_confirmed === 'boolean' ? raw.downstream_sanitized_confirmed : true,
    original_test_values: raw.original_test_values && typeof raw.original_test_values === 'object' ? (raw.original_test_values as Record<string, string>) : {},
    sanitized_values: raw.sanitized_values && typeof raw.sanitized_values === 'object' ? (raw.sanitized_values as Record<string, string>) : {},
    steps,
    final_answer: typeof raw.final_answer === 'string' ? raw.final_answer : '',
    pending_ticket_id: typeof raw.pending_ticket_id === 'string' ? raw.pending_ticket_id : null,
    audit_references: auditReferences,
    audit_reference: typeof raw.audit_reference === 'string' ? raw.audit_reference : (auditReferences[0] ?? null),
  }
}


