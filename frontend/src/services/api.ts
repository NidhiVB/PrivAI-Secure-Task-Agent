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

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/+$/, '')

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
  return handleResponse<import('../types/api').EmployeeSearchResponse>(response)
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
  return handleResponse<import('../types/api').EmployeeOperationResponse>(response)
}


