/**
 * PrivAI API TypeScript Type Definitions
 * Strictly aligned with backend Pydantic models.
 */

export type Destination = 'mock' | 'groq'

export type ContextPurpose =
  | 'general_question'
  | 'summarization'
  | 'coding'
  | 'hr_workflow'
  | 'health_information'
  | 'other'

export type ContextDataSubject =
  | 'none'
  | 'self'
  | 'third_party'
  | 'employee'
  | 'unknown'

export type ContextClassification =
  | 'public'
  | 'internal'
  | 'confidential'
  | 'restricted'

export type PolicyOutcome = 'ALLOW' | 'REDACT' | 'BLOCK' | 'REVIEW'

export type ExecutionStatus = 'completed' | 'blocked' | 'review_pending'

export type RiskBand = 'low' | 'moderate' | 'high' | 'very_high' | 'critical'

export type FindingCategory =
  | 'EMAIL'
  | 'PHONE'
  | 'EMPLOYEE_ID'
  | 'NATIONAL_ID'
  | 'SALARY'
  | 'HEALTH'
  | 'OTHER'

export interface ContextModel {
  purpose: ContextPurpose
  data_subject: ContextDataSubject
  classification: ContextClassification
}

export type ReviewStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED'

export interface ReviewPermit {
  version: string
  ticket_id: string
  permit_nonce: string
  request_digest: string
  issued_at: string
  expires_at: string
  approved_by: string
  assigned_role: string
  signature: string
}

export interface ReviewTicket {
  ticket_id: string
  request_digest: string
  submitted_at: string
  expires_at: string
  status: ReviewStatus
  assigned_role: string
  risk_score: number
  triggered_rule_ids: string[]
  decision_rationale?: string | null
  decided_by?: string | null
  decided_at?: string | null
}

export interface ReviewPendingListResponse {
  tickets: ReviewTicket[]
  total_count: number
}

export interface ReviewActionResponse {
  ticket_id: string
  status: ReviewStatus
  decided_by: string
  decided_at: string
  permit?: ReviewPermit | null
}

export interface PromptRequest {
  prompt: string
  destination: Destination
  context: ContextModel
  review_permit?: ReviewPermit | null
}

export interface Finding {
  rule_id: string
  category: FindingCategory
  start: number
  end: number
  confidence: number
  severity: number
}

export interface RiskFactors {
  severity: number
  count: number
  normalized_count: number
  context: number
  destination: number
  identifiability: number
}

export interface RiskScore {
  score: number
  band: RiskBand
  factors?: RiskFactors | null
  factor_contributions: Record<string, number>
  reason_codes: string[]
  version: string
}

export interface Explanation {
  rule_ids: string[]
  summary: string
  actions: string[]
}

export interface RedactionSummary {
  category: FindingCategory
  placeholder: string
}

export interface ProviderInfo {
  name: string
  model: string
}

export interface PromptAnalyzeResponse {
  analysis_id: string
  request_digest: string
  decision: PolicyOutcome
  risk: RiskScore
  findings: Finding[]
  explanation: Explanation
  policy_version: string
  sanitized_prompt?: string | null
  redactions?: RedactionSummary[] | null
}

export interface PromptExecuteResponse {
  request_id: string
  status: ExecutionStatus
  decision: PolicyOutcome
  risk: RiskScore
  redactions?: RedactionSummary[] | null
  provider?: ProviderInfo | null
  output?: string | null
  explanation: Explanation
  policy_version: string
  ticket_id?: string | null
}

export interface SafeErrorDetail {
  code: string
  message: string
  request_id: string
}

export interface SafeErrorResponse {
  error: SafeErrorDetail
}

export interface HealthResponse {
  status: string
  provider_mode: string
  policy_loaded: boolean
}

// PrivAI Secure Task Agent Types
export type AgentTaskStatus =
  | 'created'
  | 'planning'
  | 'running'
  | 'waiting_for_approval'
  | 'blocked'
  | 'completed'
  | 'failed'

export type AgentStepStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'blocked'
  | 'waiting_for_approval'
  | 'failed'

export interface AgentStep {
  step_number: number
  description: string
  tool_name: string
  tool_input: Record<string, unknown>
  sanitized_tool_input?: Record<string, unknown> | null
  policy_decision?: PolicyOutcome | null
  policy_reason_codes: string[]
  status: AgentStepStatus
  ticket_id?: string | null
  tool_output?: Record<string, unknown> | null
  explanation?: string | null
}

export interface AgentPlan {
  goal: string
  steps: AgentStep[]
  total_steps: number
}

export interface AgentTaskCreateRequest {
  goal: string
  destination?: Destination | null
  context?: ContextModel | null
  review_permit?: ReviewPermit | null
}

export interface AgentTaskResumeRequest {
  review_permit: ReviewPermit
}

export interface AgentTaskResponse {
  task_id: string
  goal: string
  status: AgentTaskStatus
  current_step_index: number
  plan?: AgentPlan | null
  final_answer?: string | null
  completed_steps: number
  blocked_steps: number
  waiting_steps: number
  pending_ticket_id?: string | null
  audit_references: string[]
  created_at: string
  updated_at: string
}

export interface AgentStepsResponse {
  task_id: string
  steps: AgentStep[]
}

// ==============================================================================
// Employee Privacy Demo Types
// ==============================================================================

export interface EmployeeSummary {
  employee_id: string
  name: string
  department: string
  job_title: string
  employment_status: string
  data_classification: ContextClassification
  office_location: string
}

export type FieldSensitivityTier = 'PUBLIC' | 'CONTACT_SENSITIVE' | 'RESTRICTED_PAYROLL' | 'COMPLIANCE_HEALTH'

export interface EmployeeFieldAuthorization {
  field_name: string
  sensitivity_tier: FieldSensitivityTier
  governance_action: PolicyOutcome
  authorized_for_viewer: boolean
  masked_display_value: string
  policy_rationale: string
}

export interface EmployeeDetailResponse {
  employee: EmployeeSummary
  field_authorizations: EmployeeFieldAuthorization[]
  raw_payroll_accessible: boolean
  raw_health_accessible: boolean
}

export interface EmployeeSearchResponse {
  employees: EmployeeSummary[]
  total_count: number
}

export type EmployeeOperationType =
  | 'summarize_profile'
  | 'contact_report'
  | 'request_payroll'
  | 'request_health'
  | 'custom'

export interface EmployeeOperationRequest {
  employee_id: string
  operation: EmployeeOperationType
  custom_goal?: string | null
  destination?: Destination | null
  review_permit?: ReviewPermit | null
}

export interface StepTrace {
  step_number: number
  description: string
  tool_name: string
  status: string
  policy_decision: string
  policy_reason_codes: string[]
  sanitized_tool_input?: Record<string, unknown> | null
  tool_output?: Record<string, unknown> | null
  explanation?: string | null
}

export interface EmployeeOperationResponse {
  operation: EmployeeOperationType
  employee_id: string
  task_id: string
  status: string
  policy_decision: PolicyOutcome
  policy_reason_codes: string[]
  policy_explanation: string
  risk_score: number
  downstream_sanitized_confirmed: boolean
  original_test_values?: Record<string, string> | null
  sanitized_values?: Record<string, string> | null
  steps: StepTrace[]
  final_answer: string
  pending_ticket_id?: string | null
  audit_references: string[]
}

export interface EmployeeResetResponse {
  status: string
  records_seeded: number
  isolated_db_path: string
  message: string
}


