import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { EmployeePrivacyDemo } from '../components/EmployeePrivacyDemo'
import * as api from '../services/api'
import type {
  EmployeeSearchResponse,
  EmployeeDetailResponse,
  EmployeeOperationResponse,
  EmployeeResetResponse,
} from '../types/api'

describe('Employee Privacy Demo UI Component', () => {
  const mockEmployees: EmployeeSearchResponse = {
    total_count: 3,
    employees: [
      {
        employee_id: 'EMP-1001',
        name: 'Elena Rostova',
        department: 'Engineering',
        job_title: 'Staff Security Engineer',
        employment_status: 'Active',
        data_classification: 'internal',
        office_location: 'Berlin-HQ-B2',
      },
      {
        employee_id: 'EMP-1002',
        name: 'Marcus Vance',
        department: 'Finance',
        job_title: 'Senior Financial Analyst',
        employment_status: 'Active',
        data_classification: 'confidential',
        office_location: 'London-UK-F4',
      },
      {
        employee_id: 'EMP-1003',
        name: 'Priya Sharma',
        department: 'Healthcare',
        job_title: 'Occupational Health Specialist',
        employment_status: 'Active',
        data_classification: 'confidential',
        office_location: 'SanJose-US-H1',
      },
    ],
  }

  const mockDetailEMP1001: EmployeeDetailResponse = {
    employee: mockEmployees.employees[0],
    field_authorizations: [
      {
        field_name: 'employee_id',
        sensitivity_tier: 'PUBLIC',
        governance_action: 'ALLOW',
        authorized_for_viewer: true,
        masked_display_value: 'EMP-1001',
        policy_rationale: 'Public organizational identifier',
      },
      {
        field_name: 'name',
        sensitivity_tier: 'PUBLIC',
        governance_action: 'ALLOW',
        authorized_for_viewer: true,
        masked_display_value: 'Elena Rostova',
        policy_rationale: 'Public directory employee name',
      },
      {
        field_name: 'email',
        sensitivity_tier: 'CONTACT_SENSITIVE',
        governance_action: 'REDACT',
        authorized_for_viewer: true,
        masked_display_value: 'ele***@privai-demo.internal',
        policy_rationale: 'Personal contact entity requiring tokenization',
      },
      {
        field_name: 'salary',
        sensitivity_tier: 'RESTRICTED_PAYROLL',
        governance_action: 'BLOCK',
        authorized_for_viewer: false,
        masked_display_value: '[RESTRICTED — UNAUTHORIZED PAYROLL ACCESS BLOCKED]',
        policy_rationale: 'Confidential compensation data',
      },
    ],
    raw_payroll_accessible: false,
    raw_health_accessible: false,
  }

  const mockAllowResponse: EmployeeOperationResponse = {
    operation: 'summarize_profile',
    employee_id: 'EMP-1001',
    task_id: 'task-allow-demo-1',
    status: 'completed',
    policy_decision: 'ALLOW',
    policy_reason_codes: ['RULE-DEFAULT-ALLOW'],
    policy_explanation: 'Authorized by deterministic privacy policy.',
    risk_score: 0,
    downstream_sanitized_confirmed: true,
    steps: [
      {
        step_number: 1,
        description: 'Retrieve profile for employee EMP-1001',
        tool_name: 'get_employee_record',
        status: 'completed',
        policy_decision: 'ALLOW',
        policy_reason_codes: ['RULE-DEFAULT-ALLOW'],
      },
      {
        step_number: 2,
        description: 'Summarize employee details for EMP-1001',
        tool_name: 'summarize_text',
        status: 'completed',
        policy_decision: 'ALLOW',
        policy_reason_codes: ['RULE-DEFAULT-ALLOW'],
      },
    ],
    final_answer: 'Elena Rostova is Staff Security Engineer in Engineering.',
    audit_references: ['sha256:allow_audit_digest_123'],
  }

  const mockRedactResponse: EmployeeOperationResponse = {
    operation: 'contact_report',
    employee_id: 'EMP-1002',
    task_id: 'task-redact-demo-2',
    status: 'completed',
    policy_decision: 'REDACT',
    policy_reason_codes: ['REDACT-EMAIL-PHONE-EMPID'],
    policy_explanation: 'Contact fields sanitized before AI processing.',
    risk_score: 25,
    downstream_sanitized_confirmed: true,
    original_test_values: {
      employee_id: 'EMP-1002',
      email: 'marcus.vance@privai-demo.internal',
      phone: '555-019-0183',
    },
    sanitized_values: {
      employee_id: '[EMPLOYEE_ID]',
      email: '[EMAIL]',
      phone: '[PHONE]',
    },
    steps: [
      {
        step_number: 1,
        description: 'Generate verified contact report',
        tool_name: 'format_report',
        status: 'completed',
        policy_decision: 'REDACT',
        policy_reason_codes: ['REDACT-EMAIL-PHONE-EMPID'],
        sanitized_tool_input: {
          text: 'Contact report for [EMPLOYEE_ID] with email [EMAIL] and phone [PHONE]',
        },
      },
    ],
    final_answer: 'Generated contact report for [EMPLOYEE_ID] [EMAIL] [PHONE].',
    audit_references: ['sha256:redact_audit_digest_456'],
  }

  const mockBlockResponse: EmployeeOperationResponse = {
    operation: 'request_payroll',
    employee_id: 'EMP-1002',
    task_id: 'task-block-demo-3',
    status: 'blocked',
    policy_decision: 'BLOCK',
    policy_reason_codes: ['BLOCK-UNAUTHORIZED-PAYROLL'],
    policy_explanation: 'Unauthorized compensation access blocked by firewall. Zero tool or provider calls made.',
    risk_score: 90,
    downstream_sanitized_confirmed: true,
    steps: [],
    final_answer: 'Execution blocked by privacy policy: BLOCK-UNAUTHORIZED-PAYROLL. Zero tool calls executed.',
    audit_references: ['sha256:block_audit_digest_789'],
  }

  const mockReviewResponse: EmployeeOperationResponse = {
    operation: 'request_health',
    employee_id: 'EMP-1003',
    task_id: 'task-review-demo-4',
    status: 'waiting_for_approval',
    policy_decision: 'REVIEW',
    policy_reason_codes: ['REVIEW-HEALTH-DATA'],
    policy_explanation: 'Execution suspended pending compliance human review approval.',
    risk_score: 75,
    downstream_sanitized_confirmed: true,
    pending_ticket_id: 'ticket-demo-abc12345',
    steps: [],
    final_answer: 'Task suspended pending compliance human review approval. Review ticket ticket-demo-abc12345 generated.',
    audit_references: ['sha256:review_audit_digest_321'],
  }

  const mockResetResponse: EmployeeResetResponse = {
    status: 'success',
    records_seeded: 15,
    isolated_db_path: 'privai_demo_employees.db',
    message: 'Synthetic employee demo database successfully reset and re-seeded.',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(api, 'getEmployees').mockResolvedValue(mockEmployees)
    vi.spyOn(api, 'getEmployeeDetail').mockResolvedValue(mockDetailEMP1001)
    vi.spyOn(api, 'getEmployeeDepartments').mockResolvedValue(['Engineering', 'Finance', 'Healthcare'])
    vi.spyOn(api, 'getEmployeeClassifications').mockResolvedValue(['internal', 'confidential', 'restricted'])
    vi.spyOn(api, 'resetEmployeeDemoData').mockResolvedValue(mockResetResponse)
    vi.spyOn(api, 'executeEmployeeOperation').mockResolvedValue(mockAllowResponse)
  })

  it('renders overview banner, synthetic dataset tag, and isolated DB indicators', async () => {
    render(<EmployeePrivacyDemo />)

    expect(screen.getByText(/Employee Privacy Governance Demo/i)).toBeInTheDocument()
    expect(screen.getByText(/Synthetic Dataset/i)).toBeInTheDocument()
    expect(screen.getByText(/privai_demo_employees.db/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Reset Demo Data/i })).toBeInTheDocument()

    await waitFor(() => {
      expect(screen.getByText('Elena Rostova')).toBeInTheDocument()
      expect(screen.getByText('Marcus Vance')).toBeInTheDocument()
      expect(screen.getByText('Priya Sharma')).toBeInTheDocument()
    })
  })

  it('displays field authorization rules with security tiers and masked values', async () => {
    render(<EmployeePrivacyDemo />)

    await waitFor(() => {
      expect(screen.getByText('Backend Field Authorization Policy')).toBeInTheDocument()
      expect(screen.getAllByText('PUBLIC').length).toBeGreaterThan(0)
      expect(screen.getByText('CONTACT_SENSITIVE')).toBeInTheDocument()
      expect(screen.getByText('RESTRICTED_PAYROLL')).toBeInTheDocument()
      expect(screen.getByText('[RESTRICTED — UNAUTHORIZED PAYROLL ACCESS BLOCKED]')).toBeInTheDocument()
    })
  })

  it('triggers Reset Demo Data action and displays re-seeded confirmation', async () => {
    const user = userEvent.setup()
    render(<EmployeePrivacyDemo />)

    const resetBtn = screen.getByRole('button', { name: /Reset Demo Data/i })
    await user.click(resetBtn)

    await waitFor(() => {
      expect(api.resetEmployeeDemoData).toHaveBeenCalledTimes(1)
      expect(screen.getByText(/15 synthetic employees re-seeded into isolated database/i)).toBeInTheDocument()
    })
  })

  it('executes ALLOW scenario preset and displays policy decision and agent steps', async () => {
    vi.mocked(api.executeEmployeeOperation).mockResolvedValueOnce(mockAllowResponse)
    const user = userEvent.setup()
    render(<EmployeePrivacyDemo />)

    const allowPresetBtn = screen.getByRole('button', { name: /ALLOW Scenario/i })
    await user.click(allowPresetBtn)

    await waitFor(() => {
      const banner = document.getElementById('operation-result-banner')
      expect(banner).toBeInTheDocument()
      expect(banner).toHaveTextContent('ALLOW')
      expect(screen.getByText(/Elena Rostova is Staff Security Engineer in Engineering/i)).toBeInTheDocument()
      expect(screen.getByText(/Step 1: Retrieve profile for employee EMP-1001/i)).toBeInTheDocument()
    })
  })

  it('executes REDACT scenario preset and shows Controlled Demonstration View with token comparison', async () => {
    vi.mocked(api.executeEmployeeOperation).mockResolvedValueOnce(mockRedactResponse)
    const user = userEvent.setup()
    render(<EmployeePrivacyDemo />)

    const redactPresetBtn = screen.getByRole('button', { name: /REDACT Scenario/i })
    await user.click(redactPresetBtn)

    await waitFor(() => {
      const banner = document.getElementById('operation-result-banner')
      expect(banner).toBeInTheDocument()
      expect(banner).toHaveTextContent('REDACT')
      expect(screen.getByText(/Controlled Redaction Demonstration View/i)).toBeInTheDocument()
      expect(screen.getByText('marcus.vance@privai-demo.internal')).toBeInTheDocument()
      expect(screen.getByText('555-019-0183')).toBeInTheDocument()
      expect(screen.getByText('[EMAIL]')).toBeInTheDocument()
      expect(screen.getByText('[PHONE]')).toBeInTheDocument()
      expect(screen.getByText(/Downstream Sanitized Only/i)).toBeInTheDocument()
    })
  })

  it('executes BLOCK scenario preset and confirms zero tool or provider calls', async () => {
    vi.mocked(api.executeEmployeeOperation).mockResolvedValueOnce(mockBlockResponse)
    const user = userEvent.setup()
    render(<EmployeePrivacyDemo />)

    const blockPresetBtn = document.getElementById('preset-block-btn')!
    await user.click(blockPresetBtn)
    await waitFor(() => {
      const banner = document.getElementById('operation-result-banner')
      expect(banner).toBeInTheDocument()
      expect(banner).toHaveTextContent('BLOCK')
      expect(screen.getAllByText(/BLOCK-UNAUTHORIZED-PAYROLL/i).length).toBeGreaterThan(0)
      expect(screen.getByText(/Unauthorized compensation access blocked by firewall/i)).toBeInTheDocument()
    })
  })

  it('executes REVIEW scenario preset and renders review ticket with portal link', async () => {
    vi.mocked(api.executeEmployeeOperation).mockResolvedValueOnce(mockReviewResponse)
    const onOpenReviewPortal = vi.fn()
    const user = userEvent.setup()
    render(<EmployeePrivacyDemo onOpenReviewPortal={onOpenReviewPortal} />)

    const reviewPresetBtn = screen.getByRole('button', { name: /REVIEW Scenario/i })
    await user.click(reviewPresetBtn)

    await waitFor(() => {
      const banner = document.getElementById('operation-result-banner')
      expect(banner).toBeInTheDocument()
      expect(banner).toHaveTextContent('REVIEW')
      expect(screen.getByText('ticket-demo-abc12345')).toBeInTheDocument()
      expect(screen.getByText(/Compliance Human Review Required/i)).toBeInTheDocument()
    })

    const openPortalBtn = screen.getByRole('button', { name: /Open Human Review Portal/i })
    await user.click(openPortalBtn)
    expect(onOpenReviewPortal).toHaveBeenCalledTimes(1)
  })
})
