import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AgentWorkbench } from '../components/AgentWorkbench'
import * as api from '../services/api'
import type { AgentTaskResponse } from '../types/api'

describe('PrivAI Secure Task Agent UI', () => {
  const mockAllowTask: AgentTaskResponse = {
    task_id: 'task-allow-123456',
    goal: 'Read reference company policy company_policy.txt and format summary report',
    status: 'completed',
    current_step_index: 3,
    plan: {
      goal: 'Read reference company policy company_policy.txt and format summary report',
      total_steps: 3,
      steps: [
        {
          step_number: 1,
          description: "Read contents of document 'company_policy.txt'",
          tool_name: 'read_document',
          tool_input: { document_id: 'company_policy.txt' },
          policy_decision: 'ALLOW',
          policy_reason_codes: ['RULE-DEFAULT-ALLOW'],
          status: 'completed',
          tool_output: { document_id: 'company_policy.txt', content: 'PrivAI enterprise policy...', untrusted: true },
        },
        {
          step_number: 2,
          description: "Summarize key points from 'company_policy.txt'",
          tool_name: 'summarize_text',
          tool_input: { text: 'PrivAI enterprise policy...', max_sentences: 3 },
          policy_decision: 'ALLOW',
          policy_reason_codes: ['RULE-DEFAULT-ALLOW'],
          status: 'completed',
          tool_output: { summary: 'Data minimization must be followed.' },
        },
        {
          step_number: 3,
          description: 'Format final summary report',
          tool_name: 'format_report',
          tool_input: { title: 'Summary Report: company_policy.txt', sections: [], output_filename: 'summary_policy.md' },
          policy_decision: 'ALLOW',
          policy_reason_codes: ['RULE-DEFAULT-ALLOW'],
          status: 'completed',
          tool_output: { title: 'Summary Report: company_policy.txt', status: 'written' },
        },
      ],
    },
    final_answer: 'PrivAI Secure Task Agent completed task: 3 completed steps.',
    completed_steps: 3,
    blocked_steps: 0,
    waiting_steps: 0,
    audit_references: ['sha256:digest111', 'sha256:digest222'],
    created_at: '2026-10-18T12:00:00Z',
    updated_at: '2026-10-18T12:00:01Z',
  }

  const mockWaitingTask: AgentTaskResponse = {
    task_id: 'task-review-999888',
    goal: 'Review patient clinical cardiovascular diagnosis history for medical evaluation',
    status: 'waiting_for_approval',
    current_step_index: 0,
    plan: null,
    final_answer: 'Task suspended pending compliance human review approval (Ticket: ticket-8f3a...).',
    completed_steps: 0,
    blocked_steps: 0,
    waiting_steps: 1,
    pending_ticket_id: 'ticket-8f3a12345678',
    audit_references: ['sha256:digestReview'],
    created_at: '2026-10-18T12:05:00Z',
    updated_at: '2026-10-18T12:05:00Z',
  }

  const mockBlockedTask: AgentTaskResponse = {
    task_id: 'task-block-777666',
    goal: 'Verify background records for National ID 999-00-1234 confidential file',
    status: 'blocked',
    current_step_index: 0,
    plan: null,
    final_answer: 'Task execution blocked by privacy policy: National ID detected. Zero calls made.',
    completed_steps: 0,
    blocked_steps: 1,
    waiting_steps: 0,
    audit_references: ['sha256:digestBlock'],
    created_at: '2026-10-18T12:10:00Z',
    updated_at: '2026-10-18T12:10:00Z',
  }

  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('renders Agent Workbench header, presets, and idle state', () => {
    render(<AgentWorkbench onOpenReviewPortal={vi.fn()} activePermit={null} />)

    expect(screen.getByText('PrivAI Secure Task Agent')).toBeInTheDocument()
    expect(screen.getByText(/1. Safe Policy Summary \(ALLOW\)/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Execute Secure Agent Task/i })).toBeInTheDocument()
    expect(screen.getByText('Secure Task Agent Idle')).toBeInTheDocument()
  })

  it('executes safe task and displays bounded plan with ALLOW steps', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'createAgentTask').mockResolvedValue(mockAllowTask)

    render(<AgentWorkbench onOpenReviewPortal={vi.fn()} activePermit={null} />)

    const runBtn = screen.getByRole('button', { name: /Execute Secure Agent Task/i })
    await user.click(runBtn)

    await waitFor(() => {
      expect(screen.getAllByText('COMPLETED').length).toBeGreaterThan(0)
    })

    expect(screen.getByText('task-allow-123456')).toBeInTheDocument()
    expect(screen.getByText(/Bounded Multi-Step Plan \(3 Steps\)/i)).toBeInTheDocument()
    expect(screen.getByText(/Final Task Summary & Synthesis/i)).toBeInTheDocument()
    expect(screen.getByText('sha256:digest111')).toBeInTheDocument()
  })

  it('displays waiting for approval banner when task status is review_pending', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'createAgentTask').mockResolvedValue(mockWaitingTask)

    render(<AgentWorkbench onOpenReviewPortal={vi.fn()} activePermit={null} />)

    const runBtn = screen.getByRole('button', { name: /Execute Secure Agent Task/i })
    await user.click(runBtn)

    await waitFor(() => {
      expect(screen.getByText(/Compliance Human Review Required/i)).toBeInTheDocument()
    })

    expect(screen.getByText(/ticket-8f3a12345678/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Open Review Portal/i })).toBeInTheDocument()
  })

  it('displays blocked banner when task is blocked by privacy policy', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'createAgentTask').mockResolvedValue(mockBlockedTask)

    render(<AgentWorkbench onOpenReviewPortal={vi.fn()} activePermit={null} />)

    const runBtn = screen.getByRole('button', { name: /Execute Secure Agent Task/i })
    await user.click(runBtn)

    await waitFor(() => {
      expect(screen.getByText(/Execution Blocked by Privacy Firewall/i)).toBeInTheDocument()
    })

    expect(screen.getByText(/National ID detected/i)).toBeInTheDocument()
  })
})
