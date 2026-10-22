import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RedactionPreview } from '../components/RedactionPreview'
import { ResponsePanel } from '../components/ResponsePanel'
import type { PromptExecuteResponse } from '../types/api'

describe('RedactionPreview & ResponsePanel components', () => {
  it('renders RedactionPreview with sanitized prompt and tokens applied', () => {
    render(
      <RedactionPreview
        sanitizedPrompt="Please contact [EMAIL] regarding the report."
        redactions={[{ category: 'EMAIL', placeholder: '[EMAIL]' }]}
      />
    )

    expect(screen.getByText(/Verified Redaction Preview/i)).toBeInTheDocument()
    expect(screen.getByText(/Please contact \[EMAIL\] regarding the report\./i)).toBeInTheDocument()
    expect(screen.getByText(/\[EMAIL\] \(EMAIL\)/i)).toBeInTheDocument()
  })

  it('renders ResponsePanel for completed execution with provider details', () => {
    const mockCompleted: PromptExecuteResponse = {
      request_id: 'req_test_123',
      status: 'completed',
      decision: 'ALLOW',
      risk: {
        score: 0,
        band: 'low',
        factor_contributions: {},
        reason_codes: [],
        version: 'risk-v1',
      },
      provider: {
        name: 'mock',
        model: 'mock-v1',
      },
      output: 'Mock AI generated answer for test prompt.',
      explanation: {
        rule_ids: ['RULE-DEFAULT-ALLOW'],
        summary: 'Safe prompt allowed.',
        actions: [],
      },
      policy_version: 'policy-v1',
    }

    render(<ResponsePanel response={mockCompleted} />)

    expect(screen.getByText(/AI Provider Response/i)).toBeInTheDocument()
    expect(screen.getByText(/Mock AI generated answer for test prompt\./i)).toBeInTheDocument()
    expect(screen.getByText(/Provider: mock/i)).toBeInTheDocument()
    expect(screen.getByText(/Model: mock-v1/i)).toBeInTheDocument()
    expect(screen.getByText(/Request ID: req_test_123/i)).toBeInTheDocument()
  })

  it('renders ResponsePanel for BLOCKED execution with zero provider calls statement', () => {
    const mockBlocked: PromptExecuteResponse = {
      request_id: 'req_blocked_456',
      status: 'blocked',
      decision: 'BLOCK',
      risk: {
        score: 90,
        band: 'high',
        factor_contributions: {},
        reason_codes: [],
        version: 'risk-v1',
      },
      provider: null,
      output: null,
      explanation: {
        rule_ids: ['RULE-BLOCK-SSN'],
        summary: 'Prompt blocked due to high-risk SSN finding.',
        actions: [],
      },
      policy_version: 'policy-v1',
    }

    render(<ResponsePanel response={mockBlocked} />)

    expect(screen.getByText(/Execution Blocked by Privacy Policy/i)).toBeInTheDocument()
    expect(screen.getByText(/zero external provider calls/i)).toBeInTheDocument()
    expect(screen.getByText(/Prompt blocked due to high-risk SSN finding\./i)).toBeInTheDocument()
  })

  it('renders ResponsePanel for REVIEW execution', () => {
    const mockReview: PromptExecuteResponse = {
      request_id: 'req_review_789',
      status: 'review_pending',
      decision: 'REVIEW',
      risk: {
        score: 65,
        band: 'high',
        factor_contributions: {},
        reason_codes: [],
        version: 'risk-v1',
      },
      provider: null,
      output: null,
      explanation: {
        rule_ids: ['RULE-HEALTH-REVIEW'],
        summary: 'Medical health context requires compliance approval.',
        actions: [],
      },
      policy_version: 'policy-v1',
    }

    render(<ResponsePanel response={mockReview} />)

    expect(screen.getByText(/Human Review Required/i)).toBeInTheDocument()
    expect(screen.getByText(/PENDING REVIEW/i)).toBeInTheDocument()
    expect(screen.getByText(/zero provider calls/i)).toBeInTheDocument()
  })
})
