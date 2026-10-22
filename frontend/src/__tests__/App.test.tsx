import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import * as api from '../services/api'
import type { PromptAnalyzeResponse, PromptExecuteResponse, HealthResponse } from '../types/api'

describe('PrivAI App Integration', () => {
  const mockHealth: HealthResponse = {
    status: 'ok',
    provider_mode: 'mock',
    policy_loaded: true,
  }

  const mockAnalyzeAllow: PromptAnalyzeResponse = {
    analysis_id: 'an_allow_1',
    request_digest: 'sha256:digest1234567890abcdef',
    decision: 'ALLOW',
    risk: {
      score: 0,
      band: 'low',
      factor_contributions: {},
      reason_codes: ['SCORE-BAND-LOW'],
      version: 'risk-v1',
    },
    findings: [],
    explanation: {
      rule_ids: ['RULE-DEFAULT-ALLOW'],
      summary: 'Prompt is safe for direct dispatch.',
      actions: [],
    },
    policy_version: 'policy-v1',
  }

  const mockExecuteAllow: PromptExecuteResponse = {
    request_id: 'req_allow_1',
    status: 'completed',
    decision: 'ALLOW',
    risk: {
      score: 0,
      band: 'low',
      factor_contributions: {},
      reason_codes: ['SCORE-BAND-LOW'],
      version: 'risk-v1',
    },
    provider: {
      name: 'mock',
      model: 'mock-v1',
    },
    output: 'Artificial Intelligence explanation output.',
    explanation: {
      rule_ids: ['RULE-DEFAULT-ALLOW'],
      summary: 'Safe execution completed.',
      actions: [],
    },
    policy_version: 'policy-v1',
  }

  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api, 'getHealth').mockResolvedValue(mockHealth)
  })

  it('renders header, prompt editor, and idle state initially', async () => {
    render(<App />)

    expect(screen.getByRole('banner')).toHaveTextContent(/PrivAI/i)
    await waitFor(() => {
      expect(screen.getByText(/Firewall Active \(mock\)/i)).toBeInTheDocument()
    })
    expect(screen.getByLabelText(/Prompt Content/i)).toBeInTheDocument()
    expect(screen.getByText(/Privacy Firewall Idle/i)).toBeInTheDocument()
  })

  it('analyzes prompt and renders ALLOW policy decision', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'analyzePrompt').mockResolvedValue(mockAnalyzeAllow)

    render(<App />)

    const analyzeBtn = screen.getByRole('button', { name: /Analyze prompt/i })
    await user.click(analyzeBtn)

    await waitFor(() => {
      expect(screen.getByRole('region', { name: /Privacy Analysis Results/i })).toBeInTheDocument()
    })

    expect(screen.getByText('ALLOW')).toBeInTheDocument()
    expect(screen.getByText('0')).toBeInTheDocument()
    expect(screen.getByText(/Authorized for direct execution/i)).toBeInTheDocument()

    // Execute button should now be enabled
    const executeBtn = screen.getByRole('button', { name: /Execute prompt/i })
    expect(executeBtn).toBeEnabled()
  })

  it('invalidates analysis when prompt is edited after analysis (Anti-Bypass Invariant)', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'analyzePrompt').mockResolvedValue(mockAnalyzeAllow)

    render(<App />)

    // 1. Analyze prompt
    const analyzeBtn = screen.getByRole('button', { name: /Analyze prompt/i })
    await user.click(analyzeBtn)

    await waitFor(() => {
      expect(screen.getByText('ALLOW')).toBeInTheDocument()
    })

    const executeBtn = screen.getByRole('button', { name: /Execute prompt/i })
    expect(executeBtn).toBeEnabled()

    // 2. User edits prompt content
    const textarea = screen.getByLabelText(/Prompt Content/i)
    await user.type(textarea, ' additional text')

    // 3. Stale banner must appear and execute button must be disabled immediately!
    expect(screen.getByRole('alert')).toHaveTextContent(/Input Modified/i)
    expect(executeBtn).toBeDisabled()
  })

  it('executes prompt through backend and renders AI response', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'analyzePrompt').mockResolvedValue(mockAnalyzeAllow)
    vi.spyOn(api, 'executePrompt').mockResolvedValue(mockExecuteAllow)

    render(<App />)

    // 1. Analyze
    const analyzeBtn = screen.getByRole('button', { name: /Analyze prompt/i })
    await user.click(analyzeBtn)

    await waitFor(() => {
      expect(screen.getByText('ALLOW')).toBeInTheDocument()
    })

    // 2. Execute
    const executeBtn = screen.getByRole('button', { name: /Execute prompt/i })
    await user.click(executeBtn)

    await waitFor(() => {
      expect(screen.getByRole('region', { name: /Provider Completion Output/i })).toBeInTheDocument()
    })

    expect(screen.getByText(/Artificial Intelligence explanation output\./i)).toBeInTheDocument()
    expect(screen.getByText(/Provider: mock/i)).toBeInTheDocument()
  })

  it('displays safe error banner when API returns an error', async () => {
    const user = userEvent.setup()
    vi.spyOn(api, 'analyzePrompt').mockRejectedValue(
      new api.ApiError('Internal failure in policy evaluation', 'SERVICE_UNAVAILABLE', 503, 'req_err_99')
    )

    render(<App />)

    const analyzeBtn = screen.getByRole('button', { name: /Analyze prompt/i })
    await user.click(analyzeBtn)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })

    expect(screen.getByText('SERVICE_UNAVAILABLE')).toBeInTheDocument()
    expect(screen.getByText(/Internal failure in policy evaluation/i)).toBeInTheDocument()
    expect(screen.getByText(/Request ID: req_err_99/i)).toBeInTheDocument()
  })
})
