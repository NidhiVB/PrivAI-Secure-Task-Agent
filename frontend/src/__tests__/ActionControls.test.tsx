import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ActionControls } from '../components/ActionControls'

describe('ActionControls component', () => {
  it('disables Analyze button when prompt is empty', () => {
    render(
      <ActionControls
        onAnalyze={vi.fn()}
        onExecute={vi.fn()}
        isAnalyzing={false}
        isExecuting={false}
        hasAnalyzed={false}
        isStale={false}
        canExecute={false}
        promptEmpty={true}
        isOverLimit={false}
      />
    )

    const analyzeBtn = screen.getByRole('button', { name: /Analyze prompt/i })
    expect(analyzeBtn).toBeDisabled()

    const executeBtn = screen.getByRole('button', { name: /Execute prompt/i })
    expect(executeBtn).toBeDisabled()
  })

  it('enables Analyze button and calls onAnalyze when clicked', async () => {
    const user = userEvent.setup()
    const onAnalyze = vi.fn()

    render(
      <ActionControls
        onAnalyze={onAnalyze}
        onExecute={vi.fn()}
        isAnalyzing={false}
        isExecuting={false}
        hasAnalyzed={false}
        isStale={false}
        canExecute={false}
        promptEmpty={false}
        isOverLimit={false}
      />
    )

    const analyzeBtn = screen.getByRole('button', { name: /Analyze prompt/i })
    expect(analyzeBtn).toBeEnabled()
    await user.click(analyzeBtn)
    expect(onAnalyze).toHaveBeenCalledTimes(1)
  })

  it('disables Execute button when analysis is stale and displays stale banner', () => {
    render(
      <ActionControls
        onAnalyze={vi.fn()}
        onExecute={vi.fn()}
        isAnalyzing={false}
        isExecuting={false}
        hasAnalyzed={true}
        isStale={true}
        latestDecision="ALLOW"
        canExecute={false}
        promptEmpty={false}
        isOverLimit={false}
      />
    )

    const executeBtn = screen.getByRole('button', { name: /Execute prompt/i })
    expect(executeBtn).toBeDisabled()

    expect(screen.getByRole('alert')).toHaveTextContent(/Input Modified/i)
    expect(screen.getByRole('alert')).toHaveTextContent(/Re-run Analyze Prompt to evaluate updated risks/i)
  })

  it('disables Execute button when policy decision is BLOCK', () => {
    render(
      <ActionControls
        onAnalyze={vi.fn()}
        onExecute={vi.fn()}
        isAnalyzing={false}
        isExecuting={false}
        hasAnalyzed={true}
        isStale={false}
        latestDecision="BLOCK"
        canExecute={false}
        promptEmpty={false}
        isOverLimit={false}
      />
    )

    const executeBtn = screen.getByRole('button', { name: /Execute prompt/i })
    expect(executeBtn).toBeDisabled()
    expect(screen.getByText(/Execution forbidden: Mandatory block triggered/i)).toBeInTheDocument()
  })

  it('disables Execute button when policy decision is REVIEW', () => {
    render(
      <ActionControls
        onAnalyze={vi.fn()}
        onExecute={vi.fn()}
        isAnalyzing={false}
        isExecuting={false}
        hasAnalyzed={true}
        isStale={false}
        latestDecision="REVIEW"
        canExecute={false}
        promptEmpty={false}
        isOverLimit={false}
      />
    )

    const executeBtn = screen.getByRole('button', { name: /Execute prompt/i })
    expect(executeBtn).toBeDisabled()
    expect(screen.getByText(/Execution suspended: Compliance review required/i)).toBeInTheDocument()
  })

  it('enables Execute button when decision is ALLOW and not stale', async () => {
    const user = userEvent.setup()
    const onExecute = vi.fn()

    render(
      <ActionControls
        onAnalyze={vi.fn()}
        onExecute={onExecute}
        isAnalyzing={false}
        isExecuting={false}
        hasAnalyzed={true}
        isStale={false}
        latestDecision="ALLOW"
        canExecute={true}
        promptEmpty={false}
        isOverLimit={false}
      />
    )

    const executeBtn = screen.getByRole('button', { name: /Execute prompt/i })
    expect(executeBtn).toBeEnabled()
    await user.click(executeBtn)
    expect(onExecute).toHaveBeenCalledTimes(1)
  })

  it('enables Execute button when decision is REDACT and not stale', async () => {
    const user = userEvent.setup()
    const onExecute = vi.fn()

    render(
      <ActionControls
        onAnalyze={vi.fn()}
        onExecute={onExecute}
        isAnalyzing={false}
        isExecuting={false}
        hasAnalyzed={true}
        isStale={false}
        latestDecision="REDACT"
        canExecute={true}
        promptEmpty={false}
        isOverLimit={false}
      />
    )

    const executeBtn = screen.getByRole('button', { name: /Execute prompt/i })
    expect(executeBtn).toBeEnabled()
    await user.click(executeBtn)
    expect(onExecute).toHaveBeenCalledTimes(1)
  })
})
