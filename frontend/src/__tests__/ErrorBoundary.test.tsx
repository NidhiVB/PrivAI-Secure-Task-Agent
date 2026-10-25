import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import React, { useState } from 'react'
import { ErrorBoundary } from '../components/ErrorBoundary'

const ThrowingChild = ({ shouldThrow }: { shouldThrow: boolean }) => {
  if (shouldThrow) {
    throw new Error('Simulated unhandled render exception')
  }
  return <div>Component Rendered Normal Content</div>
}

const TestHarness = () => {
  const [shouldThrow, setShouldThrow] = useState(true)
  return (
    <div>
      <button type="button" onClick={() => setShouldThrow(false)}>
        Fix Child State
      </button>
      <ErrorBoundary fallbackTitle="Custom Demo Failure">
        <ThrowingChild shouldThrow={shouldThrow} />
      </ErrorBoundary>
    </div>
  )
}

describe('ErrorBoundary Component', () => {
  it('renders children when there is no error', () => {
    render(
      <ErrorBoundary fallbackTitle="Test Error Boundary">
        <ThrowingChild shouldThrow={false} />
      </ErrorBoundary>
    )

    expect(screen.getByText('Component Rendered Normal Content')).toBeInTheDocument()
  })

  it('catches render error, displays actionable fallback card without blank screen, and allows reset', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const user = userEvent.setup()

    render(<TestHarness />)

    // Fallback card is rendered instead of blank screen
    expect(screen.getByText('Custom Demo Failure')).toBeInTheDocument()
    expect(
      screen.getByText(/A rendering error occurred while displaying this view/i)
    ).toBeInTheDocument()
    expect(
      screen.getByText(/Simulated unhandled render exception/i)
    ).toBeInTheDocument()

    // Fix the underlying child state
    const fixBtn = screen.getByRole('button', { name: /Fix Child State/i })
    await user.click(fixBtn)

    // Click Reset View & Try Again
    const resetBtn = screen.getByRole('button', { name: /Reset View & Try Again/i })
    expect(resetBtn).toBeInTheDocument()
    await user.click(resetBtn)

    // Component recovers and renders normal content
    expect(screen.getByText('Component Rendered Normal Content')).toBeInTheDocument()

    consoleSpy.mockRestore()
  })
})
