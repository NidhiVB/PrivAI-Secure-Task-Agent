import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PromptEditor, PRESETS } from '../components/PromptEditor'

describe('PromptEditor component', () => {
  it('renders prompt textarea and displays byte count', () => {
    const onChange = vi.fn()
    const onSelectPreset = vi.fn()

    render(
      <PromptEditor
        prompt="Hello PrivAI"
        onChange={onChange}
        onSelectPreset={onSelectPreset}
      />
    )

    const textarea = screen.getByLabelText(/Prompt Content/i)
    expect(textarea).toBeInTheDocument()
    expect(textarea).toHaveValue('Hello PrivAI')

    // Byte counter displays 12 / 10,240 UTF-8 bytes
    expect(screen.getByText(/12 \/ 10,240 UTF-8 bytes/i)).toBeInTheDocument()
  })

  it('triggers onChange when user types in textarea', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const onSelectPreset = vi.fn()

    render(
      <PromptEditor
        prompt=""
        onChange={onChange}
        onSelectPreset={onSelectPreset}
      />
    )

    const textarea = screen.getByLabelText(/Prompt Content/i)
    await user.type(textarea, 'A')
    expect(onChange).toHaveBeenCalledWith('A')
  })

  it('allows clicking presets to trigger onSelectPreset', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const onSelectPreset = vi.fn()

    render(
      <PromptEditor
        prompt=""
        onChange={onChange}
        onSelectPreset={onSelectPreset}
      />
    )

    const presetBtn = screen.getByRole('button', { name: /Safe General \(ALLOW\)/i })
    await user.click(presetBtn)
    expect(onSelectPreset).toHaveBeenCalledWith(PRESETS[0])
  })

  it('displays warning when prompt exceeds 10,240 UTF-8 bytes', () => {
    const largePrompt = 'A'.repeat(10241)
    render(
      <PromptEditor
        prompt={largePrompt}
        onChange={vi.fn()}
        onSelectPreset={vi.fn()}
      />
    )

    expect(screen.getByText(/10,241 \/ 10,240 UTF-8 bytes/i)).toBeInTheDocument()
  })

  it('allows clearing the prompt when not empty', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()

    render(
      <PromptEditor
        prompt="Some text"
        onChange={onChange}
        onSelectPreset={vi.fn()}
      />
    )

    const clearBtn = screen.getByRole('button', { name: /Clear prompt text/i })
    await user.click(clearBtn)
    expect(onChange).toHaveBeenCalledWith('')
  })
})
