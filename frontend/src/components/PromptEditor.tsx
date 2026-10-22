import React, { useMemo } from 'react'
import { FileText, Sparkles, Trash2, AlertCircle } from 'lucide-react'
import type { ContextModel, Destination } from '../types/api'

interface PresetPrompt {
  name: string
  prompt: string
  destination: Destination
  context: ContextModel
}

export const PRESETS: PresetPrompt[] = [
  {
    name: 'Safe General (ALLOW)',
    prompt: 'Summarize the key architectural benefits of asynchronous event loops in modern microservices.',
    destination: 'mock',
    context: {
      purpose: 'general_question',
      data_subject: 'none',
      classification: 'public',
    },
  },
  {
    name: 'Customer Email (REDACT)',
    prompt: 'Please send the revised proposal to alex.rivers@example.com before the Thursday status meeting.',
    destination: 'mock',
    context: {
      purpose: 'general_question',
      data_subject: 'none',
      classification: 'public',
    },
  },
  {
    name: 'Confidential SSN (BLOCK)',
    prompt: 'Verify background screening credentials for candidate with SSN 123-45-6789.',
    destination: 'mock',
    context: {
      purpose: 'hr_workflow',
      data_subject: 'employee',
      classification: 'confidential',
    },
  },
  {
    name: 'Patient Record (REVIEW)',
    prompt: 'The patient diagnosed with hypertension needs dosage adjustment review for their prescription.',
    destination: 'mock',
    context: {
      purpose: 'health_information',
      data_subject: 'third_party',
      classification: 'restricted',
    },
  },
]

interface PromptEditorProps {
  prompt: string
  onChange: (value: string) => void
  onSelectPreset: (preset: PresetPrompt) => void
  disabled?: boolean
}

export const PromptEditor: React.FC<PromptEditorProps> = ({
  prompt,
  onChange,
  onSelectPreset,
  disabled = false,
}) => {
  // UTF-8 byte calculation
  const utf8ByteLength = useMemo(() => {
    return new TextEncoder().encode(prompt).length
  }, [prompt])

  const MAX_BYTES = 10240
  const isOverLimit = utf8ByteLength > MAX_BYTES
  const bytePercentage = Math.min(100, Math.round((utf8ByteLength / MAX_BYTES) * 100))

  return (
    <div className="panel-card">
      <div className="panel-header">
        <h2 className="panel-title">
          <FileText size={18} color="#6366f1" aria-hidden="true" />
          Prompt Editor
        </h2>

        {prompt && (
          <button
            type="button"
            className="preset-chip"
            onClick={() => onChange('')}
            disabled={disabled}
            aria-label="Clear prompt text"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}
          >
            <Trash2 size={13} aria-hidden="true" />
            Clear
          </button>
        )}
      </div>

      {/* Preset Scenarios */}
      <div className="presets-bar" role="region" aria-label="Preset demonstration prompts">
        <span className="presets-title">
          <Sparkles size={13} style={{ display: 'inline', marginRight: '4px' }} aria-hidden="true" />
          Demo Presets:
        </span>
        {PRESETS.map((preset) => (
          <button
            key={preset.name}
            type="button"
            className="preset-chip"
            onClick={() => onSelectPreset(preset)}
            disabled={disabled}
          >
            {preset.name}
          </button>
        ))}
      </div>

      {/* Text Area */}
      <div className="form-group">
        <label htmlFor="prompt-input" className="form-label">
          Prompt Content (Max 10 KiB UTF-8)
        </label>
        <textarea
          id="prompt-input"
          className="form-textarea"
          value={prompt}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Enter prompt text for real-time security detection and policy evaluation..."
          disabled={disabled}
          rows={5}
          aria-describedby="prompt-byte-info"
        />
      </div>

      {/* Byte & Char Counter */}
      <div
        id="prompt-byte-info"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.8rem',
          color: isOverLimit ? 'var(--color-block)' : 'var(--text-dim)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {isOverLimit && <AlertCircle size={14} color="var(--color-block)" aria-hidden="true" />}
          <span>
            {utf8ByteLength.toLocaleString()} / {MAX_BYTES.toLocaleString()} UTF-8 bytes ({bytePercentage}%)
          </span>
        </div>
        <span>{prompt.length.toLocaleString()} characters</span>
      </div>

      {/* Visual meter bar */}
      <div className="risk-bar-track" style={{ height: '4px', marginTop: '-0.5rem' }}>
        <div
          className="risk-bar-fill"
          style={{
            width: `${bytePercentage}%`,
            backgroundColor: isOverLimit
              ? 'var(--color-block)'
              : bytePercentage > 80
              ? 'var(--color-redact)'
              : 'var(--border-focus)',
          }}
        />
      </div>
    </div>
  )
}
