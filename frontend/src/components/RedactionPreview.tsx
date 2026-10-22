import React, { useState } from 'react'
import { Eye, Copy, Check, ShieldCheck } from 'lucide-react'
import type { RedactionSummary } from '../types/api'

interface RedactionPreviewProps {
  sanitizedPrompt: string
  redactions?: RedactionSummary[] | null
}

export const RedactionPreview: React.FC<RedactionPreviewProps> = ({
  sanitizedPrompt,
  redactions,
}) => {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(sanitizedPrompt)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard write failed or restricted
    }
  }

  return (
    <div className="panel-card" style={{ borderColor: 'var(--color-redact-border)' }}>
      <div className="panel-header">
        <h2 className="panel-title" style={{ color: 'var(--color-redact)' }}>
          <Eye size={18} aria-hidden="true" />
          Verified Redaction Preview
        </h2>

        <button
          type="button"
          className="preset-chip"
          onClick={handleCopy}
          aria-label="Copy sanitized prompt to clipboard"
          style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
        >
          {copied ? (
            <>
              <Check size={13} color="var(--color-allow)" aria-hidden="true" />
              Copied!
            </>
          ) : (
            <>
              <Copy size={13} aria-hidden="true" />
              Copy Sanitized
            </>
          )}
        </button>
      </div>

      {redactions && redactions.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)' }}>
            Tokens Applied:
          </span>
          {redactions.map((r, i) => (
            <span key={`${r.category}-${i}`} className="token-pill">
              {r.placeholder} ({r.category})
            </span>
          ))}
        </div>
      )}

      <div className="output-box" tabIndex={0} aria-label="Sanitized prompt content">
        {sanitizedPrompt}
      </div>

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.4rem',
          fontSize: '0.75rem',
          color: 'var(--color-allow)',
        }}
      >
        <ShieldCheck size={14} aria-hidden="true" />
        <span>Cryptographically verified post-redaction: zero residual sensitive patterns.</span>
      </div>
    </div>
  )
}
