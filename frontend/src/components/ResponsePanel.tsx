import React, { useState } from 'react'
import {
  Cpu,
  Copy,
  Check,
  ShieldAlert,
  Clock,
  FileTerminal,
} from 'lucide-react'
import type { PromptExecuteResponse } from '../types/api'

interface ResponsePanelProps {
  response: PromptExecuteResponse
}

export const ResponsePanel: React.FC<ResponsePanelProps> = ({ response }) => {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    if (!response.output) return
    try {
      await navigator.clipboard.writeText(response.output)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard write failed
    }
  }

  // State 1: BLOCKED Execution
  if (response.status === 'blocked' || response.decision === 'BLOCK') {
    return (
      <div className="panel-card" style={{ borderColor: 'var(--color-block-border)' }} role="region" aria-label="Execution Blocked">
        <div className="panel-header">
          <h2 className="panel-title" style={{ color: 'var(--color-block)' }}>
            <ShieldAlert size={18} aria-hidden="true" />
            Execution Blocked by Privacy Policy
          </h2>
          <span className="decision-badge block">BLOCKED</span>
        </div>

        <div
          style={{
            padding: '1rem',
            background: 'var(--color-block-bg)',
            border: '1px solid var(--color-block-border)',
            borderRadius: 'var(--radius-md)',
            color: '#fca5a5',
            fontSize: '0.88rem',
            lineHeight: 1.6,
          }}
        >
          <p>
            <strong>Security Boundary Protection:</strong> This prompt triggered a mandatory BLOCK policy
            rule. AI provider dispatch was terminated immediately with <strong>zero external provider calls</strong>.
          </p>
          <div style={{ marginTop: '0.5rem', color: '#fecaca', fontSize: '0.82rem' }}>
            {response.explanation.summary}
          </div>
        </div>

        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
          Request ID: {response.request_id}
        </div>
      </div>
    )
  }

  // State 2: REVIEW_PENDING Execution
  if (response.status === 'review_pending' || response.decision === 'REVIEW') {
    return (
      <div className="panel-card" style={{ borderColor: 'var(--color-review-border)' }} role="region" aria-label="Execution Review Pending">
        <div className="panel-header">
          <h2 className="panel-title" style={{ color: 'var(--color-review)' }}>
            <Clock size={18} aria-hidden="true" />
            Human Review Required
          </h2>
          <span className="decision-badge review">PENDING REVIEW</span>
        </div>

        <div
          style={{
            padding: '1rem',
            background: 'var(--color-review-bg)',
            border: '1px solid var(--color-review-border)',
            borderRadius: 'var(--radius-md)',
            color: '#d8b4fe',
            fontSize: '0.88rem',
            lineHeight: 1.6,
          }}
        >
          <p>
            <strong>Compliance Intercept:</strong> This prompt contains sensitive information requiring
            authorized human review before dissemination. The request has been held with <strong>zero provider calls</strong>.
          </p>
          <div style={{ marginTop: '0.5rem', color: '#e9d5ff', fontSize: '0.82rem' }}>
            {response.explanation.summary}
          </div>
          {response.ticket_id && (
            <div
              style={{
                marginTop: '0.75rem',
                padding: '0.5rem 0.75rem',
                background: 'rgba(0, 0, 0, 0.25)',
                borderRadius: 'var(--radius-sm)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                border: '1px dashed var(--color-review-border)',
              }}
            >
              <strong>Review Ticket ID:</strong> {response.ticket_id} (Active 24h TTL)
            </div>
          )}
        </div>

        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
          Request ID: {response.request_id}
        </div>
      </div>
    )
  }

  // State 3: COMPLETED Execution (ALLOW or REDACT)
  return (
    <div className="panel-card" style={{ borderColor: 'var(--color-allow-border)' }} role="region" aria-label="Provider Completion Output">
      <div className="panel-header">
        <h2 className="panel-title" style={{ color: 'var(--color-allow)' }}>
          <FileTerminal size={18} aria-hidden="true" />
          AI Provider Response
        </h2>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span className={`decision-badge ${response.decision.toLowerCase()}`}>
            {response.decision}
          </span>

          {response.output && (
            <button
              type="button"
              className="preset-chip"
              onClick={handleCopy}
              aria-label="Copy provider response"
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
            >
              {copied ? (
                <>
                  <Check size={13} color="var(--color-allow)" aria-hidden="true" />
                  Copied
                </>
              ) : (
                <>
                  <Copy size={13} aria-hidden="true" />
                  Copy
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Provider Details Bar */}
      {response.provider && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '1rem',
            padding: '0.5rem 0.75rem',
            background: 'var(--bg-input)',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.78rem',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Cpu size={14} color="#06b6d4" aria-hidden="true" />
            <span>Provider: {response.provider.name}</span>
          </div>
          <div>Model: {response.provider.model}</div>
          <div style={{ marginLeft: 'auto', color: 'var(--color-allow)' }}>
            Status: {response.status}
          </div>
        </div>
      )}

      {/* Output Content */}
      <div className="output-box" tabIndex={0} aria-label="Generated output text">
        {response.output || 'No output text returned.'}
      </div>

      {/* Audit Footnote */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.72rem',
          color: 'var(--text-dim)',
          fontFamily: 'var(--font-mono)',
        }}
      >
        <span>Request ID: {response.request_id}</span>
        <span>Policy: {response.policy_version}</span>
      </div>
    </div>
  )
}
