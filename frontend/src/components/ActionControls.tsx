import React from 'react'
import { ShieldCheck, Send, Loader2, AlertTriangle, CheckCircle2, XCircle, Clock } from 'lucide-react'
import type { PolicyOutcome } from '../types/api'

interface ActionControlsProps {
  onAnalyze: () => void
  onExecute: () => void
  isAnalyzing: boolean
  isExecuting: boolean
  hasAnalyzed: boolean
  isStale: boolean
  latestDecision?: PolicyOutcome
  canExecute: boolean
  hasPermit?: boolean
  promptEmpty: boolean
  isOverLimit: boolean
}

export const ActionControls: React.FC<ActionControlsProps> = ({
  onAnalyze,
  onExecute,
  isAnalyzing,
  isExecuting,
  hasAnalyzed,
  isStale,
  latestDecision,
  canExecute,
  hasPermit,
  promptEmpty,
  isOverLimit,
}) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
      {/* Stale Invalidation Banner */}
      {isStale && hasAnalyzed && (
        <div className="stale-banner" role="alert">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} aria-hidden="true" />
          <div>
            <strong>Input Modified:</strong> Prompt or context metadata changed since last analysis.
            Re-run <em>Analyze Prompt</em> to evaluate updated risks before execution.
          </div>
        </div>
      )}

      {/* Primary Actions */}
      <div className="btn-group">
        {/* Analyze Button */}
        <button
          type="button"
          className="btn btn-primary"
          onClick={onAnalyze}
          disabled={isAnalyzing || isExecuting || promptEmpty || isOverLimit}
          aria-label="Analyze prompt security and evaluate policy"
        >
          {isAnalyzing ? (
            <>
              <Loader2 size={16} className="spin" aria-hidden="true" />
              Analyzing Security...
            </>
          ) : (
            <>
              <ShieldCheck size={18} aria-hidden="true" />
              Analyze Prompt
            </>
          )}
        </button>

        {/* Execute Button */}
        <button
          type="button"
          className="btn btn-success"
          onClick={onExecute}
          disabled={!canExecute || isAnalyzing || isExecuting}
          title={
            !hasAnalyzed
              ? 'Analyze prompt first to determine policy authorization'
              : isStale
              ? 'Analysis is stale: re-analyze before executing'
              : latestDecision === 'BLOCK'
              ? 'Execution blocked by security policy'
              : latestDecision === 'REVIEW' && !hasPermit
              ? 'Execution requires human review sign-off'
              : 'Submit for authoritative server-side execution'
          }
          aria-label="Execute prompt with AI provider"
        >
          {isExecuting ? (
            <>
              <Loader2 size={16} className="spin" aria-hidden="true" />
              Enforcing & Executing...
            </>
          ) : (
            <>
              <Send size={18} aria-hidden="true" />
              Execute Prompt
            </>
          )}
        </button>
      </div>

      {/* Execution Status Guidance Text */}
      <div style={{ fontSize: '0.82rem', color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        {!hasAnalyzed ? (
          <span>Pre-flight policy analysis required prior to provider execution.</span>
        ) : isStale ? (
          <span style={{ color: '#fbbf24' }}>
            Analysis is outdated. Re-analyze required to verify current prompt content.
          </span>
        ) : latestDecision === 'ALLOW' ? (
          <span style={{ color: 'var(--color-allow)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <CheckCircle2 size={14} aria-hidden="true" /> Authorized for direct execution (no sensitive findings).
          </span>
        ) : latestDecision === 'REDACT' ? (
          <span style={{ color: 'var(--color-redact)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <CheckCircle2 size={14} aria-hidden="true" /> Authorized for sanitized execution (verified redactions applied).
          </span>
        ) : latestDecision === 'BLOCK' ? (
          <span style={{ color: 'var(--color-block)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <XCircle size={14} aria-hidden="true" /> Execution forbidden: Mandatory block triggered by policy engine.
          </span>
        ) : latestDecision === 'REVIEW' ? (
          hasPermit ? (
            <span style={{ color: 'var(--color-allow)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              <CheckCircle2 size={14} aria-hidden="true" /> Authorized by Review Permit (single-use cryptographic permit active).
            </span>
          ) : (
            <span style={{ color: 'var(--color-review)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              <Clock size={14} aria-hidden="true" /> Execution suspended: Compliance review required before dispatch.
            </span>
          )
        ) : null}
      </div>
    </div>
  )
}
