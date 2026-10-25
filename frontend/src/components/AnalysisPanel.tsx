import React from 'react'
import {
  ShieldAlert,
  CheckCircle,
  Clock,
  EyeOff,
  Layers,
} from 'lucide-react'
import type { Finding, PolicyOutcome, RiskScore } from '../types/api'

interface AnalysisPanelProps {
  decision: PolicyOutcome
  risk: RiskScore
  findings: Finding[]
  explanation: {
    rule_ids: string[]
    summary: string
    actions: string[]
  }
  policyVersion: string
  requestDigest: string
}

export const AnalysisPanel: React.FC<AnalysisPanelProps> = ({
  decision,
  risk,
  findings,
  explanation,
  policyVersion,
  requestDigest,
}) => {
  const safeFindings = Array.isArray(findings) ? findings : []
  const safeActions = Array.isArray(explanation?.actions) ? explanation.actions : []
  const safeRuleIds = Array.isArray(explanation?.rule_ids) ? explanation.rule_ids : []
  const safeReasonCodes = Array.isArray(risk?.reason_codes) ? risk.reason_codes : []

  const getDecisionIcon = (action: PolicyOutcome) => {
    switch (action) {
      case 'ALLOW':
        return <CheckCircle size={18} aria-hidden="true" />
      case 'REDACT':
        return <EyeOff size={18} aria-hidden="true" />
      case 'BLOCK':
        return <ShieldAlert size={18} aria-hidden="true" />
      case 'REVIEW':
        return <Clock size={18} aria-hidden="true" />
    }
  }

  const getRiskColor = (band: string) => {
    switch (band) {
      case 'low':
        return 'var(--color-allow)'
      case 'moderate':
        return 'var(--color-redact)'
      default:
        return 'var(--color-block)'
    }
  }

  return (
    <div className="panel-card" role="region" aria-label="Privacy Analysis Results">
      <div className="panel-header">
        <h2 className="panel-title">
          <Layers size={18} color="#4f46e5" aria-hidden="true" />
          Privacy Analysis & Policy Decision
        </h2>
        <div className={`decision-badge ${decision.toLowerCase()}`}>
          {getDecisionIcon(decision)}
          <span>{decision}</span>
        </div>
      </div>

      {/* Risk Meter */}
      <div className="risk-meter-container">
        <div className={`risk-score-circle ${risk.band.toLowerCase()}`}>
          <span>{risk.score}</span>
          <span style={{ fontSize: '0.62rem', fontWeight: 600, color: 'var(--text-dim)' }}>/ 100</span>
        </div>

        <div className="risk-meta">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="risk-band-tag">Risk Band: {risk.band.toUpperCase()}</span>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
              {risk.version}
            </span>
          </div>

          <div className="risk-bar-track">
            <div
              className="risk-bar-fill"
              style={{
                width: `${Math.min(100, risk.score)}%`,
                backgroundColor: getRiskColor(risk.band),
              }}
            />
          </div>

          {risk.factors && (
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(5, 1fr)',
                gap: '0.25rem',
                fontSize: '0.68rem',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-muted)',
                marginTop: '0.35rem',
              }}
            >
              <div title="Severity factor S">S: {risk.factors.severity.toFixed(2)}</div>
              <div title="Normalized finding count N">N: {risk.factors.normalized_count.toFixed(2)}</div>
              <div title="Context sensitivity C">C: {risk.factors.context.toFixed(2)}</div>
              <div title="Destination exposure D">D: {risk.factors.destination.toFixed(2)}</div>
              <div title="Identifiability/linkage factor I">I: {risk.factors.identifiability.toFixed(2)}</div>
            </div>
          )}
        </div>
      </div>

      {/* Findings List (Data Minimization: strictly no sensitive values) */}
      <div className="form-group">
        <label className="form-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span>Detected Sensitive Entities ({safeFindings.length})</span>
          <span style={{ textTransform: 'none', color: 'var(--text-dim)', fontSize: '0.75rem' }}>
            Raw values omitted per privacy standard
          </span>
        </label>

        {safeFindings.length === 0 ? (
          <div
            style={{
              padding: '0.75rem',
              background: 'var(--bg-input)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.85rem',
              color: 'var(--color-allow)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            <CheckCircle size={15} aria-hidden="true" />
            Zero sensitive patterns detected in prompt.
          </div>
        ) : (
          <div className="findings-list">
            {safeFindings.map((f, idx) => (
              <div key={`${f.rule_id}-${f.start}-${idx}`} className="finding-item">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span className="finding-tag">{f.category}</span>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{f.rule_id}</span>
                </div>
                <div className="finding-offsets">
                  <span>
                    offsets: [{f.start}..{f.end}] • conf: {Math.round(f.confidence * 100)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Explanation & Reason Codes */}
      <div className="form-group">
        <label className="form-label">Policy Explanation & Actions</label>
        <div
          style={{
            padding: '0.85rem',
            background: 'var(--bg-input)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border-subtle)',
            fontSize: '0.85rem',
            lineHeight: 1.5,
          }}
        >
          <div style={{ marginBottom: '0.5rem' }}>{explanation?.summary || 'Policy evaluation completed.'}</div>

          {safeActions.length > 0 && (
            <ul style={{ paddingLeft: '1.25rem', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
              {safeActions.map((act, i) => (
                <li key={i}>{act}</li>
              ))}
            </ul>
          )}

          {/* Reason Code Tags */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.65rem' }}>
            {safeRuleIds.map((rId) => (
              <span
                key={rId}
                style={{
                  padding: '0.2rem 0.5rem',
                  borderRadius: '4px',
                  background: '#1e293b',
                  color: '#94a3b8',
                  fontSize: '0.72rem',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                #{rId}
              </span>
            ))}
            {safeReasonCodes.map((rc) => (
              <span
                key={rc}
                style={{
                  padding: '0.2rem 0.5rem',
                  borderRadius: '4px',
                  background: '#1e293b',
                  color: '#64748b',
                  fontSize: '0.72rem',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                #{rc}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Metadata Digest */}
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
        <span>Digest: {requestDigest.substring(0, 24)}...</span>
        <span>Engine: {policyVersion}</span>
      </div>
    </div>
  )
}
