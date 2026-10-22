import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AnalysisPanel } from '../components/AnalysisPanel'
import type { Finding, RiskScore } from '../types/api'

describe('AnalysisPanel component', () => {
  const mockRisk: RiskScore = {
    score: 18,
    band: 'low',
    factors: {
      severity: 0.2,
      count: 1,
      normalized_count: 0.2,
      context: 0.0,
      destination: 0.0,
      identifiability: 0.2,
    },
    factor_contributions: { severity: 0.06 },
    reason_codes: ['SCORE-BAND-LOW'],
    version: 'risk-v1',
  }

  const mockFindings: Finding[] = [
    {
      rule_id: 'DETECT-EMAIL-001',
      category: 'EMAIL',
      start: 12,
      end: 32,
      confidence: 0.95,
      severity: 0.4,
    },
  ]

  const mockExplanation = {
    rule_ids: ['RULE-PII-REDACT'],
    summary: 'Email detected; verified redaction required prior to execution.',
    actions: ['Inspect sanitized prompt preview.'],
  }

  it('renders ALLOW decision badge and risk score', () => {
    render(
      <AnalysisPanel
        decision="ALLOW"
        risk={mockRisk}
        findings={[]}
        explanation={{
          rule_ids: ['RULE-DEFAULT-ALLOW'],
          summary: 'No sensitive entities detected.',
          actions: [],
        }}
        policyVersion="policy-v1"
        requestDigest="sha256:1234567890abcdef12345678"
      />
    )

    expect(screen.getByText('ALLOW')).toBeInTheDocument()
    expect(screen.getByText('18')).toBeInTheDocument()
    expect(screen.getByText(/Risk Band: LOW/i)).toBeInTheDocument()
    expect(screen.getByText(/Zero sensitive patterns detected in prompt/i)).toBeInTheDocument()
  })

  it('renders REDACT decision and finding category without raw sensitive text', () => {
    render(
      <AnalysisPanel
        decision="REDACT"
        risk={{ ...mockRisk, score: 35, band: 'moderate' }}
        findings={mockFindings}
        explanation={mockExplanation}
        policyVersion="policy-v1"
        requestDigest="sha256:1234567890abcdef12345678"
      />
    )

    expect(screen.getByText('REDACT')).toBeInTheDocument()
    expect(screen.getByText('EMAIL')).toBeInTheDocument()
    expect(screen.getByText('DETECT-EMAIL-001')).toBeInTheDocument()
    expect(screen.getByText(/offsets: \[12\.\.32\]/i)).toBeInTheDocument()
    expect(screen.getByText(/95%/i)).toBeInTheDocument()

    // Verifies raw email or prompt is never in findings display
    expect(screen.queryByText(/@example\.com/i)).not.toBeInTheDocument()
  })

  it('renders BLOCK decision and explanations', () => {
    render(
      <AnalysisPanel
        decision="BLOCK"
        risk={{ ...mockRisk, score: 85, band: 'high' }}
        findings={[
          {
            rule_id: 'DETECT-NATID-001',
            category: 'NATIONAL_ID',
            start: 0,
            end: 11,
            confidence: 0.99,
            severity: 1.0,
          },
        ]}
        explanation={{
          rule_ids: ['RULE-BLOCK-CONFIDENTIAL-PII'],
          summary: 'National identifiers strictly forbidden in external destination.',
          actions: ['Remove SSN and re-evaluate.'],
        }}
        policyVersion="policy-v1"
        requestDigest="sha256:1234567890abcdef12345678"
      />
    )

    expect(screen.getByText('BLOCK')).toBeInTheDocument()
    expect(screen.getByText('NATIONAL_ID')).toBeInTheDocument()
    expect(screen.getByText(/National identifiers strictly forbidden/i)).toBeInTheDocument()
    expect(screen.getByText(/Remove SSN and re-evaluate/i)).toBeInTheDocument()
  })

  it('renders REVIEW decision', () => {
    render(
      <AnalysisPanel
        decision="REVIEW"
        risk={{ ...mockRisk, score: 65, band: 'high' }}
        findings={[
          {
            rule_id: 'DETECT-HEALTH-001',
            category: 'HEALTH',
            start: 5,
            end: 20,
            confidence: 0.9,
            severity: 0.8,
          },
        ]}
        explanation={{
          rule_ids: ['RULE-HEALTH-REVIEW'],
          summary: 'Protected health information intercepted.',
          actions: ['Compliance sign-off needed.'],
        }}
        policyVersion="policy-v1"
        requestDigest="sha256:1234567890abcdef12345678"
      />
    )

    expect(screen.getByText('REVIEW')).toBeInTheDocument()
    expect(screen.getByText('HEALTH')).toBeInTheDocument()
  })
})
