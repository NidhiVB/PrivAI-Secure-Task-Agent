import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { Header } from './components/Header'
import { PromptEditor, PRESETS } from './components/PromptEditor'
import { ContextForm } from './components/ContextForm'
import { ActionControls } from './components/ActionControls'
import { AnalysisPanel } from './components/AnalysisPanel'
import { RedactionPreview } from './components/RedactionPreview'
import { ResponsePanel } from './components/ResponsePanel'
import { ErrorBanner } from './components/ErrorBanner'
import { ReviewPortal } from './components/ReviewPortal'
import { AgentWorkbench } from './components/AgentWorkbench'
import { EmployeePrivacyDemo } from './components/EmployeePrivacyDemo'
import { ErrorBoundary } from './components/ErrorBoundary'
import { analyzePrompt, executePrompt, getHealth, ApiError } from './services/api'
import type {
  ContextModel,
  Destination,
  HealthResponse,
  PromptAnalyzeResponse,
  PromptExecuteResponse,
  ReviewPermit,
} from './types/api'
import { Shield, ShieldCheck, Bot, Users } from 'lucide-react'

export const App: React.FC = () => {
  // Navigation Mode: Privacy Firewall vs Secure Task Agent vs Employee Privacy Demo
  const [activeMode, setActiveMode] = useState<'firewall' | 'agent' | 'employee_demo'>('firewall')

  // Input State (never saved to localStorage per privacy requirement)
  const [prompt, setPrompt] = useState<string>(PRESETS[1].prompt)
  const [destination, setDestination] = useState<Destination>('mock')
  const [context, setContext] = useState<ContextModel>({
    purpose: 'general_question',
    data_subject: 'none',
    classification: 'public',
  })

  // Analysis & Execution State
  const [analysisResult, setAnalysisResult] = useState<PromptAnalyzeResponse | null>(null)
  const [executionResult, setExecutionResult] = useState<PromptExecuteResponse | null>(null)
  const [reviewPermit, setReviewPermit] = useState<ReviewPermit | null>(null)
  const [showReviewPortal, setShowReviewPortal] = useState<boolean>(false)
  const [isStale, setIsStale] = useState<boolean>(false)

  // Loading & Network State
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false)
  const [isExecuting, setIsExecuting] = useState<boolean>(false)
  const [error, setError] = useState<Error | ApiError | null>(null)

  // System Health
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthLoading, setHealthLoading] = useState<boolean>(true)

  // Initial health check
  useEffect(() => {
    let mounted = true
    const checkHealth = async () => {
      try {
        const data = await getHealth()
        if (mounted) {
          setHealth(data)
          setHealthLoading(false)
        }
      } catch {
        if (mounted) {
          setHealth(null)
          setHealthLoading(false)
        }
      }
    }
    checkHealth()
    const interval = setInterval(checkHealth, 30000)
    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [])

  // Invalidate analysis when prompt or context changes (Anti-Bypass Security Invariant)
  const handlePromptChange = useCallback((newPrompt: string) => {
    setPrompt(newPrompt)
    setIsStale(true)
    setExecutionResult(null)
    setReviewPermit(null)
    setError(null)
  }, [])

  const handleDestinationChange = useCallback((newDest: Destination) => {
    setDestination(newDest)
    setIsStale(true)
    setExecutionResult(null)
    setReviewPermit(null)
    setError(null)
  }, [])

  const handleContextChange = useCallback((newContext: ContextModel) => {
    setContext(newContext)
    setIsStale(true)
    setExecutionResult(null)
    setReviewPermit(null)
    setError(null)
  }, [])

  const handleSelectPreset = useCallback((preset: typeof PRESETS[0]) => {
    setPrompt(preset.prompt)
    setDestination(preset.destination)
    setContext(preset.context)
    setIsStale(true)
    setExecutionResult(null)
    setReviewPermit(null)
    setError(null)
  }, [])

  // Validation
  const utf8ByteLength = useMemo(() => new TextEncoder().encode(prompt).length, [prompt])
  const isOverLimit = utf8ByteLength > 10240
  const isPromptEmpty = !prompt.trim()

  // Can execute only if analyzed, NOT stale, and decision is ALLOW/REDACT, or REVIEW with an active permit
  const canExecute = useMemo(() => {
    if (!analysisResult || isStale) return false
    if (analysisResult.decision === 'ALLOW' || analysisResult.decision === 'REDACT') return true
    if (analysisResult.decision === 'REVIEW' && reviewPermit !== null) return true
    return false
  }, [analysisResult, isStale, reviewPermit])

  // Actions
  const handleAnalyze = async () => {
    if (isPromptEmpty || isOverLimit) return
    setIsAnalyzing(true)
    setError(null)

    try {
      const response = await analyzePrompt({
        prompt,
        destination,
        context,
      })
      setAnalysisResult(response)
      setIsStale(false)
      setExecutionResult(null)
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Analysis failed'))
    } finally {
      setIsAnalyzing(false)
    }
  }

  const handleExecute = async () => {
    if (!canExecute) return
    setIsExecuting(true)
    setError(null)

    try {
      const response = await executePrompt({
        prompt,
        destination,
        context,
        review_permit: reviewPermit,
      })
      setExecutionResult(response)
      if (reviewPermit) {
        setReviewPermit(null)
      }
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Execution failed'))
    } finally {
      setIsExecuting(false)
    }
  }

  const handleApplyPermit = useCallback((permit: ReviewPermit) => {
    setReviewPermit(permit)
  }, [])

  return (
    <div className="app-container">
      {/* Header with live firewall health and team access key */}
      <Header health={health} healthLoading={healthLoading} onTeamKeyChange={() => setError(null)} />

      {/* Error notification banner */}
      <ErrorBanner error={error} onDismiss={() => setError(null)} />

      {/* Mode Navigation Tabs */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem' }} role="tablist" aria-label="System Mode">
        <button
          type="button"
          role="tab"
          aria-selected={activeMode === 'firewall'}
          className={`btn ${activeMode === 'firewall' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveMode('firewall')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            fontSize: '0.88rem',
            padding: '0.55rem 1.25rem',
          }}
        >
          <Shield size={16} />
          Privacy Firewall
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeMode === 'agent'}
          className={`btn ${activeMode === 'agent' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveMode('agent')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            fontSize: '0.88rem',
            padding: '0.55rem 1.25rem',
          }}
        >
          <Bot size={16} />
          Secure Task Agent
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeMode === 'employee_demo'}
          className={`btn ${activeMode === 'employee_demo' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveMode('employee_demo')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            fontSize: '0.88rem',
            padding: '0.55rem 1.25rem',
          }}
        >
          <Users size={16} />
          Employee Privacy Demo
        </button>
      </div>

      {activeMode === 'employee_demo' ? (
        <ErrorBoundary fallbackTitle="Employee Privacy Demo Error">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {showReviewPortal && (
              <ReviewPortal
                onApplyPermit={handleApplyPermit}
                activeTicketId={executionResult?.ticket_id}
              />
            )}
            <EmployeePrivacyDemo
              onOpenReviewPortal={() => setShowReviewPortal((prev) => !prev)}
              activePermit={reviewPermit}
            />
          </div>
        </ErrorBoundary>
      ) : activeMode === 'agent' ? (
        <ErrorBoundary fallbackTitle="Secure Agent Workbench Error">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {showReviewPortal && (
              <ReviewPortal
                onApplyPermit={handleApplyPermit}
                activeTicketId={executionResult?.ticket_id}
              />
            )}
            <AgentWorkbench
              onOpenReviewPortal={() => setShowReviewPortal((prev) => !prev)}
              activePermit={reviewPermit}
            />
          </div>
        </ErrorBoundary>
      ) : (
        /* Main Grid: Left Column Editor & Context, Right Column Analysis & Execution */
        <ErrorBoundary fallbackTitle="Privacy Firewall Error">
          <main className="dashboard-grid">
          {/* Left Column: Form Controls */}
          <section style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }} aria-label="Prompt Input Area">
            <PromptEditor
              prompt={prompt}
            onChange={handlePromptChange}
            onSelectPreset={handleSelectPreset}
            disabled={isAnalyzing || isExecuting}
          />

          <ContextForm
            destination={destination}
            context={context}
            onDestinationChange={handleDestinationChange}
            onContextChange={handleContextChange}
            disabled={isAnalyzing || isExecuting}
          />

          <ActionControls
            onAnalyze={handleAnalyze}
            onExecute={handleExecute}
            isAnalyzing={isAnalyzing}
            isExecuting={isExecuting}
            hasAnalyzed={!!analysisResult}
            isStale={isStale}
            latestDecision={analysisResult?.decision}
            canExecute={canExecute}
            hasPermit={!!reviewPermit}
            promptEmpty={isPromptEmpty}
            isOverLimit={isOverLimit}
          />

          {/* Enterprise Review Portal Toggle */}
          <div style={{ marginTop: '0.5rem', display: 'flex', justifyContent: 'center' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setShowReviewPortal((prev) => !prev)}
              style={{
                width: '100%',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                fontSize: '0.85rem',
                padding: '0.6rem 1rem',
              }}
            >
              <ShieldCheck size={16} color="var(--color-review)" />
              {showReviewPortal ? 'Hide Human-Review Portal' : 'Open Enterprise Human-Review Portal'}
              {executionResult?.status === 'review_pending' && (
                <span className="decision-badge review" style={{ fontSize: '0.68rem', padding: '0.1rem 0.4rem', marginLeft: '0.4rem' }}>
                  1 Ticket Pending
                </span>
              )}
            </button>
          </div>
        </section>

        {/* Right Column: Security Analysis & Provider Output */}
        <section style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }} aria-label="Firewall Results Area">
          {showReviewPortal && (
            <ReviewPortal
              onApplyPermit={handleApplyPermit}
              activeTicketId={executionResult?.ticket_id}
            />
          )}

          {analysisResult ? (
            <>
              {/* Privacy Analysis Panel */}
              <AnalysisPanel
                decision={analysisResult.decision}
                risk={analysisResult.risk}
                findings={analysisResult.findings}
                explanation={analysisResult.explanation}
                policyVersion={analysisResult.policy_version}
                requestDigest={analysisResult.request_digest}
              />

              {/* Redaction Preview (Shown when backend provides sanitized prompt or decision is REDACT) */}
              {(analysisResult.decision === 'REDACT' || analysisResult.sanitized_prompt) &&
                analysisResult.sanitized_prompt && (
                  <RedactionPreview
                    sanitizedPrompt={analysisResult.sanitized_prompt}
                    redactions={analysisResult.redactions}
                  />
                )}

              {/* Execution Output Panel (Shown when executed) */}
              {executionResult && <ResponsePanel response={executionResult} />}
            </>
          ) : (
            <div className="panel-card empty-state">
              <Shield className="empty-icon" aria-hidden="true" />
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-main)' }}>
                Privacy Firewall Idle
              </h3>
              <p style={{ maxWidth: '340px', fontSize: '0.85rem' }}>
                Select a demo preset or enter your prompt on the left, then click{' '}
                <strong>Analyze Prompt</strong> to inspect sensitive patterns, calculate risk, and verify policy compliance.
              </p>
            </div>
          )}
        </section>
      </main>
      </ErrorBoundary>
      )}
    </div>
  )
}

export default App
