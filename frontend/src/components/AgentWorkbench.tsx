import React, { useState } from 'react'
import {
  Bot,
  Play,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  ShieldAlert,
  FileText,
  Search,
  FileSpreadsheet,
  Lock,
} from 'lucide-react'
import { createAgentTask, resumeAgentTask, ApiError } from '../services/api'
import type {
  AgentTaskResponse,
  AgentStep,
  ContextModel,
  Destination,
  ReviewPermit,
} from '../types/api'

export const AGENT_PRESETS = [
  {
    name: '1. Safe Policy Summary (ALLOW)',
    goal: 'Read reference company policy company_policy.txt and format summary report',
    destination: 'mock' as Destination,
    context: {
      purpose: 'general_question' as const,
      data_subject: 'none' as const,
      classification: 'public' as const,
    },
  },
  {
    name: '2. Support PII Scrubbing (REDACT)',
    goal: 'Summarize support details for incident_report_sample.txt with contact test.ops@example.com and EMP-4921',
    destination: 'mock' as Destination,
    context: {
      purpose: 'summarization' as const,
      data_subject: 'employee' as const,
      classification: 'internal' as const,
    },
  },
  {
    name: '3. Mandatory National ID Override (BLOCK)',
    goal: 'Verify background records for National ID 999-00-1234 confidential file',
    destination: 'mock' as Destination,
    context: {
      purpose: 'general_question' as const,
      data_subject: 'none' as const,
      classification: 'public' as const,
    },
  },
  {
    name: '4. Clinical Health Record (REVIEW)',
    goal: 'Review patient clinical cardiovascular diagnosis history for medical evaluation',
    destination: 'mock' as Destination,
    context: {
      purpose: 'health_information' as const,
      data_subject: 'self' as const,
      classification: 'public' as const,
    },
  },
  {
    name: '5. Adversarial Document Quarantine',
    goal: 'Inspect external document adversarial_injection.txt and check for compliance',
    destination: 'mock' as Destination,
    context: {
      purpose: 'general_question' as const,
      data_subject: 'none' as const,
      classification: 'public' as const,
    },
  },
]

interface AgentWorkbenchProps {
  onOpenReviewPortal: () => void
  activePermit: ReviewPermit | null
}

export const AgentWorkbench: React.FC<AgentWorkbenchProps> = ({
  onOpenReviewPortal,
  activePermit,
}) => {
  const [goal, setGoal] = useState<string>(AGENT_PRESETS[0].goal)
  const [destination, setDestination] = useState<Destination>('mock')
  const [context, setContext] = useState<ContextModel>(AGENT_PRESETS[0].context)

  const [activeTask, setActiveTask] = useState<AgentTaskResponse | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)

  const handleSelectPreset = (preset: typeof AGENT_PRESETS[0]) => {
    setGoal(preset.goal)
    setDestination(preset.destination)
    setContext(preset.context)
    setError(null)
  }

  const handleRunTask = async () => {
    if (!goal.trim()) return
    setIsLoading(true)
    setError(null)

    try {
      const response = await createAgentTask({
        goal,
        destination,
        context,
        review_permit: activePermit,
      })
      setActiveTask(response)
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`[${err.code}] ${err.message}`)
      } else if (err instanceof Error) {
        setError(err.message)
      } else {
        setError('Agent task creation failed.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  const handleResumeTask = async () => {
    if (!activeTask || !activePermit) return
    setIsLoading(true)
    setError(null)

    try {
      const response = await resumeAgentTask(activeTask.task_id, {
        review_permit: activePermit,
      })
      setActiveTask(response)
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`[${err.code}] ${err.message}`)
      } else if (err instanceof Error) {
        setError(err.message)
      } else {
        setError('Failed to resume task.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <span className="decision-badge allow"><CheckCircle2 size={13} /> COMPLETED</span>
      case 'waiting_for_approval':
        return <span className="decision-badge review"><Clock size={13} /> WAITING FOR APPROVAL</span>
      case 'blocked':
        return <span className="decision-badge block"><XCircle size={13} /> BLOCKED</span>
      case 'running':
      case 'planning':
        return <span className="decision-badge" style={{ backgroundColor: 'var(--color-primary-bg)', color: 'var(--color-primary)' }}><Bot size={13} /> RUNNING</span>
      default:
        return <span className="decision-badge">{status.toUpperCase()}</span>
    }
  }

  const getToolIcon = (toolName: string) => {
    switch (toolName) {
      case 'read_document':
        return <FileText size={15} color="var(--color-primary)" />
      case 'search_documents':
        return <Search size={15} color="#3b82f6" />
      case 'format_report':
        return <FileSpreadsheet size={15} color="#10b981" />
      case 'summarize_text':
      default:
        return <Bot size={15} color="var(--color-review)" />
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%' }}>
      {/* Top Banner introducing the Secure Task Agent */}
      <div className="panel-card" style={{ borderLeft: '4px solid var(--color-primary)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <Bot size={22} color="var(--color-primary)" />
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
            PrivAI Secure Task Agent
          </h2>
          <span className="decision-badge" style={{ fontSize: '0.7rem', padding: '0.1rem 0.5rem', backgroundColor: 'var(--color-primary-bg)', color: 'var(--color-primary)' }}>
            Bounded & Policy-Governed
          </span>
        </div>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
          The Secure Task Agent creates a bounded multi-step plan, selects exclusively from server-allowlisted tools (
          <code>read_document</code>, <code>search_documents</code>, <code>summarize_text</code>, <code>format_report</code>),
          and enforces the PrivAI privacy firewall at every step before execution.
        </p>
      </div>

      {error && (
        <div className="error-banner" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <AlertTriangle size={18} />
          <div style={{ fontSize: '0.85rem' }}>{error}</div>
        </div>
      )}

      {/* Two Column Grid: Left Goal & Context, Right Plan & Results */}
      <div className="dashboard-grid">
        {/* Left Column: Task Goal Input & Context Configuration */}
        <section style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Preset Buttons */}
          <div className="panel-card">
            <label style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem', display: 'block' }}>
              Synthetic Demonstration Scenarios
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {AGENT_PRESETS.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => handleSelectPreset(preset)}
                  style={{
                    textAlign: 'left',
                    fontSize: '0.8rem',
                    padding: '0.5rem 0.75rem',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <span>{preset.name}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Goal Input Form */}
          <div className="panel-card">
            <label htmlFor="agent-goal" style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem', display: 'block' }}>
              Task Objective / Goal
            </label>
            <textarea
              id="agent-goal"
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              disabled={isLoading}
              rows={4}
              style={{
                width: '100%',
                padding: '0.75rem',
                borderRadius: '8px',
                border: '1px solid var(--border-color)',
                backgroundColor: 'var(--bg-input)',
                color: 'var(--text-main)',
                fontFamily: 'inherit',
                fontSize: '0.9rem',
                resize: 'vertical',
                boxSizing: 'border-box',
              }}
              placeholder="e.g. Read reference company policy company_policy.txt and format summary report"
            />

            {/* Context Selectors */}
            <div style={{ marginTop: '1rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
                  Destination
                </label>
                <select
                  value={destination}
                  onChange={(e) => setDestination(e.target.value as Destination)}
                  disabled={isLoading}
                  style={{ width: '100%', padding: '0.4rem', borderRadius: '6px', border: '1px solid var(--border-color)', backgroundColor: 'var(--bg-input)', color: 'var(--text-main)' }}
                >
                  <option value="mock">mock (offline safe)</option>
                  <option value="groq">groq (cloud LLM)</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
                  Classification
                </label>
                <select
                  value={context.classification}
                  onChange={(e) => setContext({ ...context, classification: e.target.value as any })}
                  disabled={isLoading}
                  style={{ width: '100%', padding: '0.4rem', borderRadius: '6px', border: '1px solid var(--border-color)', backgroundColor: 'var(--bg-input)', color: 'var(--text-main)' }}
                >
                  <option value="public">Public</option>
                  <option value="internal">Internal</option>
                  <option value="confidential">Confidential</option>
                  <option value="restricted">Restricted</option>
                </select>
              </div>
            </div>

            {/* Run Button */}
            <div style={{ marginTop: '1.25rem' }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleRunTask}
                disabled={isLoading || !goal.trim()}
                style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
              >
                <Play size={16} />
                {isLoading ? 'Agent Planning & Executing...' : 'Execute Secure Agent Task'}
              </button>
            </div>
          </div>
        </section>

        {/* Right Column: Execution Plan, Steps, Results, and Approval Banner */}
        <section style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {activeTask ? (
            <>
              {/* Task Header Card */}
              <div className="panel-card">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Task ID:</span>
                    <code style={{ fontSize: '0.8rem', color: 'var(--text-main)' }}>{activeTask.task_id}</code>
                  </div>
                  {getStatusBadge(activeTask.status)}
                </div>

                <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  <div>Completed Steps: <strong style={{ color: 'var(--color-allow)' }}>{activeTask.completed_steps}</strong></div>
                  <div>Blocked Steps: <strong style={{ color: 'var(--color-block)' }}>{activeTask.blocked_steps}</strong></div>
                  <div>Waiting Steps: <strong style={{ color: 'var(--color-review)' }}>{activeTask.waiting_steps}</strong></div>
                </div>
              </div>

              {/* Waiting for Approval Action Banner */}
              {activeTask.status === 'waiting_for_approval' && (
                <div className="panel-card" style={{ borderLeft: '4px solid var(--color-review)', backgroundColor: 'var(--color-review-bg)' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                    <ShieldAlert size={20} color="var(--color-review)" style={{ flexShrink: 0, marginTop: '2px' }} />
                    <div style={{ width: '100%' }}>
                      <h4 style={{ margin: '0 0 0.25rem 0', color: 'var(--color-review)', fontSize: '0.95rem' }}>
                        Compliance Human Review Required
                      </h4>
                      <p style={{ margin: '0 0 0.75rem 0', fontSize: '0.85rem', color: 'var(--text-main)' }}>
                        This task triggered compliance rules. Review ticket <code>{activeTask.pending_ticket_id}</code> was created in SQLite. Zero AI provider or tool calls were made while pending approval.
                      </p>

                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={onOpenReviewPortal}
                          style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
                        >
                          Open Review Portal
                        </button>
                        {activePermit && (
                          <button
                            type="button"
                            className="btn btn-primary"
                            onClick={handleResumeTask}
                            disabled={isLoading}
                            style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
                          >
                            <Lock size={13} style={{ marginRight: '4px' }} />
                            Resume Task with Active Permit
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Blocked by Policy Banner */}
              {activeTask.status === 'blocked' && (
                <div className="panel-card" style={{ borderLeft: '4px solid var(--color-block)', backgroundColor: 'var(--color-block-bg)' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                    <XCircle size={20} color="var(--color-block)" style={{ flexShrink: 0, marginTop: '2px' }} />
                    <div>
                      <h4 style={{ margin: '0 0 0.25rem 0', color: 'var(--color-block)', fontSize: '0.95rem' }}>
                        Execution Blocked by Privacy Firewall
                      </h4>
                      <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-main)' }}>
                        {activeTask.final_answer || 'High-risk content detected. Zero tool and zero provider calls were executed.'}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Bounded Execution Steps */}
              {activeTask.plan && activeTask.plan.steps.length > 0 && (
                <div className="panel-card">
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-main)', margin: '0 0 0.75rem 0' }}>
                    Bounded Multi-Step Plan ({activeTask.plan.steps.length} Steps)
                  </h3>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {activeTask.plan.steps.map((step: AgentStep) => (
                      <div
                        key={step.step_number}
                        style={{
                          padding: '0.75rem',
                          borderRadius: '8px',
                          border: '1px solid var(--border-color)',
                          backgroundColor: 'var(--bg-main)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.5rem',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            {getToolIcon(step.tool_name)}
                            <span style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-main)' }}>
                              Step {step.step_number}: {step.description}
                            </span>
                          </div>
                          <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                            {step.policy_decision && (
                              <span className={`decision-badge ${step.policy_decision.toLowerCase()}`} style={{ fontSize: '0.7rem' }}>
                                {step.policy_decision}
                              </span>
                            )}
                            <span className="decision-badge" style={{ fontSize: '0.7rem' }}>
                              {step.status.toUpperCase()}
                            </span>
                          </div>
                        </div>

                        {/* Tool input / sanitized input */}
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                          <div><strong>Tool:</strong> <code>{step.tool_name}</code></div>
                          {step.sanitized_tool_input ? (
                            <div style={{ marginTop: '0.2rem' }}>
                              <strong>Sanitized Input (REDACT):</strong> <code>{JSON.stringify(step.sanitized_tool_input)}</code>
                            </div>
                          ) : (
                            <div style={{ marginTop: '0.2rem' }}>
                              <strong>Input:</strong> <code>{JSON.stringify(step.tool_input)}</code>
                            </div>
                          )}
                        </div>

                        {/* Tool output if completed */}
                        {step.tool_output && (
                          <div style={{ marginTop: '0.3rem', padding: '0.5rem', borderRadius: '4px', backgroundColor: 'var(--bg-input)', fontSize: '0.78rem' }}>
                            <strong style={{ color: 'var(--color-allow)' }}>Tool Output:</strong>
                            <pre style={{ margin: '0.25rem 0 0 0', whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text-main)' }}>
                              {JSON.stringify(step.tool_output, null, 2)}
                            </pre>
                          </div>
                        )}

                        {step.explanation && (
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                            {step.explanation}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Final Synthesized Answer */}
              {activeTask.status === 'completed' && activeTask.final_answer && (
                <div className="panel-card" style={{ borderLeft: '4px solid var(--color-allow)' }}>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--color-allow)', margin: '0 0 0.5rem 0' }}>
                    Final Task Summary & Synthesis
                  </h3>
                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '0.85rem', color: 'var(--text-main)', fontFamily: 'inherit' }}>
                    {activeTask.final_answer}
                  </pre>

                  {/* Audit References */}
                  {activeTask.audit_references && activeTask.audit_references.length > 0 && (
                    <div style={{ marginTop: '0.75rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-color)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <strong>Cryptographic Audit Digests:</strong>
                      <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1.25rem' }}>
                        {activeTask.audit_references.map((ref, i) => (
                          <li key={i}><code>{ref}</code></li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="panel-card empty-state">
              <Bot className="empty-icon" aria-hidden="true" />
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-main)' }}>
                Secure Task Agent Idle
              </h3>
              <p style={{ maxWidth: '360px', fontSize: '0.85rem' }}>
                Select an agent preset or type an objective on the left, then click{' '}
                <strong>Execute Secure Agent Task</strong> to generate a bounded plan and run allowlisted tools under PrivAI firewall enforcement.
              </p>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
