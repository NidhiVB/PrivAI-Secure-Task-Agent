import React, { useState, useEffect, useCallback } from 'react'
import {
  Users,
  Search,
  RotateCcw,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowRight,
  Lock,
  FileText,
  Sparkles,
  ExternalLink,
} from 'lucide-react'
import {
  getEmployees,
  getEmployeeDetail,
  getEmployeeDepartments,
  getEmployeeClassifications,
  resetEmployeeDemoData,
  executeEmployeeOperation,
  resumeAgentTask,
  ApiError,
} from '../services/api'
import type {
  EmployeeSummary,
  EmployeeDetailResponse,
  EmployeeOperationType,
  EmployeeOperationResponse,
  EmployeeResetResponse,
  ReviewPermit,
  Destination,
} from '../types/api'

interface EmployeePrivacyDemoProps {
  onOpenReviewPortal?: () => void
  activePermit?: ReviewPermit | null
}

export const EmployeePrivacyDemo: React.FC<EmployeePrivacyDemoProps> = ({
  onOpenReviewPortal,
  activePermit,
}) => {
  // Directory state
  const [employees, setEmployees] = useState<EmployeeSummary[]>([])
  const [departments, setDepartments] = useState<string[]>([])
  const [classifications, setClassifications] = useState<string[]>([])
  const [selectedEmpId, setSelectedEmpId] = useState<string | null>(null)
  const [selectedDetail, setSelectedDetail] = useState<EmployeeDetailResponse | null>(null)
  const [isLoadingDirectory, setIsLoadingDirectory] = useState<boolean>(true)
  const [isLoadingDetail, setIsLoadingDetail] = useState<boolean>(false)

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [selectedDept, setSelectedDept] = useState<string>('')
  const [selectedClassif, setSelectedClassif] = useState<string>('')

  // Operations and execution state
  const [operation, setOperation] = useState<EmployeeOperationType>('summarize_profile')
  const [destination] = useState<Destination>('mock')
  const [isExecuting, setIsExecuting] = useState<boolean>(false)
  const [isResuming, setIsResuming] = useState<boolean>(false)
  const [operationResult, setOperationResult] = useState<EmployeeOperationResponse | null>(null)
  const [resetFeedback, setResetFeedback] = useState<EmployeeResetResponse | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  // Fetch directory list
  const fetchDirectory = useCallback(async () => {
    setIsLoadingDirectory(true)
    setErrorMessage(null)
    try {
      const resp = await getEmployees({
        query: searchQuery || undefined,
        department: selectedDept || undefined,
        classification: selectedClassif || undefined,
      })
      setEmployees(resp.employees)
      if (resp.employees.length > 0 && !selectedEmpId) {
        setSelectedEmpId(resp.employees[0].employee_id)
      }
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to fetch employee directory')
    } finally {
      setIsLoadingDirectory(false)
    }
  }, [searchQuery, selectedDept, selectedClassif, selectedEmpId])

  // Fetch departments and classifications on mount
  useEffect(() => {
    let mounted = true
    const loadMetadata = async () => {
      try {
        const [depts, classifs] = await Promise.all([
          getEmployeeDepartments(),
          getEmployeeClassifications(),
        ])
        if (mounted) {
          setDepartments(depts)
          setClassifications(classifs)
        }
      } catch {
        // Fallback gracefully
      }
    }
    loadMetadata()
    return () => {
      mounted = false
    }
  }, [])

  // Refetch directory whenever filters change
  useEffect(() => {
    fetchDirectory()
  }, [fetchDirectory])

  // Fetch detail whenever selected employee changes
  useEffect(() => {
    if (!selectedEmpId) {
      setSelectedDetail(null)
      return
    }
    let mounted = true
    const loadDetail = async () => {
      setIsLoadingDetail(true)
      try {
        const detail = await getEmployeeDetail(selectedEmpId)
        if (mounted) {
          setSelectedDetail(detail)
        }
      } catch (err) {
        if (mounted) {
          setErrorMessage(err instanceof Error ? err.message : 'Failed to load employee details')
        }
      } finally {
        if (mounted) {
          setIsLoadingDetail(false)
        }
      }
    }
    loadDetail()
    return () => {
      mounted = false
    }
  }, [selectedEmpId])

  // Reset Demo Data handler
  const handleResetData = async () => {
    setErrorMessage(null)
    setResetFeedback(null)
    try {
      const resp = await resetEmployeeDemoData()
      setResetFeedback(resp)
      setSelectedEmpId('EMP-1001')
      setOperationResult(null)
      await fetchDirectory()
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to reset demo data')
    }
  }

  // Execute operation
  const handleExecuteOperation = async (targetEmpId?: string, targetOp?: EmployeeOperationType) => {
    const empId = targetEmpId || selectedEmpId
    const op = targetOp || operation
    if (!empId) {
      setErrorMessage('Please select an employee first.')
      return
    }

    setIsExecuting(true)
    setErrorMessage(null)
    setResetFeedback(null)

    try {
      const resp = await executeEmployeeOperation({
        employee_id: empId,
        operation: op,
        destination,
        review_permit: activePermit,
      })
      setOperationResult(resp)
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(`[${err.code}] ${err.message}`)
      } else {
        setErrorMessage(err instanceof Error ? err.message : 'Operation execution failed')
      }
    } finally {
      setIsExecuting(false)
    }
  }

  // Quick Preset Handlers (ALLOW, REDACT, BLOCK, REVIEW)
  const triggerPreset = async (preset: 'ALLOW' | 'REDACT' | 'BLOCK' | 'REVIEW') => {
    if (preset === 'ALLOW') {
      setSelectedEmpId('EMP-1001')
      setOperation('summarize_profile')
      await handleExecuteOperation('EMP-1001', 'summarize_profile')
    } else if (preset === 'REDACT') {
      setSelectedEmpId('EMP-1002')
      setOperation('contact_report')
      await handleExecuteOperation('EMP-1002', 'contact_report')
    } else if (preset === 'BLOCK') {
      setSelectedEmpId('EMP-1002')
      setOperation('request_payroll')
      await handleExecuteOperation('EMP-1002', 'request_payroll')
    } else if (preset === 'REVIEW') {
      setSelectedEmpId('EMP-1003')
      setOperation('request_health')
      await handleExecuteOperation('EMP-1003', 'request_health')
    }
  }

  // Resume suspended task with active permit
  const handleResumeTask = async () => {
    if (!operationResult || !operationResult.task_id || !activePermit) {
      return
    }
    setIsResuming(true)
    setErrorMessage(null)
    try {
      const resumedTask = await resumeAgentTask(operationResult.task_id, {
        review_permit: activePermit,
      })
      // Update operation result to reflect completion
      setOperationResult((prev) => {
        if (!prev) return null
        return {
          ...prev,
          status: resumedTask.status,
          policy_decision: 'ALLOW',
          policy_explanation: 'Task resumed and authorized with single-use compliance review permit.',
          final_answer: resumedTask.final_answer || 'Resumed task completed successfully.',
          pending_ticket_id: null,
          steps: resumedTask.plan
            ? resumedTask.plan.steps.map((s) => ({
                step_number: s.step_number,
                description: s.description,
                tool_name: s.tool_name,
                status: s.status,
                policy_decision: s.policy_decision || 'ALLOW',
                policy_reason_codes: s.policy_reason_codes,
                sanitized_tool_input: s.sanitized_tool_input,
                tool_output: s.tool_output,
                explanation: s.explanation,
              }))
            : prev.steps,
        }
      })
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Failed to resume task')
    } finally {
      setIsResuming(false)
    }
  }

  // Badge styling helpers
  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return {
          bg: 'var(--color-allow-bg)',
          border: 'var(--color-allow-border)',
          color: 'var(--color-allow)',
          icon: <ShieldCheck size={16} />,
        }
      case 'REDACT':
        return {
          bg: 'var(--color-redact-bg)',
          border: 'var(--color-redact-border)',
          color: '#fbbf24',
          icon: <AlertTriangle size={16} />,
        }
      case 'BLOCK':
        return {
          bg: 'var(--color-block-bg)',
          border: 'var(--color-block-border)',
          color: '#f87171',
          icon: <XCircle size={16} />,
        }
      case 'REVIEW':
        return {
          bg: 'var(--color-review-bg)',
          border: 'var(--color-review-border)',
          color: '#c084fc',
          icon: <Clock size={16} />,
        }
      default:
        return {
          bg: 'rgba(255, 255, 255, 0.05)',
          border: 'var(--border-subtle)',
          color: 'var(--text-muted)',
          icon: <Shield size={16} />,
        }
    }
  }

  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'PUBLIC':
        return '#06b6d4'
      case 'CONTACT_SENSITIVE':
        return '#f59e0b'
      case 'RESTRICTED_PAYROLL':
        return '#ef4444'
      case 'COMPLIANCE_HEALTH':
        return '#a855f7'
      default:
        return 'var(--text-muted)'
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Module Overview Banner & Reset Demo Data */}
      <div
        className="card"
        style={{
          background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(17, 24, 39, 0.9) 100%)',
          borderColor: 'var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--primary-gradient)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#fff',
                }}
              >
                <Users size={18} />
              </div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
                Employee Privacy Governance Demo
              </h2>
              <span
                style={{
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  padding: '0.15rem 0.5rem',
                  borderRadius: '12px',
                  background: 'rgba(6, 182, 212, 0.15)',
                  color: '#22d3ee',
                  border: '1px solid rgba(6, 182, 212, 0.3)',
                }}
              >
                Synthetic Dataset
              </span>
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', maxWidth: '780px', lineHeight: 1.5 }}>
              Interactive enterprise directory demonstration backed by real Privacy Firewall governance and allowlisted tools.
              Exercising authoritative <strong>ALLOW</strong>, <strong>REDACT</strong>, <strong>BLOCK</strong>, and <strong>REVIEW</strong> decisions with strict database isolation.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              type="button"
              id="reset-demo-data-btn"
              onClick={handleResetData}
              className="btn btn-secondary"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                fontSize: '0.82rem',
                padding: '0.5rem 1rem',
                borderColor: 'rgba(239, 68, 68, 0.4)',
                color: '#fca5a5',
              }}
              title="Resets only privai_demo_employees.db. Historical and forensic databases are strictly preserved."
            >
              <RotateCcw size={14} />
              Reset Demo Data
            </button>
          </div>
        </div>

        {/* Isolation Guarantee Pill */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 0.85rem',
            borderRadius: 'var(--radius-sm)',
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            fontSize: '0.78rem',
            color: 'var(--text-dim)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          <Lock size={12} color="#10b981" />
          <span>Storage: Isolated demo database (<code style={{ color: '#93c5fd' }}>privai_demo_employees.db</code>)</span>
          <span style={{ color: 'var(--border-subtle)' }}>|</span>
          <span style={{ color: '#6ee7b7' }}>SHA-256 Protected: Historical databases strictly isolated</span>
        </div>

        {/* Reset Feedback Notice */}
        {resetFeedback && (
          <div
            style={{
              padding: '0.65rem 0.95rem',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(16, 185, 129, 0.12)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              color: '#6ee7b7',
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            <CheckCircle2 size={16} />
            <span>
              {resetFeedback.message} ({resetFeedback.records_seeded} synthetic employees re-seeded into isolated database).
            </span>
          </div>
        )}

        {/* Error Notification */}
        {errorMessage && (
          <div
            style={{
              padding: '0.65rem 0.95rem',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#fca5a5',
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            <ShieldAlert size={16} />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* One-Click Scenario Presets */}
        <div>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.6rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            One-Click Privacy Scenarios (Demonstrating All 4 Decisions)
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem' }}>
            {/* ALLOW Preset */}
            <button
              type="button"
              id="preset-allow-btn"
              onClick={() => triggerPreset('ALLOW')}
              disabled={isExecuting}
              style={{
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                borderRadius: 'var(--radius-md)',
                padding: '0.75rem 1rem',
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.35rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.88rem', color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <ShieldCheck size={15} /> ALLOW Scenario
                </span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(16, 185, 129, 0.2)', padding: '0.1rem 0.4rem', borderRadius: '4px', color: '#6ee7b7' }}>
                  EMP-1001
                </span>
              </div>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Summarize public profile (Elena Rostova). Safe operational data permitted without sanitization.
              </span>
            </button>

            {/* REDACT Preset */}
            <button
              type="button"
              id="preset-redact-btn"
              onClick={() => triggerPreset('REDACT')}
              disabled={isExecuting}
              style={{
                background: 'rgba(245, 158, 11, 0.08)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                borderRadius: 'var(--radius-md)',
                padding: '0.75rem 1rem',
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.35rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.88rem', color: '#fbbf24', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <AlertTriangle size={15} /> REDACT Scenario
                </span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(245, 158, 11, 0.2)', padding: '0.1rem 0.4rem', borderRadius: '4px', color: '#fde68a' }}>
                  EMP-1002
                </span>
              </div>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Generate contact report (Marcus Vance). Personal email & phone sanitized to deterministic tokens.
              </span>
            </button>

            {/* BLOCK Preset */}
            <button
              type="button"
              id="preset-block-btn"
              onClick={() => triggerPreset('BLOCK')}
              disabled={isExecuting}
              style={{
                background: 'rgba(239, 68, 68, 0.08)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: 'var(--radius-md)',
                padding: '0.75rem 1rem',
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.35rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.88rem', color: '#f87171', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <XCircle size={15} /> BLOCK Scenario
                </span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(239, 68, 68, 0.2)', padding: '0.1rem 0.4rem', borderRadius: '4px', color: '#fca5a5' }}>
                  EMP-1002
                </span>
              </div>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Request payroll compensation access. Unauthorized confidential salary request blocked at firewall.
              </span>
            </button>

            {/* REVIEW Preset */}
            <button
              type="button"
              id="preset-review-btn"
              onClick={() => triggerPreset('REVIEW')}
              disabled={isExecuting}
              style={{
                background: 'rgba(168, 85, 247, 0.08)',
                border: '1px solid rgba(168, 85, 247, 0.3)',
                borderRadius: 'var(--radius-md)',
                padding: '0.75rem 1rem',
                textAlign: 'left',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.35rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.88rem', color: '#c084fc', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <Clock size={15} /> REVIEW Scenario
                </span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(168, 85, 247, 0.2)', padding: '0.1rem 0.4rem', borderRadius: '4px', color: '#e9d5ff' }}>
                  EMP-1003
                </span>
              </div>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Request sensitive health record (Priya Sharma). Suspends task and mints approval ticket.
              </span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(420px, 1.15fr) minmax(440px, 1.35fr)', gap: '1.5rem', alignItems: 'start' }}>
        {/* Left Column: Directory, Search, Field Authorization, & Action Form */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Search & Filters */}
          <div className="card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <div style={{ position: 'relative', flex: 1 }}>
                <Search size={14} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
                <input
                  type="text"
                  id="employee-search-input"
                  placeholder="Search by ID, name, or department..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="input"
                  style={{ paddingLeft: '2.25rem', fontSize: '0.85rem' }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: '140px' }}>
                <label htmlFor="dept-filter" style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block', marginBottom: '0.25rem' }}>
                  Department
                </label>
                <select
                  id="dept-filter"
                  value={selectedDept}
                  onChange={(e) => setSelectedDept(e.target.value)}
                  className="select"
                  style={{ fontSize: '0.82rem', padding: '0.4rem 0.6rem' }}
                >
                  <option value="">All Departments</option>
                  {departments.map((dept) => (
                    <option key={dept} value={dept}>
                      {dept}
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ flex: 1, minWidth: '140px' }}>
                <label htmlFor="classif-filter" style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block', marginBottom: '0.25rem' }}>
                  Classification
                </label>
                <select
                  id="classif-filter"
                  value={selectedClassif}
                  onChange={(e) => setSelectedClassif(e.target.value)}
                  className="select"
                  style={{ fontSize: '0.82rem', padding: '0.4rem 0.6rem' }}
                >
                  <option value="">All Classifications</option>
                  {classifications.map((cl) => (
                    <option key={cl} value={cl}>
                      {cl.toUpperCase()}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Directory Table */}
          <div className="card" style={{ padding: '0', overflow: 'hidden' }}>
            <div
              style={{
                padding: '0.75rem 1rem',
                borderBottom: '1px solid var(--border-subtle)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: 'rgba(255, 255, 255, 0.02)',
              }}
            >
              <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)' }}>
                Synthetic Directory ({employees.length} records)
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                Select an employee to inspect
              </span>
            </div>

            <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
              {isLoadingDirectory ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                  Loading synthetic directory...
                </div>
              ) : employees.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                  No matching employees found.
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-dim)', textAlign: 'left' }}>
                      <th style={{ padding: '0.5rem 0.75rem' }}>ID</th>
                      <th style={{ padding: '0.5rem 0.75rem' }}>Name</th>
                      <th style={{ padding: '0.5rem 0.75rem' }}>Department</th>
                      <th style={{ padding: '0.5rem 0.75rem' }}>Role</th>
                      <th style={{ padding: '0.5rem 0.75rem' }}>Class.</th>
                    </tr>
                  </thead>
                  <tbody>
                    {employees.map((emp) => {
                      const isSelected = emp.employee_id === selectedEmpId
                      return (
                        <tr
                          key={emp.employee_id}
                          id={`emp-row-${emp.employee_id}`}
                          onClick={() => setSelectedEmpId(emp.employee_id)}
                          style={{
                            cursor: 'pointer',
                            borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                            background: isSelected ? 'rgba(79, 70, 229, 0.15)' : 'transparent',
                            transition: 'background 0.15s ease',
                          }}
                        >
                          <td style={{ padding: '0.5rem 0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 600, color: isSelected ? '#93c5fd' : 'var(--text-main)' }}>
                            {emp.employee_id}
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem', fontWeight: 500, color: isSelected ? '#fff' : 'var(--text-main)' }}>
                            {emp.name}
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem', color: 'var(--text-muted)' }}>
                            {emp.department}
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem', color: 'var(--text-muted)' }}>
                            {emp.job_title}
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem' }}>
                            <span
                              style={{
                                fontSize: '0.68rem',
                                padding: '0.15rem 0.4rem',
                                borderRadius: '4px',
                                fontFamily: 'var(--font-mono)',
                                background:
                                  emp.data_classification === 'confidential' || emp.data_classification === 'restricted'
                                    ? 'rgba(239, 68, 68, 0.15)'
                                    : 'rgba(6, 182, 212, 0.15)',
                                color:
                                  emp.data_classification === 'confidential' || emp.data_classification === 'restricted'
                                    ? '#fca5a5'
                                    : '#67e8f9',
                                border:
                                  emp.data_classification === 'confidential' || emp.data_classification === 'restricted'
                                    ? '1px solid rgba(239, 68, 68, 0.3)'
                                    : '1px solid rgba(6, 182, 212, 0.3)',
                              }}
                            >
                              {emp.data_classification.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Authorized Fields View */}
          <div className="card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Shield size={16} color="#3b82f6" />
                <h3 style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-main)' }}>
                  Backend Field Authorization Policy
                </h3>
              </div>
              {selectedDetail && (
                <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                  {selectedDetail.employee.employee_id} ({selectedDetail.employee.name})
                </span>
              )}
            </div>

            {isLoadingDetail ? (
              <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.82rem' }}>
                Loading authorization rules...
              </div>
            ) : selectedDetail ? (
              <div style={{ maxHeight: '240px', overflowY: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-dim)', textAlign: 'left' }}>
                      <th style={{ padding: '0.35rem 0.5rem' }}>Field</th>
                      <th style={{ padding: '0.35rem 0.5rem' }}>Sensitivity Tier</th>
                      <th style={{ padding: '0.35rem 0.5rem' }}>Policy Action</th>
                      <th style={{ padding: '0.35rem 0.5rem' }}>Masked Viewer Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedDetail.field_authorizations.map((field) => {
                      const decBadge = getDecisionBadge(field.governance_action)
                      return (
                        <tr key={field.field_name} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.03)' }}>
                          <td style={{ padding: '0.35rem 0.5rem', fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-main)' }}>
                            {field.field_name}
                          </td>
                          <td style={{ padding: '0.35rem 0.5rem' }}>
                            <span
                              style={{
                                fontSize: '0.68rem',
                                color: getTierColor(field.sensitivity_tier),
                                fontWeight: 600,
                              }}
                            >
                              {field.sensitivity_tier}
                            </span>
                          </td>
                          <td style={{ padding: '0.35rem 0.5rem' }}>
                            <span
                              style={{
                                fontSize: '0.68rem',
                                padding: '0.1rem 0.35rem',
                                borderRadius: '3px',
                                background: decBadge.bg,
                                color: decBadge.color,
                                border: `1px solid ${decBadge.border}`,
                                fontWeight: 700,
                              }}
                            >
                              {field.governance_action}
                            </span>
                          </td>
                          <td
                            style={{
                              padding: '0.35rem 0.5rem',
                              fontFamily: 'var(--font-mono)',
                              color: field.authorized_for_viewer ? 'var(--text-muted)' : '#f87171',
                            }}
                          >
                            {field.masked_display_value}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>
                Select an employee from directory above.
              </div>
            )}
          </div>

          {/* Operation Selector & Submit */}
          <div className="card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <h3 style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-main)' }}>
              Choose Privacy Operation
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem' }}>
              <button
                type="button"
                onClick={() => setOperation('summarize_profile')}
                className={`btn ${operation === 'summarize_profile' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.8rem', padding: '0.5rem', justifyContent: 'flex-start' }}
              >
                1. Summarize Profile (ALLOW)
              </button>
              <button
                type="button"
                onClick={() => setOperation('contact_report')}
                className={`btn ${operation === 'contact_report' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.8rem', padding: '0.5rem', justifyContent: 'flex-start' }}
              >
                2. Contact Report (REDACT)
              </button>
              <button
                type="button"
                onClick={() => setOperation('request_payroll')}
                className={`btn ${operation === 'request_payroll' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.8rem', padding: '0.5rem', justifyContent: 'flex-start' }}
              >
                3. Request Payroll (BLOCK)
              </button>
              <button
                type="button"
                onClick={() => setOperation('request_health')}
                className={`btn ${operation === 'request_health' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.8rem', padding: '0.5rem', justifyContent: 'flex-start' }}
              >
                4. Request Health (REVIEW)
              </button>
            </div>

            <button
              type="button"
              id="submit-employee-op-btn"
              onClick={() => handleExecuteOperation()}
              disabled={isExecuting || !selectedEmpId}
              className="btn btn-primary"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                padding: '0.65rem 1rem',
                fontSize: '0.88rem',
                fontWeight: 600,
                marginTop: '0.25rem',
              }}
            >
              {isExecuting ? (
                <>
                  <div className="spinner" style={{ width: '14px', height: '14px' }} />
                  Dispatching to PrivAI Agent...
                </>
              ) : (
                <>
                  <Sparkles size={16} />
                  Submit Request to PrivAI Security Agent
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Column: Policy Decision, Execution Steps, Redaction Demonstration, and Results */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {operationResult ? (
            <>
              {/* Decision Banner Card */}
              {(() => {
                const dec = getDecisionBadge(operationResult.policy_decision)
                return (
                  <div
                    className="card"
                    id="operation-result-banner"
                    style={{
                      background: dec.bg,
                      borderColor: dec.border,
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.75rem',
                      padding: '1.25rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                        <div style={{ color: dec.color }}>{dec.icon}</div>
                        <div>
                          <span
                            style={{
                              fontSize: '0.72rem',
                              color: 'var(--text-dim)',
                              textTransform: 'uppercase',
                              letterSpacing: '0.05em',
                              display: 'block',
                            }}
                          >
                            Backend Policy Decision
                          </span>
                          <span style={{ fontSize: '1.25rem', fontWeight: 800, color: dec.color, letterSpacing: '-0.02em' }}>
                            {operationResult.policy_decision}
                          </span>
                        </div>
                      </div>

                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <span
                          style={{
                            fontSize: '0.75rem',
                            fontFamily: 'var(--font-mono)',
                            padding: '0.25rem 0.5rem',
                            borderRadius: '4px',
                            background: 'rgba(0,0,0,0.3)',
                            color: 'var(--text-main)',
                            border: '1px solid rgba(255, 255, 255, 0.1)',
                          }}
                        >
                          Status: {operationResult.status.toUpperCase()}
                        </span>
                        <span
                          style={{
                            fontSize: '0.75rem',
                            fontFamily: 'var(--font-mono)',
                            padding: '0.25rem 0.5rem',
                            borderRadius: '4px',
                            background: 'rgba(0,0,0,0.3)',
                            color: operationResult.risk_score > 50 ? '#fca5a5' : '#6ee7b7',
                            border: '1px solid rgba(255, 255, 255, 0.1)',
                          }}
                        >
                          Risk: {operationResult.risk_score}/100
                        </span>
                      </div>
                    </div>

                    <p style={{ fontSize: '0.85rem', color: 'var(--text-main)', margin: 0, lineHeight: 1.5 }}>
                      {operationResult.policy_explanation}
                    </p>

                    {operationResult.policy_reason_codes.length > 0 && (
                      <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                        {operationResult.policy_reason_codes.map((code) => (
                          <span
                            key={code}
                            style={{
                              fontSize: '0.7rem',
                              fontFamily: 'var(--font-mono)',
                              background: 'rgba(0, 0, 0, 0.25)',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '3px',
                              color: dec.color,
                            }}
                          >
                            {code}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })()}

              {/* Controlled Demonstration View for REDACT */}
              {operationResult.operation === 'contact_report' && (
                <div
                  className="card"
                  id="controlled-redaction-view"
                  style={{
                    background: 'rgba(245, 158, 11, 0.04)',
                    borderColor: 'rgba(245, 158, 11, 0.3)',
                    padding: '1.25rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.75rem',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <AlertTriangle size={16} color="#fbbf24" />
                      <h4 style={{ fontSize: '0.92rem', fontWeight: 700, color: '#fde68a' }}>
                        Controlled Redaction Demonstration View
                      </h4>
                    </div>
                    {operationResult.downstream_sanitized_confirmed && (
                      <span
                        style={{
                          fontSize: '0.72rem',
                          background: 'rgba(16, 185, 129, 0.15)',
                          color: '#6ee7b7',
                          border: '1px solid rgba(16, 185, 129, 0.3)',
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.25rem',
                        }}
                      >
                        <CheckCircle2 size={12} /> Downstream Sanitized Only
                      </span>
                    )}
                  </div>

                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0 }}>
                    In compliance with PrivAI security invariants, raw contact personal data is isolated to this controlled preview. Downstream agent tools and AI models receive only the sanitized token stream.
                  </p>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                    <div style={{ background: 'var(--bg-input)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block', marginBottom: '0.35rem' }}>
                        Original Test Value (Protected)
                      </span>
                      {operationResult.original_test_values && (
                        <div style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                          <div><span style={{ color: 'var(--text-dim)' }}>ID:</span> <span style={{ color: '#f87171' }}>{operationResult.original_test_values.employee_id}</span></div>
                          <div><span style={{ color: 'var(--text-dim)' }}>Email:</span> <span style={{ color: '#f87171' }}>{operationResult.original_test_values.email}</span></div>
                          <div><span style={{ color: 'var(--text-dim)' }}>Phone:</span> <span style={{ color: '#f87171' }}>{operationResult.original_test_values.phone}</span></div>
                        </div>
                      )}
                    </div>

                    <div style={{ background: 'var(--bg-input)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                      <span style={{ fontSize: '0.72rem', color: '#fbbf24', textTransform: 'uppercase', display: 'block', marginBottom: '0.35rem' }}>
                        Sanitized Output Stream (Downstream)
                      </span>
                      {operationResult.sanitized_values && (
                        <div style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                          <div><span style={{ color: 'var(--text-dim)' }}>ID:</span> <span className="token-pill">{operationResult.sanitized_values.employee_id}</span></div>
                          <div><span style={{ color: 'var(--text-dim)' }}>Email:</span> <span className="token-pill">{operationResult.sanitized_values.email}</span></div>
                          <div><span style={{ color: 'var(--text-dim)' }}>Phone:</span> <span className="token-pill">{operationResult.sanitized_values.phone}</span></div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* REVIEW Pending Action Card */}
              {operationResult.policy_decision === 'REVIEW' && (
                <div
                  className="card"
                  id="pending-review-action-card"
                  style={{
                    background: 'rgba(168, 85, 247, 0.08)',
                    borderColor: 'rgba(168, 85, 247, 0.35)',
                    padding: '1.25rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.75rem',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Clock size={16} color="#c084fc" />
                      <h4 style={{ fontSize: '0.92rem', fontWeight: 700, color: '#e9d5ff' }}>
                        Compliance Human Review Required
                      </h4>
                    </div>
                    {operationResult.pending_ticket_id && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#d8b4fe', background: 'rgba(0,0,0,0.3)', padding: '0.15rem 0.45rem', borderRadius: '4px' }}>
                        {operationResult.pending_ticket_id}
                      </span>
                    )}
                  </div>

                  <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', margin: 0 }}>
                    Task execution is safely paused in status <code>waiting_for_approval</code>. Zero sensitive health tools or external AI providers were called. To resume, approve the pending ticket in the Human Review Portal.
                  </p>

                  <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', marginTop: '0.25rem' }}>
                    {onOpenReviewPortal && (
                      <button
                        type="button"
                        id="open-review-portal-btn"
                        onClick={onOpenReviewPortal}
                        className="btn btn-secondary"
                        style={{
                          fontSize: '0.82rem',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          borderColor: 'rgba(168, 85, 247, 0.4)',
                          color: '#e9d5ff',
                        }}
                      >
                        <ExternalLink size={14} />
                        Open Human Review Portal
                      </button>
                    )}

                    {activePermit && operationResult.status === 'waiting_for_approval' && (
                      <button
                        type="button"
                        id="resume-with-permit-btn"
                        onClick={handleResumeTask}
                        disabled={isResuming}
                        className="btn btn-primary"
                        style={{
                          fontSize: '0.82rem',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                        }}
                      >
                        {isResuming ? (
                          <>
                            <div className="spinner" style={{ width: '12px', height: '12px' }} />
                            Resuming Task...
                          </>
                        ) : (
                          <>
                            <ArrowRight size={14} />
                            Resume Task with Active Permit ({activePermit.permit_nonce.slice(0, 8)}...)
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </div>
              )}

              {/* Execution Steps Trace */}
              <div className="card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h4 style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <FileText size={15} color="#38bdf8" />
                    Agent Tool Execution Trace ({operationResult.steps.length} steps)
                  </h4>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    Task ID: {operationResult.task_id}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {operationResult.steps.length === 0 ? (
                    <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem', padding: '0.5rem' }}>
                      Execution blocked before step dispatch (0 tool calls).
                    </div>
                  ) : (
                    operationResult.steps.map((st) => {
                      const dec = getDecisionBadge(st.policy_decision)
                      return (
                        <div
                          key={st.step_number}
                          style={{
                            padding: '0.65rem 0.85rem',
                            borderRadius: 'var(--radius-sm)',
                            background: 'rgba(255, 255, 255, 0.02)',
                            border: '1px solid var(--border-subtle)',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '0.35rem',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontWeight: 600, fontSize: '0.82rem', color: 'var(--text-main)' }}>
                              Step {st.step_number}: {st.description}
                            </span>
                            <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                              <span
                                style={{
                                  fontSize: '0.68rem',
                                  padding: '0.1rem 0.35rem',
                                  borderRadius: '3px',
                                  background: dec.bg,
                                  color: dec.color,
                                  border: `1px solid ${dec.border}`,
                                  fontWeight: 700,
                                }}
                              >
                                {st.policy_decision}
                              </span>
                              <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                                {st.status}
                              </span>
                            </div>
                          </div>

                          <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                            Tool: <span style={{ color: '#38bdf8' }}>{st.tool_name}</span>
                          </div>

                          {st.sanitized_tool_input && (
                            <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', background: 'rgba(0,0,0,0.2)', padding: '0.35rem', borderRadius: '4px' }}>
                              <span style={{ color: '#fbbf24' }}>Sanitized Input:</span> {JSON.stringify(st.sanitized_tool_input)}
                            </div>
                          )}
                        </div>
                      )
                    })
                  )}
                </div>
              </div>

              {/* Synthesized Output Result */}
              <div className="card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Synthesized Agent Response
                </span>
                <div className="output-box" id="employee-op-output-box" style={{ fontSize: '0.82rem' }}>
                  {operationResult.final_answer}
                </div>
              </div>

              {/* Audit Trail Reference */}
              {operationResult.audit_references.length > 0 && (
                <div
                  style={{
                    padding: '0.75rem',
                    borderRadius: 'var(--radius-sm)',
                    background: 'rgba(15, 23, 42, 0.5)',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '0.75rem',
                    color: 'var(--text-dim)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.3rem',
                  }}
                >
                  <span style={{ fontWeight: 600, color: 'var(--text-muted)' }}>
                    Cryptographic Audit Digests (Stored in Shared Audit Log):
                  </span>
                  {operationResult.audit_references.map((ref, idx) => (
                    <div key={idx} style={{ fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>
                      • {ref}
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            /* Idle State */
            <div className="card empty-state" style={{ minHeight: '400px' }}>
              <Users className="empty-icon" />
              <h3 style={{ fontSize: '1rem', color: 'var(--text-main)', marginTop: '0.5rem' }}>
                No Privacy Operation Dispatched Yet
              </h3>
              <p style={{ maxWidth: '420px', fontSize: '0.85rem' }}>
                Select an employee from the synthetic directory or click one of the <strong>One-Click Privacy Scenarios</strong> above to see live backend policy decisions, redactions, and execution traces.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
