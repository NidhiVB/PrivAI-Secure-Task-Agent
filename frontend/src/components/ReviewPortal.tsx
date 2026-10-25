import React, { useState, useCallback, useEffect } from 'react'
import {
  ShieldCheck,
  Key,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Send,
  LogOut,
} from 'lucide-react'
import { listPendingReviews, approveReview, rejectReview, getDemoToken } from '../services/api'
import type { ReviewTicket, ReviewPermit } from '../types/api'

interface ReviewPortalProps {
  onApplyPermit?: (permit: ReviewPermit) => void
  activeTicketId?: string | null
}

export const REVIEWER_TOKEN_STORAGE_KEY = 'privai_reviewer_token'
export const REVIEWER_ROLE_STORAGE_KEY = 'privai_reviewer_role'

function base64UrlEncode(strOrBuffer: string | Uint8Array): string {
  let base64 = ''
  if (typeof strOrBuffer === 'string') {
    base64 = btoa(strOrBuffer)
  } else {
    let binary = ''
    const bytes = strOrBuffer
    const len = bytes.byteLength
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    base64 = btoa(binary)
  }
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

/**
 * Mint a cryptographically compliant HS256 JWT using standard Web Crypto API.
 * Uses exact claims and audience/issuer expected by backend decode_reviewer_token.
 */
export async function createReviewerToken(
  userId: string,
  role: string,
  secretKey?: string
): Promise<string> {
  const secret =
    secretKey ||
    (import.meta.env.VITE_JWT_SECRET_KEY as string) ||
    'privai-dev-jwt-secret-replace-in-production-only-32bytes'

  const header = { alg: 'HS256', typ: 'JWT' }
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    sub: userId,
    roles: [role],
    permissions: ['PrivAI:Reviewer'],
    iat: now,
    exp: now + 3600,
    iss: 'privai-auth',
    aud: 'privai-api',
  }

  const encodedHeader = base64UrlEncode(JSON.stringify(header))
  const encodedPayload = base64UrlEncode(JSON.stringify(payload))
  const data = `${encodedHeader}.${encodedPayload}`

  const encoder = new TextEncoder()
  const cryptoObj =
    typeof window !== 'undefined' && window.crypto?.subtle
      ? window.crypto
      : typeof globalThis !== 'undefined' && globalThis.crypto?.subtle
      ? globalThis.crypto
      : null

  if (cryptoObj?.subtle) {
    const key = await cryptoObj.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    )
    const sigBuffer = await cryptoObj.subtle.sign('HMAC', key, encoder.encode(data))
    const encodedSignature = base64UrlEncode(new Uint8Array(sigBuffer))
    return `${data}.${encodedSignature}`
  }

  throw new Error('Web Crypto API is required for reviewer token signing.')
}

export function getStoredReviewerToken(): string {
  try {
    return sessionStorage.getItem(REVIEWER_TOKEN_STORAGE_KEY) || ''
  } catch {
    return ''
  }
}

export function setStoredReviewerToken(token: string): void {
  try {
    if (token) {
      sessionStorage.setItem(REVIEWER_TOKEN_STORAGE_KEY, token.trim())
    } else {
      sessionStorage.removeItem(REVIEWER_TOKEN_STORAGE_KEY)
    }
  } catch {}
}

export function clearStoredReviewerToken(): void {
  try {
    sessionStorage.removeItem(REVIEWER_TOKEN_STORAGE_KEY)
    sessionStorage.removeItem(REVIEWER_ROLE_STORAGE_KEY)
  } catch {}
}

export interface DecodedReviewerClaims {
  sub: string
  roles: string[]
  permissions: string[]
  exp?: number
  iss?: string
  aud?: string
}

export function parseReviewerClaims(rawToken: string): DecodedReviewerClaims | null {
  if (!rawToken || typeof rawToken !== 'string') return null
  const parts = rawToken.trim().split('.')
  if (parts.length !== 3) return null

  // Ensure signature segment has valid base64url characters and is not a malformed mock signature
  const sig = parts[2]
  if (!sig || sig.length % 4 === 1 || sig === 'dev_signature') {
    return null
  }

  try {
    let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    while (b64.length % 4) b64 += '='
    const jsonStr = atob(b64)
    const parsed = JSON.parse(jsonStr)
    if (!parsed || typeof parsed !== 'object') return null
    if (!parsed.sub || !Array.isArray(parsed.roles)) return null
    return parsed as DecodedReviewerClaims
  } catch {
    return null
  }
}

export const ReviewPortal: React.FC<ReviewPortalProps> = ({ onApplyPermit, activeTicketId }) => {
  const [token, setToken] = useState<string>('')
  const [activeRole, setActiveRole] = useState<string>('compliance_officer')
  const [tickets, setTickets] = useState<ReviewTicket[]>([])
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [successMessage, setSuccessMessage] = useState<string | null>(null)
  const [authStatus, setAuthStatus] = useState<'unauthenticated' | 'authenticated'>('unauthenticated')

  // Action state per ticket
  const [actioningTicketId, setActioningTicketId] = useState<string | null>(null)
  const [rationale, setRationale] = useState<string>('')
  const [issuedPermit, setIssuedPermit] = useState<ReviewPermit | null>(null)

  const fetchTickets = useCallback(
    async (tokenOverride?: string) => {
      const activeJwt = (tokenOverride ?? token).trim()
      if (!activeJwt) {
        setAuthStatus('unauthenticated')
        setTickets([])
        return
      }

      setLoading(true)
      setError(null)
      try {
        const res = await listPendingReviews(activeJwt)
        setTickets(res.tickets)
        setAuthStatus('authenticated')
        setStoredReviewerToken(activeJwt)
      } catch (err) {
        clearStoredReviewerToken()
        setAuthStatus('unauthenticated')
        setTickets([])
        setError(err instanceof Error ? err.message : 'Failed to fetch pending tickets.')
      } finally {
        setLoading(false)
      }
    },
    [token]
  )

  // Initial load effect: inspects stored token safely without throwing errors on missing or malformed tokens
  useEffect(() => {
    let isMounted = true
    const initPortal = async () => {
      const stored = getStoredReviewerToken()
      if (!stored) {
        if (isMounted) {
          setAuthStatus('unauthenticated')
          setToken('')
        }
        return
      }

      // Check client-side sanity of stored token
      const claims = parseReviewerClaims(stored)
      const now = Math.floor(Date.now() / 1000)
      if (!claims || (claims.exp && claims.exp < now)) {
        // Stale or malformed token: gracefully clear storage, stay unauthenticated
        clearStoredReviewerToken()
        if (isMounted) {
          setAuthStatus('unauthenticated')
          setToken('')
        }
        return
      }

      if (isMounted) {
        setToken(stored)
        if (claims.roles[0]) {
          setActiveRole(claims.roles[0])
        }
      }
      await fetchTickets(stored)
    }

    initPortal()
    return () => {
      isMounted = false
    }
  }, [fetchTickets])

  const handleRoleSelect = async (role: string) => {
    setActiveRole(role)
    setError(null)
    setLoading(true)
    try {
      let generatedToken = ''
      try {
        // 1. Prefer server-authoritative demo token endpoint
        const res = await getDemoToken(role)
        generatedToken = res.token
      } catch {
        // 2. Fallback to client-side Web Crypto HS256 signing
        generatedToken = await createReviewerToken(`reviewer_${role}`, role)
      }

      setToken(generatedToken)
      setStoredReviewerToken(generatedToken)
      await fetchTickets(generatedToken)
    } catch (err) {
      clearStoredReviewerToken()
      setAuthStatus('unauthenticated')
      setError(err instanceof Error ? err.message : 'Role connection failed.')
    } finally {
      setLoading(false)
    }
  }

  const handleDisconnect = () => {
    clearStoredReviewerToken()
    setToken('')
    setTickets([])
    setError(null)
    setSuccessMessage(null)
    setAuthStatus('unauthenticated')
  }

  const handleApprove = async (ticket: ReviewTicket) => {
    if (!rationale.trim() || rationale.trim().length < 5) {
      setError('A valid justification/rationale of at least 5 characters is required.')
      return
    }
    setActioningTicketId(ticket.ticket_id)
    setError(null)
    try {
      const res = await approveReview(ticket.ticket_id, rationale.trim(), token.trim())
      setSuccessMessage(`Ticket #${ticket.ticket_id.slice(0, 8)} approved successfully.`)
      if (res.permit) {
        setIssuedPermit(res.permit)
      }
      setRationale('')
      await fetchTickets()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Approval failed.')
    } finally {
      setActioningTicketId(null)
    }
  }

  const handleReject = async (ticket: ReviewTicket) => {
    if (!rationale.trim() || rationale.trim().length < 5) {
      setError('A valid rejection rationale of at least 5 characters is required.')
      return
    }
    setActioningTicketId(ticket.ticket_id)
    setError(null)
    try {
      await rejectReview(ticket.ticket_id, rationale.trim(), token.trim())
      setSuccessMessage(`Ticket #${ticket.ticket_id.slice(0, 8)} rejected. Zero provider calls dispatched.`)
      setRationale('')
      await fetchTickets()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Rejection failed.')
    } finally {
      setActioningTicketId(null)
    }
  }

  return (
    <div className="panel-card" style={{ borderColor: 'var(--color-review-border)' }} role="region" aria-label="Enterprise Review Portal">
      <div className="panel-header">
        <h2 className="panel-title" style={{ color: 'var(--color-review)' }}>
          <ShieldCheck size={20} aria-hidden="true" />
          Enterprise Human-Review Portal
        </h2>
        {authStatus === 'authenticated' ? (
          <span className="decision-badge review">AUTHENTICATED RBAC</span>
        ) : (
          <span
            className="decision-badge"
            style={{
              backgroundColor: 'rgba(100, 116, 139, 0.2)',
              color: '#94a3b8',
              border: '1px solid rgba(148, 163, 184, 0.3)',
            }}
          >
            UNAUTHENTICATED
          </span>
        )}
      </div>

      {/* Auth Control Bar */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Quick Role Connect:</span>
          <button
            type="button"
            className={`preset-chip ${activeRole === 'compliance_officer' && token && authStatus === 'authenticated' ? 'active' : ''}`}
            onClick={() => handleRoleSelect('compliance_officer')}
            disabled={loading}
          >
            Compliance Officer
          </button>
          <button
            type="button"
            className={`preset-chip ${activeRole === 'hr_admin' && token && authStatus === 'authenticated' ? 'active' : ''}`}
            onClick={() => handleRoleSelect('hr_admin')}
            disabled={loading}
          >
            HR Administrator
          </button>
          <button
            type="button"
            className={`preset-chip ${activeRole === 'security_admin' && token && authStatus === 'authenticated' ? 'active' : ''}`}
            onClick={() => handleRoleSelect('security_admin')}
            disabled={loading}
          >
            Security Admin (All)
          </button>

          {authStatus === 'authenticated' && (
            <button
              type="button"
              onClick={handleDisconnect}
              className="preset-chip"
              style={{
                color: '#f87171',
                borderColor: 'rgba(239, 68, 68, 0.4)',
                fontSize: '0.75rem',
                marginLeft: 'auto',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
              }}
              title="Disconnect reviewer session"
            >
              <LogOut size={12} />
              Disconnect
            </button>
          )}
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Key size={15} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-dim)' }} />
            <input
              type="password"
              placeholder="Enter JWT Bearer Token (or click a Quick Role Connect above)..."
              value={token}
              onChange={(e) => setToken(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 0.5rem 0.45rem 2.2rem',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-main)',
                fontSize: '0.82rem',
                fontFamily: 'var(--font-mono)',
              }}
            />
          </div>
          <button
            type="button"
            onClick={() => fetchTickets()}
            disabled={loading}
            className="btn btn-secondary"
            style={{ padding: '0.45rem 0.85rem', fontSize: '0.82rem' }}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            Refresh Queue
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div style={{ padding: '0.6rem 0.8rem', background: 'var(--color-block-bg)', border: '1px solid var(--color-block-border)', borderRadius: 'var(--radius-sm)', color: '#fca5a5', fontSize: '0.82rem', marginBottom: '0.75rem' }}>
          <AlertTriangle size={14} style={{ display: 'inline', marginRight: '6px' }} />
          {error}
        </div>
      )}

      {successMessage && (
        <div style={{ padding: '0.6rem 0.8rem', background: 'var(--color-allow-bg)', border: '1px solid var(--color-allow-border)', borderRadius: 'var(--radius-sm)', color: '#6ee7b7', fontSize: '0.82rem', marginBottom: '0.75rem' }}>
          <CheckCircle2 size={14} style={{ display: 'inline', marginRight: '6px' }} />
          {successMessage}
        </div>
      )}

      {/* Issued Permit Notification */}
      {issuedPermit && (
        <div style={{ padding: '0.85rem', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid var(--color-allow-border)', borderRadius: 'var(--radius-md)', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span style={{ fontWeight: 600, color: 'var(--color-allow)', fontSize: '0.88rem' }}>
              Cryptographic Review Permit Issued (5-min TTL)
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Nonce: {issuedPermit.permit_nonce.slice(0, 12)}...
            </span>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.6rem' }}>
            Bound to Ticket ID: <code style={{ color: 'var(--text-main)' }}>{issuedPermit.ticket_id}</code>. Single-use and anti-replay protected.
          </p>
          {onApplyPermit && (
            <button
              type="button"
              className="btn btn-primary"
              style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}
              onClick={() => onApplyPermit(issuedPermit)}
            >
              <Send size={13} style={{ marginRight: '6px' }} />
              Apply Permit & Dispatch Original Prompt
            </button>
          )}
        </div>
      )}

      {/* Pending Tickets Queue */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-main)' }}>
            Active Pending Queue ({tickets.length})
          </span>
          {activeTicketId && (
            <span style={{ fontSize: '0.75rem', color: 'var(--color-review)' }}>
              Current Request Ticket: #{activeTicketId.slice(0, 8)}
            </span>
          )}
        </div>

        {authStatus === 'unauthenticated' ? (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-dim)', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', fontSize: '0.85rem' }}>
            <Clock size={20} style={{ margin: '0 auto 0.5rem auto', opacity: 0.5 }} />
            No active reviewer session. Select a role above or provide a Bearer JWT to connect.
          </div>
        ) : tickets.length === 0 ? (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-dim)', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', fontSize: '0.85rem' }}>
            <Clock size={20} style={{ margin: '0 auto 0.5rem auto', opacity: 0.5 }} />
            No active review tickets matching your assigned role ({activeRole}).
          </div>
        ) : (
          tickets.map((t) => (
            <div
              key={t.ticket_id}
              style={{
                padding: '0.85rem',
                background: t.ticket_id === activeTicketId ? 'rgba(168, 85, 247, 0.08)' : 'var(--bg-input)',
                border: t.ticket_id === activeTicketId ? '1px solid var(--color-review-border)' : '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-main)' }}>
                  #{t.ticket_id.slice(0, 8)}...
                </span>
                <span className="preset-chip" style={{ fontSize: '0.7rem', color: 'var(--color-review)' }}>
                  Assigned: {t.assigned_role}
                </span>
              </div>

              <div style={{ display: 'flex', gap: '1rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                <span>Risk Score: <strong style={{ color: t.risk_score >= 60 ? 'var(--color-block)' : 'var(--color-redact)' }}>{t.risk_score}/100</strong></span>
                <span>Expires At: {new Date(t.expires_at).toLocaleTimeString()} (24h TTL)</span>
              </div>

              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                Triggered Rules: {t.triggered_rule_ids.join(', ')}
              </div>

              {/* Action Form */}
              <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <input
                  type="text"
                  placeholder="Enter decision rationale (min 5 chars)..."
                  value={rationale}
                  onChange={(e) => setRationale(e.target.value)}
                  disabled={actioningTicketId === t.ticket_id}
                  style={{
                    padding: '0.4rem 0.6rem',
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    color: 'var(--text-main)',
                    fontSize: '0.8rem',
                  }}
                />

                <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    onClick={() => handleReject(t)}
                    disabled={actioningTicketId === t.ticket_id}
                    className="preset-chip"
                    style={{ color: 'var(--color-block)', borderColor: 'var(--color-block-border)' }}
                  >
                    <XCircle size={13} style={{ marginRight: '4px' }} />
                    Reject
                  </button>
                  <button
                    type="button"
                    onClick={() => handleApprove(t)}
                    disabled={actioningTicketId === t.ticket_id}
                    className="btn btn-primary"
                    style={{ padding: '0.35rem 0.75rem', fontSize: '0.78rem' }}
                  >
                    <CheckCircle2 size={13} style={{ marginRight: '4px' }} />
                    Approve & Issue Permit
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
